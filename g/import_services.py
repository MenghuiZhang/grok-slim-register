"""Multi-target account import services and background job orchestration.

The module intentionally has no Flask dependency.  ``app.py`` supplies the
existing sub2api importer and the in-memory registration records at runtime.
Secrets are stored in ``import_services.json`` but are never exposed by the
redacted configuration returned to the browser.
"""

from __future__ import annotations

import copy
import json
import os
import re
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

import requests


try:
    from filelock import FileLock
except Exception:  # pragma: no cover - dependency is installed in production
    FileLock = None  # type: ignore[assignment]


TARGETS = (
    "sub2api",
    "cpa_local",
    "cpa_remote",
    "grok2api_local",
    "grok2api_web",
    "grok2api_console",
    "grok2api_build",
    "grok2api_jiujiu",
)

TARGET_LABELS = {
    "sub2api": "Sub2API",
    "cpa_local": "CPA 本地凭证",
    "cpa_remote": "CLIProxyAPI",
    "grok2api_local": "grok2api 本地池",
    "grok2api_web": "grok2api Web",
    "grok2api_console": "grok2api Console",
    "grok2api_build": "grok2api Build",
    "grok2api_jiujiu": "grok2api jiujiu",
}

# SSO-only fan-out runs before OAuth-dependent targets.  This lets ordinary
# management uploads use the configured worker pool while device flow remains
# serial and ensures CPA failure never blocks Web/Console/local delivery.
EXECUTION_ORDER = (
    "sub2api",
    "grok2api_local",
    "grok2api_web",
    "grok2api_console",
    "grok2api_jiujiu",
    "cpa_local",
    "cpa_remote",
    "grok2api_build",
)

SECRET_FIELDS = {
    ("services", "sub2api", "password"),
    ("services", "cpa", "management_key"),
    ("services", "grok2api", "password"),
    ("services", "grok2api", "app_key"),
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _deep_merge(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _atomic_json(path: Path, payload: Any, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temp_name, mode)
        except OSError:
            pass
        os.replace(temp_name, path)
        temp_name = ""
        # fsync the directory entry as well as the file contents.  This keeps
        # a successful save durable across an immediate container/host restart.
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            # Some filesystems (notably a few Docker Desktop mounts) do not
            # support directory fsync.  The atomic replace above still holds.
            pass
    finally:
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def mask_secret(value: str, keep: int = 3) -> str:
    value = str(value or "")
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "•" * len(value)
    return value[:keep] + "•" * min(12, len(value) - keep * 2) + value[-keep:]


def default_config(base_dir: Path) -> dict:
    return {
        "version": 1,
        "services": {
            "sub2api": {
                "base_url": "http://127.0.0.1:9898",
                "email": "",
                "password": "",
                "group_name": "grok",
                "group_id": "",
                "auto_targets": [],
                "proxy_mode": "direct",
                "proxy_url": "",
                "tls_verify": True,
                "timeout": 120,
            },
            "cpa": {
                "base_url": "",
                "management_key": "",
                "auto_targets": [],
                "proxy_mode": "direct",
                "proxy_url": "",
                "tls_verify": True,
                "timeout": 60,
            },
            "grok2api": {
                "remote_type": "chenyme",
                "base_url": "",
                "username": "",
                "password": "",
                "app_key": "",
                "pool_name": "ssoBasic",
                "allow_legacy_full_save": False,
                "auto_targets": [],
                "proxy_mode": "direct",
                "proxy_url": "",
                "tls_verify": True,
                "timeout": 120,
            },
        },
        "runtime": {
            "upload_workers": 5,
            "history_limit": 100,
            "history_days": 30,
            "oauth_timeout": 28,
        },
        "test_states": {
            "sub2api": {"status": "untested", "message": "尚未测试", "tested_at": ""},
            "cpa": {"status": "untested", "message": "尚未测试", "tested_at": ""},
            "grok2api": {"status": "untested", "message": "尚未测试", "tested_at": ""},
        },
        "paths": {
            "cpa_dir": str((base_dir / "converted_auth" / "cpa").resolve()),
            "grok2api_token_file": str(
                (base_dir / "converted_auth" / "grok2api" / "token.json").resolve()
            ),
            "jobs_dir": str((base_dir / "logs" / "import_jobs").resolve()),
        },
    }


class ImportConfigStore:
    def __init__(self, base_dir: Path, env_reader: Callable[[], dict] | None = None):
        self.base_dir = Path(base_dir).resolve()
        # Configuration is application state, not generated credential output.
        # ``data`` is the dedicated persistent Docker mount.  Keep the former
        # location for a one-way, non-destructive migration.
        self.path = self.base_dir / "data" / "import_services.json"
        self.legacy_path = self.base_dir / "converted_auth" / "import_services.json"
        self._env_reader = env_reader or (lambda: dict(os.environ))
        self._lock = threading.RLock()

    def _migrated_defaults(self) -> dict:
        cfg = default_config(self.base_dir)
        env = self._env_reader() or {}
        sub2 = cfg["services"]["sub2api"]
        sub2["base_url"] = str(
            env.get("SUB2API_URL") or env.get("UPSTREAM_URL") or sub2["base_url"]
        ).strip()
        sub2["email"] = str(env.get("UPSTREAM_ADMIN_EMAIL") or "").strip()
        sub2["password"] = str(env.get("UPSTREAM_ADMIN_PASSWORD") or "")
        sub2["group_name"] = str(env.get("SUB2API_GROK_GROUP_NAME") or "grok").strip()
        sub2["group_id"] = str(env.get("SUB2API_GROK_GROUP_ID") or "").strip()
        return cfg

    def load(self) -> dict:
        with self._lock:
            defaults = self._migrated_defaults()
            source = self.path
            migrate_legacy = False
            if not source.is_file() and self.legacy_path.is_file():
                source = self.legacy_path
                migrate_legacy = True
            if not source.is_file():
                return defaults
            try:
                raw = json.loads(source.read_text(encoding="utf-8"))
            except Exception:
                broken = source.with_name(f"{source.name}.broken-{int(time.time())}")
                try:
                    source.replace(broken)
                except OSError:
                    pass
                return defaults
            merged = _deep_merge(defaults, raw if isinstance(raw, dict) else {})
            merged["paths"] = defaults["paths"]
            if migrate_legacy:
                _atomic_json(self.path, merged)
            return merged

    def save(self, incoming: dict) -> dict:
        if not isinstance(incoming, dict):
            raise ValueError("配置必须是 JSON object")
        with self._lock:
            before = self.load()
            # Browser callers may edit service/runtime settings only.  Paths,
            # version and test states are server-owned and cannot be forged.
            allowed_incoming = {
                key: copy.deepcopy(incoming[key])
                for key in ("services", "runtime", "clear_secrets")
                if key in incoming
            }
            candidate = _deep_merge(before, allowed_incoming)
            # Empty secret input means keep; explicit ``clear_secrets`` clears it.
            clear = set(str(x) for x in allowed_incoming.get("clear_secrets", []) if x)
            for path in SECRET_FIELDS:
                root, service, field = path
                sent = ((allowed_incoming.get(root) or {}).get(service) or {}).get(field, None)
                dotted = f"{service}.{field}"
                if dotted in clear:
                    candidate[root][service][field] = ""
                elif sent in (None, ""):
                    candidate[root][service][field] = before[root][service].get(field, "")
            candidate.pop("clear_secrets", None)
            self._validate(candidate)
            for service in ("sub2api", "cpa", "grok2api"):
                if before["services"].get(service) != candidate["services"].get(service):
                    candidate["test_states"][service] = {
                        "status": "untested",
                        "message": "配置已变化，请重新测试",
                        "tested_at": "",
                    }
                    # A changed service may not retain automatic delivery until retested.
                    candidate["services"][service]["auto_targets"] = []
            _atomic_json(self.path, candidate)
            return candidate

    def update_test_state(self, service: str, result: dict) -> dict:
        if service not in ("sub2api", "cpa", "grok2api"):
            raise ValueError("未知服务")
        with self._lock:
            cfg = self.load()
            cfg["test_states"][service] = {
                "status": "passed" if result.get("ok") else "failed",
                "message": str(result.get("message") or result.get("error") or "测试失败")[:500],
                "tested_at": _utc_now(),
                "details": result.get("details") or {},
            }
            _atomic_json(self.path, cfg)
            return cfg

    def set_auto_targets(self, service: str, targets: Iterable[str]) -> dict:
        if service not in ("sub2api", "cpa", "grok2api"):
            raise ValueError("未知服务")
        targets = [str(x) for x in targets if str(x) in TARGETS]
        cfg = self.load()
        if targets and cfg["test_states"][service].get("status") != "passed":
            raise ValueError("请先测试该服务，测试通过后才能开启自动导入")
        current = cfg["services"][service]
        if service == "sub2api" and targets:
            if not all(str(current.get(key) or "").strip() for key in ("base_url", "email", "password", "group_name")):
                raise ValueError("Sub2API 自动导入缺少地址、管理员凭据或分组名称")
        if service == "cpa" and "cpa_remote" in targets:
            if not str(current.get("base_url") or "").strip() or not str(current.get("management_key") or "").strip():
                raise ValueError("CLIProxyAPI 自动上传缺少地址或管理密钥")
        if service == "grok2api":
            remote = set(targets) - {"grok2api_local"}
            if remote and not str(current.get("base_url") or "").strip():
                raise ValueError("grok2api 远端自动导入缺少服务地址")
            if current.get("remote_type") == "chenyme":
                if "grok2api_jiujiu" in remote:
                    raise ValueError("chenyme 模式不能启用 jiujiu 目标")
                if remote and not all(str(current.get(key) or "").strip() for key in ("username", "password")):
                    raise ValueError("chenyme 自动导入缺少管理员用户名或密码")
            elif remote:
                if remote - {"grok2api_jiujiu"}:
                    raise ValueError("jiujiu 模式仅支持 jiujiu 远端目标")
                if not str(current.get("app_key") or "").strip():
                    raise ValueError("jiujiu 自动导入缺少 app key")
        cfg["services"][service]["auto_targets"] = list(dict.fromkeys(targets))
        _atomic_json(self.path, cfg)
        return cfg

    def redacted(self, cfg: dict | None = None) -> dict:
        result = copy.deepcopy(cfg or self.load())
        for root, service, field in SECRET_FIELDS:
            value = str(result[root][service].get(field) or "")
            result[root][service][field] = ""
            result[root][service][f"{field}_set"] = bool(value)
            result[root][service][f"{field}_masked"] = mask_secret(value)
        return result

    def _validate(self, cfg: dict) -> None:
        services = cfg.get("services") or {}
        for name in ("sub2api", "cpa", "grok2api"):
            service = services.get(name)
            if not isinstance(service, dict):
                raise ValueError(f"缺少 {name} 配置")
            if service.get("proxy_mode") not in ("direct", "register", "custom"):
                raise ValueError(f"{name} proxy_mode 无效")
            if service.get("proxy_mode") == "custom" and not str(service.get("proxy_url") or "").strip():
                raise ValueError(f"{name} 自定义代理不能为空")
            timeout = int(service.get("timeout") or 0)
            if timeout < 5 or timeout > 600:
                raise ValueError(f"{name} timeout 必须在 5 到 600 秒之间")
            service["timeout"] = timeout
            service["tls_verify"] = bool(service.get("tls_verify", True))
            auto = [str(x) for x in service.get("auto_targets") or []]
            service["auto_targets"] = list(dict.fromkeys(x for x in auto if x in TARGETS))
        grok2api = services["grok2api"]
        if grok2api.get("remote_type") not in ("chenyme", "jiujiu"):
            raise ValueError("grok2api remote_type 仅支持 chenyme/jiujiu")
        if grok2api.get("pool_name") not in ("ssoBasic", "ssoSuper"):
            raise ValueError("grok2api pool_name 仅支持 ssoBasic/ssoSuper")
        runtime = cfg.get("runtime") or {}
        workers = int(runtime.get("upload_workers") or 5)
        if workers < 1 or workers > 20:
            raise ValueError("upload_workers 必须在 1 到 20 之间")
        runtime["upload_workers"] = workers
        runtime["history_limit"] = max(1, min(500, int(runtime.get("history_limit") or 100)))
        runtime["history_days"] = max(1, min(365, int(runtime.get("history_days") or 30)))
        runtime["oauth_timeout"] = max(10, min(120, int(runtime.get("oauth_timeout") or 28)))
        cfg["paths"] = default_config(self.base_dir)["paths"]


def _proxy_kwargs(service: dict, register_proxy: str = "") -> dict:
    # 已确认的运行规则：下游测试/换票/上传强制直连，
    # 不得复用注册代理，也不继承系统环境代理。
    return {
        "proxies": {"http": "", "https": ""},
        "verify": bool(service.get("tls_verify", True)),
    }


class ImportTargets:
    """Network and local-storage adapters for non-sub2api targets."""

    def __init__(self, base_dir: Path, config_store: ImportConfigStore):
        self.base_dir = Path(base_dir).resolve()
        self.config_store = config_store
        self._chenyme_auth: dict[tuple[str, str], dict] = {}
        self._auth_lock = threading.Lock()

    def _request(self, method: str, url: str, service: dict, register_proxy: str = "", **kwargs):
        kwargs.setdefault("timeout", int(service.get("timeout") or 60))
        kwargs.update({k: v for k, v in _proxy_kwargs(service, register_proxy).items() if k not in kwargs})
        session = requests.Session()
        session.trust_env = False
        return session.request(method, url, **kwargs)

    @staticmethod
    def _error(response) -> str:
        try:
            payload = response.json()
            if isinstance(payload, dict):
                error = payload.get("error")
                if isinstance(error, dict):
                    return str(error.get("message") or error.get("code") or error)[:300]
                return str(payload.get("message") or payload.get("detail") or payload)[:300]
        except Exception:
            pass
        return str(getattr(response, "text", "") or "")[:300]

    def test_cpa(self, cfg: dict, register_proxy: str = "") -> dict:
        service = cfg["services"]["cpa"]
        base = str(service.get("base_url") or "").strip().rstrip("/")
        key = str(service.get("management_key") or "").strip()
        cpa_dir = Path(cfg["paths"]["cpa_dir"]).resolve()
        allowed = (self.base_dir / "converted_auth").resolve()
        if allowed not in cpa_dir.parents:
            return {"ok": False, "message": "CPA 目录必须位于 converted_auth 内"}
        try:
            cpa_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return {"ok": False, "message": f"CPA 本地目录不可用: {exc}"}
        if not base and not key:
            return {"ok": True, "message": "CPA 本地目录可用；CLIProxyAPI 远端未配置", "details": {"local": True, "remote": False}}
        if not base or not key:
            return {"ok": False, "message": "CLIProxyAPI 地址和管理密钥必须同时填写"}
        try:
            response = self._request(
                "GET",
                f"{base}/v0/management/auth-files",
                service,
                register_proxy,
                headers={"Authorization": f"Bearer {key}", "X-Management-Key": key},
            )
        except Exception as exc:
            return {"ok": False, "message": f"连接 CLIProxyAPI 失败: {exc}"}
        ok = 200 <= response.status_code < 300
        return {
            "ok": ok,
            "message": "CLIProxyAPI 鉴权通过" if ok else f"CLIProxyAPI 测试失败 HTTP {response.status_code}: {self._error(response)}",
            "details": {"status": response.status_code, "base_url": base},
        }

    def upload_cpa(self, auth: dict, cfg: dict, register_proxy: str = "") -> dict:
        service = cfg["services"]["cpa"]
        base = str(service.get("base_url") or "").strip().rstrip("/")
        key = str(service.get("management_key") or "").strip()
        if not base or not key:
            raise ValueError("CLIProxyAPI 未配置地址或管理密钥")
        email = str(auth.get("email") or "").strip()
        filename = re.sub(r"[^A-Za-z0-9_.-]+", "_", email or "xai-account") + ".json"
        body = (json.dumps(auth, ensure_ascii=False) + "\n").encode("utf-8")
        response = self._request(
            "POST",
            f"{base}/v0/management/auth-files",
            service,
            register_proxy,
            headers={"Authorization": f"Bearer {key}", "X-Management-Key": key},
            files={"file": (filename, body, "application/json")},
        )
        if not 200 <= response.status_code < 300:
            raise RuntimeError(f"HTTP {response.status_code}: {self._error(response)}")
        return {"ok": True, "name": filename, "status": response.status_code}

    @staticmethod
    def _normalize_sso(value: str) -> str:
        token = str(value or "").strip()
        return token[4:] if token.startswith("sso=") else token

    def test_grok2api(self, cfg: dict, register_proxy: str = "") -> dict:
        service = cfg["services"]["grok2api"]
        token_path = Path(cfg["paths"]["grok2api_token_file"])
        try:
            token_path.parent.mkdir(parents=True, exist_ok=True)
            if token_path.exists():
                payload = json.loads(token_path.read_text(encoding="utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("本地 token.json 根节点不是 object")
        except Exception as exc:
            return {"ok": False, "message": f"本地池检查失败: {exc}"}
        base = str(service.get("base_url") or "").strip()
        if not base:
            return {"ok": True, "message": "grok2api 本地池可用；远端未配置", "details": {"local": True}}
        try:
            if service.get("remote_type") == "chenyme":
                self._chenyme_login(service, register_proxy, force=True)
                return {"ok": True, "message": "grok2api chenyme 管理员登录通过", "details": {"local": True, "remote": "chenyme"}}
            bases = self._jiujiu_bases(base)
            key = str(service.get("app_key") or "").strip()
            if not key:
                return {"ok": False, "message": "jiujiu 模式缺少 app key"}
            response = self._request(
                "GET", f"{bases[0]}/tokens", service, register_proxy, params={"app_key": key}
            )
            ok = 200 <= response.status_code < 300
            return {"ok": ok, "message": "grok2api jiujiu 只读探测通过" if ok else f"jiujiu 探测失败 HTTP {response.status_code}: {self._error(response)}"}
        except Exception as exc:
            return {"ok": False, "message": f"grok2api 测试失败: {exc}"}

    def add_local(self, sso: str, email: str, cfg: dict) -> dict:
        token = self._normalize_sso(sso)
        if not token:
            raise ValueError("SSO 为空")
        path = Path(cfg["paths"]["grok2api_token_file"]).resolve()
        allowed = (self.base_dir / "converted_auth").resolve()
        if allowed not in path.parents:
            raise ValueError("grok2api token 文件必须位于 converted_auth 内")
        path.parent.mkdir(parents=True, exist_ok=True)
        if FileLock is None:
            raise RuntimeError("filelock 依赖不可用")
        lock_path = str(path) + ".lock"
        with FileLock(lock_path, timeout=30):
            data: dict = {}
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("token.json 根节点不是 object")
            pool_name = cfg["services"]["grok2api"].get("pool_name") or "ssoBasic"
            pool = data.get(pool_name) or []
            if not isinstance(pool, list):
                raise ValueError(f"{pool_name} 不是数组")
            existing = {
                self._normalize_sso(item if isinstance(item, str) else item.get("token", ""))
                for item in pool
                if isinstance(item, (str, dict))
            }
            if token not in existing:
                pool.append({"token": token, "tags": ["auto-register"], "note": email})
            data[pool_name] = pool
            if path.exists():
                backup = path.with_suffix(path.suffix + ".bak")
                backup.write_bytes(path.read_bytes())
                try:
                    backup.chmod(0o600)
                except OSError:
                    pass
            _atomic_json(path, data)
        return {"ok": True, "pool": pool_name, "duplicate": token in existing}

    @staticmethod
    def _chenyme_base(value: str) -> str:
        base = str(value or "").strip().rstrip("/")
        for suffix in ("/api/admin/v1/accounts/web/import", "/api/admin/v1/auth/login", "/api/admin/v1"):
            if base.lower().endswith(suffix):
                return base[: -len(suffix)].rstrip("/")
        return base

    def _chenyme_login(self, service: dict, register_proxy: str, force: bool = False) -> str:
        base = self._chenyme_base(service.get("base_url"))
        username = str(service.get("username") or "").strip()
        password = str(service.get("password") or "")
        if not base or not username or not password:
            raise ValueError("chenyme 缺少地址、用户名或密码")
        key = (base, username)
        now = time.time()
        with self._auth_lock:
            cached = self._chenyme_auth.get(key) or {}
            if not force and cached.get("token") and float(cached.get("expires_at") or 0) > now + 30:
                return str(cached["token"])
            response = self._request(
                "POST",
                f"{base}/api/admin/v1/auth/login",
                service,
                register_proxy,
                headers={"Content-Type": "application/json"},
                json={"username": username, "password": password},
            )
            if not 200 <= response.status_code < 300:
                raise RuntimeError(f"登录失败 HTTP {response.status_code}: {self._error(response)}")
            payload = response.json()
            tokens = ((payload.get("data") or {}).get("tokens") or {}) if isinstance(payload, dict) else {}
            access = str(tokens.get("accessToken") or "").strip()
            if not access:
                raise RuntimeError("登录响应缺少 accessToken")
            expires_at = now + 300
            expires_text = str(tokens.get("accessTokenExpiresAt") or "")
            if expires_text:
                try:
                    expires_at = datetime.fromisoformat(expires_text.replace("Z", "+00:00")).timestamp()
                except ValueError:
                    pass
            self._chenyme_auth[key] = {"token": access, "expires_at": expires_at}
            return access

    @staticmethod
    def _parse_sse(text: str) -> dict:
        complete = None
        for block in str(text or "").replace("\r\n", "\n").split("\n\n"):
            event = "message"
            lines: list[str] = []
            for line in block.splitlines():
                if line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    lines.append(line[5:].lstrip())
            if not lines:
                continue
            raw = "\n".join(lines)
            try:
                data = json.loads(raw)
            except Exception:
                data = {"message": raw}
            if event == "error":
                raise RuntimeError(str(data.get("message") or data.get("error") or data))
            if event == "complete" and isinstance(data, dict):
                complete = data
        if complete is None:
            raise RuntimeError("导入响应缺少 complete 事件")
        return complete

    def _chenyme_import(self, route: str, document: dict, label: str, cfg: dict, register_proxy: str) -> dict:
        service = cfg["services"]["grok2api"]
        base = self._chenyme_base(service.get("base_url"))
        endpoint = f"{base}/api/admin/v1/{route.lstrip('/')}"
        content = (json.dumps(document, ensure_ascii=False) + "\n").encode("utf-8")

        def send(token: str):
            return self._request(
                "POST",
                endpoint,
                service,
                register_proxy,
                headers={"Authorization": f"Bearer {token}"},
                files={"files": (f"grok-{label.lower()}-import.json", content, "application/json")},
            )

        token = self._chenyme_login(service, register_proxy)
        response = send(token)
        if response.status_code == 401:
            response = send(self._chenyme_login(service, register_proxy, force=True))
        if not 200 <= response.status_code < 300:
            raise RuntimeError(f"HTTP {response.status_code}: {self._error(response)}")
        result = self._parse_sse(response.text)
        return {"ok": True, **{k: result.get(k, 0) for k in ("created", "updated", "synced", "syncFailed")}}

    def import_chenyme_sso(self, provider: str, sso: str, email: str, cfg: dict, register_proxy: str = "") -> dict:
        token = self._normalize_sso(sso)
        if provider == "web":
            return self._chenyme_import(
                "accounts/web/import",
                {"provider": "grok_web", "accounts": [{"name": email or "Grok Web", "email": email, "sso_token": token, "tier": "auto"}]},
                "Web",
                cfg,
                register_proxy,
            )
        if provider == "console":
            return self._chenyme_import(
                "accounts/console/import",
                {"provider": "grok_console", "accounts": [{"name": email or "Grok Console", "email": email, "sso_token": token}]},
                "Console",
                cfg,
                register_proxy,
            )
        raise ValueError("未知 chenyme SSO provider")

    def import_chenyme_build(self, auth: dict, cfg: dict, register_proxy: str = "") -> dict:
        entry = {
            "provider": "grok_build",
            "name": auth.get("email") or "Grok Build",
            "email": auth.get("email") or "",
            "access_token": auth.get("access_token") or "",
            "refresh_token": auth.get("refresh_token") or "",
            "id_token": auth.get("id_token") or "",
            "token_type": auth.get("token_type") or "Bearer",
            "expires_at": auth.get("expired") or auth.get("expires_at") or "",
            "expires_in": int(auth.get("expires_in") or 0),
            "sub": auth.get("sub") or "",
            "user_id": auth.get("user_id") or "",
            "principal_id": auth.get("principal_id") or "",
            "team_id": auth.get("team_id") or "",
        }
        if auth.get("client_id"):
            entry["client_id"] = auth["client_id"]
        return self._chenyme_import(
            "accounts/import", {"provider": "grok_build", "accounts": [entry]}, "Build", cfg, register_proxy
        )

    @staticmethod
    def _jiujiu_bases(base: str) -> list[str]:
        base = str(base or "").strip().rstrip("/")
        if base.lower().endswith("/admin/api"):
            return [base]
        return list(dict.fromkeys([base, f"{base}/api" if base.lower().endswith("/admin") else f"{base}/admin/api"]))

    def import_jiujiu(self, sso: str, cfg: dict, register_proxy: str = "") -> dict:
        service = cfg["services"]["grok2api"]
        base = str(service.get("base_url") or "").strip()
        key = str(service.get("app_key") or "").strip()
        if not base or not key:
            raise ValueError("jiujiu 缺少地址或 app key")
        pool = "basic" if service.get("pool_name") == "ssoBasic" else "super"
        incompatible = []
        for api_base in self._jiujiu_bases(base):
            response = self._request(
                "POST",
                f"{api_base}/tokens/add",
                service,
                register_proxy,
                params={"app_key": key},
                json={"tokens": [self._normalize_sso(sso)], "pool": pool, "tags": ["auto-register"]},
            )
            if 200 <= response.status_code < 300:
                return {"ok": True, "pool": pool, "status": response.status_code}
            if response.status_code in (404, 405):
                incompatible.append(f"{api_base}: HTTP {response.status_code}")
                continue
            raise RuntimeError(f"HTTP {response.status_code}: {self._error(response)}")
        if not bool(service.get("allow_legacy_full_save", False)):
            raise RuntimeError("/tokens/add 不受支持；旧版全量保存未启用: " + "; ".join(incompatible))

        current = None
        selected_base = ""
        etag = ""
        load_errors: list[str] = []
        for api_base in self._jiujiu_bases(base):
            response = self._request(
                "GET", f"{api_base}/tokens", service, register_proxy, params={"app_key": key}
            )
            if response.status_code != 200:
                load_errors.append(f"{api_base}: HTTP {response.status_code}")
                continue
            payload = response.json()
            candidate = payload.get("tokens") if isinstance(payload, dict) and "tokens" in payload else payload
            if not isinstance(candidate, dict):
                load_errors.append(f"{api_base}: unexpected payload")
                continue
            current = candidate
            selected_base = api_base
            etag = str(response.headers.get("ETag") or response.headers.get("etag") or "")
            break
        if current is None or not selected_base:
            raise RuntimeError("无法安全读取旧版 token 池: " + "; ".join(load_errors))
        if not etag:
            raise RuntimeError("旧版接口未返回 ETag，拒绝并发不安全的全量保存")
        pool_name = str(service.get("pool_name") or "ssoBasic")
        items = current.get(pool_name) or []
        if not isinstance(items, list):
            raise RuntimeError(f"{pool_name} 不是数组")
        normalized = self._normalize_sso(sso)
        existing = {
            self._normalize_sso(item if isinstance(item, str) else item.get("token", ""))
            for item in items
            if isinstance(item, (str, dict))
        }
        if normalized not in existing:
            items.append({"token": normalized, "tags": ["auto-register"]})
        current[pool_name] = items
        response = self._request(
            "POST",
            f"{selected_base}/tokens",
            service,
            register_proxy,
            params={"app_key": key},
            headers={"If-Match": etag, "Content-Type": "application/json"},
            json=current,
        )
        if not 200 <= response.status_code < 300:
            raise RuntimeError(f"旧版全量保存失败 HTTP {response.status_code}: {self._error(response)}")
        return {"ok": True, "pool": pool_name, "legacy": True, "duplicate": normalized in existing}


class ImportJobManager:
    def __init__(
        self,
        base_dir: Path,
        config_store: ImportConfigStore,
        targets: ImportTargets,
        *,
        sub2api_importer: Callable[..., dict],
        token_exchanger: Callable[[str, int], dict],
        token_exchanger_enabled: Callable[[], bool] | None = None,
        register_proxy_getter: Callable[[], str] | None = None,
        log: Callable[[str, str], None] | None = None,
        on_job_complete: Callable[[dict], None] | None = None,
        source_resolver: Callable[[dict, list[dict]], list[dict]] | None = None,
    ):
        self.base_dir = Path(base_dir).resolve()
        self.config_store = config_store
        self.targets = targets
        self.sub2api_importer = sub2api_importer
        self.token_exchanger = token_exchanger
        # 返回 False 时导入任务不再调本机 device flow 兜底换票（注册侧已关自动换票）
        self.token_exchanger_enabled = token_exchanger_enabled or (lambda: True)
        self.register_proxy_getter = register_proxy_getter or (lambda: "")
        self.log = log or (lambda _message, _level="info": None)
        self.on_job_complete = on_job_complete
        self.source_resolver = source_resolver
        self._jobs: dict[str, dict] = {}
        self._private_accounts: dict[str, list[dict]] = {}
        self._lock = threading.RLock()
        self._oauth_lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="import-job")
        self._load_history()

    @staticmethod
    def _safe_job(job: dict) -> dict:
        result = copy.deepcopy(job)
        result.pop("config_snapshot", None)
        for account in result.get("accounts") or []:
            account.pop("sso", None)
            account.pop("auth_token", None)
        return result

    def _job_path(self, job_id: str, cfg: dict | None = None) -> Path:
        cfg = cfg or self.config_store.load()
        return Path(cfg["paths"]["jobs_dir"]) / f"{job_id}.json"

    def _persist(self, job: dict) -> None:
        _atomic_json(self._job_path(job["id"]), self._safe_job(job))

    def _load_history(self) -> None:
        cfg = self.config_store.load()
        jobs_dir = Path(cfg["paths"]["jobs_dir"])
        jobs_dir.mkdir(parents=True, exist_ok=True)
        for path in sorted(jobs_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                job = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(job, dict) or not job.get("id"):
                    continue
                if job.get("status") in ("queued", "running", "cancelling"):
                    job["status"] = "interrupted"
                    job["message"] = "服务重启导致任务中断；请重新选择来源并重试未完成目标"
                    job["finished_at"] = _utc_now()
                    _atomic_json(path, job)
                self._jobs[str(job["id"])] = job
            except Exception:
                continue
        self.prune_history()

    def prune_history(self) -> None:
        cfg = self.config_store.load()
        limit = int(cfg["runtime"].get("history_limit") or 100)
        cutoff = datetime.now(timezone.utc) - timedelta(days=int(cfg["runtime"].get("history_days") or 30))
        with self._lock:
            ordered = sorted(self._jobs.values(), key=lambda x: x.get("created_at", ""), reverse=True)
            keep_ids: set[str] = set()
            for job in ordered[:limit]:
                try:
                    created = datetime.fromisoformat(str(job.get("created_at") or "").replace("Z", "+00:00"))
                except ValueError:
                    created = datetime.now(timezone.utc)
                if created >= cutoff:
                    keep_ids.add(str(job["id"]))
            remove = [job_id for job_id in self._jobs if job_id not in keep_ids]
            for job_id in remove:
                self._jobs.pop(job_id, None)
                self._private_accounts.pop(job_id, None)
                try:
                    self._job_path(job_id, cfg).unlink()
                except OSError:
                    pass

    def list_jobs(self) -> list[dict]:
        with self._lock:
            return [
                self._safe_job(x)
                for x in sorted(self._jobs.values(), key=lambda job: job.get("created_at", ""), reverse=True)
            ]

    def get(self, job_id: str) -> dict | None:
        with self._lock:
            job = self._jobs.get(str(job_id))
            return self._safe_job(job) if job else None

    def create_job(self, accounts: list[dict], target_names: Iterable[str], *, source: dict,
                   force_refresh: bool = False, allow_marked: bool = False,
                   allow_review: bool = False, automatic: bool = False) -> dict:
        selected = list(dict.fromkeys(str(x) for x in target_names if str(x) in TARGETS))
        if not selected:
            raise ValueError("至少选择一个导入目标")
        allow_review = bool(allow_review) and not bool(automatic)
        normalized: list[dict] = []
        seen: set[str] = set()
        blocked_review = False
        for raw in accounts[:10000]:
            review_override = False
            sso = str(raw.get("sso") or "").strip()
            if not sso or sso in seen:
                continue
            seen.add(sso)
            clean = raw.get("clean")
            requested_targets = raw.get("targets")
            if isinstance(requested_targets, (list, tuple, set)):
                requested_set = {str(x) for x in requested_targets}
                account_targets = [x for x in selected if x in requested_set]
            else:
                account_targets = list(selected)
            # 无 BFS/风控检查：注册结果直接允许全部目标
            if not account_targets:
                continue
            normalized.append({
                "id": str(raw.get("id") or uuid.uuid4().hex),
                "email": str(raw.get("email") or "").strip(),
                "sso": sso,
                "auth_token": raw.get("auth_token") if isinstance(raw.get("auth_token"), dict) else None,
                "clean": clean,
                "risk_status": str(raw.get("risk_status") or ""),
                "_review_override": review_override,
                "targets": account_targets,
            })
        if not normalized:
            if blocked_review and not allow_review:
                raise ValueError("REVIEW 账号需要勾选“允许手动导入 REVIEW”后才能创建任务")
            raise ValueError("没有符合当前目标和风控规则的有效账号")
        job_id = uuid.uuid4().hex[:16]
        cfg = self.config_store.load()
        public_accounts = [
            {
                "id": item["id"],
                "email": item["email"],
                "clean": item["clean"],
                "targets": {target: {"status": "pending", "message": "等待执行"} for target in item["targets"]},
            }
            for item in normalized
        ]
        job = {
            "id": job_id,
            "status": "queued",
            "message": "任务已进入队列",
            "automatic": bool(automatic),
            "source": copy.deepcopy(source),
            "selected_targets": selected,
            "force_refresh": bool(force_refresh),
            "allow_marked": bool(allow_marked),
            "allow_review": bool(allow_review),
            # 创建时快照换票开关：自动任务跟随注册面板勾选（关了就不在本机换票）；
            # 手动任务是显式操作（CPA/grok2api 必须换票），始终允许本机换票
            "token_exchange_allowed": (
                True if not automatic else bool(self.token_exchanger_enabled())
            ),
            "created_at": _utc_now(),
            "started_at": "",
            "finished_at": "",
            "cancel_requested": False,
            "progress": {"completed": 0, "total": sum(len(x["targets"]) for x in normalized), "success": 0, "failed": 0, "skipped": 0},
            "accounts": public_accounts,
            "config_snapshot": cfg,
        }
        with self._lock:
            self._jobs[job_id] = job
            self._private_accounts[job_id] = normalized
            self._persist(job)
        self._executor.submit(self._run, job_id)
        self.log(f"导入任务 {job_id} 已创建 · {len(normalized)} 个账号 · {len(selected)} 个目标", "info")
        return self._safe_job(job)

    def cancel(self, job_id: str) -> dict:
        with self._lock:
            job = self._jobs.get(str(job_id))
            if not job:
                raise KeyError("任务不存在")
            if job.get("status") not in ("queued", "running", "cancelling"):
                return self._safe_job(job)
            job["cancel_requested"] = True
            job["status"] = "cancelling"
            job["message"] = "正在取消；当前请求完成后停止"
            self._persist(job)
            return self._safe_job(job)

    def retry(self, job_id: str) -> dict:
        with self._lock:
            previous = self._jobs.get(str(job_id))
            private = self._private_accounts.get(str(job_id))
            if not previous:
                raise KeyError("任务不存在")
            if previous.get("status") in ("queued", "running", "cancelling"):
                raise ValueError("任务仍在执行")
            if not private and callable(self.source_resolver):
                private = self.source_resolver(previous.get("source") or {}, previous.get("accounts") or [])
                if private:
                    self._private_accounts[str(job_id)] = private
            if not private:
                raise ValueError("原来源无法安全恢复；请重新选择来源并创建任务")
            retry_accounts: list[dict] = []
            for account in private:
                public = next((x for x in previous.get("accounts") or [] if x.get("id") == account.get("id")), None)
                if not public:
                    continue
                failed_targets = [
                    target
                    for target, state in (public.get("targets") or {}).items()
                    if state.get("status") in ("failed", "skipped", "pending", "running")
                ]
                if failed_targets:
                    retry_accounts.append({**account, "targets": failed_targets})
        if not retry_accounts:
            raise ValueError("没有失败或未完成的目标")
        selected = list(dict.fromkeys(target for account in retry_accounts for target in account["targets"]))
        # ``create_job`` recomputes eligibility, so pass only targets which were
        # present on the original account and retain the explicit manual override.
        result = self.create_job(
            retry_accounts,
            selected,
            source={"type": "retry", "job_id": str(job_id)},
            force_refresh=bool(previous.get("force_refresh")),
            allow_marked=bool(previous.get("allow_marked", True)),
            allow_review=bool(previous.get("allow_review")),
            automatic=False,
        )
        # 重试任务继承原任务的换票开关快照（创建时已定，不随 checkbox 实时变化）
        with self._lock:
            stored = self._jobs.get(result.get("id"))
            if stored is not None and "token_exchange_allowed" in previous:
                stored["token_exchange_allowed"] = bool(previous.get("token_exchange_allowed"))
                self._persist(stored)
        return self._safe_job(stored or result)

    def clear_history(self) -> int:
        with self._lock:
            removable = [job_id for job_id, job in self._jobs.items() if job.get("status") not in ("queued", "running", "cancelling")]
            for job_id in removable:
                self._jobs.pop(job_id, None)
                self._private_accounts.pop(job_id, None)
                try:
                    self._job_path(job_id).unlink()
                except OSError:
                    pass
            return len(removable)

    def _find_public(self, job: dict, account_id: str) -> dict:
        return next(item for item in job["accounts"] if item["id"] == account_id)

    @staticmethod
    def _sanitize_message(job: dict, message: Any) -> str:
        text = str(message or "")
        cfg = job.get("config_snapshot") or {}
        services = cfg.get("services") or {}
        secrets = [
            (services.get("sub2api") or {}).get("password"),
            (services.get("cpa") or {}).get("management_key"),
            (services.get("grok2api") or {}).get("password"),
            (services.get("grok2api") or {}).get("app_key"),
        ]
        for secret in secrets:
            secret = str(secret or "")
            if secret:
                text = text.replace(secret, "***")
        text = re.sub(r"(https?://)[^\s/@]+@", r"\1***@", text, flags=re.I)
        text = re.sub(r"([?&](?:app_key|key|token)=)[^&\s]+", r"\1***", text, flags=re.I)
        return text[:500]

    def _set_target(self, job: dict, account_id: str, target: str, status: str, message: str, details: dict | None = None) -> None:
        with self._lock:
            row = self._find_public(job, account_id)["targets"][target]
            previous = row.get("status")
            row.update({"status": status, "message": self._sanitize_message(job, message), "updated_at": _utc_now()})
            if status in ("success", "failed", "skipped"):
                row["finished_at"] = _utc_now()
            if details:
                row["details"] = details
            if previous not in ("success", "failed", "skipped") and status in ("success", "failed", "skipped"):
                job["progress"]["completed"] += 1
                job["progress"][status] += 1
            self._persist(job)

    def _token_for(self, account: dict, job: dict) -> tuple[dict | None, str]:
        from g.device_flow import is_auth_token_usable

        token = account.get("auth_token") if isinstance(account.get("auth_token"), dict) else None
        force = bool(job.get("force_refresh"))
        if token and is_auth_token_usable(token) and not force:
            return token, "registration-cache"
        # device flow 已不可用（approve 403）。有 refresh_token 时放行过期 token：
        # grok2api Build 导入只要求 refresh_token，由网关侧自行验证并轮换；
        # 纯 access_token 过期的没有可续的凭据，继续走 device flow 兜底。
        if token and str(token.get("refresh_token") or "").strip():
            return token, "refresh-token"
        # Reuse an existing valid CPA file before starting device flow.
        from convert_sso_json import SSORecord, cpa_path_for_record, load_cpa_token

        record = SSORecord(source=self.base_dir / "register_sso" / "unknown.json", email=account["email"], sso=account["sso"], session_id=account["id"])
        cpa_path = cpa_path_for_record(self.base_dir / "converted_auth", record)
        cached = load_cpa_token(cpa_path) if not force else None
        if cached and is_auth_token_usable(cached):
            return cached, "cpa-cache"
        # 换票开关关闭（注册侧取消勾选）时仅自动任务受控：纯 SSO 不再跑本机 device flow；
        # 导入中心手动任务是显式操作，CPA/grok2api 目标必须换票，不受此开关影响
        if not bool(job.get("token_exchange_allowed", True)):
            return None, "自动换 token 已关闭（注册面板已取消勾选）"
        # Multiple ordinary uploads may run concurrently, but xAI device flow
        # remains strictly serial to avoid approval/rate-limit collisions.
        with self._oauth_lock:
            result = self.token_exchanger(account["sso"], int(job["config_snapshot"]["runtime"].get("oauth_timeout") or 28))
        token = result.get("token") if isinstance(result, dict) else None
        if isinstance(result, dict) and result.get("ok") and isinstance(token, dict) and is_auth_token_usable(token):
            return token, "device-flow"
        return None, str(result.get("error") if isinstance(result, dict) else "OAuth 换票失败")

    def _write_cpa(self, account: dict, token: dict, job: dict) -> tuple[dict, Path]:
        from convert_sso_json import SSORecord, build_cpa_record, cpa_path_for_record, load_cpa_token

        record = SSORecord(source=self.base_dir / "register_sso" / "unknown.json", email=account["email"], sso=account["sso"], session_id=account["id"])
        output_dir = self.base_dir / "converted_auth"
        path = cpa_path_for_record(output_dir, record)
        auth = build_cpa_record(
            token,
            email=account["email"],
            sso=account["sso"],
            disabled=False,
        )
        written = not path.exists() or load_cpa_token(path) is None or bool(job.get("force_refresh"))
        if written:
            _atomic_json(path, auth)
        return {**auth, "_written": written}, path

    def _retry(self, fn: Callable[[], dict]) -> dict:
        last: Exception | None = None
        for attempt in range(3):
            try:
                return fn()
            except Exception as exc:
                last = exc
                text = str(exc).lower()
                permanent = any(marker in text for marker in ("401", "403", "invalid", "缺少", "未配置", "格式", "不是"))
                if permanent or attempt >= 2:
                    break
                time.sleep(0.5 * (2**attempt))
        raise last or RuntimeError("导入失败")

    def _run_target(self, target: str, account: dict, token: dict | None, auth: dict | None, job: dict, register_proxy: str) -> tuple[dict, dict | None, dict | None]:
        cfg = job["config_snapshot"]
        if target == "sub2api":
            sub2 = cfg["services"]["sub2api"]
            # The legacy importer may fall back to local device flow, so keep
            # its whole per-account path under the same OAuth serialization.
            with self._oauth_lock:
                result = self.sub2api_importer(
                    accounts=[{"email": account["email"], "sso": account["sso"], "auth_token": token}],
                    merge=True,
                    max_workers=1,
                    base_url=str(sub2.get("base_url") or ""),
                    email=str(sub2.get("email") or ""),
                    password=str(sub2.get("password") or ""),
                    group_name=str(sub2.get("group_name") or ""),
                    group_id=str(sub2.get("group_id") or ""),
                    proxy_mode=str(sub2.get("proxy_mode") or "direct"),
                    proxy_url=str(sub2.get("proxy_url") or ""),
                    register_proxy=register_proxy,
                    tls_verify=bool(sub2.get("tls_verify", True)),
                    allow_local_device_flow=bool(job.get("token_exchange_allowed", True)),
                )
            if not (result.get("ok") or int(result.get("success") or 0) > 0):
                raise RuntimeError(result.get("message") or "Sub2API 导入失败")
            return {"ok": True, "success": result.get("success", 1)}, token, auth
        if target in ("cpa_local", "cpa_remote", "grok2api_build"):
            if token is None:
                if account.get("_oauth_attempted"):
                    raise RuntimeError(account.get("_oauth_error") or "OAuth 换票失败")
                token, reason = self._token_for(account, job)
                account["_oauth_attempted"] = True
                account["_oauth_error"] = "" if token is not None else reason
                if token is None:
                    raise RuntimeError(reason)
            if auth is None:
                auth, path = self._write_cpa(account, token, job)
            else:
                path = Path(cfg["paths"]["cpa_dir"]) / "cached.json"
            written = bool(auth.pop("_written", False))
            if target == "cpa_local":
                return {"ok": True, "path": str(path), "written": written}, token, auth
            if target == "cpa_remote":
                return self._retry(lambda: self.targets.upload_cpa(auth or {}, cfg, register_proxy)), token, auth
            return self._retry(lambda: self.targets.import_chenyme_build(auth or {}, cfg, register_proxy)), token, auth
        if target == "grok2api_local":
            return self.targets.add_local(account["sso"], account["email"], cfg), token, auth
        if target == "grok2api_web":
            return self._retry(lambda: self.targets.import_chenyme_sso("web", account["sso"], account["email"], cfg, register_proxy)), token, auth
        if target == "grok2api_console":
            return self._retry(lambda: self.targets.import_chenyme_sso("console", account["sso"], account["email"], cfg, register_proxy)), token, auth
        if target == "grok2api_jiujiu":
            return self._retry(lambda: self.targets.import_jiujiu(account["sso"], cfg, register_proxy)), token, auth
        raise ValueError(f"未知目标: {target}")

    def _process_account(self, job: dict, account: dict, register_proxy: str, order: dict[str, int]) -> None:
        token = account.get("auth_token") if isinstance(account.get("auth_token"), dict) else None
        auth = None
        oauth_targets = {
            "sub2api",
            "cpa_local",
            "cpa_remote",
            "grok2api_local",
            "grok2api_build",
            "grok2api_jiujiu",
        }
        # 换票开关关闭（注册面板取消勾选）时，自动任务不跑本机 device flow：
        # 必须有 token 才能导入的目标直接跳过（sub2api 走服务端 sso-to-oauth 纯 SSO 导入）
        from g.device_flow import is_auth_token_usable

        exchange_allowed = bool(job.get("token_exchange_allowed", True))
        needs_token = bool(oauth_targets.intersection(account["targets"]))
        token_required_targets = {"cpa_local", "cpa_remote", "grok2api_build"}
        if needs_token and exchange_allowed:
            token, reason = self._token_for(account, job)
            account["_oauth_attempted"] = True
            account["_oauth_error"] = "" if token is not None else reason
        for target in sorted(account["targets"], key=lambda x: order.get(x, 999)):
            if job.get("cancel_requested"):
                self._set_target(job, account["id"], target, "skipped", "任务已取消")
                continue
            try:
                if (
                    target in token_required_targets
                    and not exchange_allowed
                    and not is_auth_token_usable(token)
                ):
                    self._set_target(
                        job,
                        account["id"],
                        target,
                        "skipped",
                        "自动换 token 已关闭且无可用缓存 token",
                    )
                    continue
                self._set_target(job, account["id"], target, "running", "正在执行")
                result, token, auth = self._run_target(target, account, token, auth, job, register_proxy)
                details = {k: v for k, v in result.items() if k not in ("ok", "access_token", "refresh_token", "id_token")}
                self._set_target(job, account["id"], target, "success", "导入成功", details)
            except Exception as exc:
                self._set_target(job, account["id"], target, "failed", str(exc))
        account["auth_token"] = None
        account.pop("_oauth_attempted", None)
        account.pop("_oauth_error", None)
        token = None
        auth = None

    def _run(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs[job_id]
            accounts = self._private_accounts[job_id]
            job["status"] = "running"
            job["message"] = "任务执行中"
            job["started_at"] = _utc_now()
            self._persist(job)
        register_proxy = self.register_proxy_getter()
        order = {name: index for index, name in enumerate(EXECUTION_ORDER)}
        workers = int(job["config_snapshot"]["runtime"].get("upload_workers") or 5)
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix=f"import-{job_id}") as pool:
            futures = [pool.submit(self._process_account, job, account, register_proxy, order) for account in accounts]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:  # defensive: target errors are normally captured per-cell
                    self.log(f"导入任务 {job_id} worker 异常: {exc}", "error")
        with self._lock:
            cancelled = bool(job.get("cancel_requested"))
            failed = int(job["progress"].get("failed") or 0)
            success = int(job["progress"].get("success") or 0)
            skipped = int(job["progress"].get("skipped") or 0)
            job["status"] = "cancelled" if cancelled else ("partial" if failed and success else ("failed" if failed else "completed"))
            job["message"] = "任务已取消" if cancelled else ("部分目标失败" if failed else "导入完成")
            if not cancelled and skipped:
                job["status"] = "partial" if success else "failed"
                job["message"] = "部分目标已跳过" if success else "全部目标未导入（检测阻断或已跳过）"
            job["finished_at"] = _utc_now()
            self._persist(job)
        self.log(f"导入任务 {job_id} 结束 · {job['message']}", "success" if job["status"] == "completed" else "warn")
        if callable(self.on_job_complete):
            try:
                self.on_job_complete(self._safe_job(job))
            except Exception as exc:
                self.log(f"导入任务 {job_id} 完成回调失败: {exc}", "warn")
        self.prune_history()
