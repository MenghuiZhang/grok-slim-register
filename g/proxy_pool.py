"""注册代理池：持久化配置 + 进程内健康状态 + 账号级租约。

凭据只保存在 data/proxy_pool.json；对外序列化始终脱敏。
运行时不依赖 HTTP_PROXY/GROK_PROXY 等全局环境变量，避免并发串代理。
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import threading

from filelock import FileLock
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import quote, unquote, urlsplit


SUPPORTED_SCHEMES = {"http", "https", "socks5", "socks5h"}
STRATEGIES = {"round_robin", "random", "least_used"}
COOLDOWN_SECONDS = (60, 300, 900, 1800)
MAX_PROXIES = 10_000
MAX_UPLOAD_BYTES = 5 * 1024 * 1024


class ProxyConfigError(ValueError):
    def __init__(self, message: str, *, line: int | None = None):
        super().__init__(message)
        self.line = line


def _scheme(value: str) -> str:
    value = (value or "http").strip().lower()
    if value not in SUPPORTED_SCHEMES:
        raise ProxyConfigError(f"不支持的代理协议: {value}")
    return value


def parse_proxy_line(raw: str, default_scheme: str = "http") -> dict[str, str]:
    """解析并规范化单条代理，返回可直接传给注册链路的 spec。"""
    text = str(raw or "").strip()
    if not text:
        raise ProxyConfigError("空代理")
    if "\n" in text or "\r" in text:
        raise ProxyConfigError("单条代理不能包含换行")
    scheme = _scheme(default_scheme)

    # host:port:user:pass（仅在第二段是端口时采用该格式）
    if "://" not in text and "@" not in text:
        parts = text.split(":")
        if len(parts) >= 4 and parts[1].isdigit():
            host, port = parts[0], parts[1]
            username = ":".join(parts[2:-1])
            password = parts[-1]
            text = (
                f"{scheme}://{quote(username, safe='{}-_')}:{quote(password, safe='{}-_')}"
                f"@{host}:{port}"
            )
        else:
            text = f"{scheme}://{text}"
    elif "://" not in text:
        text = f"{scheme}://{text}"

    parsed = urlsplit(text)
    sch = _scheme(parsed.scheme)
    if not parsed.hostname:
        raise ProxyConfigError("缺少代理主机")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ProxyConfigError("代理端口无效") from exc
    if port is None or not 1 <= int(port) <= 65535:
        raise ProxyConfigError("代理端口必须在 1-65535")
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    host = parsed.hostname
    host_show = f"[{host}]" if ":" in host and not host.startswith("[") else host
    auth = ""
    if username:
        auth = f"{quote(username, safe='{}-_')}:{quote(password, safe='{}-_')}@"
    spec = f"{sch}://{auth}{host_show}:{port}"
    return {
        "spec": spec,
        "scheme": sch,
        "host": host,
        "port": str(port),
        "username": username,
        "password": password,
    }


def mask_proxy(spec: str) -> str:
    try:
        p = parse_proxy_line(spec)
        auth = "***:******@" if p["username"] else ""
        host = f"[{p['host']}]" if ":" in p["host"] else p["host"]
        return f"{p['scheme']}://{auth}{host}:{p['port']}"
    except Exception:
        return "invalid://******"


def proxy_identity(spec: str) -> str:
    """浏览器 launch 级身份；包含认证/会话但不泄露凭据。"""
    return hashlib.sha256(str(spec or "").encode("utf-8")).hexdigest()


def expand_proxy_template(spec: str, *, account: str, session: str) -> str:
    account_tag = re.sub(r"[^A-Za-z0-9_-]", "-", account or "account")[:48]
    return str(spec).replace("{session}", session).replace("{account}", account_tag)


def parse_proxy_lines(
    text: str, *, default_scheme: str = "http", limit: int = MAX_PROXIES
) -> tuple[list[dict[str, str]], list[dict[str, Any]], int]:
    rows: list[dict[str, str]] = []
    errors: list[dict[str, Any]] = []
    seen: set[str] = set()
    duplicates = 0
    for lineno, raw in enumerate(str(text or "").splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        try:
            parsed = parse_proxy_line(value, default_scheme)
        except ProxyConfigError as exc:
            errors.append({"line": lineno, "value": value[:160], "error": str(exc)})
            continue
        key = parsed["spec"]
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        rows.append(parsed)
        if len(rows) > limit:
            errors.append({"line": lineno, "value": "", "error": f"代理数量超过 {limit}"})
            break
    return rows, errors, duplicates


@dataclass(frozen=True)
class ProxyLease:
    proxy_id: str
    spec: str
    masked: str
    account: str
    session: str
    direct: bool = False

    @property
    def identity(self) -> str:
        return "direct" if self.direct else proxy_identity(self.spec)

    def audit(self) -> dict[str, Any]:
        if self.direct:
            return {"proxy_mode": "direct"}
        return {
            "proxy_mode": "pool",
            "proxy_id": self.proxy_id,
            "proxy": self.masked,
        }


class ProxyPool:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._cv = threading.Condition(self._lock)
        self._cursor = 0
        self._data = self._default_document()
        self._runtime: dict[str, dict[str, Any]] = {}
        self.reload()

    @staticmethod
    def _default_document() -> dict[str, Any]:
        return {
            "version": 1,
            "settings": {
                "strategy": "round_robin",
                "default_scheme": "http",
                "default_max_concurrency": 1,
                "align_geo": True,
            },
            "proxies": [],
        }

    def reload(self) -> None:
        with self._cv:
            doc = self._default_document()
            if self.path.exists():
                try:
                    loaded = json.loads(self.path.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        doc.update(loaded)
                        settings = self._default_document()["settings"]
                        settings.update(loaded.get("settings") or {})
                        doc["settings"] = settings
                except Exception:
                    # 保留默认空池，不让损坏的私密配置拖垮 Web。
                    doc = self._default_document()
            clean: list[dict[str, Any]] = []
            for idx, item in enumerate(doc.get("proxies") or []):
                if not isinstance(item, dict) or not item.get("spec"):
                    continue
                try:
                    parsed = parse_proxy_line(
                        item["spec"], doc["settings"].get("default_scheme", "http")
                    )
                except ProxyConfigError:
                    continue
                clean.append(
                    {
                        "id": str(item.get("id") or uuid.uuid4().hex),
                        "spec": parsed["spec"],
                        "label": str(item.get("label") or f"代理 {idx + 1}"),
                        "enabled": bool(item.get("enabled", True)),
                        "max_concurrency": item.get("max_concurrency"),
                        "pending_delete": bool(item.get("pending_delete", False)),
                        "disabled_reason": str(item.get("disabled_reason") or ""),
                        "disabled_at": str(item.get("disabled_at") or ""),
                        "bot_failures": int(item.get("bot_failures") or 0),
                        "last_failure_code": str(item.get("last_failure_code") or ""),
                        "last_failure_message": str(item.get("last_failure_message") or ""),
                        "last_failure_at": str(item.get("last_failure_at") or ""),
                        "isolation_events": list(item.get("isolation_events") or [])[-20:],
                    }
                )
            doc["proxies"] = clean[:MAX_PROXIES]
            self._data = doc
            for item in clean:
                self._runtime.setdefault(item["id"], self._new_runtime())
            self._cv.notify_all()

    @staticmethod
    def _new_runtime() -> dict[str, Any]:
        return {
            "in_use": 0,
            "success": 0,
            "failures": 0,
            "marked": 0,
            "consecutive_marked": 0,
            "network_failures": 0,
            "cooldown_until": 0.0,
            "health": "untested",
            "health_message": "尚未测试",
            "egress_ip": "",
            "egress_cc": "",
            "region": "",
            "timezone": "",
            "tested_at": "",
        }

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # 跨进程锁：多进程注册时防止并发读-改-写互相覆盖
        with FileLock(str(self.path) + ".lock", timeout=15):
            temp = self.path.with_name(self.path.name + ".tmp")
            temp.write_text(json.dumps(self._data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            temp.replace(self.path)
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def settings(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._data["settings"])

    def update_settings(self, values: dict[str, Any]) -> dict[str, Any]:
        with self._cv:
            current = self._data["settings"]
            if "strategy" in values:
                strategy = str(values["strategy"])
                if strategy not in STRATEGIES:
                    raise ProxyConfigError("调度策略无效")
                current["strategy"] = strategy
            if "default_scheme" in values:
                current["default_scheme"] = _scheme(str(values["default_scheme"]))
            if "default_max_concurrency" in values:
                n = int(values["default_max_concurrency"])
                if not 1 <= n <= 64:
                    raise ProxyConfigError("默认并发必须在 1-64")
                current["default_max_concurrency"] = n
            if "align_geo" in values:
                current["align_geo"] = bool(values["align_geo"])
            self._save_locked()
            self._cv.notify_all()
            return dict(current)

    def import_text(self, text: str, *, mode: str = "append") -> dict[str, Any]:
        encoded = str(text or "").encode("utf-8")
        if len(encoded) > MAX_UPLOAD_BYTES:
            raise ProxyConfigError("代理文件超过 5 MB")
        with self._cv:
            rows, errors, duplicates = parse_proxy_lines(
                text,
                default_scheme=self._data["settings"].get("default_scheme", "http"),
            )
            if errors:
                return {"ok": False, "valid": len(rows), "duplicates": duplicates, "errors": errors}
            if mode not in ("append", "replace"):
                raise ProxyConfigError("导入模式必须是 append/replace")
            if mode == "replace":
                existing = []
                for old in self._data["proxies"]:
                    rt = self._runtime.setdefault(old["id"], self._new_runtime())
                    if int(rt.get("in_use") or 0) > 0:
                        old["enabled"] = False
                        old["pending_delete"] = True
                        existing.append(old)
                    else:
                        self._runtime.pop(old["id"], None)
            else:
                existing = list(self._data["proxies"])
            existing_specs = {x["spec"] for x in existing if not x.get("pending_delete")}
            added = 0
            added_ids: list[str] = []
            for row in rows:
                if row["spec"] in existing_specs:
                    duplicates += 1
                    continue
                item = {
                    "id": uuid.uuid4().hex,
                    "spec": row["spec"],
                    "label": f"代理 {len(existing) + 1}",
                    "enabled": True,
                    "max_concurrency": None,
                    "pending_delete": False,
                    "disabled_reason": "",
                    "disabled_at": "",
                    "bot_failures": 0,
                    "last_failure_code": "",
                    "last_failure_message": "",
                    "last_failure_at": "",
                    "isolation_events": [],
                }
                existing.append(item)
                existing_specs.add(row["spec"])
                self._runtime[item["id"]] = self._new_runtime()
                added += 1
                added_ids.append(item["id"])
            if len(existing) > MAX_PROXIES:
                raise ProxyConfigError(f"代理数量超过 {MAX_PROXIES}")
            self._data["proxies"] = existing
            self._save_locked()
            self._cv.notify_all()
            return {
                "ok": True,
                "added": added,
                "added_ids": added_ids,
                "duplicates": duplicates,
                "total": len(existing),
            }

    def _entry(self, proxy_id: str) -> Optional[dict[str, Any]]:
        return next((x for x in self._data["proxies"] if x["id"] == proxy_id), None)

    def update_entry(self, proxy_id: str, values: dict[str, Any]) -> dict[str, Any]:
        with self._cv:
            item = self._entry(proxy_id)
            if item is None:
                raise KeyError(proxy_id)
            if "enabled" in values:
                item["enabled"] = bool(values["enabled"])
                if item["enabled"]:
                    item["disabled_reason"] = ""
                    item["disabled_at"] = ""
            if "label" in values:
                item["label"] = str(values["label"] or "").strip()[:80] or item["label"]
            if "max_concurrency" in values:
                raw = values["max_concurrency"]
                if raw in (None, ""):
                    item["max_concurrency"] = None
                else:
                    n = int(raw)
                    if not 1 <= n <= 64:
                        raise ProxyConfigError("单代理并发必须在 1-64")
                    item["max_concurrency"] = n
            self._save_locked()
            self._cv.notify_all()
            return self._public_item(item)

    def delete(self, ids: Iterable[str]) -> dict[str, int]:
        wanted = {str(x) for x in ids}
        with self._cv:
            removed = pending = 0
            kept = []
            for item in self._data["proxies"]:
                if item["id"] not in wanted:
                    kept.append(item)
                    continue
                rt = self._runtime.setdefault(item["id"], self._new_runtime())
                if rt["in_use"]:
                    item["pending_delete"] = True
                    item["enabled"] = False
                    kept.append(item)
                    pending += 1
                else:
                    self._runtime.pop(item["id"], None)
                    removed += 1
            self._data["proxies"] = kept
            self._save_locked()
            self._cv.notify_all()
            return {"removed": removed, "pending": pending}

    def dedupe(self) -> dict[str, int]:
        """按 spec 精确去重，每组保留列表顺序第一条。

        重复项与批量删除同规则：空闲直接删，占用中（in_use > 0）标记
        pending_delete 并停用，租约释放后自动清理，不打断进行中的注册。
        """
        with self._cv:
            removed = pending = 0
            kept: list[dict[str, Any]] = []
            seen_specs: set[str] = set()
            for item in self._data["proxies"]:
                if not item.get("pending_delete") and item["spec"] in seen_specs:
                    rt = self._runtime.setdefault(item["id"], self._new_runtime())
                    if rt["in_use"]:
                        item["pending_delete"] = True
                        item["enabled"] = False
                        kept.append(item)
                        pending += 1
                    else:
                        self._runtime.pop(item["id"], None)
                        removed += 1
                    continue
                seen_specs.add(item["spec"])
                kept.append(item)
            self._data["proxies"] = kept
            self._save_locked()
            self._cv.notify_all()
            return {"removed": removed, "pending": pending}

    def move(self, proxy_id: str, direction: str) -> None:
        with self._cv:
            items = self._data["proxies"]
            idx = next((i for i, x in enumerate(items) if x["id"] == proxy_id), -1)
            if idx < 0:
                raise KeyError(proxy_id)
            target = idx - 1 if direction == "up" else idx + 1 if direction == "down" else idx
            target = max(0, min(target, len(items) - 1))
            if target != idx:
                items[idx], items[target] = items[target], items[idx]
                self._save_locked()
                self._cv.notify_all()

    def _public_item(self, item: dict[str, Any]) -> dict[str, Any]:
        rt = dict(self._runtime.setdefault(item["id"], self._new_runtime()))
        rt["cooldown_remaining"] = max(0, int(float(rt.get("cooldown_until") or 0) - time.time()))
        rt.pop("cooldown_until", None)
        return {
            "id": item["id"],
            "label": item["label"],
            "proxy": mask_proxy(item["spec"]),
            "enabled": item["enabled"],
            "max_concurrency": item.get("max_concurrency"),
            "pending_delete": item.get("pending_delete", False),
            "disabled_reason": item.get("disabled_reason", ""),
            "disabled_at": item.get("disabled_at", ""),
            "bot_failures": int(item.get("bot_failures") or 0),
            "last_failure_code": item.get("last_failure_code", ""),
            "last_failure_message": item.get("last_failure_message", ""),
            "last_failure_at": item.get("last_failure_at", ""),
            "isolation_events": list(item.get("isolation_events") or [])[-20:],
            **rt,
        }

    def list_public(
        self,
        *,
        page: int = 1,
        per_page: int = 50,
        query: str = "",
        status: str = "",
    ) -> dict[str, Any]:
        with self._lock:
            q = str(query or "").strip().lower()
            items = [self._public_item(x) for x in self._data["proxies"]]
            ip_counts: dict[str, int] = {}
            for row in items:
                ip = str(row.get("egress_ip") or "")
                if ip:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
            for row in items:
                row["duplicate_egress"] = bool(
                    row.get("egress_ip") and ip_counts.get(str(row["egress_ip"]), 0) > 1
                )
            if q:
                items = [x for x in items if q in (x["label"] + " " + x["proxy"] + " " + x.get("region", "")).lower()]
            if status:
                if status == "disabled":
                    items = [x for x in items if not x["enabled"]]
                elif status == "cooldown":
                    items = [x for x in items if x["cooldown_remaining"] > 0]
                elif status == "busy":
                    items = [x for x in items if x["in_use"] > 0]
                else:
                    items = [x for x in items if x["health"] == status]
            page = max(1, int(page))
            per_page = max(1, min(int(per_page), 2000))
            start = (page - 1) * per_page
            return {
                "items": items[start : start + per_page],
                "total": len(items),
                "page": page,
                "per_page": per_page,
                "settings": dict(self._data["settings"]),
                "summary": self.summary(),
            }

    def summary(self) -> dict[str, int]:
        with self._lock:
            now = time.time()
            total = len(self._data["proxies"])
            enabled = [x for x in self._data["proxies"] if x.get("enabled")]
            runtimes = [self._runtime.setdefault(x["id"], self._new_runtime()) for x in enabled]
            ip_counts: dict[str, int] = {}
            for rt in runtimes:
                ip = str(rt.get("egress_ip") or "")
                if ip:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
            return {
                "total": total,
                "enabled": len(enabled),
                "healthy": sum(1 for x in runtimes if x["health"] == "healthy" and x["cooldown_until"] <= now),
                "untested": sum(1 for x in runtimes if x["health"] == "untested"),
                "cooldown": sum(1 for x in runtimes if x["cooldown_until"] > now),
                "disabled": total - len(enabled),
                "busy": sum(int(x["in_use"]) for x in runtimes),
                "duplicate_egress": sum(count for count in ip_counts.values() if count > 1),
            }

    def _eligible_locked(self, exclude: set[str]) -> list[dict[str, Any]]:
        now = time.time()
        default_cap = int(self._data["settings"].get("default_max_concurrency") or 1)
        out = []
        for item in self._data["proxies"]:
            if item["id"] in exclude or not item.get("enabled") or item.get("pending_delete"):
                continue
            rt = self._runtime.setdefault(item["id"], self._new_runtime())
            cap = int(item.get("max_concurrency") or default_cap)
            if rt["cooldown_until"] > now or rt["in_use"] >= cap or rt["health"] in ("unhealthy", "testing"):
                continue
            out.append(item)
        return out

    def acquire(
        self,
        account: str,
        *,
        stop_event: threading.Event | None = None,
        exclude: Optional[set[str]] = None,
        wait: bool = True,
        wait_timeout: Optional[float] = None,
    ) -> Optional[ProxyLease]:
        excluded = set(exclude or set())
        deadline = time.monotonic() + max(0.0, float(wait_timeout)) if wait_timeout is not None else None
        with self._cv:
            if not self._data["proxies"]:
                return ProxyLease("direct", "", "直连", account, "", True)
            while True:
                if stop_event is not None and stop_event.is_set():
                    return None
                candidates = self._eligible_locked(excluded)
                if candidates:
                    strategy = self._data["settings"].get("strategy", "round_robin")
                    if strategy == "random":
                        item = random.choice(candidates)
                    elif strategy == "least_used":
                        item = min(candidates, key=lambda x: (self._runtime[x["id"]]["in_use"], self._runtime[x["id"]]["success"] + self._runtime[x["id"]]["failures"]))
                    else:
                        all_items = self._data["proxies"]
                        ordered = all_items[self._cursor :] + all_items[: self._cursor]
                        ids = {x["id"] for x in candidates}
                        item = next(x for x in ordered if x["id"] in ids)
                        self._cursor = (all_items.index(item) + 1) % max(1, len(all_items))
                    rt = self._runtime[item["id"]]
                    rt["in_use"] += 1
                    session = uuid.uuid4().hex[:16]
                    spec = expand_proxy_template(item["spec"], account=account, session=session)
                    return ProxyLease(item["id"], spec, mask_proxy(spec), account, session)
                if not wait:
                    return None
                if deadline is not None and time.monotonic() >= deadline:
                    return None
                self._cv.wait(timeout=0.5)

    def retry_exclusions(self, attempted_ids: Iterable[str], egress_ip: str = "") -> set[str]:
        """Exclude attempted rows and any row known to share the same egress."""
        excluded = {str(x) for x in attempted_ids}
        ip = str(egress_ip or "").strip()
        if not ip:
            return excluded
        with self._lock:
            for item in self._data["proxies"]:
                rt = self._runtime.setdefault(item["id"], self._new_runtime())
                if str(rt.get("egress_ip") or "").strip() == ip:
                    excluded.add(item["id"])
        return excluded

    def release(self, lease: ProxyLease | None, outcome: str = "neutral", message: str = "") -> None:
        if lease is None or lease.direct:
            return
        with self._cv:
            rt = self._runtime.get(lease.proxy_id)
            if rt is None:
                return
            rt["in_use"] = max(0, int(rt["in_use"]) - 1)
            if outcome == "success":
                rt["success"] += 1
                rt["network_failures"] = 0
                rt["cooldown_until"] = 0.0
                rt["health"] = "healthy"
                rt["health_message"] = "最近注册成功"
            elif outcome == "network":
                rt["failures"] += 1
                rt["network_failures"] += 1
                idx = min(rt["network_failures"] - 1, len(COOLDOWN_SECONDS) - 1)
                rt["cooldown_until"] = time.time() + COOLDOWN_SECONDS[idx]
                rt["health"] = "unhealthy"
                rt["health_message"] = str(message or "网络故障")[:160]
            elif outcome == "marked":
                rt["marked"] += 1
                rt["consecutive_marked"] += 1
                idx = min(rt["consecutive_marked"] - 1, len(COOLDOWN_SECONDS) - 1)
                seconds = COOLDOWN_SECONDS[idx]
                rt["cooldown_until"] = time.time() + seconds
                rt["health"] = "unhealthy"
                rt["health_message"] = (
                    f"Risk MARKED 连续 {rt['consecutive_marked']} 次，冷却 {seconds // 60} 分钟"
                )
            elif outcome == "failure":
                rt["failures"] += 1
            item = self._entry(lease.proxy_id)
            if item and item.get("pending_delete") and rt["in_use"] == 0:
                self._data["proxies"] = [x for x in self._data["proxies"] if x["id"] != lease.proxy_id]
                self._runtime.pop(lease.proxy_id, None)
                self._save_locked()
            self._cv.notify_all()

    def mark_risk_clean(self, lease: ProxyLease | None) -> None:
        """Only a conclusive Risk CLEAN resets the MARKED cooldown ladder."""
        if lease is None or lease.direct:
            return
        with self._cv:
            rt = self._runtime.get(lease.proxy_id)
            if rt is None:
                return
            rt["consecutive_marked"] = 0
            self._cv.notify_all()

    def disable_for_bot(
        self,
        lease: ProxyLease | None,
        *,
        domain: str = "",
        logical_id: str = "",
        message: str = "risk MARKED",
    ) -> Optional[dict[str, Any]]:
        """Atomically release a lease and persistently isolate its proxy.

        Doing both under the pool condition lock closes the window where another
        worker could acquire the proxy after MARKED but before it was disabled.
        Existing leases are intentionally allowed to finish.
        """
        if lease is None or lease.direct:
            return None
        with self._cv:
            item = self._entry(lease.proxy_id)
            rt = self._runtime.get(lease.proxy_id)
            if item is None or rt is None:
                return None
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            rt["in_use"] = max(0, int(rt.get("in_use") or 0) - 1)
            rt["marked"] = int(rt.get("marked") or 0) + 1
            rt["consecutive_marked"] = int(rt.get("consecutive_marked") or 0) + 1
            rt["health_message"] = "Bot MARKED，已自动停用"
            item["enabled"] = False
            item["disabled_reason"] = "BOT_MARKED"
            item["disabled_at"] = now
            item["bot_failures"] = int(item.get("bot_failures") or 0) + 1
            item["last_failure_code"] = "BOT_MARKED"
            item["last_failure_message"] = str(message or "risk MARKED")[:160]
            item["last_failure_at"] = now
            event = {
                "at": now,
                "code": "BOT_MARKED",
                "proxy": lease.masked,
                "domain": str(domain or ""),
                "logical_id": str(logical_id or ""),
                "message": str(message or "risk MARKED")[:160],
            }
            item["isolation_events"] = (list(item.get("isolation_events") or []) + [event])[-20:]
            self._save_locked()
            self._cv.notify_all()
            return self._public_item(item)

    def set_health(self, proxy_id: str, result: dict[str, Any]) -> None:
        with self._cv:
            rt = self._runtime.get(proxy_id)
            if rt is None:
                return
            ok = bool(result.get("ok"))
            rt["health"] = "healthy" if ok else "unhealthy"
            rt["health_message"] = str(result.get("message") or result.get("error") or "")[:160]
            rt["egress_ip"] = str(result.get("egress_ip") or result.get("ip") or "")
            rt["egress_cc"] = str(result.get("egress_cc") or result.get("cc") or "").upper()
            # ASN detection is disabled; clear any value left by an older runtime.
            rt.pop("egress_asn", None)
            rt["region"] = str(result.get("egress_region") or result.get("region") or result.get("country") or "")
            rt["timezone"] = str(result.get("egress_timezone") or result.get("timezone") or "")
            rt["tested_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            if ok:
                rt["cooldown_until"] = 0.0
                rt["network_failures"] = 0
            else:
                rt["network_failures"] = int(rt.get("network_failures") or 0) + 1
                idx = min(rt["network_failures"] - 1, len(COOLDOWN_SECONDS) - 1)
                rt["cooldown_until"] = time.time() + COOLDOWN_SECONDS[idx]
            self._cv.notify_all()

    def block_known_asn(self, asn: Any) -> int:
        digits = re.sub(r"\D", "", str(asn or ""))
        if not digits:
            return 0
        changed = 0
        with self._cv:
            for rt in self._runtime.values():
                if re.sub(r"\D", "", str(rt.get("egress_asn") or "")) != digits:
                    continue
                if rt.get("health") != "blocked_asn":
                    changed += 1
                rt["health"] = "blocked_asn"
                rt["health_message"] = f"AS{digits} 已列入黑名单"
            self._cv.notify_all()
        return changed

    def unblock_known_asn(self, asn: Any) -> int:
        digits = re.sub(r"\D", "", str(asn or ""))
        if not digits:
            return 0
        changed = 0
        with self._cv:
            for rt in self._runtime.values():
                if (
                    re.sub(r"\D", "", str(rt.get("egress_asn") or "")) == digits
                    and rt.get("health") == "blocked_asn"
                ):
                    rt["health"] = "untested"
                    rt["health_message"] = "ASN 规则已移除，等待重新预检"
                    changed += 1
            self._cv.notify_all()
        return changed

    def begin_health_check(self, ids: Iterable[str] | None = None) -> list[str]:
        with self._cv:
            wanted = set(str(x) for x in ids) if ids is not None else None
            out: list[str] = []
            for item in self._data["proxies"]:
                if not item.get("enabled") or (wanted is not None and item["id"] not in wanted):
                    continue
                rt = self._runtime.setdefault(item["id"], self._new_runtime())
                rt["health"] = "testing"
                rt["health_message"] = "正在检查出口与 xAI"
                out.append(item["id"])
            self._cv.notify_all()
            return out

    def begin_due_health_checks(self) -> list[str]:
        now = time.time()
        with self._cv:
            due = [
                item["id"]
                for item in self._data["proxies"]
                if item.get("enabled")
                and (self._runtime.setdefault(item["id"], self._new_runtime())).get("health") == "unhealthy"
                and float(self._runtime[item["id"]].get("cooldown_until") or 0) <= now
            ]
        return self.begin_health_check(due) if due else []

    def secret_spec(self, proxy_id: str) -> str:
        with self._lock:
            item = self._entry(proxy_id)
            if item is None:
                raise KeyError(proxy_id)
            return str(item["spec"])

    def lease_geo(self, lease: ProxyLease | None) -> dict[str, str]:
        if lease is None or lease.direct:
            return {}
        with self._lock:
            rt = self._runtime.get(lease.proxy_id) or {}
            return {
                "cc": str(rt.get("egress_cc") or ""),
                "region": str(rt.get("region") or ""),
                "timezone": str(rt.get("timezone") or ""),
                "ip": str(rt.get("egress_ip") or ""),
            }

    def lease_audit(self, lease: ProxyLease | None) -> dict[str, Any]:
        if lease is None:
            return {"proxy_mode": "direct"}
        out = lease.audit()
        geo = self.lease_geo(lease)
        if geo.get("ip"):
            out["proxy_egress"] = geo["ip"]
        if geo.get("cc") or geo.get("region"):
            out["proxy_region"] = " ".join(x for x in (geo.get("cc"), geo.get("region")) if x)
        return out


_POOLS: dict[str, ProxyPool] = {}
_POOLS_LOCK = threading.Lock()


def get_proxy_pool(base_dir: Path | str | None = None) -> ProxyPool:
    root = Path(base_dir or Path(__file__).resolve().parents[1]).resolve()
    path = root / "data" / "proxy_pool.json"
    key = str(path)
    with _POOLS_LOCK:
        if key not in _POOLS:
            _POOLS[key] = ProxyPool(path)
        return _POOLS[key]
