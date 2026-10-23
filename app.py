"""
Grok 注册机 Web 控制台
启动: python app.py
浏览器打开 http://127.0.0.1:3333
"""
import json
import hmac
import os
import re
import subprocess
import sys
import threading
import time
import uuid
import concurrent.futures
from functools import wraps
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, send_from_directory

from g.log_buffer import LogBuffer
from g.device_flow import (
    _device_flow_error_kind,
    _device_flow_wait_seconds,
    _mark_device_flow_cooldown,
    decode_jwt_payload,
    is_auth_token_usable,
    sso_device_flow_to_token,
    token_to_auth_entry,
)
from log_storage import clear_capture_dirs, enforce_storage_limits, storage_stats
from g.email_config import (
    EMAIL_CONFIG_KEYS,
    EMAIL_DEFAULTS,
    PROVIDER_LABELS,
    PROVIDERS,
    normalize_provider,
    redact_config,
    resolved_email_config,
    serialize_structured_config,
    validate_provider_config,
)
from g.import_services import (
    ImportConfigStore,
    ImportJobManager,
    ImportTargets,
    TARGET_LABELS,
    TARGETS,
)
from g.proxy_pool import (
    MAX_UPLOAD_BYTES,
    ProxyConfigError,
    expand_proxy_template,
    get_proxy_pool,
    mask_proxy,
    parse_proxy_lines,
)
from g.domain_pool import DomainPoolError, get_domain_pool

BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"
proxy_pool = get_proxy_pool(BASE_DIR)

load_dotenv(ENV_PATH)
MONITOR_TOKEN = str(os.getenv("MONITOR_TOKEN") or "").strip()
domain_pool = get_domain_pool(BASE_DIR)
try:
    configured_cf_domains = (
        resolved_email_config(dict(os.environ))["providers"]["cloudflare_temp"].get("domains") or []
    )
    if configured_cf_domains:
        domain_pool.reconcile_configured(configured_cf_domains)
except Exception:
    pass
enforce_storage_limits(BASE_DIR)

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=str(BASE_DIR / "static"))


def require_monitor_token(fn):
    """Fail-closed authentication for newly added operational endpoints."""
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not MONITOR_TOKEN:
            return jsonify({"ok": False, "message": "MONITOR_TOKEN 未配置"}), 503
        authorization = str(request.headers.get("Authorization") or "")
        supplied = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
        supplied = supplied or str(request.headers.get("X-Monitor-Token") or "").strip()
        if not supplied or not hmac.compare_digest(supplied, MONITOR_TOKEN):
            return jsonify({"ok": False, "message": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapped

# 主流程日志（建邮/camoufox/castle/发码/signup/SSO…）
logs = LogBuffer(maxlen=3000)
# 右侧副区：risk 探测 + 换 token（不进主日志，避免刷屏）
post_logs = LogBuffer(maxlen=2000)


def _is_post_process_log(message: str) -> bool:
    """
    risk / 换 token / 协议 / NSFW 相关日志 → 右侧副区。
    主区只保留注册主路径，便于盯吞吐。
    注意：主路径「CLEAN 已计成功 · 换 token/协议/NSFW 异步处理中」仍留主区。
    """
    msg = str(message or "")
    if not msg:
        return False
    # 主路径宣告异步，不当后置步骤
    if "异步处理中" in msg and "CLEAN" in msg:
        return False
    # 换 token 操作本身 / device flow
    if re.search(
        r"换\s*token\s*(开始|成功|失败|异常|返回体|：|：approve)|"
        r"\[后台\]\s*换\s*token|"
        r"device\s*flow|"
        r"device_flow",
        msg,
        re.I,
    ):
        return True
    # 协议 / NSFW / unhinged（enrich 后置）
    if re.search(
        r"\[后台\].*(NSFW|unhinged|协议)|"
        r"\bNSFW\b|"
        r"unhinged|"
        r"协议/NSFW|"
        r"协议失败|"
        r"NSFW失败|"
        r"token=async|"
        r"enrich",
        msg,
        re.I,
    ):
        return True
    # risk 探测全链路（含 MARKED/CLEAN/INFRA/调度）
    if re.search(
        r"\brisk\s*(探测|CLEAN|MARKED|INFRA|跳过|基建)|"
        r"risk\s+CLEAN|"
        r"risk\s+MARKED|"
        r"risk\s+INFRA|"
        r"调度\s*risk|"
        r"绕过成功列表",
        msg,
        re.I,
    ):
        return True
    return False


def _route_engine_log(msg: str, level: str = "info") -> None:
    if _is_post_process_log(msg):
        post_logs.emit(msg, level)
    else:
        logs.emit(msg, level)


def _sso_preview(sso: object) -> str:
    text = str(sso or "")
    return (text[:10] + "…" + text[-6:]) if len(text) > 20 else ("已读取" if text else "")


def _lease_token_proxy(account: dict) -> tuple[str | None, object | None, str]:
    """换票节点：优先复用账号记录的注册节点，其次从代理池租一个。

    都没有时返回 ``None``，交给 device_flow 继承进程/环境代理，
    不再强制直连（直连只在代理池为空时才会自然发生）。

    注册节点的原始 spec 只在内存里（``_proxy_spec``），落盘的 ``proxy`` 是脱敏值，
    所以这里优先读 ``_proxy_spec``，避免拿 ``***`` 去连代理。
    """
    recorded = str(account.get("_proxy_spec") or account.get("proxy_spec") or "").strip()
    if not recorded:
        legacy = str(account.get("proxy") or "").strip()
        if legacy and "***" not in legacy:
            recorded = legacy
    if recorded:
        try:
            label = mask_proxy(recorded)
        except Exception:
            label = "已记录节点"
        return recorded, None, label
    name = str(account.get("id") or account.get("email") or "token-exchange")
    try:
        lease = proxy_pool.acquire(name, wait=False)
    except Exception:
        return None, None, "环境代理/直连"
    if lease is None:
        return None, None, "环境代理/直连"
    if lease.direct:
        return None, None, "直连（代理池为空）"
    return lease.spec, lease, lease.masked


_NETWORK_ERROR_HINTS = (
    "err_",
    "net::",
    "econn",
    "eai_again",
    "etimedout",
    "timed out",
    "timeout",
    "tunnel connection failed",
    "proxy",
    "dns",
)


def _looks_like_network_error(message: str) -> bool:
    text = str(message or "").lower()
    return any(hint in text for hint in _NETWORK_ERROR_HINTS)


def _release_token_proxy(lease, ok: bool, message: str = "") -> None:
    if lease is None:
        return
    try:
        # 换票失败多是账号/限流问题，不拿它给节点记风险；成功则刷新节点健康
        proxy_pool.release(
            lease,
            outcome="success" if ok else "neutral",
            message=str(message or "")[:160],
        )
    except Exception:
        pass


class RegisterRunner:
    """注册流程管理器：N 个 worker 并行，每个 worker 串行驱动子进程注册。

    - 每个 worker 独立子进程（独立浏览器、独立临时 profile，跑完即销毁）
    - 每轮结果写独立 --out 文件，精确归属；成功号进入 recent_success 供导入服务引用
    - 成功后异步换 token（SSO → access_token）：结果回写 JSON 并缓存给导入服务复用
    """

    MAX_WORKERS = 8
    # 换 token 单次超时（秒）；device flow 本身还有内部轮询预算
    TOKEN_EXCHANGE_TIMEOUT = 28

    def __init__(self, log_fn) -> None:
        self._log = log_fn
        self._lock = threading.RLock()
        self._procs: dict[int, subprocess.Popen] = {}
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._next_round = 0
        self._live_workers = 0
        # device flow 串行：同一时刻只换一个号，避免 approve/rate_limited 互相踩踏
        self._token_lock = threading.Lock()
        self._pending_tokens = 0
        self._finalized = True
        # 批次序号：防止上一批的收尾线程误结束下一批任务
        self._run_seq = 0
        self.auto_exchange_token = True
        self.token_ok_count = 0
        self.token_fail_count = 0
        self.file_lock = threading.RLock()
        self.recent_success: list[dict] = []
        self.on_run_start = None
        self.on_run_complete = None
        self.on_account = None
        self.status = "idle"
        self.error_message = ""
        self.start_time: float | None = None
        self.end_time: float | None = None
        self.target_count = 0
        self.workers = 0
        self.success_count = 0
        self.fail_count = 0
        self.output_file = ""
        # 池里有节点但都被占用时，最多等这么久再跳过该轮（0 = 不等待）
        try:
            self.proxy_lease_wait = max(
                0.0, float(os.getenv("GROK_PROXY_LEASE_WAIT", "120") or 0)
            )
        except (TypeError, ValueError):
            self.proxy_lease_wait = 120.0

    def is_running(self) -> bool:
        with self._lock:
            # 注册子进程跑完但后台还在换 token，也算任务进行中（UI 不应判定结束）
            return self._live_workers > 0 or self._pending_tokens > 0

    def start(self, target: int = 1, workers: int = 3, env_overrides: dict | None = None) -> dict:
        with self._lock:
            if self.is_running():
                return {"ok": False, "message": "注册任务正在运行", "status": self.status}
            self._stop.clear()
            self.status = "running"
            self.error_message = ""
            self.start_time = time.time()
            self.end_time = None
            self.target_count = max(1, int(target))
            self.workers = max(1, min(self.MAX_WORKERS, int(workers)))
            self._next_round = 0
            self.success_count = 0
            self.fail_count = 0
            self.token_ok_count = 0
            self.token_fail_count = 0
            self._pending_tokens = 0
            self._finalized = False
            self._run_seq += 1
            raw_exchange = str(
                (env_overrides or {}).get(
                    "GROK_AUTO_EXCHANGE_TOKEN",
                    os.environ.get("GROK_AUTO_EXCHANGE_TOKEN", "1"),
                )
            ).strip().lower()
            self.auto_exchange_token = raw_exchange not in ("0", "false", "no", "off")
            self.output_file = ""
            count = min(self.workers, self.target_count)
            self._threads = [
                threading.Thread(
                    target=self._worker,
                    args=(wid + 1, dict(env_overrides or {})),
                    daemon=True,
                    name=f"register-w{wid + 1}",
                )
                for wid in range(count)
            ]
            self._live_workers = len(self._threads)
            for t in self._threads:
                t.start()
        return {
            "ok": True,
            "message": f"已开始注册：目标 {self.target_count} 个 · {self.workers} 进程并行",
            "status": "running",
            "target": self.target_count,
            "workers": self.workers,
            "register_mode": "ui",
        }

    def stop(self) -> dict:
        with self._lock:
            if not self.is_running():
                return {"ok": False, "message": "当前没有运行中的注册任务", "status": self.status}
            self.status = "stopping"
            self._stop.set()
            procs = list(self._procs.values())
        for proc in procs:
            if proc.poll() is None:
                try:
                    proc.terminate()
                except Exception:
                    pass
        self._log("已发送停止信号，等待各 worker 当前轮退出…", "warn")
        return {"ok": True, "message": "已发送停止信号", "status": "stopping"}

    def get_status(self) -> dict:
        with self._lock:
            running = self.is_running()
            elapsed = 0.0
            if self.start_time:
                end = time.time() if running else float(self.end_time or self.start_time)
                elapsed = max(0.0, end - float(self.start_time))
            done = self.success_count + self.fail_count
            progress = min(100.0, done / self.target_count * 100) if self.target_count else 0.0
            accounts = list(self.recent_success)[:50]
            return {
                "status": self.status,
                "running": running,
                "success_count": self.success_count,
                "fail_count": self.fail_count,
                "target_count": self.target_count,
                "workers": self.workers,
                "progress": round(progress, 1),
                "elapsed": round(elapsed, 1),
                "avg_seconds": round(elapsed / done, 1) if done else 0.0,
                "output_file": self.output_file,
                "error_message": self.error_message,
                "register_mode": "ui",
                "risk_check_enabled": False,
                "auto_exchange_token": self.auto_exchange_token,
                "token_ok_count": self.token_ok_count,
                "token_fail_count": self.token_fail_count,
                "token_pending_count": self._pending_tokens,
                "recent_success": [
                    {
                        "id": item.get("id"),
                        "email": item.get("email") or "",
                        "sso_preview": _sso_preview(item.get("sso")),
                        "sso": bool(item.get("sso")),
                        "has_token": is_auth_token_usable(item.get("auth_token")),
                        "token_status": str(item.get("token_status") or ""),
                    }
                    for item in accounts
                ],
            }

    def _env(self, overrides: dict) -> dict:
        env = dict(os.environ)
        env.update({str(key): str(value) for key, value in overrides.items() if value is not None})
        env["PYTHONUNBUFFERED"] = "1"
        return env

    def _claim_round(self) -> int:
        """worker 领取下一轮次号；任务结束/停止返回 0。"""
        with self._lock:
            if self._stop.is_set() or self._next_round >= self.target_count:
                return 0
            self._next_round += 1
            return self._next_round

    def _read_result(self, rel_path: str) -> dict | None:
        try:
            payload = json.loads((BASE_DIR / rel_path).read_text(encoding="utf-8"))
        except Exception:
            return None
        if not payload.get("ok") or not payload.get("sso"):
            return None
        payload.setdefault("id", Path(rel_path).stem)
        payload["_file"] = rel_path
        return payload

    def _read_error(self, rel_path: str) -> str:
        try:
            payload = json.loads((BASE_DIR / rel_path).read_text(encoding="utf-8"))
        except Exception:
            return ""
        return str(payload.get("error") or "")

    def _lease_register_proxy(self, wid: int, rnd: int):
        """每轮注册前从代理池租一个节点。

        返回 ``(lease, skipped)``：

        - ``lease.direct``：代理池为空，本轮直连（与旧行为一致）
        - ``lease`` 为 None 且 ``skipped=False``：租约异常，本轮直连
        - ``skipped=True``：等待超时/已停止，本轮不注册
        """
        try:
            summary = proxy_pool.summary()
        except Exception:
            summary = {}
        if summary.get("total") and not summary.get("enabled"):
            # 全被停用（含 Bot MARKED 自动隔离）时不必干等
            return None, True
        try:
            lease = proxy_pool.acquire(
                f"w{wid}-r{rnd}",
                stop_event=self._stop,
                wait=True,
                wait_timeout=self.proxy_lease_wait,
            )
        except Exception as exc:
            self._log(f"[W{wid}] 代理租约异常，本轮直连: {exc}", "warn")
            return None, False
        if lease is None:
            return None, True
        return lease, self._stop.is_set()

    def _release_register_proxy(self, lease, *, ok: bool, error: str, logp: str) -> None:
        """释放注册节点：成功记 healthy，网络类失败进冷却，其余只计数。"""
        if lease is None or getattr(lease, "direct", False):
            return
        outcome = (
            "success"
            if ok
            else ("network" if _looks_like_network_error(error) else "neutral")
        )
        try:
            proxy_pool.release(lease, outcome=outcome, message=str(error or "")[:160])
        except Exception as exc:
            self._log(f"{logp} 释放代理失败: {exc}", "warn")

    def _worker(self, wid: int, overrides: dict) -> None:
        logp = f"[W{wid}]"
        with self._lock:
            seq = self._run_seq
        try:
            if wid == 1 and callable(self.on_run_start):
                try:
                    self.on_run_start()
                except Exception as exc:
                    self._log(f"{logp} 批次启动回调异常: {exc}", "warn")
            while True:
                rnd = self._claim_round()
                if not rnd:
                    break
                lease, skipped = self._lease_register_proxy(wid, rnd)
                if skipped:
                    self._release_register_proxy(lease, ok=False, error="", logp=logp)
                    if self._stop.is_set():
                        break
                    with self._lock:
                        self.fail_count += 1
                    self._log(
                        f"{logp} 第 {rnd} 轮跳过：代理池没有可用节点（占用/冷却/停用）",
                        "warn",
                    )
                    continue
                round_env = dict(overrides)
                # 旧单代理变量一律不参与注册，节点只由代理池租约决定
                for legacy in ("GROK_PROXY", "DEBUG_PROXY"):
                    round_env.pop(legacy, None)
                if lease is not None and not lease.direct:
                    # 子进程按账号拿节点：注册浏览器 + 收码邮箱都锁同一出口
                    round_env["GROK_REGISTER_PROXY"] = lease.spec
                    node_label = lease.masked
                else:
                    round_env.pop("GROK_REGISTER_PROXY", None)
                    node_label = "直连（代理池为空）"
                self._log(
                    f"{logp} 第 {rnd}/{self.target_count} 轮注册开始 · 节点 {node_label}",
                    "info",
                )
                rel_out = f"register_sso/ui_{uuid.uuid4().hex}.json"
                cmd = [
                    sys.executable,
                    "-m",
                    "g.ui_register",
                    "--headless",
                    "--window",
                    "1500x950",
                    "--out",
                    rel_out,
                ]
                account: dict | None = None
                code = -1
                error = ""
                try:
                    proc = subprocess.Popen(
                        cmd,
                        cwd=str(BASE_DIR),
                        env=self._env(round_env),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1,
                    )
                    with self._lock:
                        self._procs[wid] = proc
                    if proc.stdout is not None:
                        for raw in proc.stdout:
                            line = raw.rstrip("\n")
                            if not line:
                                continue
                            if line.startswith("[ui-register] "):
                                line = line[len("[ui-register] "):]
                            self._log(f"{logp} {line}", "info")
                    code = proc.wait()
                    if self._stop.is_set():
                        self._log(f"{logp} 已停止", "warn")
                        return
                    account = self._read_result(rel_out) if code == 0 else None
                    error = "" if account else self._read_error(rel_out)
                    if account is not None:
                        # 原始 spec 只留在内存给换 token 复用，落盘只写脱敏值
                        if lease is not None and not lease.direct:
                            account["_proxy_spec"] = lease.spec
                            account["proxy"] = lease.masked
                            account["proxy_mode"] = "pool"
                        else:
                            account["_proxy_spec"] = ""
                            account["proxy"] = ""
                            account["proxy_mode"] = "direct"
                        self._persist_result(account)
                    if code == 0 and account:
                        with self._lock:
                            self.success_count += 1
                            self.output_file = rel_out
                        with self.file_lock:
                            self.recent_success.insert(0, account)
                            del self.recent_success[200:]
                        self._log(
                            f"{logp} 成功：{account.get('email')}（sso 已保存 · 节点 {node_label}）",
                            "success",
                        )
                        # 换 token 与自动导入都在后台做：注册主循环不等，吞吐不受影响
                        if self.auto_exchange_token and account.get("sso"):
                            self._start_token_exchange(account, wid, seq)
                        else:
                            self._queue_auto_import(account, logp)
                    else:
                        with self._lock:
                            self.fail_count += 1
                        detail = f" · {error}" if error else ""
                        self._log(
                            f"{logp} 第 {rnd} 轮失败（exit={code}）{detail}", "error"
                        )
                finally:
                    with self._lock:
                        self._procs.pop(wid, None)
                    self._release_register_proxy(
                        lease, ok=account is not None, error=error, logp=logp
                    )
        except Exception as exc:
            with self._lock:
                self.error_message = str(exc)
            self._log(f"[W{wid}] worker 异常: {exc}", "error")
        finally:
            with self._lock:
                self._procs.pop(wid, None)
                self._live_workers -= 1
                finalize = (
                    self._run_seq == seq
                    and self._live_workers <= 0
                    and self._pending_tokens <= 0
                )
            if finalize:
                self._finalize(seq)

    def _finalize(self, seq: int) -> None:
        """所有 worker 与后台换 token 都结束后收尾（每批只执行一次）。"""
        with self._lock:
            if self._finalized or self._run_seq != seq:
                return
            self._finalized = True
            self.end_time = time.time()
            self.status = "error" if self.error_message else ("idle" if self._stop.is_set() else "done")
            callback = self.on_run_complete
        if callable(callback):
            try:
                callback()
            except Exception:
                pass

    def _queue_auto_import(self, account: dict, logp: str) -> None:
        if not callable(self.on_account):
            return
        try:
            self.on_account([account])
        except Exception as exc:
            self._log(f"{logp} 自动导入入队失败: {exc}", "warn")

    def _start_token_exchange(self, account: dict, wid: int, seq: int) -> None:
        with self._lock:
            self._pending_tokens += 1
        threading.Thread(
            target=self._exchange_token,
            args=(account, wid, seq),
            daemon=True,
            name=f"token-w{wid}",
        ).start()

    def _exchange_token(self, account: dict, wid: int, seq: int) -> None:
        """SSO → access_token（device flow），成功后回写结果文件并交给导入服务。"""
        logp = f"[W{wid}]"
        email = str(account.get("email") or "")
        try:
            with self._token_lock:
                # 复用节点：账号记录的注册节点 → 代理池租约 → 环境代理，不强制直连
                proxy_spec, lease, proxy_label = _lease_token_proxy(account)
                self._log(
                    f"{logp} 换 token 开始：{email or '（无邮箱）'} · 节点 {proxy_label}",
                    "info",
                )
                result = None
                try:
                    result = sso_device_flow_to_token(
                        str(account.get("sso") or ""),
                        timeout=self.TOKEN_EXCHANGE_TIMEOUT,
                        issue_token=True,
                        proxy_spec=proxy_spec,
                    )
                finally:
                    _release_token_proxy(
                        lease,
                        bool(
                            isinstance(result, dict)
                            and result.get("ok")
                            and result.get("token")
                        ),
                        "token exchange",
                    )
                    account["token_proxy"] = proxy_label
            token = result.get("token") if isinstance(result, dict) else None
            if (
                isinstance(result, dict)
                and result.get("ok")
                and isinstance(token, dict)
                and is_auth_token_usable(token)
            ):
                account["auth_token"] = token
                account["token_status"] = "ok"
                account.pop("token_error", None)
                with self._lock:
                    self.token_ok_count += 1
                self._persist_result(account)
                self._log(f"{logp} 换 token 成功：{email} · 已缓存", "success")
            else:
                error = str(
                    (result or {}).get("error") if isinstance(result, dict) else ""
                ) or "OAuth 换票失败"
                account["token_status"] = "failed"
                account["token_error"] = error[:200]
                with self._lock:
                    self.token_fail_count += 1
                self._persist_result(account)
                self._log(f"{logp} 换 token 失败：{email} · {error}", "warn")
        except Exception as exc:
            account["token_status"] = "failed"
            account["token_error"] = str(exc)[:200]
            with self._lock:
                self.token_fail_count += 1
            self._log(f"{logp} 换 token 异常：{email} · {exc}", "error")
        finally:
            # 有 token 就直接复用，没有则由导入服务走 device flow 兜底
            self._queue_auto_import(account, logp)
            finalize = False
            with self._lock:
                self._pending_tokens -= 1
                if (
                    self._run_seq == seq
                    and self._live_workers <= 0
                    and self._pending_tokens <= 0
                ):
                    finalize = True
            if finalize:
                self._finalize(seq)

    def _persist_result(self, account: dict) -> None:
        """把 token / token_status 回写到 register_sso/*.json，便于后续直接复用。"""
        rel_path = str(account.get("_file") or "")
        if not rel_path:
            return
        path = BASE_DIR / rel_path
        payload = {key: value for key, value in account.items() if not key.startswith("_")}
        temp_path = path.with_name(f".{path.name}.tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temp_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            os.replace(temp_path, path)
        except Exception as exc:
            self._log(f"结果回写失败（{rel_path}）: {exc}", "warn")
            try:
                temp_path.unlink()
            except OSError:
                pass


runner = RegisterRunner(log_fn=_route_engine_log)


def _on_registration_complete() -> None:
    _stop_proxy_pool_health_checks()


runner.on_run_complete = _on_registration_complete

CONFIG_KEYS = (
    "WORKER_DOMAIN",
    "FREEMAIL_TOKEN",
    "FREEMAIL_ADMIN_KEY",
    "FREEMAIL_DOMAIN",
    "FREEMAIL_RANDOM_SUBDOMAIN",
    "FREEMAIL_API_STYLE",
    "LOG_MAX_MB",
    "LOG_ROTATE_FILE_COUNT",
    "UI_HOST",
    "UI_PORT",
    "SUB2API_URL",
    "SUB2API_DOCKER_CONTAINER",
    "SUB2API_DB_HOST",
    "SUB2API_DB_PORT",
    "SUB2API_DB_NAME",
    "SUB2API_DB_USER",
    "SUB2API_DB_PASSWORD",
    "SUB2API_GROK_GROUP_ID",
    "SUB2API_GROK_GROUP_NAME",
    "UPSTREAM_URL",
    "UPSTREAM_ADMIN_EMAIL",
    "UPSTREAM_ADMIN_PASSWORD",
    "EMAIL_TYPE",
    "OUTLOOK_ACCOUNTS",
    "OUTLOOK_ALIAS_LIMIT",
) + EMAIL_CONFIG_KEYS

DEFAULTS = {
    "WORKER_DOMAIN": "",
    "FREEMAIL_TOKEN": "",
    "FREEMAIL_ADMIN_KEY": "",
    "FREEMAIL_DOMAIN": "auto",
    "FREEMAIL_RANDOM_SUBDOMAIN": "0",
    "FREEMAIL_API_STYLE": "auto",
    "LOG_MAX_MB": "10",
    "LOG_ROTATE_FILE_COUNT": "3",
    "UI_HOST": "127.0.0.1",
    "UI_PORT": "3333",
    "SUB2API_URL": "http://127.0.0.1:9898",
    "SUB2API_DOCKER_CONTAINER": "sub2api",
    "SUB2API_DB_HOST": "postgres",
    "SUB2API_DB_PORT": "5432",
    "SUB2API_DB_NAME": "sub2api",
    "SUB2API_DB_USER": "ige",
    "SUB2API_DB_PASSWORD": "ige_pass",
    "SUB2API_GROK_GROUP_ID": "23",
    "SUB2API_GROK_GROUP_NAME": "grok",
    "UPSTREAM_URL": "http://127.0.0.1:9898",
    "UPSTREAM_ADMIN_EMAIL": "",
    "UPSTREAM_ADMIN_PASSWORD": "",
    "EMAIL_TYPE": "freemail",
    "OUTLOOK_ACCOUNTS": "",
    "OUTLOOK_ALIAS_LIMIT": "5",
}
DEFAULTS.update(EMAIL_DEFAULTS)

LEGACY_SUB2_CONFIG_KEYS = frozenset({
    "SUB2API_URL",
    "SUB2API_DOCKER_CONTAINER",
    "SUB2API_DB_HOST",
    "SUB2API_DB_PORT",
    "SUB2API_DB_NAME",
    "SUB2API_DB_USER",
    "SUB2API_DB_PASSWORD",
    "SUB2API_GROK_GROUP_ID",
    "SUB2API_GROK_GROUP_NAME",
    "UPSTREAM_URL",
    "UPSTREAM_ADMIN_EMAIL",
    "UPSTREAM_ADMIN_PASSWORD",
})

# Deliberately process-local: a restart makes a provider require a fresh test
# before it can be newly activated. A migrated already-active provider remains
# runnable until the user edits or switches it.
EMAIL_TEST_STATES: dict[str, dict] = {
    name: {"status": "untested", "message": "尚未测试", "tested_at": ""}
    for name in PROVIDERS
}


def _decode_config_value(key: str, value: str) -> str:
    if key == "OUTLOOK_ACCOUNTS":
        return value.replace("\\n", "\n")
    return value


def _encode_config_value(key: str, value: object) -> str:
    text = str(value or "")
    if key == "OUTLOOK_ACCOUNTS":
        return text.replace("\r\n", "\n").replace("\r", "\n").replace(
            "\n", "\\n"
        )
    return text


def read_env_file() -> dict:
    data = dict(DEFAULTS)
    if not ENV_PATH.exists():
        # fallback to process env
        for k in CONFIG_KEYS:
            data[k] = os.getenv(k, data[k]) or data[k]
        return data

    for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, val = raw.split("=", 1)
        key = key.strip()
        if key in CONFIG_KEYS:
            data[key] = _decode_config_value(
                key, val.strip().strip('"').strip("'")
            )
    # process env overrides missing blanks only for runtime consistency
    for k in CONFIG_KEYS:
        if not data.get(k):
            data[k] = os.getenv(k, data.get(k, "")) or data.get(k, "")
    return data


def write_env_file(values: dict) -> None:
    existing_lines = []
    if ENV_PATH.exists():
        existing_lines = ENV_PATH.read_text(encoding="utf-8").splitlines()

    written = set()
    out = []
    for line in existing_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            out.append(line)
            continue
        key = stripped.split("=", 1)[0].strip()
        if key == "GROK_PROXY":
            # 旧单代理已废弃；不迁移、不保留。
            continue
        if key in values:
            out.append(f"{key}={_encode_config_value(key, values[key])}")
            written.add(key)
        else:
            out.append(line)
            if key in CONFIG_KEYS:
                written.add(key)

    # append missing keys
    for key in CONFIG_KEYS:
        if key not in written:
            if out and out[-1].strip():
                out.append("")
            value = values.get(key, DEFAULTS.get(key, ""))
            out.append(f"{key}={_encode_config_value(key, value)}")

    # ensure example comments if file was empty
    if not existing_lines:
        out = [
            "# 统一邮箱服务（优先读取；旧变量保留用于回滚）",
            f"EMAIL_PROVIDER={values.get('EMAIL_PROVIDER', EMAIL_DEFAULTS['EMAIL_PROVIDER'])}",
            f"EMAIL_TIMEOUT_SECONDS={values.get('EMAIL_TIMEOUT_SECONDS', EMAIL_DEFAULTS['EMAIL_TIMEOUT_SECONDS'])}",
            f"EMAIL_PROXY_MODE={values.get('EMAIL_PROXY_MODE', EMAIL_DEFAULTS['EMAIL_PROXY_MODE'])}",
            f"EMAIL_PROXY_URL={values.get('EMAIL_PROXY_URL', '')}",
            f"EMAIL_TLS_VERIFY={values.get('EMAIL_TLS_VERIFY', EMAIL_DEFAULTS['EMAIL_TLS_VERIFY'])}",
            f"EMAIL_OUTLOOK_ACCOUNTS_JSON={values.get('EMAIL_OUTLOOK_ACCOUNTS_JSON', '[]')}",
            f"EMAIL_OUTLOOK_DEFAULT_ALIAS_LIMIT={values.get('EMAIL_OUTLOOK_DEFAULT_ALIAS_LIMIT', '5')}",
            f"EMAIL_OUTLOOK_CONCURRENCY={values.get('EMAIL_OUTLOOK_CONCURRENCY', '5')}",
            f"EMAIL_FREEMAIL_BASE_URL={values.get('EMAIL_FREEMAIL_BASE_URL', '')}",
            f"EMAIL_FREEMAIL_TOKEN={values.get('EMAIL_FREEMAIL_TOKEN', '')}",
            f"EMAIL_FREEMAIL_DOMAIN={values.get('EMAIL_FREEMAIL_DOMAIN', 'auto')}",
            f"EMAIL_FREEMAIL_CONCURRENCY={values.get('EMAIL_FREEMAIL_CONCURRENCY', '10')}",
            f"EMAIL_YYDS_BASE_URL={values.get('EMAIL_YYDS_BASE_URL', EMAIL_DEFAULTS['EMAIL_YYDS_BASE_URL'])}",
            f"EMAIL_YYDS_API_KEY={values.get('EMAIL_YYDS_API_KEY', '')}",
            f"EMAIL_YYDS_DOMAIN={values.get('EMAIL_YYDS_DOMAIN', 'auto')}",
            f"EMAIL_YYDS_PLATFORM_CODE={values.get('EMAIL_YYDS_PLATFORM_CODE', 'grok')}",
            f"EMAIL_YYDS_CONCURRENCY={values.get('EMAIL_YYDS_CONCURRENCY', '5')}",
            f"EMAIL_CF_TEMP_BASE_URL={values.get('EMAIL_CF_TEMP_BASE_URL', '')}",
            f"EMAIL_CF_TEMP_SITE_TOKEN={values.get('EMAIL_CF_TEMP_SITE_TOKEN', '')}",
            f"EMAIL_CF_TEMP_ADMIN_KEY={values.get('EMAIL_CF_TEMP_ADMIN_KEY', '')}",
            f"EMAIL_CF_TEMP_DOMAINS_JSON={values.get('EMAIL_CF_TEMP_DOMAINS_JSON', '[]')}",
            f"EMAIL_CF_TEMP_AUTO_DOMAIN={values.get('EMAIL_CF_TEMP_AUTO_DOMAIN', '1')}",
            f"EMAIL_CF_TEMP_RANDOM_SUBDOMAIN={values.get('EMAIL_CF_TEMP_RANDOM_SUBDOMAIN', '0')}",
            f"EMAIL_CF_TEMP_CONCURRENCY={values.get('EMAIL_CF_TEMP_CONCURRENCY', '10')}",
            "",
            "# freemail API 配置",
            f"WORKER_DOMAIN={values.get('WORKER_DOMAIN', '')}",
            f"FREEMAIL_TOKEN={values.get('FREEMAIL_TOKEN', '')}",
            f"FREEMAIL_ADMIN_KEY={values.get('FREEMAIL_ADMIN_KEY', '')}",
            f"FREEMAIL_DOMAIN={values.get('FREEMAIL_DOMAIN', DEFAULTS['FREEMAIL_DOMAIN'])}",
            f"FREEMAIL_RANDOM_SUBDOMAIN={values.get('FREEMAIL_RANDOM_SUBDOMAIN', DEFAULTS['FREEMAIL_RANDOM_SUBDOMAIN'])}",
            f"FREEMAIL_API_STYLE={values.get('FREEMAIL_API_STYLE', DEFAULTS['FREEMAIL_API_STYLE'])}",
            "",
            "# Outlook/Hotmail 加号地址",
            f"EMAIL_TYPE={values.get('EMAIL_TYPE', DEFAULTS['EMAIL_TYPE'])}",
            "OUTLOOK_ACCOUNTS="
            f"{_encode_config_value('OUTLOOK_ACCOUNTS', values.get('OUTLOOK_ACCOUNTS', ''))}",
            f"OUTLOOK_ALIAS_LIMIT={values.get('OUTLOOK_ALIAS_LIMIT', DEFAULTS['OUTLOOK_ALIAS_LIMIT'])}",
            "",
            "# Turnstile：checkbox 位置点击（不依赖外部 solver）",
            f"LOG_MAX_MB={values.get('LOG_MAX_MB', DEFAULTS['LOG_MAX_MB'])}",
            f"LOG_ROTATE_FILE_COUNT={values.get('LOG_ROTATE_FILE_COUNT', DEFAULTS['LOG_ROTATE_FILE_COUNT'])}",
            "",
            "# Web 控制台",
            f"UI_HOST={values.get('UI_HOST', DEFAULTS['UI_HOST'])}",
            f"UI_PORT={values.get('UI_PORT', DEFAULTS['UI_PORT'])}",
            "",
            "# sub2api Grok（成功账号导入）",
            f"SUB2API_URL={values.get('SUB2API_URL', DEFAULTS['SUB2API_URL'])}",
            f"SUB2API_DOCKER_CONTAINER={values.get('SUB2API_DOCKER_CONTAINER', DEFAULTS['SUB2API_DOCKER_CONTAINER'])}",
            f"SUB2API_DB_HOST={values.get('SUB2API_DB_HOST', DEFAULTS['SUB2API_DB_HOST'])}",
            f"SUB2API_DB_PORT={values.get('SUB2API_DB_PORT', DEFAULTS['SUB2API_DB_PORT'])}",
            f"SUB2API_DB_NAME={values.get('SUB2API_DB_NAME', DEFAULTS['SUB2API_DB_NAME'])}",
            f"SUB2API_DB_USER={values.get('SUB2API_DB_USER', DEFAULTS['SUB2API_DB_USER'])}",
            f"SUB2API_DB_PASSWORD={values.get('SUB2API_DB_PASSWORD', DEFAULTS['SUB2API_DB_PASSWORD'])}",
            f"SUB2API_GROK_GROUP_ID={values.get('SUB2API_GROK_GROUP_ID', DEFAULTS['SUB2API_GROK_GROUP_ID'])}",
            f"SUB2API_GROK_GROUP_NAME={values.get('SUB2API_GROK_GROUP_NAME', DEFAULTS['SUB2API_GROK_GROUP_NAME'])}",
            f"UPSTREAM_URL={values.get('UPSTREAM_URL', values.get('SUB2API_URL', DEFAULTS['SUB2API_URL']))}",
            f"UPSTREAM_ADMIN_EMAIL={values.get('UPSTREAM_ADMIN_EMAIL', '')}",
            f"UPSTREAM_ADMIN_PASSWORD={values.get('UPSTREAM_ADMIN_PASSWORD', '')}",
            "",
        ]

    ENV_PATH.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")


def _sync_proxy_env_aliases() -> None:
    """清理已废弃的进程级注册代理，防止绕过账号租约。"""
    for alias in ("GROK_PROXY", "XAI_PROXY", "SAME_SESSION_PROXY", "GROK_SAME_SESSION_PROXY"):
        os.environ.pop(alias, None)


_sync_proxy_env_aliases()


def apply_env_to_process(values: dict) -> None:
    for k, v in values.items():
        os.environ[k] = v or ""
    # reload dotenv for any other readers
    load_dotenv(ENV_PATH, override=True)
    _sync_proxy_env_aliases()


def env_snapshot():
    cfg = read_env_file()
    email_cfg = resolved_email_config(cfg)
    worker = cfg.get("WORKER_DOMAIN", "").strip()
    token = cfg.get("FREEMAIL_TOKEN", "").strip()
    mail_domain = (cfg.get("FREEMAIL_DOMAIN") or DEFAULTS["FREEMAIL_DOMAIN"]).strip() or "auto"
    random_subdomain = str(
        cfg.get(
            "FREEMAIL_RANDOM_SUBDOMAIN",
            DEFAULTS["FREEMAIL_RANDOM_SUBDOMAIN"],
        )
    ).lower() in ("1", "true", "yes", "on")
    sub2 = get_sub2api_config_from_cfg(cfg)
    sub2_url = sub2["url"]
    admin_email = sub2.get("admin_email") or ""
    admin_password = sub2.get("admin_password") or ""
    # HTTP 导入：URL + 管理员账号密码 + 分组名称（ID 运行时自动解析）
    configured = bool(sub2_url and admin_email and admin_password and sub2["group_name"])
    return {
        "worker_domain_set": bool(worker),
        "freemail_token_set": bool(token),
        "worker_domain": worker,
        "freemail_domain": mail_domain,
        "freemail_random_subdomain": random_subdomain,
        "ui_host": cfg.get("UI_HOST") or DEFAULTS["UI_HOST"],
        "ui_port": cfg.get("UI_PORT") or DEFAULTS["UI_PORT"],
        "grok_proxy": "",
        "grok_proxy_set": bool(proxy_pool.summary().get("enabled")),
        "proxy_pool": proxy_pool.summary(),
        "sub2api_url": sub2_url,
        "sub2api_container": sub2["container"],
        "sub2api_group_id": sub2["group_id"],
        "sub2api_group_name": sub2["group_name"],
        "sub2api_configured": configured,
        "upstream_admin_email": admin_email,
        # legacy names consumed by existing UI
        "upstream_url": sub2_url,
        "upstream_configured": configured,
        "upstream_password_set": bool(admin_password),
        "email_type": email_cfg["provider"],
        "email_provider": email_cfg["provider"],
        "email_provider_label": PROVIDER_LABELS[email_cfg["provider"]],
        "email_configured": not validate_provider_config(email_cfg),
        "outlook_accounts": "",
        "outlook_alias_limit": str(email_cfg["providers"]["outlook"]["default_alias_limit"]),
    }


def normalize_upstream_url(url: str) -> str:
    u = (url or "").strip().rstrip("/")
    if not u:
        return ""
    if not re.match(r"^https?://", u, re.I):
        u = "http://" + u
    return u.rstrip("/")


def get_upstream_config() -> dict:
    sub2 = get_sub2api_config()
    return {
        "url": sub2["url"],
        "email": sub2.get("admin_email") or "",
        "password": sub2.get("admin_password") or "",
    }


def get_sub2api_config_from_cfg(cfg: dict) -> dict:
    url = normalize_upstream_url(
        cfg.get("SUB2API_URL")
        or cfg.get("UPSTREAM_URL")
        or DEFAULTS["SUB2API_URL"]
    )
    return {
        "url": url,
        "container": (cfg.get("SUB2API_DOCKER_CONTAINER") or DEFAULTS["SUB2API_DOCKER_CONTAINER"]).strip(),
        "db_host": (cfg.get("SUB2API_DB_HOST") or DEFAULTS["SUB2API_DB_HOST"]).strip(),
        "db_port": (cfg.get("SUB2API_DB_PORT") or DEFAULTS["SUB2API_DB_PORT"]).strip(),
        "db_name": (cfg.get("SUB2API_DB_NAME") or DEFAULTS["SUB2API_DB_NAME"]).strip(),
        "db_user": (cfg.get("SUB2API_DB_USER") or DEFAULTS["SUB2API_DB_USER"]).strip(),
        "db_password": (cfg.get("SUB2API_DB_PASSWORD") or DEFAULTS["SUB2API_DB_PASSWORD"]).strip(),
        "group_id": (cfg.get("SUB2API_GROK_GROUP_ID") or DEFAULTS["SUB2API_GROK_GROUP_ID"]).strip(),
        "group_name": (cfg.get("SUB2API_GROK_GROUP_NAME") or DEFAULTS["SUB2API_GROK_GROUP_NAME"]).strip(),
        "admin_email": (cfg.get("UPSTREAM_ADMIN_EMAIL") or "").strip(),
        "admin_password": (cfg.get("UPSTREAM_ADMIN_PASSWORD") or "").strip(),
    }


def get_sub2api_config() -> dict:
    return get_sub2api_config_from_cfg(read_env_file())


def sub2api_list_groups(
    *,
    token: str,
    base_url: str,
    platform: str | None = None,
    page_size: int = 100,
) -> dict:
    """拉取 sub2api 分组列表。platform 为空则拉全部分组（便于按名称随意指定）。"""
    params: dict = {
        "page": 1,
        "page_size": max(1, min(int(page_size or 100), 200)),
    }
    plat = str(platform or "").strip()
    if plat:
        params["platform"] = plat
    groups_resp = sub2api_http_request(
        "GET",
        "/api/v1/admin/groups",
        token=token,
        base_url=base_url,
        params=params,
        timeout=15,
    )
    if not groups_resp.get("ok"):
        return {
            "ok": False,
            "error": groups_resp.get("error") or "读取分组失败",
            "items": [],
            "status_code": groups_resp.get("status_code"),
        }
    data = groups_resp.get("data") or {}
    items = data.get("items") if isinstance(data, dict) else []
    if not isinstance(items, list):
        items = []
    cleaned = [it for it in items if isinstance(it, dict)]
    return {"ok": True, "items": cleaned, "raw": data}


def sub2api_list_grok_groups(
    *,
    token: str,
    base_url: str,
    page_size: int = 100,
) -> dict:
    """兼容旧调用：默认拉全部分组（不再锁死 platform=grok）。"""
    return sub2api_list_groups(
        token=token,
        base_url=base_url,
        platform=None,
        page_size=page_size,
    )


def _group_preview_text(items: list[dict], limit: int = 12) -> str:
    preview = []
    for it in (items or [])[: max(1, limit)]:
        if not isinstance(it, dict) or it.get("id") is None:
            continue
        name = str(it.get("name") or "").strip() or "?"
        plat = str(it.get("platform") or "").strip()
        if plat:
            preview.append(f"{name}({it.get('id')}/{plat})")
        else:
            preview.append(f"{name}({it.get('id')})")
    return ", ".join(preview)


def resolve_sub2api_group(
    *,
    token: str,
    base_url: str,
    group_name: str | None = None,
    group_id: str | int | None = None,
    persist: bool = False,
    prefer_platform: str | None = "grok",
) -> dict:
    """
    按分组名称解析 group_id（名称优先；可指定任意已存在分组，不限 grok）。
    同名多条时优先 prefer_platform（默认 grok），再精确名、再唯一模糊。
    命中后可把解析到的 ID 写回 .env。
    """
    want_name = str(group_name or "").strip()
    want_id_raw = str(group_id or "").strip()
    want_id = None
    if want_id_raw.isdigit():
        want_id = int(want_id_raw)
    prefer = str(prefer_platform or "").strip().lower()

    listed = sub2api_list_groups(token=token, base_url=base_url, platform=None)
    if not listed.get("ok"):
        return {
            "ok": False,
            "error": listed.get("error") or "读取分组失败",
            "items": [],
            "status_code": listed.get("status_code"),
        }
    items = listed.get("items") or []

    matched = None
    match_by = ""
    if want_name:
        want_l = want_name.lower()
        exact = [
            it for it in items
            if str(it.get("name") or "").strip().lower() == want_l
        ]
        if len(exact) == 1:
            matched = exact[0]
            match_by = "name"
        elif len(exact) > 1:
            # 同名多平台：优先 prefer_platform
            if prefer:
                preferred = [
                    it for it in exact
                    if str(it.get("platform") or "").strip().lower() == prefer
                ]
                if preferred:
                    matched = preferred[0]
                    match_by = f"name+{prefer}"
            if matched is None:
                matched = exact[0]
                match_by = "name_multi"
        # 包含匹配（仅唯一命中时接受）
        if matched is None:
            fuzzy = [
                it for it in items
                if want_l in str(it.get("name") or "").strip().lower()
            ]
            if len(fuzzy) == 1:
                matched = fuzzy[0]
                match_by = "name_fuzzy"
            elif len(fuzzy) > 1 and prefer:
                preferred = [
                    it for it in fuzzy
                    if str(it.get("platform") or "").strip().lower() == prefer
                ]
                if len(preferred) == 1:
                    matched = preferred[0]
                    match_by = f"name_fuzzy+{prefer}"
        # 填了名称就必须按名称命中，禁止回退到旧 ID
    elif want_id is not None:
        for it in items:
            try:
                if int(it.get("id") or 0) == want_id:
                    matched = it
                    match_by = "id"
                    break
            except (TypeError, ValueError):
                continue

    if matched is None:
        preview = _group_preview_text(items, 12)
        hint = f"可选: {preview}" if preview else "当前无任何分组"
        target = want_name or (f"id={want_id}" if want_id is not None else "(未指定)")
        return {
            "ok": False,
            "error": (
                f"sub2api 分组未匹配: {target}。{hint}。"
                "名称必须是 sub2api 里已有的分组（可任意平台）；新分组请先在 sub2api 后台创建。"
            ),
            "items": items,
            "group_name": want_name,
            "group_id": want_id,
        }

    try:
        gid = int(matched.get("id"))
    except (TypeError, ValueError):
        return {
            "ok": False,
            "error": f"分组 ID 非法: {matched.get('id')}",
            "items": items,
        }
    gname = str(matched.get("name") or want_name or "").strip() or str(gid)
    gplat = str(matched.get("platform") or "").strip()

    if persist:
        try:
            cfg = read_env_file()
            cfg["SUB2API_GROK_GROUP_ID"] = str(gid)
            cfg["SUB2API_GROK_GROUP_NAME"] = gname
            write_env_file(cfg)
            apply_env_to_process({
                "SUB2API_GROK_GROUP_ID": str(gid),
                "SUB2API_GROK_GROUP_NAME": gname,
            })
        except Exception:
            # 解析成功即可用；写回失败不阻断导入
            pass

    return {
        "ok": True,
        "group_id": gid,
        "group_name": gname,
        "platform": gplat,
        "match_by": match_by,
        "group": matched,
        "items": items,
    }


def _rfc3339_seconds(value) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        if re.fullmatch(r"\d+(\.\d+)?", raw):
            return datetime.fromtimestamp(float(raw), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        s = raw.replace("Z", "+00:00")
        if "." in s:
            head, tail = s.split(".", 1)
            tz = ""
            for marker in ("+", "-"):
                pos = tail.find(marker)
                if pos > 0:
                    tz = tail[pos:]
                    tail = tail[:pos]
                    break
            s = head + "." + tail[:6].ljust(6, "0") + tz
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return raw


def _entry_to_sub2api_credentials(entry: dict, email_hint: str = "") -> tuple[dict, str, str, str, str]:

    access = (entry or {}).get("access_token") or (entry or {}).get("key") or ""
    refresh = (entry or {}).get("refresh_token") or ""
    payload = decode_jwt_payload(access)
    issuer = (entry or {}).get("oidc_issuer") or payload.get("iss") or "https://auth.x.ai"
    client_id = (
        (entry or {}).get("client_id")
        or (entry or {}).get("oidc_client_id")
        or payload.get("client_id")
        or payload.get("aud")
        or "b1a00492-073a-47ea-816f-4c329264a828"
    )
    user_id = (entry or {}).get("user_id") or payload.get("sub") or payload.get("principal_id") or ""
    principal_id = (entry or {}).get("principal_id") or payload.get("principal_id") or user_id
    principal_type = (entry or {}).get("principal_type") or payload.get("principal_type") or "User"
    email = (email_hint or (entry or {}).get("email") or payload.get("email") or "").strip()
    expires_at = _rfc3339_seconds((entry or {}).get("expires_at") or payload.get("exp") or "")
    auth_key = (entry or {}).get("auth_key") or (f"{issuer}::{user_id}" if user_id else "")
    credentials = {
        "access_token": access,
        "refresh_token": refresh,
        "expires_at": expires_at,
        "base_url": (entry or {}).get("base_url") or "https://cli-chat-proxy.grok.com/v1",
        "auth_key": auth_key,
        "user_id": user_id,
        "auth_mode": (entry or {}).get("auth_mode") or "oidc",
        "client_id": client_id,
        "oidc_issuer": issuer,
        "email": email,
        "token_type": (entry or {}).get("token_type") or "Bearer",
        "principal_id": principal_id,
        "principal_type": principal_type,
    }
    if payload.get("scope"):
        credentials["scope"] = payload.get("scope")
    if payload.get("team_id"):
        credentials["team_id"] = payload.get("team_id")
    if payload.get("sub"):
        credentials["sub"] = payload.get("sub")
    name = email or (f"Grok {user_id}" if user_id else "Grok OAuth")
    return credentials, name, auth_key, user_id, email


_SUB2_HTTP_CONTEXT = threading.local()


def _set_sub2_http_options(
    *, proxy_mode: str = "direct", proxy_url: str = "", register_proxy: str = "", tls_verify: bool = True
) -> None:
    _SUB2_HTTP_CONTEXT.proxy_url = ""
    _SUB2_HTTP_CONTEXT.tls_verify = bool(tls_verify)


def _http_session():
    """Create an isolated upstream session with the current service policy."""
    import requests

    s = requests.Session()
    s.trust_env = False
    proxy_url = str(getattr(_SUB2_HTTP_CONTEXT, "proxy_url", "") or "").strip()
    if proxy_url:
        s.proxies.update({"http": proxy_url, "https": proxy_url})
    s.verify = bool(getattr(_SUB2_HTTP_CONTEXT, "tls_verify", True))
    return s


def _sub2api_api_data(resp_json) -> dict | list | None:
    """解析 sub2api 统一响应 {code, message, data}。"""
    if not isinstance(resp_json, dict):
        return None
    if "data" in resp_json:
        return resp_json.get("data")
    return resp_json


def _sub2api_api_ok(status_code: int, resp_json) -> bool:
    if status_code < 200 or status_code >= 300:
        return False
    if isinstance(resp_json, dict) and "code" in resp_json:
        try:
            return int(resp_json.get("code")) == 0
        except (TypeError, ValueError):
            return False
    return True


def _sub2api_api_message(resp_json, fallback: str = "") -> str:
    if isinstance(resp_json, dict):
        msg = resp_json.get("message") or resp_json.get("error") or ""
        if msg:
            return str(msg)
        data = resp_json.get("data")
        if isinstance(data, dict) and data.get("message"):
            return str(data["message"])
    return fallback or "unknown error"


def sub2api_http_login(
    base_url: str | None = None,
    email: str | None = None,
    password: str | None = None,
    cfg: dict | None = None,
) -> dict:
    """管理员登录，拿 Bearer access_token。"""
    import requests

    cfg = dict(cfg or get_sub2api_config())
    base = normalize_upstream_url(base_url if base_url is not None else cfg.get("url"))
    admin_email = (email if email is not None else cfg.get("admin_email") or "").strip()
    admin_password = password if password is not None else (cfg.get("admin_password") or "")
    if not base:
        return {"ok": False, "error": "请先填写 SUB2API_URL"}
    if not admin_email or not admin_password:
        return {"ok": False, "error": "请先填写 UPSTREAM_ADMIN_EMAIL / UPSTREAM_ADMIN_PASSWORD"}

    try:
        r = _http_session().post(
            f"{base}/api/v1/auth/login",
            json={"email": admin_email, "password": admin_password},
            timeout=12,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        try:
            body = r.json()
        except Exception:
            body = {"raw": (r.text or "")[:300]}
        if not _sub2api_api_ok(r.status_code, body):
            return {
                "ok": False,
                "error": f"登录失败 HTTP {r.status_code}: {_sub2api_api_message(body, r.text[:200])}",
                "status_code": r.status_code,
                "base_url": base,
            }
        data = _sub2api_api_data(body) or {}
        if not isinstance(data, dict):
            data = {}
        token = (
            data.get("access_token")
            or data.get("token")
            or body.get("access_token")
            or body.get("token")
            or ""
        )
        if not token:
            return {"ok": False, "error": "登录成功但未返回 access_token", "base_url": base}
        return {
            "ok": True,
            "access_token": token,
            "refresh_token": data.get("refresh_token") or "",
            "base_url": base,
            "email": admin_email,
        }
    except requests.exceptions.ConnectionError:
        return {"ok": False, "error": f"连接 sub2api 失败: {base}", "base_url": base}
    except requests.exceptions.Timeout:
        return {"ok": False, "error": f"登录超时: {base}", "base_url": base}
    except Exception as e:
        return {"ok": False, "error": f"登录异常: {e}", "base_url": base}


def sub2api_http_request(
    method: str,
    path: str,
    *,
    token: str,
    base_url: str,
    json_body: dict | list | None = None,
    params: dict | None = None,
    timeout: float = 30.0,
) -> dict:
    """带 Bearer 的 sub2api Admin API 请求。"""
    import requests

    base = normalize_upstream_url(base_url)
    if not base:
        return {"ok": False, "error": "缺少 base_url"}
    if not path.startswith("/"):
        path = "/" + path
    url = f"{base}{path}"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    try:
        r = _http_session().request(
            method.upper(),
            url,
            headers=headers,
            json=json_body,
            params=params,
            timeout=timeout,
        )
        try:
            body = r.json()
        except Exception:
            body = {"raw": (r.text or "")[:500]}
        ok = _sub2api_api_ok(r.status_code, body)
        return {
            "ok": ok,
            "status_code": r.status_code,
            "body": body,
            "data": _sub2api_api_data(body),
            "error": None if ok else _sub2api_api_message(body, f"HTTP {r.status_code}"),
        }
    except requests.exceptions.ConnectionError:
        return {"ok": False, "error": f"连接失败: {url}"}
    except requests.exceptions.Timeout:
        return {"ok": False, "error": f"请求超时: {url}"}
    except Exception as e:
        return {"ok": False, "error": f"请求异常: {e}"}


def sub2api_find_account(
    token: str,
    base_url: str,
    *,
    email: str = "",
    user_id: str = "",
    auth_key: str = "",
    name: str = "",
) -> dict | None:
    """按 email / user_id / auth_key 在 grok 账号里找已有记录。"""
    keywords: list[str] = []
    for k in (email, user_id, name, (auth_key.split("::")[-1] if auth_key else "")):
        k = (k or "").strip()
        if k and k not in keywords:
            keywords.append(k)
    if not keywords:
        return None

    for kw in keywords[:3]:
        resp = sub2api_http_request(
            "GET",
            "/api/v1/admin/accounts",
            token=token,
            base_url=base_url,
            params={
                "page": 1,
                "page_size": 20,
                "platform": "grok",
                "keyword": kw,
            },
            timeout=15,
        )
        if not resp.get("ok"):
            continue
        data = resp.get("data") or {}
        items = data.get("items") if isinstance(data, dict) else None
        if not isinstance(items, list):
            continue
        email_l = (email or "").strip().lower()
        for it in items:
            if not isinstance(it, dict):
                continue
            cred = it.get("credentials") or {}
            if not isinstance(cred, dict):
                cred = {}
            it_email = (cred.get("email") or it.get("name") or "").strip().lower()
            it_uid = str(cred.get("user_id") or cred.get("sub") or "").strip()
            it_ak = str(cred.get("auth_key") or "").strip()
            if email_l and it_email == email_l:
                return it
            if user_id and it_uid and it_uid == user_id:
                return it
            if auth_key and it_ak and it_ak == auth_key:
                return it
            if name and (it.get("name") or "") == name:
                return it
    return None


def sub2api_import_auth_entry(
    entry: dict,
    email_hint: str = "",
    merge: bool = True,
    *,
    token: str | None = None,
    base_url: str | None = None,
    cfg: dict | None = None,
) -> dict:
    """通过 HTTP Admin API 写入/更新 grok oauth 账号。"""
    cfg = dict(cfg or get_sub2api_config())
    base = normalize_upstream_url(base_url or cfg.get("url"))
    credentials, name, auth_key, user_id, email = _entry_to_sub2api_credentials(entry, email_hint)

    if not token:
        login = sub2api_http_login(base_url=base, cfg=cfg)
        if not login.get("ok"):
            return {
                "ok": False,
                "error": login.get("error") or "sub2api 登录失败",
                "email": email or None,
                "user_id": user_id or None,
            }
        token = login["access_token"]
        base = login.get("base_url") or base

    # 优先按分组名称解析 ID；已有数字 ID 仅作兜底
    resolved = resolve_sub2api_group(
        token=token,
        base_url=base,
        group_name=cfg.get("group_name"),
        group_id=cfg.get("group_id"),
        persist=False,
    )
    if not resolved.get("ok"):
        return {
            "ok": False,
            "error": resolved.get("error") or "分组解析失败",
            "email": email or None,
            "user_id": user_id or None,
        }
    group_id = int(resolved["group_id"])
    cfg["group_id"] = str(group_id)
    if resolved.get("group_name"):
        cfg["group_name"] = str(resolved["group_name"])

    existing = sub2api_find_account(
        token,
        base,
        email=email,
        user_id=user_id,
        auth_key=auth_key,
        name=name,
    )

    payload = {
        "name": name,
        "platform": "grok",
        "type": "oauth",
        "group_ids": [group_id],
        "concurrency": 1,
        "priority": 50,
        "rate_multiplier": 1.0,
        "auto_pause_on_expired": True,
        "status": "active",
        "schedulable": True,
        "credentials": credentials,
    }

    if existing and existing.get("id") is not None:
        if not merge:
            return {
                "ok": False,
                "error": "sub2api 已存在相同账号",
                "email": email or None,
                "user_id": user_id or None,
                "id": existing.get("id"),
                "duplicate": True,
            }
        account_id = existing["id"]
        # 保留已有分组，确保目标 group 在列表里
        old_gids = existing.get("group_ids") or []
        if isinstance(old_gids, list):
            gids = []
            for g in old_gids:
                try:
                    gids.append(int(g))
                except (TypeError, ValueError):
                    pass
            if group_id not in gids:
                gids.append(group_id)
            if gids:
                payload["group_ids"] = gids
        resp = sub2api_http_request(
            "PUT",
            f"/api/v1/admin/accounts/{account_id}",
            token=token,
            base_url=base,
            json_body=payload,
            timeout=30,
        )
        if not resp.get("ok"):
            return {
                "ok": False,
                "error": resp.get("error") or "更新账号失败",
                "email": email or None,
                "user_id": user_id or None,
            }
        data = resp.get("data") if isinstance(resp.get("data"), dict) else {}
        return {
            "ok": True,
            "id": data.get("id") or account_id,
            "action": "updated",
            "group_id": group_id,
            "email": email or None,
            "user_id": user_id or None,
            "auth_key": auth_key,
            "expires_at": credentials.get("expires_at") or "",
            "has_refresh_token": bool(credentials.get("refresh_token")),
        }

    resp = sub2api_http_request(
        "POST",
        "/api/v1/admin/accounts",
        token=token,
        base_url=base,
        json_body=payload,
        timeout=30,
    )
    if not resp.get("ok"):
        return {
            "ok": False,
            "error": resp.get("error") or "创建账号失败",
            "email": email or None,
            "user_id": user_id or None,
        }
    data = resp.get("data") if isinstance(resp.get("data"), dict) else {}
    return {
        "ok": True,
        "id": data.get("id"),
        "action": "inserted",
        "group_id": group_id,
        "email": email or None,
        "user_id": user_id or None,
        "auth_key": auth_key,
        "expires_at": credentials.get("expires_at") or "",
        "has_refresh_token": bool(credentials.get("refresh_token")),
    }


def sub2api_import_sso_tokens_http(
    sso_tokens: list[str],
    *,
    token: str,
    base_url: str,
    group_id: int,
    emails: list[str] | None = None,
) -> dict:
    """
    调用 sub2api 服务端 sso-to-oauth：
    POST /api/v1/admin/grok/sso-to-oauth
    body: {sso_tokens, group_ids}
    返回 data: {created: [...], failed: [{index, error}, ...]}
    """
    tokens = [str(t).strip() for t in (sso_tokens or []) if str(t).strip()]
    if not tokens:
        return {"ok": False, "error": "sso_tokens 为空", "created": [], "failed": []}

    body: dict = {
        "sso_tokens": tokens,
        "group_ids": [int(group_id)],
        "auto_pause_on_expired": True,
    }
    # 部分版本支持 name；不强制
    if emails and len(emails) == 1 and emails[0]:
        body["name"] = emails[0]

    resp = sub2api_http_request(
        "POST",
        "/api/v1/admin/grok/sso-to-oauth",
        token=token,
        base_url=base_url,
        json_body=body,
        timeout=120,
    )
    if not resp.get("ok"):
        return {
            "ok": False,
            "error": resp.get("error") or "sso-to-oauth 失败",
            "created": [],
            "failed": [{"index": i + 1, "error": resp.get("error") or "request failed"} for i in range(len(tokens))],
            "status_code": resp.get("status_code"),
        }
    data = resp.get("data") if isinstance(resp.get("data"), dict) else {}
    created_raw = data.get("created") if isinstance(data.get("created"), list) else []
    failed = data.get("failed") if isinstance(data.get("failed"), list) else []
    # 服务端结构：{index, name, email, account:{id, credentials, ...}}
    # 展平 account，方便上层直接取 id / credentials
    created: list[dict] = []
    for c in created_raw:
        if not isinstance(c, dict):
            continue
        acc = c.get("account") if isinstance(c.get("account"), dict) else {}
        flat = dict(c)
        if acc:
            # 顶层优先保留 index/name/email；id/credentials 从 account 补
            if flat.get("id") is None and acc.get("id") is not None:
                flat["id"] = acc.get("id")
            if not isinstance(flat.get("credentials"), dict) and isinstance(
                acc.get("credentials"), dict
            ):
                flat["credentials"] = acc.get("credentials")
            for k in ("user_id", "expires_at", "status", "platform", "type"):
                if flat.get(k) is None and acc.get(k) is not None:
                    flat[k] = acc.get(k)
            if not flat.get("email"):
                cred = acc.get("credentials") if isinstance(acc.get("credentials"), dict) else {}
                flat["email"] = (
                    c.get("email")
                    or acc.get("name")
                    or cred.get("email")
                    or c.get("name")
                )
            flat["_account"] = acc
        created.append(flat)
    return {
        "ok": True,
        "created": created,
        "failed": failed,
        "raw": data,
    }


def test_upstream_connectivity(
    base_url: str | None = None,
    password: str | None = None,
    email: str | None = None,
    group_id: str | int | None = None,
    group_name: str | None = None,
) -> dict:
    """验证 sub2api HTTP 登录，并按分组名称自动解析 group_id。"""
    import requests

    cfg = get_sub2api_config()
    base = normalize_upstream_url(base_url if base_url is not None else cfg["url"])
    admin_email = (email if email is not None else cfg.get("admin_email") or "").strip()
    admin_password = password if password is not None else (cfg.get("admin_password") or "")
    if base:
        cfg["url"] = base
    if admin_email:
        cfg["admin_email"] = admin_email
    if admin_password is not None and str(admin_password) != "":
        cfg["admin_password"] = admin_password
    if group_id is not None and str(group_id).strip() != "":
        cfg["group_id"] = str(group_id).strip()
    if group_name is not None and str(group_name).strip() != "":
        cfg["group_name"] = str(group_name).strip()

    if not base:
        return {"ok": False, "message": "请先填写 SUB2API_URL"}
    if not cfg.get("admin_email") or not cfg.get("admin_password"):
        return {"ok": False, "message": "请先填写管理员邮箱与密码（UPSTREAM_ADMIN_EMAIL / PASSWORD）", "base_url": base}
    if not str(cfg.get("group_name") or "").strip():
        return {"ok": False, "message": "请先填写分组名称（SUB2API_GROK_GROUP_NAME）", "base_url": base}

    health = None
    try:
        hr = _http_session().get(f"{base}/health", timeout=6)
        if hr.status_code == 200:
            try:
                health = hr.json()
            except Exception:
                health = {"raw": hr.text[:200]}
        else:
            return {
                "ok": False,
                "message": f"sub2api 健康检查 HTTP {hr.status_code}",
                "base_url": base,
                "health_status": hr.status_code,
            }
    except requests.exceptions.ConnectionError:
        return {"ok": False, "message": f"连接 sub2api 失败: {base}", "base_url": base}
    except requests.exceptions.Timeout:
        return {"ok": False, "message": f"sub2api 健康检查超时: {base}", "base_url": base}
    except Exception as e:
        return {"ok": False, "message": f"sub2api 健康检查异常: {e}", "base_url": base}

    login = sub2api_http_login(base_url=base, email=cfg.get("admin_email"), password=cfg.get("admin_password"), cfg=cfg)
    if not login.get("ok"):
        return {
            "ok": False,
            "message": login.get("error") or "管理员登录失败",
            "base_url": base,
            "health": health,
            "health_ok": True,
            "login_ok": False,
        }

    token = login["access_token"]
    resolved = resolve_sub2api_group(
        token=token,
        base_url=base or login.get("base_url") or "",
        group_name=cfg.get("group_name"),
        group_id=cfg.get("group_id"),
        persist=True,
    )
    if not resolved.get("ok"):
        return {
            "ok": False,
            "message": resolved.get("error") or "分组解析失败",
            "base_url": base,
            "health": health,
            "health_ok": True,
            "login_ok": True,
            "groups": [
                {"id": it.get("id"), "name": it.get("name")}
                for it in (resolved.get("items") or [])[:20]
            ],
        }

    gname = resolved.get("group_name") or cfg.get("group_name")
    gid = resolved.get("group_id")
    group = resolved.get("group") or {}
    gplat = resolved.get("platform") or group.get("platform") or ""
    return {
        "ok": True,
        "message": (
            f"sub2api HTTP 连通正常，分组 {gname} → id={gid}"
            + (f"/{gplat}" if gplat else "")
            + "（按名称自动解析）"
        ),
        "base_url": base,
        "health": health,
        "health_ok": True,
        "login_ok": True,
        "http_ok": True,
        "group": {
            "group_id": gid,
            "group_name": gname,
            "platform": gplat,
            "status": group.get("status"),
            "match_by": resolved.get("match_by"),
        },
        "groups": [
            {"id": it.get("id"), "name": it.get("name"), "platform": it.get("platform")}
            for it in (resolved.get("items") or [])[:30]
        ],
    }


def _parse_sso_import_lines(sso_lines: list[str]) -> list[tuple[str, str]]:
    """解析 email----sso / 纯 sso 行，返回 [(email, sso), ...]。"""
    out: list[tuple[str, str]] = []
    for raw in sso_lines or []:
        for line in str(raw or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            email = ""
            sso = line
            if "----" in line:
                parts = line.split("----")
                email = parts[0].strip()
                sso = parts[-1].strip()
            elif ":" in line and not line.startswith("eyJ"):
                parts = line.rsplit(":", 1)
                email = parts[0].strip()
                sso = parts[-1].strip()
            if sso:
                out.append((email, sso))
    return out


def _normalize_import_accounts(
    sso_lines: list[str] | None = None,
    accounts: list[dict] | None = None,
) -> list[dict]:
    """
    统一导入入参：
    - accounts: [{email?, sso, auth_token?}, ...]（注册成功缓存 token 的首选路径）
    - sso_lines: email----sso / 纯 sso（无 token，需 device flow）
    """
    out: list[dict] = []
    seen_sso: set[str] = set()

    if accounts:
        for raw in accounts:
            if not isinstance(raw, dict):
                continue
            sso = str(raw.get("sso") or "").strip()
            if not sso or sso in seen_sso:
                continue
            seen_sso.add(sso)
            email = str(raw.get("email") or "").strip()
            token = raw.get("auth_token")
            out.append(
                {
                    "email": email,
                    "sso": sso,
                    "auth_token": token if isinstance(token, dict) else None,
                }
            )

    if sso_lines:
        for email, sso in _parse_sso_import_lines(sso_lines):
            sso = (sso or "").strip()
            if not sso or sso in seen_sso:
                continue
            seen_sso.add(sso)
            out.append(
                {
                    "email": (email or "").strip(),
                    "sso": sso,
                    "auth_token": None,
                }
            )
    return out


def import_sso_to_upstream(
    sso_lines: list[str] | None = None,
    merge: bool = True,
    max_workers: int = 1,
    base_url: str | None = None,
    password: str | None = None,
    email: str | None = None,
    group_name: str | None = None,
    group_id: str | None = None,
    proxy_mode: str = "direct",
    proxy_url: str = "",
    register_proxy: str = "",
    tls_verify: bool = True,
    accounts: list[dict] | None = None,
) -> dict:
    """
    导入 SSO 到 sub2api 的 grok 分组（HTTP Admin API）。

    流程：
    1) 有缓存 auth_token（注册流水线 risk 后前台换票）→ HTTP 直写 accounts
    2) 无缓存 → 服务端 /api/v1/admin/grok/sso-to-oauth
    3) sso-to-oauth 失败且可重试 → 本机 device flow 仅作兜底，再 HTTP 写 accounts
    """
    import time

    del max_workers  # 保留参数兼容；HTTP 写串行更稳
    _set_sub2_http_options(
        proxy_mode=proxy_mode,
        proxy_url=proxy_url,
        register_proxy=register_proxy,
        tls_verify=tls_verify,
    )
    sub2 = get_sub2api_config()
    if base_url:
        sub2["url"] = normalize_upstream_url(base_url)
    if email is not None and str(email).strip():
        sub2["admin_email"] = str(email).strip()
    if password is not None and str(password) != "":
        sub2["admin_password"] = str(password)
    if group_name is not None and str(group_name).strip():
        sub2["group_name"] = str(group_name).strip()
    if group_id is not None:
        sub2["group_id"] = str(group_id).strip()

    items = _normalize_import_accounts(sso_lines=sso_lines, accounts=accounts)
    if not items:
        return {"ok": False, "message": "没有可导入的 SSO"}
    if not sub2.get("url"):
        return {"ok": False, "message": "请先配置 SUB2API_URL"}
    if not str(sub2.get("group_name") or "").strip():
        return {"ok": False, "message": "请先配置分组名称（SUB2API_GROK_GROUP_NAME）"}
    if not sub2.get("admin_email") or not sub2.get("admin_password"):
        return {"ok": False, "message": "请先配置管理员邮箱与密码（UPSTREAM_ADMIN_EMAIL / PASSWORD）"}

    login = sub2api_http_login(cfg=sub2)
    if not login.get("ok"):
        return {
            "ok": False,
            "message": login.get("error") or "sub2api 管理员登录失败",
            "base_url": sub2.get("url"),
        }
    api_token = login["access_token"]
    api_base = login.get("base_url") or sub2.get("url")

    resolved = resolve_sub2api_group(
        token=api_token,
        base_url=api_base,
        group_name=sub2.get("group_name"),
        group_id=sub2.get("group_id"),
        persist=True,
    )
    if not resolved.get("ok"):
        return {
            "ok": False,
            "message": resolved.get("error") or "分组名称未能解析到 ID",
            "base_url": api_base,
            "group_name": sub2.get("group_name"),
        }
    group_id = int(resolved["group_id"])
    sub2["group_id"] = str(group_id)
    if resolved.get("group_name"):
        sub2["group_name"] = str(resolved["group_name"])
    gplat = resolved.get("platform") or ""
    logs.emit(
        f"sub2api 分组解析: {sub2.get('group_name')} → id={group_id}"
        + (f"/{gplat}" if gplat else "")
        + f"（by {resolved.get('match_by') or 'name'}）",
        "info",
    )
    if gplat and gplat.lower() != "grok":
        logs.emit(
            f"提示：目标分组 platform={gplat}（非 grok）。Grok 账号仍可写入该 group_ids，"
            "若 sub2api 侧有平台校验失败再换回 grok 分组。",
            "warn",
        )

    results_by_idx: dict[int, dict] = {}
    imported: list[dict] = []
    ok_count = 0
    fail_count = 0
    cached_hits = 0
    flow_hits = 0
    sso_api_hits = 0

    def _write_token_to_sub2api(entry: dict, email_hint: str, idx: int) -> dict:
        item: dict = {
            "index": idx,
            "email": email_hint or None,
            "sso_hint": None,
        }
        data = sub2api_import_auth_entry(
            entry,
            email_hint=email_hint,
            merge=merge,
            token=api_token,
            base_url=api_base,
            cfg=sub2,
        )
        if not data.get("ok"):
            item["status"] = "failed"
            item["error"] = data.get("error") or "sub2api 写入失败"
            item["email"] = data.get("email") or email_hint or None
            item["user_id"] = data.get("user_id") or entry.get("user_id")
            return item

        item["status"] = "ok"
        item["account_id"] = data.get("id")
        item["action"] = data.get("action")
        item["group_id"] = data.get("group_id")
        item["email"] = data.get("email") or email_hint or entry.get("email") or None
        item["user_id"] = data.get("user_id") or entry.get("user_id")
        item["expires_at"] = data.get("expires_at") or entry.get("expires_at")
        item["has_refresh_token"] = bool(
            data.get("has_refresh_token")
            if "has_refresh_token" in data
            else entry.get("refresh_token")
        )
        return item

    def _device_flow_to_token(sso: str, idx: int, *, pass_label: str, max_attempts: int):
        flow = None
        last_flow_err = "本机 device flow 失败"
        for attempt in range(1, max_attempts + 1):
            # 导入必须真正换票；覆盖全局诊断开关 GROK_DEVICE_FLOW_ISSUE_TOKEN=0
            flow = sso_device_flow_to_token(sso, timeout=28, issue_token=True)
            if flow.get("ok") and flow.get("token"):
                return flow, None
            if flow.get("ok") and not flow.get("token"):
                last_flow_err = flow.get("note") or "device approve 成功但未下发 token"
            else:
                last_flow_err = flow.get("error") or last_flow_err
            if "会话无效" in str(last_flow_err) or "非有效 JWT" in str(last_flow_err):
                break
            kind = _device_flow_error_kind(str(last_flow_err))
            if attempt < max_attempts:
                wait = _device_flow_wait_seconds(str(last_flow_err), attempt)
                if kind == "rate_limited":
                    _mark_device_flow_cooldown(wait)
                logs.emit(
                    f"sub2api 导入{pass_label} [{idx}/{len(items)}] device flow 重试 "
                    f"{attempt}/{max_attempts}（{kind}: {last_flow_err}），等待 {wait:.0f}s…",
                    "warn",
                )
                time.sleep(wait)
        return None, last_flow_err

    def _mark_ok(item: dict) -> None:
        nonlocal ok_count
        ok_count += 1
        imported.append(
            {
                "id": item.get("account_id"),
                "email": item.get("email"),
                "user_id": item.get("user_id"),
                "expires_at": item.get("expires_at"),
                "has_refresh_token": item.get("has_refresh_token"),
            }
        )

    # —— 路径 A：有缓存 token（注册时 CLEAN 后已换票）→ HTTP 直写 accounts ——
    need_sso_indices: list[int] = []
    cached_ready = sum(1 for it in items if is_auth_token_usable(it.get("auth_token")))
    if cached_ready:
        logs.emit(
            f"sub2api 导入：{len(items)} 条中 {cached_ready} 条已有注册缓存 token，优先直写（不换票）",
            "info",
        )
    elif items:
        logs.emit(
            f"sub2api 导入：{len(items)} 条无可用缓存 token，走 sso-to-oauth；本机换票仅兜底",
            "info",
        )

    for idx, acc in enumerate(items, 1):
        email_hint = acc.get("email") or ""
        sso = acc.get("sso") or ""
        auth_token = acc.get("auth_token") if isinstance(acc.get("auth_token"), dict) else None
        sso_hint = (sso[:12] + "...") if len(sso) > 12 else sso

        if is_auth_token_usable(auth_token):
            try:
                entry = token_to_auth_entry(auth_token, email=email_hint or "")
                item = _write_token_to_sub2api(entry, email_hint or "", idx)
                item["sso_hint"] = sso_hint
                item["via"] = "cached_token_http"
                if item.get("status") == "ok":
                    cached_hits += 1
                    _mark_ok(item)
                    logs.emit(
                        f"sub2api 导入 [{idx}/{len(items)}] 成功(cached_token_http): "
                        f"{item.get('email') or item.get('user_id') or 'ok'}",
                        "success",
                    )
                else:
                    fail_count += 1
                    logs.emit(
                        f"sub2api 导入 [{idx}/{len(items)}] 失败(cached_token_http): {item.get('error')}",
                        "warn",
                    )
                results_by_idx[idx] = item
            except Exception as e:
                fail_count += 1
                item = {
                    "index": idx,
                    "email": email_hint or None,
                    "sso_hint": sso_hint,
                    "status": "failed",
                    "error": f"导入异常: {e}",
                    "retryable": True,
                    "via": "error",
                }
                results_by_idx[idx] = item
                logs.emit(f"sub2api 导入 [{idx}/{len(items)}] 异常: {e}", "error")
        else:
            need_sso_indices.append(idx)

    # —— 路径 B：无缓存 → 服务端 sso-to-oauth（批量，服务端自己换票） ——
    if need_sso_indices:
        sso_list = [items[i - 1].get("sso") or "" for i in need_sso_indices]
        email_list = [items[i - 1].get("email") or "" for i in need_sso_indices]
        logs.emit(
            f"sub2api HTTP 导入：{len(need_sso_indices)} 条走服务端 sso-to-oauth…",
            "info",
        )
        # 分批，避免一次塞太多
        batch_size = 20
        for batch_start in range(0, len(need_sso_indices), batch_size):
            batch_idxs = need_sso_indices[batch_start : batch_start + batch_size]
            batch_tokens = [items[i - 1].get("sso") or "" for i in batch_idxs]
            batch_emails = [items[i - 1].get("email") or "" for i in batch_idxs]
            api_result = sub2api_import_sso_tokens_http(
                batch_tokens,
                token=api_token,
                base_url=api_base,
                group_id=group_id,
                emails=batch_emails if len(batch_emails) == 1 else None,
            )

            # 建立 index(1-based in batch) -> result
            created_by_index: dict[int, dict] = {}
            failed_by_index: dict[int, str] = {}
            if api_result.get("ok"):
                for c in api_result.get("created") or []:
                    if not isinstance(c, dict):
                        continue
                    # created 可能是账号对象或 {index, ...}
                    ci = c.get("index")
                    if ci is None and c.get("id") is not None:
                        # 无 index 时按顺序不好对齐，先跳过 index 映射，后面按失败列表补
                        pass
                    if ci is not None:
                        try:
                            created_by_index[int(ci)] = c
                        except (TypeError, ValueError):
                            pass
                # 若 created 无 index 字段，按返回顺序对齐成功数
                if not created_by_index and api_result.get("created"):
                    created_list = [c for c in api_result["created"] if isinstance(c, dict)]
                    failed_set = set()
                    for f in api_result.get("failed") or []:
                        if isinstance(f, dict) and f.get("index") is not None:
                            try:
                                failed_set.add(int(f["index"]))
                            except (TypeError, ValueError):
                                pass
                    # 1-based batch positions not in failed → success in order
                    success_slots = [i for i in range(1, len(batch_idxs) + 1) if i not in failed_set]
                    for slot, c in zip(success_slots, created_list):
                        created_by_index[slot] = c

                for f in api_result.get("failed") or []:
                    if not isinstance(f, dict):
                        continue
                    fi = f.get("index")
                    if fi is None:
                        continue
                    try:
                        failed_by_index[int(fi)] = str(f.get("error") or "sso-to-oauth failed")
                    except (TypeError, ValueError):
                        pass
            else:
                # 整批失败：全部标记，后面可走 device flow 兜底
                err = api_result.get("error") or "sso-to-oauth 请求失败"
                for bi, idx in enumerate(batch_idxs, 1):
                    failed_by_index[bi] = err

            for bi, idx in enumerate(batch_idxs, 1):
                email_hint = items[idx - 1].get("email") or ""
                sso = items[idx - 1].get("sso") or ""
                sso_hint = (sso[:12] + "...") if len(sso) > 12 else sso
                if bi in created_by_index:
                    c = created_by_index[bi]
                    acc = c.get("account") if isinstance(c.get("account"), dict) else (
                        c.get("_account") if isinstance(c.get("_account"), dict) else {}
                    )
                    cred = c.get("credentials") if isinstance(c.get("credentials"), dict) else {}
                    if not cred and isinstance(acc.get("credentials"), dict):
                        cred = acc["credentials"]
                    account_id = c.get("id") if c.get("id") is not None else acc.get("id")
                    email_out = (
                        email_hint
                        or c.get("email")
                        or cred.get("email")
                        or acc.get("name")
                        or c.get("name")
                        or None
                    )
                    item = {
                        "index": idx,
                        "email": email_out,
                        "sso_hint": sso_hint,
                        "status": "ok",
                        "account_id": account_id,
                        "action": "sso_to_oauth",
                        "group_id": group_id,
                        "user_id": cred.get("user_id")
                        or cred.get("sub")
                        or c.get("user_id")
                        or acc.get("user_id"),
                        "expires_at": cred.get("expires_at")
                        or c.get("expires_at")
                        or acc.get("expires_at"),
                        "has_refresh_token": bool(
                            cred.get("refresh_token")
                            or (acc.get("credentials_status") or {}).get("has_refresh_token")
                        ),
                        "via": "sso_to_oauth_http",
                    }
                    sso_api_hits += 1
                    _mark_ok(item)
                    results_by_idx[idx] = item
                    logs.emit(
                        f"sub2api 导入 [{idx}/{len(items)}] 成功(sso_to_oauth_http): "
                        f"{item.get('email') or item.get('user_id') or 'ok'}"
                        f" · id={account_id} · group={group_id}",
                        "success",
                    )
                else:
                    err = failed_by_index.get(bi) or "sso-to-oauth 未返回成功"
                    # 无效 SSO 不重试；限流/超时等可走本机 device flow
                    err_l = err.lower()
                    invalid = (
                        "unauthorized" in err_l
                        or "invalid" in err_l
                        or "expired" in err_l
                        or "会话无效" in err
                        or "非有效" in err
                    )
                    item = {
                        "index": idx,
                        "email": email_hint or None,
                        "sso_hint": sso_hint,
                        "status": "failed",
                        "error": err,
                        "retryable": not invalid,
                        "via": "sso_to_oauth_http",
                    }
                    results_by_idx[idx] = item
                    fail_count += 1
                    logs.emit(
                        f"sub2api 导入 [{idx}/{len(items)}] 失败(sso_to_oauth_http): {err}",
                        "warn",
                    )

    # —— 路径 C：sso-to-oauth 可重试失败 → 本机 device flow 兜底 + HTTP 写 accounts ——
    retry_list = [
        idx
        for idx in range(1, len(items) + 1)
        if results_by_idx.get(idx, {}).get("status") == "failed"
        and results_by_idx[idx].get("retryable", False)
        and results_by_idx[idx].get("via") == "sso_to_oauth_http"
    ]
    if retry_list:
        logs.emit(
            f"sub2api 导入：sso-to-oauth 后 {len(retry_list)} 条可重试，"
            f"启用本机 device flow 兜底换票…",
            "warn",
        )
        for j, idx in enumerate(retry_list):
            if j > 0:
                time.sleep(5.0)
            email_hint = items[idx - 1].get("email") or ""
            sso = items[idx - 1].get("sso") or ""
            sso_hint = (sso[:12] + "...") if len(sso) > 12 else sso
            flow, last_flow_err = _device_flow_to_token(
                sso, idx, pass_label="·兜底", max_attempts=4
            )
            if not flow or not flow.get("token"):
                item = {
                    "index": idx,
                    "email": email_hint or None,
                    "sso_hint": sso_hint,
                    "status": "failed",
                    "error": last_flow_err or "本机 device flow 失败",
                    "via": "device_flow_http",
                }
                results_by_idx[idx] = item
                logs.emit(
                    f"sub2api 导入·兜底 [{idx}/{len(items)}] 仍失败: {item.get('error')}",
                    "warn",
                )
                continue
            try:
                entry = token_to_auth_entry(flow["token"], email=email_hint or "")
                item = _write_token_to_sub2api(entry, email_hint or "", idx)
                item["sso_hint"] = sso_hint
                item["via"] = "device_flow_http"
                if item.get("status") == "ok":
                    flow_hits += 1
                    fail_count = max(0, fail_count - 1)
                    _mark_ok(item)
                    results_by_idx[idx] = item
                    logs.emit(
                        f"sub2api 导入·兜底 [{idx}/{len(items)}] 成功(device_flow_http): "
                        f"{item.get('email') or item.get('user_id') or 'ok'}",
                        "success",
                    )
                else:
                    results_by_idx[idx] = item
                    logs.emit(
                        f"sub2api 导入·兜底 [{idx}/{len(items)}] 写库失败: {item.get('error')}",
                        "warn",
                    )
            except Exception as e:
                results_by_idx[idx] = {
                    "index": idx,
                    "email": email_hint or None,
                    "sso_hint": sso_hint,
                    "status": "failed",
                    "error": f"兜底异常: {e}",
                    "via": "device_flow_http",
                }
                logs.emit(f"sub2api 导入·兜底 [{idx}/{len(items)}] 异常: {e}", "error")

    # 补全未处理 index（理论上不应有）
    for idx in range(1, len(items) + 1):
        if idx not in results_by_idx:
            fail_count += 1
            results_by_idx[idx] = {
                "index": idx,
                "email": items[idx - 1].get("email") or None,
                "status": "failed",
                "error": "未处理",
                "via": "error",
            }

    results = [results_by_idx[i] for i in sorted(results_by_idx)]
    msg = (
        f"SSO 导入 sub2api(HTTP) 完成：{ok_count} 成功, {fail_count} 失败"
        f"（缓存直写 {cached_hits}，sso-to-oauth {sso_api_hits}，device flow {flow_hits}）"
    )
    return {
        "ok": fail_count == 0 and ok_count > 0,
        "message": msg,
        "success": ok_count,
        "fail": fail_count,
        "total": len(items),
        "cached_hits": cached_hits,
        "sso_api_hits": sso_api_hits,
        "flow_hits": flow_hits,
        "results": results,
        "imported": imported,
        "base_url": api_base,
        "group_id": str(group_id),
        "group_name": sub2.get("group_name"),
        "mode": "http_admin_api",
    }


def _exchange_import_token(sso: str, timeout: int) -> dict:
    """导入兜底换票：同样复用节点（代理池租约），不强制直连。"""
    proxy_spec, lease, proxy_label = _lease_token_proxy({"id": "import-token"})
    result = None
    try:
        result = sso_device_flow_to_token(
            sso, timeout=timeout, issue_token=True, proxy_spec=proxy_spec
        )
        return result
    finally:
        _release_token_proxy(
            lease,
            bool(isinstance(result, dict) and result.get("ok") and result.get("token")),
            f"import token exchange · {proxy_label}",
        )


def _clear_completed_import_tokens(job: dict) -> None:
    oauth_targets = {"sub2api", "cpa_local", "cpa_remote", "grok2api_build"}
    rows = {str(item.get("id") or ""): item for item in job.get("accounts") or []}
    with runner.file_lock:
        for item in runner.recent_success:
            row = rows.get(str(item.get("id") or ""))
            if not row:
                continue
            sub2_state = (row.get("targets") or {}).get("sub2api") or {}
            if sub2_state.get("status") == "success":
                item["imported"] = True  # old status/API compatibility
            if oauth_targets.intersection((row.get("targets") or {}).keys()):
                item["auth_token"] = None
                # 内存里不再保留 access_token；token_status 标记已消费
                if item.get("token_status") == "ok":
                    item["token_status"] = "imported"


IMPORT_CONFIG = ImportConfigStore(BASE_DIR, env_reader=read_env_file)
IMPORT_TARGETS = ImportTargets(BASE_DIR, IMPORT_CONFIG)
IMPORT_JOBS = ImportJobManager(
    BASE_DIR,
    IMPORT_CONFIG,
    IMPORT_TARGETS,
    sub2api_importer=import_sso_to_upstream,
    token_exchanger=_exchange_import_token,
    register_proxy_getter=lambda: "",
    log=logs.emit,
    on_job_complete=_clear_completed_import_tokens,
    source_resolver=lambda source, rows: _resolve_import_retry_source(source, rows),
)
IMPORT_PREVIEWS: dict[str, dict] = {}
IMPORT_PREVIEW_LOCK = threading.RLock()


def _queue_configured_auto_import(accounts: list[dict]) -> None:
    """新号注册成功后按 import-services 配置自动分发（无 BFS/风控过滤）。"""
    accounts = [item for item in accounts if item.get("sso")]
    if not accounts:
        return
    cfg = IMPORT_CONFIG.load()
    targets: list[str] = []
    for service in ("sub2api", "cpa", "grok2api"):
        targets.extend(cfg["services"][service].get("auto_targets") or [])
    targets = list(dict.fromkeys(target for target in targets if target in TARGETS))
    if not targets:
        return
    IMPORT_JOBS.create_job(
        accounts,
        targets,
        source={"type": "automatic", "registered_at": datetime.now(timezone.utc).isoformat()},
        force_refresh=False,
        allow_marked=False,
        automatic=True,
    )


runner.on_account = _queue_configured_auto_import


def mask_secret(value: str, keep: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "*" * min(12, len(value) - keep * 2) + value[-keep:]


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/email-settings")
def email_settings():
    return render_template("email_settings.html")


@app.get("/import-services")
def import_services_page():
    return render_template("import_services.html")


@app.get("/proxy-settings")
def proxy_settings_page():
    return render_template("proxy_settings.html")


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "service": "grok-register-ui"})


@app.get("/api/status")
def status():
    data = runner.get_status()
    data["env"] = env_snapshot()
    data["proxy_pool"] = proxy_pool.summary()
    data["domain_pool"] = domain_pool.summary()
    return jsonify(data)


@app.get("/api/config")
def get_config():
    cfg = read_env_file()
    return jsonify({
        "ok": True,
        "config": {
            "WORKER_DOMAIN": cfg.get("WORKER_DOMAIN", ""),
            # Email credentials moved to /api/email-config and are write-only.
            "FREEMAIL_TOKEN": "",
            "FREEMAIL_ADMIN_KEY": "",
            "FREEMAIL_DOMAIN": cfg.get("FREEMAIL_DOMAIN", DEFAULTS["FREEMAIL_DOMAIN"]),
            "FREEMAIL_RANDOM_SUBDOMAIN": cfg.get(
                "FREEMAIL_RANDOM_SUBDOMAIN",
                DEFAULTS["FREEMAIL_RANDOM_SUBDOMAIN"],
            ),
            "FREEMAIL_API_STYLE": cfg.get("FREEMAIL_API_STYLE", DEFAULTS["FREEMAIL_API_STYLE"]),
            "LOG_MAX_MB": cfg.get("LOG_MAX_MB", DEFAULTS["LOG_MAX_MB"]),
            "LOG_ROTATE_FILE_COUNT": cfg.get("LOG_ROTATE_FILE_COUNT", DEFAULTS["LOG_ROTATE_FILE_COUNT"]),
            "UI_HOST": cfg.get("UI_HOST", DEFAULTS["UI_HOST"]),
            "UI_PORT": cfg.get("UI_PORT", DEFAULTS["UI_PORT"]),
            "SUB2API_URL": cfg.get("SUB2API_URL", cfg.get("UPSTREAM_URL", DEFAULTS["SUB2API_URL"])),
            "SUB2API_DOCKER_CONTAINER": cfg.get("SUB2API_DOCKER_CONTAINER", DEFAULTS["SUB2API_DOCKER_CONTAINER"]),
            "SUB2API_DB_HOST": cfg.get("SUB2API_DB_HOST", DEFAULTS["SUB2API_DB_HOST"]),
            "SUB2API_DB_PORT": cfg.get("SUB2API_DB_PORT", DEFAULTS["SUB2API_DB_PORT"]),
            "SUB2API_DB_NAME": cfg.get("SUB2API_DB_NAME", DEFAULTS["SUB2API_DB_NAME"]),
            "SUB2API_DB_USER": cfg.get("SUB2API_DB_USER", DEFAULTS["SUB2API_DB_USER"]),
            "SUB2API_DB_PASSWORD": "",
            "SUB2API_GROK_GROUP_ID": cfg.get("SUB2API_GROK_GROUP_ID", DEFAULTS["SUB2API_GROK_GROUP_ID"]),
            "SUB2API_GROK_GROUP_NAME": cfg.get("SUB2API_GROK_GROUP_NAME", DEFAULTS["SUB2API_GROK_GROUP_NAME"]),
            "UPSTREAM_URL": cfg.get("SUB2API_URL", cfg.get("UPSTREAM_URL", DEFAULTS["SUB2API_URL"])),
            "UPSTREAM_ADMIN_EMAIL": cfg.get("UPSTREAM_ADMIN_EMAIL", ""),
            "UPSTREAM_ADMIN_PASSWORD": "",
            "EMAIL_TYPE": cfg.get("EMAIL_TYPE", DEFAULTS["EMAIL_TYPE"]),
            "OUTLOOK_ACCOUNTS": "",
            "OUTLOOK_ALIAS_LIMIT": cfg.get("OUTLOOK_ALIAS_LIMIT", DEFAULTS["OUTLOOK_ALIAS_LIMIT"]),
        },
        "masked": {
            "FREEMAIL_TOKEN": mask_secret(cfg.get("FREEMAIL_TOKEN", "")),
            "FREEMAIL_ADMIN_KEY": mask_secret(cfg.get("FREEMAIL_ADMIN_KEY", "")),
            "SUB2API_DB_PASSWORD": mask_secret(cfg.get("SUB2API_DB_PASSWORD", DEFAULTS["SUB2API_DB_PASSWORD"])),
            "UPSTREAM_ADMIN_PASSWORD": mask_secret(cfg.get("UPSTREAM_ADMIN_PASSWORD", "")),
        },
    })


def _sync_cf_domain_env() -> None:
    """Keep the legacy provider list aligned with currently active pool rows."""
    values = read_env_file()
    active_domains = domain_pool.active_domains()
    values["EMAIL_CF_TEMP_DOMAINS_JSON"] = json.dumps(
        active_domains, ensure_ascii=False, separators=(",", ":")
    )
    values["EMAIL_CF_TEMP_AUTO_DOMAIN"] = (
        "0" if domain_pool.summary().get("total") else values.get("EMAIL_CF_TEMP_AUTO_DOMAIN", "1")
    )
    write_env_file(values)
    os.environ["EMAIL_CF_TEMP_DOMAINS_JSON"] = values["EMAIL_CF_TEMP_DOMAINS_JSON"]
    os.environ["EMAIL_CF_TEMP_AUTO_DOMAIN"] = values["EMAIL_CF_TEMP_AUTO_DOMAIN"]


@app.get("/api/email-config")
def get_email_config():
    structured = resolved_email_config(read_env_file())
    if domain_pool.summary().get("total"):
        active_domains = domain_pool.active_domains()
        structured["providers"]["cloudflare_temp"]["domains"] = active_domains
        structured["providers"]["cloudflare_temp"]["auto_domain"] = False
    try:
        from g.email_service import EmailService
        cf_health = dict(EmailService._cf_domain_health)
        outlook_health = dict(EmailService._outlook_health)
    except Exception:
        cf_health = {}
        outlook_health = {}
    return jsonify({
        "ok": True,
        "config": redact_config(structured, mask_secret),
        "labels": PROVIDER_LABELS,
        "test_states": EMAIL_TEST_STATES,
        "running": runner.is_running(),
        "runtime": {"cloudflare_domain_health": cf_health, "outlook_account_health": outlook_health},
        "domain_pool": domain_pool.list_public(page=1, per_page=50),
        "note": "密钥只写不读；留空表示保留现有值",
    })


@app.post("/api/email-config")
def save_email_config():
    if runner.is_running():
        return jsonify({"ok": False, "message": "任务运行中，请先停止再修改邮箱配置"}), 409
    body = request.get_json(silent=True) or {}
    current = read_env_file()
    before = resolved_email_config(current)
    active = before["provider"]
    # Saving is a draft operation; activation has a separate endpoint.
    body = dict(body)
    body["provider"] = active
    providers = dict(body.get("providers") or {})
    cloudflare_temp = dict(providers.get("cloudflare_temp") or {})
    if domain_pool.summary().get("total"):
        cloudflare_temp["domains"] = domain_pool.active_domains()
        cloudflare_temp["auto_domain"] = False
    providers["cloudflare_temp"] = cloudflare_temp
    body["providers"] = providers
    try:
        values = serialize_structured_config(current, body)
        after = resolved_email_config(values)
        write_env_file(values)
        apply_env_to_process(values)
        common_changed = before["common"] != after["common"]
        for provider in PROVIDERS:
            if common_changed or before["providers"][provider] != after["providers"][provider]:
                EMAIL_TEST_STATES[provider] = {
                    "status": "untested",
                    "message": "配置已变化，请重新测试",
                    "tested_at": "",
                }
        logs.emit("邮箱配置已保存", "success")
        return jsonify({
            "ok": True,
            "message": "邮箱配置已保存",
            "config": redact_config(after, mask_secret),
            "test_states": EMAIL_TEST_STATES,
        })
    except Exception as exc:
        return jsonify({"ok": False, "message": f"保存邮箱配置失败: {exc}"}), 400


@app.post("/api/email-config/test")
def test_email_config():
    if runner.is_running():
        return jsonify({"ok": False, "message": "任务运行中不能测试邮箱配置"}), 409
    body = request.get_json(silent=True) or {}
    provider = normalize_provider(body.get("provider"))
    structured = resolved_email_config(read_env_file())
    errors = validate_provider_config(structured, provider)
    if errors:
        return jsonify({"ok": False, "message": "；".join(errors)}), 400
    try:
        from g.email_service import EmailService

        result = EmailService(provider_override=provider).test_connection(
            test_all_domains=bool(body.get("test_all_domains"))
        )
    except Exception as exc:
        result = {"ok": False, "message": str(exc)}
    now = datetime.now(timezone.utc).isoformat()
    EMAIL_TEST_STATES[provider] = {
        "status": "passed" if result.get("ok") else "failed",
        "message": str(result.get("message") or "测试失败"),
        "tested_at": now,
        "details": result.get("details") or {},
    }
    code = 200 if result.get("ok") else 502
    return jsonify({**result, "provider": provider, "test_state": EMAIL_TEST_STATES[provider]}), code


@app.post("/api/email-config/activate")
def activate_email_config():
    if runner.is_running():
        return jsonify({"ok": False, "message": "任务运行中不能切换邮箱服务"}), 409
    body = request.get_json(silent=True) or {}
    provider = normalize_provider(body.get("provider"))
    current = read_env_file()
    structured = resolved_email_config(current)
    errors = validate_provider_config(structured, provider)
    if errors:
        return jsonify({"ok": False, "message": "；".join(errors)}), 400
    if EMAIL_TEST_STATES[provider].get("status") != "passed":
        return jsonify({"ok": False, "message": "请先测试该邮箱服务，测试通过后才能启用"}), 409
    values = serialize_structured_config(current, {"provider": provider})
    write_env_file(values)
    apply_env_to_process(values)
    logs.emit(f"当前邮箱服务已切换为 {PROVIDER_LABELS[provider]}", "success")
    return jsonify({"ok": True, "message": f"已启用 {PROVIDER_LABELS[provider]}", "provider": provider})


@app.delete("/api/email-config/<provider>")
def clear_email_provider(provider: str):
    if runner.is_running():
        return jsonify({"ok": False, "message": "任务运行中不能清除邮箱配置"}), 409
    provider = normalize_provider(provider)
    current = read_env_file()
    active = resolved_email_config(current)["provider"]
    if provider == active:
        return jsonify({"ok": False, "message": "当前启用的服务不能清除，请先切换到其他已验证服务"}), 409
    resets = {
        "outlook": {"accounts": [], "default_alias_limit": 5, "concurrency": 5},
        "freemail": {"base_url": "", "token": "", "domain": "auto", "concurrency": 10},
        "yyds": {"base_url": EMAIL_DEFAULTS["EMAIL_YYDS_BASE_URL"], "api_key": "", "domain": "auto", "platform_code": "grok", "concurrency": 5},
        "cloudflare_temp": {"base_url": "", "site_token": "", "admin_key": "", "domains": [], "auto_domain": True, "random_subdomain": False, "concurrency": 10},
    }
    clear_markers = {
        "freemail": ["freemail.token"],
        "yyds": ["yyds.api_key"],
        "cloudflare_temp": ["cloudflare_temp.site_token", "cloudflare_temp.admin_key"],
    }.get(provider, [])
    values = serialize_structured_config(current, {
        "provider": active,
        "providers": {provider: resets[provider]},
        "clear_secrets": clear_markers,
    })
    write_env_file(values)
    apply_env_to_process(values)
    EMAIL_TEST_STATES[provider] = {"status": "untested", "message": "配置已清除", "tested_at": ""}
    return jsonify({"ok": True, "message": f"已清除 {PROVIDER_LABELS[provider]} 配置"})


@app.get("/api/email-config/domains")
def email_config_domains():
    provider = normalize_provider(request.args.get("provider"))
    try:
        from g.email_service import EmailService

        result = EmailService(provider_override=provider).discover_domains()
        return jsonify(result), (200 if result.get("ok") else 502)
    except Exception as exc:
        return jsonify({"ok": False, "domains": [], "message": str(exc)}), 500


@app.get("/api/domains")
def domain_pool_list():
    try:
        data = domain_pool.list_public(
            page=request.args.get("page", 1, type=int),
            per_page=request.args.get("per_page", 50, type=int),
            query=request.args.get("q", "", type=str),
            status=request.args.get("status", "", type=str),
        )
        return jsonify({"ok": True, **data})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400


@app.post("/api/domains")
def domain_pool_add():
    body = request.get_json(silent=True) or {}
    values = body.get("domains")
    if not isinstance(values, list):
        values = [body.get("domain")]
    try:
        if body.get("replace"):
            if runner.is_running():
                return jsonify({"ok": False, "message": "任务运行中不能整体替换域名列表"}), 409
            result = domain_pool.reconcile_configured([str(x or "") for x in values])
            message = (
                f"域名列表已生效：启用 {result['active']}，新增 {result['added']}，"
                f"停用旧域 {result['disabled']}"
            )
        else:
            if runner.is_running():
                return jsonify({"ok": False, "message": "任务运行中不能添加新域名，可启停已有域名"}), 409
            result = domain_pool.add([str(x or "") for x in values], enabled=True)
            message = (
                f"导入完成并立即启用：新增 {result['added']}，已存在 {result['duplicates']}，"
                f"无效 {result['invalid']}"
            )
        _sync_cf_domain_env()
        return jsonify({"ok": True, **result, "message": message})
    except DomainPoolError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400


@app.patch("/api/domains/<domain_id>")
def domain_pool_update(domain_id: str):
    try:
        values = request.get_json(silent=True) or {}
        item = domain_pool.update(domain_id, values)
        _sync_cf_domain_env()
        return jsonify({"ok": True, "item": item})
    except KeyError:
        return jsonify({"ok": False, "message": "域名不存在"}), 404
    except DomainPoolError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 409


def _test_domain(domain_id: str) -> dict:
    try:
        item = domain_pool.get_public(domain_id)
        from g.email_service import EmailService

        service = EmailService(provider_override="cloudflare_temp")
        _token, address = service.create_email_for_domain(item["domain"])
        ok = bool(address)
        deleted = False
        if address:
            try:
                deleted = bool(service.delete_email(address))
            except Exception:
                deleted = False
        message = "创建并删除测试邮箱成功" if ok else "创建测试邮箱失败"
        if ok and not deleted:
            message = "创建测试邮箱成功；清理失败"
        domain_pool.set_email_health(domain_id, ok=ok, message=message)
        return {"id": domain_id, "ok": ok, "message": message}
    except KeyError:
        return {"id": domain_id, "ok": False, "message": "域名不存在"}
    except Exception as exc:
        try:
            domain_pool.set_email_health(domain_id, ok=False, message=str(exc))
        except Exception:
            pass
        return {"id": domain_id, "ok": False, "message": str(exc)}


@app.post("/api/domains/test")
def domain_pool_test():
    body = request.get_json(silent=True) or {}
    ids = body.get("ids") or []
    if not isinstance(ids, list) or not ids:
        return jsonify({"ok": False, "message": "请选择要测试的域名"}), 400
    ids = [str(x) for x in ids[:2000]]
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(ids))) as pool:
        results = list(pool.map(_test_domain, ids))
    passed = sum(1 for x in results if x["ok"])
    return jsonify({"ok": True, "all_passed": passed == len(results), "passed": passed, "total": len(results), "results": results})


@app.post("/api/domains/bulk")
def domain_pool_bulk():
    body = request.get_json(silent=True) or {}
    ids = [str(x) for x in (body.get("ids") or [])]
    action = str(body.get("action") or "")
    if not ids:
        return jsonify({"ok": False, "message": "请选择域名"}), 400
    if action not in {"enable", "disable", "delete"}:
        return jsonify({"ok": False, "message": "批量操作无效"}), 400
    if action == "delete":
        if runner.is_running():
            return jsonify({"ok": False, "message": "任务运行中不能删除域名"}), 409
        result = domain_pool.delete(ids)
        _sync_cf_domain_env()
        return jsonify({"ok": True, **result, "message": f"已永久删除 {result['removed']} 个域名及其历史"})
    changed = failed = 0
    errors = []
    for domain_id in ids[:2000]:
        try:
            domain_pool.update(domain_id, {"enabled": action == "enable"})
            changed += 1
        except Exception as exc:
            failed += 1
            errors.append({"id": domain_id, "message": str(exc)})
    _sync_cf_domain_env()
    return jsonify({"ok": True, "all_passed": failed == 0, "changed": changed, "failed": failed, "errors": errors[:100]})


@app.post("/api/domains/<domain_id>/move")
def domain_pool_move(domain_id: str):
    if runner.is_running():
        return jsonify({"ok": False, "message": "任务运行中不能调整域名顺序"}), 409
    direction = str((request.get_json(silent=True) or {}).get("direction") or "")
    if direction not in {"up", "down"}:
        return jsonify({"ok": False, "message": "direction 必须是 up/down"}), 400
    try:
        domain_pool.move(domain_id, direction)
        return jsonify({"ok": True})
    except KeyError:
        return jsonify({"ok": False, "message": "域名不存在"}), 404


@app.get("/api/mail-domains")
def mail_domains():
    """从 freemail / cloudflare_temp_email 自动拉取可用邮箱域名"""
    from g.email_service import EmailService

    worker = request.args.get("worker_domain")
    token = request.args.get("token")
    # 未传 token 时用已保存配置；传空字符串表示无密码
    if token is None:
        token = read_env_file().get("FREEMAIL_TOKEN", "")
    if worker is None:
        worker = read_env_file().get("WORKER_DOMAIN", "")
    try:
        result = EmailService.fetch_mail_domains(worker_domain=worker, token=token)
        code = 200 if result.get("ok") else 502
        return jsonify(result), code
    except Exception as e:
        return jsonify({
            "ok": False,
            "domains": [],
            "default_domains": [],
            "random_subdomain_domains": [],
            "selected": "auto",
            "message": str(e),
            "settings": {},
        }), 500


@app.post("/api/config")
def save_config():
    if runner.is_running():
        return jsonify({"ok": False, "message": "任务运行中，请先停止再修改配置"}), 409

    body = request.get_json(silent=True) or {}
    current = read_env_file()
    legacy_sub2_update = bool(LEGACY_SUB2_CONFIG_KEYS.intersection(body))

    worker = str(body.get("WORKER_DOMAIN", current.get("WORKER_DOMAIN", ""))).strip()
    token = str(body.get("FREEMAIL_TOKEN", current.get("FREEMAIL_TOKEN", ""))).strip()
    admin_key = str(
        body.get(
            "FREEMAIL_ADMIN_KEY",
            current.get("FREEMAIL_ADMIN_KEY", ""),
        )
    ).strip()
    mail_domain = str(body.get("FREEMAIL_DOMAIN", current.get("FREEMAIL_DOMAIN", DEFAULTS["FREEMAIL_DOMAIN"]))).strip() or "auto"
    random_subdomain_raw = body.get(
        "FREEMAIL_RANDOM_SUBDOMAIN",
        current.get(
            "FREEMAIL_RANDOM_SUBDOMAIN",
            DEFAULTS["FREEMAIL_RANDOM_SUBDOMAIN"],
        ),
    )
    random_subdomain = str(random_subdomain_raw).strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    api_style = str(body.get("FREEMAIL_API_STYLE", current.get("FREEMAIL_API_STYLE", DEFAULTS["FREEMAIL_API_STYLE"]))).strip() or "auto"
    log_max_mb = str(body.get(
        "LOG_MAX_MB",
        current.get("LOG_MAX_MB", DEFAULTS["LOG_MAX_MB"]),
    )).strip()
    log_rotate_file_count = str(body.get(
        "LOG_ROTATE_FILE_COUNT",
        current.get("LOG_ROTATE_FILE_COUNT", DEFAULTS["LOG_ROTATE_FILE_COUNT"]),
    )).strip()
    ui_host = str(body.get("UI_HOST", current.get("UI_HOST", DEFAULTS["UI_HOST"]))).strip() or "127.0.0.1"
    ui_port = str(body.get("UI_PORT", current.get("UI_PORT", DEFAULTS["UI_PORT"]))).strip() or "3333"
    sub2api_url = str(body.get("SUB2API_URL", body.get("UPSTREAM_URL", current.get("SUB2API_URL", current.get("UPSTREAM_URL", DEFAULTS["SUB2API_URL"]))))).strip()
    sub2api_container = str(body.get("SUB2API_DOCKER_CONTAINER", current.get("SUB2API_DOCKER_CONTAINER", DEFAULTS["SUB2API_DOCKER_CONTAINER"]))).strip() or DEFAULTS["SUB2API_DOCKER_CONTAINER"]
    sub2api_db_host = str(body.get("SUB2API_DB_HOST", current.get("SUB2API_DB_HOST", DEFAULTS["SUB2API_DB_HOST"]))).strip() or DEFAULTS["SUB2API_DB_HOST"]
    sub2api_db_port = str(body.get("SUB2API_DB_PORT", current.get("SUB2API_DB_PORT", DEFAULTS["SUB2API_DB_PORT"]))).strip() or DEFAULTS["SUB2API_DB_PORT"]
    sub2api_db_name = str(body.get("SUB2API_DB_NAME", current.get("SUB2API_DB_NAME", DEFAULTS["SUB2API_DB_NAME"]))).strip() or DEFAULTS["SUB2API_DB_NAME"]
    sub2api_db_user = str(body.get("SUB2API_DB_USER", current.get("SUB2API_DB_USER", DEFAULTS["SUB2API_DB_USER"]))).strip() or DEFAULTS["SUB2API_DB_USER"]
    sub2api_db_password = str(body.get("SUB2API_DB_PASSWORD", current.get("SUB2API_DB_PASSWORD", DEFAULTS["SUB2API_DB_PASSWORD"]))).strip() or DEFAULTS["SUB2API_DB_PASSWORD"]
    # 页面只维护分组名称；ID 由连通测试/导入时自动拉取并回写
    sub2api_group_name = str(
        body.get(
            "SUB2API_GROK_GROUP_NAME",
            current.get("SUB2API_GROK_GROUP_NAME", DEFAULTS["SUB2API_GROK_GROUP_NAME"]),
        )
    ).strip() or DEFAULTS["SUB2API_GROK_GROUP_NAME"]
    # 兼容旧前端仍传 ID：有则暂存，最终以名称解析结果为准
    sub2api_group_id = str(
        body.get(
            "SUB2API_GROK_GROUP_ID",
            current.get("SUB2API_GROK_GROUP_ID", DEFAULTS["SUB2API_GROK_GROUP_ID"]),
        )
        or ""
    ).strip()
    upstream_url = sub2api_url
    upstream_email = str(body.get("UPSTREAM_ADMIN_EMAIL", current.get("UPSTREAM_ADMIN_EMAIL", ""))).strip()
    upstream_pwd = str(body.get("UPSTREAM_ADMIN_PASSWORD", current.get("UPSTREAM_ADMIN_PASSWORD", ""))).strip()
    email_type = str(body.get("EMAIL_TYPE", current.get("EMAIL_TYPE", DEFAULTS["EMAIL_TYPE"]))).strip().lower()
    outlook_accounts = str(body.get("OUTLOOK_ACCOUNTS", current.get("OUTLOOK_ACCOUNTS", ""))).strip()
    outlook_alias_limit = str(body.get("OUTLOOK_ALIAS_LIMIT", current.get("OUTLOOK_ALIAS_LIMIT", DEFAULTS["OUTLOOK_ALIAS_LIMIT"]))).strip() or "5"

    # 允许前端传空密钥表示“保留原值”：用特殊标记
    if body.get("FREEMAIL_TOKEN") is None:
        token = current.get("FREEMAIL_TOKEN", "")
    if body.get("FREEMAIL_ADMIN_KEY") is None:
        admin_key = current.get("FREEMAIL_ADMIN_KEY", "")
    if body.get("UPSTREAM_ADMIN_EMAIL") is None:
        upstream_email = current.get("UPSTREAM_ADMIN_EMAIL", "")
    if body.get("UPSTREAM_ADMIN_PASSWORD") is None:
        upstream_pwd = current.get("UPSTREAM_ADMIN_PASSWORD", "")


    # 规范化 worker 域名
    worker = worker.replace("https://", "").replace("http://", "").strip().rstrip("/")
    if mail_domain.lower() in ("", "auto", "default", "随机", "自动"):
        mail_domain = "auto"
    sub2api_url = normalize_upstream_url(sub2api_url) or DEFAULTS["SUB2API_URL"]
    upstream_url = sub2api_url

    legacy_email_update = any(
        key in body
        for key in (
            "EMAIL_TYPE", "OUTLOOK_ACCOUNTS", "OUTLOOK_ALIAS_LIMIT",
            "WORKER_DOMAIN", "FREEMAIL_TOKEN", "FREEMAIL_ADMIN_KEY",
            "FREEMAIL_DOMAIN", "FREEMAIL_RANDOM_SUBDOMAIN", "FREEMAIL_API_STYLE",
        )
    )
    if legacy_email_update and email_type in ("outlook", "outlook-hotmail"):
        if not outlook_accounts:
            return jsonify({"ok": False, "message": "邮箱类型为 Outlook 时，必须填写账号列表"}), 400
        if (
            not re.fullmatch(r"\d{1,3}", outlook_alias_limit)
            or not (1 <= int(outlook_alias_limit) <= 999)
        ):
            return jsonify(
                {"ok": False, "message": "Outlook 加号地址上限范围 1-999"}
            ), 400
    elif legacy_email_update:
        if not worker or not token:
            return jsonify({"ok": False, "message": "WORKER_DOMAIN 与 FREEMAIL_TOKEN 为必填"}), 400
        if random_subdomain and mail_domain == "auto":
            return jsonify(
                {
                    "ok": False,
                    "message": "启用随机子域名时，请选择 RANDOM_SUBDOMAIN_DOMAINS 中的基础域名",
                }
            ), 400

    if not re.fullmatch(r"\d{2,5}", ui_port):
        return jsonify({"ok": False, "message": "UI_PORT 必须是 2-5 位数字"}), 400
    storage_ranges = (
        ("LOG_MAX_MB", log_max_mb, 1, 1024),
        ("LOG_ROTATE_FILE_COUNT", log_rotate_file_count, 1, 20),
    )
    for name, raw_value, minimum, maximum in storage_ranges:
        if not re.fullmatch(r"\d+", raw_value) or not (minimum <= int(raw_value) <= maximum):
            return jsonify({
                "ok": False,
                "message": f"{name} 范围 {minimum}-{maximum}",
            }), 400
    if legacy_sub2_update:
        if not re.fullmatch(r"\d{2,5}", sub2api_db_port):
            return jsonify({"ok": False, "message": "SUB2API_DB_PORT 必须是 2-5 位数字"}), 400
        if not sub2api_group_name:
            return jsonify({"ok": False, "message": "请填写分组名称"}), 400
        # 旧缓存 ID 可保留；非法则清空，等名称解析后回写
        if sub2api_group_id and not re.fullmatch(r"\d+", sub2api_group_id):
            sub2api_group_id = ""
    values = {
        "WORKER_DOMAIN": worker,
        "FREEMAIL_TOKEN": token,
        "FREEMAIL_ADMIN_KEY": admin_key,
        "FREEMAIL_DOMAIN": mail_domain,
        "FREEMAIL_RANDOM_SUBDOMAIN": "1" if random_subdomain else "0",
        "FREEMAIL_API_STYLE": api_style,
        "LOG_MAX_MB": log_max_mb,
        "LOG_ROTATE_FILE_COUNT": log_rotate_file_count,
        "UI_HOST": ui_host,
        "UI_PORT": ui_port,
        "EMAIL_TYPE": email_type,
        "OUTLOOK_ACCOUNTS": outlook_accounts,
        "OUTLOOK_ALIAS_LIMIT": outlook_alias_limit,
    }
    if legacy_sub2_update:
        values.update({
            "SUB2API_URL": sub2api_url,
            "SUB2API_DOCKER_CONTAINER": sub2api_container,
            "SUB2API_DB_HOST": sub2api_db_host,
            "SUB2API_DB_PORT": sub2api_db_port,
            "SUB2API_DB_NAME": sub2api_db_name,
            "SUB2API_DB_USER": sub2api_db_user,
            "SUB2API_DB_PASSWORD": sub2api_db_password,
            "SUB2API_GROK_GROUP_ID": sub2api_group_id,
            "SUB2API_GROK_GROUP_NAME": sub2api_group_name,
            "UPSTREAM_URL": upstream_url,
            "UPSTREAM_ADMIN_EMAIL": upstream_email,
            "UPSTREAM_ADMIN_PASSWORD": upstream_pwd,
        })
    storage_keys = (
        "LOG_MAX_MB",
        "LOG_ROTATE_FILE_COUNT",
    )
    storage_changed = any(
        str(current.get(key, DEFAULTS[key])) != str(values[key])
        for key in storage_keys
    )

    try:
        write_env_file(values)
        apply_env_to_process(values)
        logs.emit("综合配置已保存到 .env", "success")

        if storage_changed:
            enforce_storage_limits(BASE_DIR)

        # 保存后自动测试 sub2api HTTP 通道，并按名称解析 group_id 回写
        upstream_test = None
        if legacy_sub2_update and sub2api_url and upstream_email and upstream_pwd and sub2api_group_name:
            try:
                upstream_test = test_upstream_connectivity(
                    sub2api_url,
                    password=upstream_pwd,
                    email=upstream_email,
                    group_name=sub2api_group_name,
                    group_id=sub2api_group_id or None,
                )
                level = "success" if upstream_test.get("ok") else "warn"
                logs.emit(f"sub2api 连通性: {upstream_test.get('message')}", level)
                if upstream_test.get("ok") and isinstance(upstream_test.get("group"), dict):
                    g = upstream_test["group"]
                    if g.get("group_id") is not None:
                        sub2api_group_id = str(g.get("group_id"))
                        values["SUB2API_GROK_GROUP_ID"] = sub2api_group_id
                    if g.get("group_name"):
                        sub2api_group_name = str(g.get("group_name"))
                        values["SUB2API_GROK_GROUP_NAME"] = sub2api_group_name
                    # 再写一次，保证返回/侧栏立刻是解析后的 ID
                    try:
                        write_env_file(values)
                        apply_env_to_process({
                            "SUB2API_GROK_GROUP_ID": values.get("SUB2API_GROK_GROUP_ID", ""),
                            "SUB2API_GROK_GROUP_NAME": values.get("SUB2API_GROK_GROUP_NAME", ""),
                        })
                    except Exception:
                        pass
            except Exception as te:
                upstream_test = {"ok": False, "message": str(te)}
                logs.emit(f"sub2api 连通性测试异常: {te}", "warn")

        msg = "配置已保存"
        if upstream_test is not None:
            if upstream_test.get("ok"):
                g = upstream_test.get("group") or {}
                msg += f"；sub2api 连通正常，分组 {g.get('group_name') or sub2api_group_name} → id={g.get('group_id') or sub2api_group_id or '?'}"
            else:
                msg += f"；sub2api 连通失败: {upstream_test.get('message')}"

        return jsonify({
            "ok": True,
            "message": msg,
            "env": env_snapshot(),
            "config": values,
            "upstream_test": upstream_test,
        })
    except Exception as e:
        return jsonify({"ok": False, "message": f"保存失败: {e}"}), 500


@app.get("/api/logs")
def get_logs():
    after_id = request.args.get("after_id", 0, type=int)
    post_after_id = request.args.get("post_after_id", 0, type=int)
    limit = request.args.get("limit", 200, type=int)
    limit = max(1, min(limit, 500))
    latest = logs.latest_id()
    post_latest = post_logs.latest_id()
    # after_id 大于服务端序号 = 页面是旧会话，需重置游标
    reset = bool(after_id and after_id > latest)
    post_reset = bool(post_after_id and post_after_id > post_latest)
    return jsonify({
        "logs": logs.since(after_id, limit),
        "latest_id": latest,
        "reset": reset,
        # 右侧：risk / 换 token
        "post_logs": post_logs.since(post_after_id, limit),
        "post_latest_id": post_latest,
        "post_reset": post_reset,
    })


@app.post("/api/start")
def start():
    body = request.get_json(silent=True) or {}
    target = body.get("target", 1)
    try:
        target = int(target)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "message": "注册数量必须是整数"}), 400
    if target < 1 or target > 1000:
        return jsonify({"ok": False, "message": "注册数量范围 1-1000"}), 400
    workers = body.get("workers", 3)
    try:
        workers = int(workers)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "message": "并发进程数必须是整数"}), 400
    if workers < 1 or workers > 8:
        return jsonify({"ok": False, "message": "并发进程数范围 1-8"}), 400

    cfg_env = read_env_file()
    if "auto_exchange" in body:
        # 注册成功后是否自动把 SSO 换成 access_token（默认开）
        cfg_env["GROK_AUTO_EXCHANGE_TOKEN"] = "1" if body.get("auto_exchange") else "0"
    active_domains: list[str] = []
    if domain_pool.summary().get("total"):
        active_domains = domain_pool.active_domains()
        active_json = json.dumps(active_domains, ensure_ascii=False)
        cfg_env["EMAIL_CF_TEMP_DOMAINS_JSON"] = active_json
        # A configured pool is authoritative even when every row is disabled.
        # Never fall back to a provider-selected or stale legacy domain.
        cfg_env["EMAIL_CF_TEMP_AUTO_DOMAIN"] = "0"
    email_cfg = resolved_email_config(cfg_env)
    if (
        email_cfg.get("provider") == "cloudflare_temp"
        and domain_pool.summary().get("total")
        and not active_domains
    ):
        return jsonify({
            "ok": False,
            "message": "Cloudflare Temp 域名池没有已启用域名，请先启用至少一个域名。",
        }), 409
    email_errors = validate_provider_config(email_cfg)
    if email_errors:
        return jsonify({
            "ok": False,
            "message": "邮箱配置不可用：" + "；".join(email_errors) + "。请前往「邮箱配置」。",
        }), 400

    logs.emit(f"注册路径: ui_register（{workers} 进程并行，目标 {target} 个）", "info")
    result = runner.start(target=target, workers=workers, env_overrides=cfg_env)
    code = 200 if result.get("ok") else 409
    return jsonify(result), code


@app.post("/api/stop")
def stop():
    result = runner.stop()
    code = 200 if result.get("ok") else 409
    return jsonify(result), code


@app.post("/api/logs/clear")
def clear_logs():
    logs.clear()
    post_logs.clear()
    logs.emit("日志已清空", "info")
    post_logs.emit("Risk/换 token 日志已清空", "info")
    return jsonify({"ok": True})


@app.get("/api/storage")
def get_storage():
    return jsonify({"ok": True, **storage_stats(BASE_DIR)})


@app.delete("/api/storage/captures")
def clear_diagnostic_captures():
    if runner.is_running():
        return jsonify({
            "ok": False,
            "message": "注册任务运行中，停止后才能清理诊断抓包",
        }), 409
    result = clear_capture_dirs(BASE_DIR / "logs" / "fo_captures")
    logs.emit(
        f"已清理 {result['removed_groups']} 组诊断抓包",
        "success",
    )
    return jsonify({
        "ok": True,
        "message": f"已清理 {result['removed_groups']} 组诊断抓包",
        **result,
    })


@app.get("/api/keys")
def list_keys():
    keys_dir = BASE_DIR / "keys"
    if not keys_dir.exists():
        return jsonify({"files": []})
    files = []
    for p in sorted(keys_dir.glob("*.txt"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            lines = sum(1 for _ in open(p, "r", encoding="utf-8", errors="ignore") if _.strip())
        except Exception:
            lines = 0
        files.append({
            "name": p.name,
            "path": str(p.relative_to(BASE_DIR)).replace("\\", "/"),
            "size": p.stat().st_size,
            "count": lines,
            "mtime": p.stat().st_mtime,
        })
    return jsonify({"files": files[:30]})


def _short_proxy_err(err: str, max_len: int = 96) -> str:
    """把 curl 长错误压成一行可读短句。"""
    s = str(err or "").strip()
    if not s:
        return "未知错误"
    low = s.lower()
    # curl (28) 超时
    if "curl: (28)" in low or "timed out" in low or "timeout" in low:
        m = re.search(r"after\s+(\d+)\s*milliseconds", s, re.I)
        if m:
            return f"连接超时（{m.group(1)}ms）"
        return "连接超时"
    if "curl: (7)" in low or "couldn't connect" in low or "connection refused" in low:
        return "无法连接代理（拒绝/未监听）"
    if "curl: (35)" in low or "ssl" in low or "tls" in low:
        return "TLS/SSL 握手失败"
    if "curl: (56)" in low or "recv failure" in low:
        return "代理中断连接"
    if "curl: (97)" in low or "socks" in low:
        return "SOCKS 握手失败（协议/鉴权？）"
    # 去掉 See https://… 长尾巴
    s = re.split(r"\s+See https?://", s, maxsplit=1)[0]
    s = re.sub(r"\s+", " ", s).strip()
    # Failed to perform, curl: (N) …
    m = re.search(r"curl:\s*\((\d+)\)\s*(.+)$", s, re.I)
    if m:
        s = f"curl({m.group(1)}) {m.group(2).strip()}"
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return s


def _curl_get(creq, url: str, proxies=None, timeout: float = 8.0, *, allow_redirects: bool = True):
    kw = {
        "timeout": timeout,
        "impersonate": "chrome124",
        "allow_redirects": allow_redirects,
    }
    if proxies:
        kw["proxies"] = proxies
    return creq.get(url, **kw)


def _probe_egress_via_proxy(creq, proxies=None, timeout: float = 8.0) -> dict:
    """
    先测出口：IP + 国家/城市。
    主源 mayips.com；失败再 ip-api / Cloudflare / ipify(+mayips 补地区)。
    """
    import time as _time
    import json as _json

    t0 = _time.time()
    out: dict = {
        "ok": False,
        "ip": "",
        "cc": "",
        "country": "",
        "city": "",
        "region": "",
        "timezone": "",
        "postal": "",
        "at": "",
        "source": "",
        "ms": 0,
        "error": "",
    }
    # 单源别拖太久，串行失败时别堆到 30s+；总预算耗尽后跳过剩余源
    to = max(2.0, min(10.0, float(timeout or 8.0)))
    per = min(6.0, max(1.5, to / 2))
    deadline = t0 + to
    errors: list[str] = []

    def _finish(src: str, **fields) -> dict:
        out.update(fields)
        out["ok"] = True
        out["source"] = src
        out["ms"] = round((_time.time() - t0) * 1000)
        return out

    def _parse_mayips(text: str) -> dict | None:
        try:
            data = _json.loads((text or "").strip() or "{}")
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        ip = str(data.get("ip") or "").strip()
        if not ip:
            return None
        cc = str(data.get("country") or "").strip().upper()
        return {
            "ip": ip,
            "cc": cc[:2] if cc else "",
            "country": cc,
            "city": str(data.get("city") or "").strip(),
            "region": str(data.get("state") or "").strip(),
            "postal": str(data.get("postal") or "").strip(),
            "at": str(data.get("at") or "").strip(),
        }

    def _enrich_geo_with_mayips(ip: str) -> dict | None:
        """只有裸 IP 时，用 mayips ?ip= 补国家/城市（仍走同一代理）。"""
        ip = (ip or "").strip()
        if not ip:
            return None
        try:
            r = _curl_get(
                creq,
                f"https://mayips.com/?ip={ip}",
                proxies=proxies,
                timeout=per,
            )
            return _parse_mayips(r.text or "")
        except Exception:
            return None

    # 1) mayips.com（主源：IP + 地区）
    try:
        r = _curl_get(creq, "https://mayips.com/", proxies=proxies, timeout=per)
        parsed = _parse_mayips(r.text or "")
        if parsed:
            return _finish("mayips", **parsed)
        errors.append(f"mayips:http_{getattr(r, 'status_code', 0)}")
    except Exception as e:
        errors.append(f"mayips:{type(e).__name__}:{_short_proxy_err(str(e), 48)}")

    # 2) ip-api.com
    if _time.time() >= deadline:
        errors.append("egress-budget")
    else:
        try:
            r = _curl_get(
                creq,
                "http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,timezone,query",
                proxies=proxies,
                timeout=per,
            )
            data = _json.loads((r.text or "").strip() or "{}")
            if str(data.get("status") or "").lower() == "success":
                return _finish(
                    "ip-api",
                    ip=str(data.get("query") or "").strip(),
                    cc=str(data.get("countryCode") or "").upper(),
                    country=str(data.get("country") or "").strip(),
                    city=str(data.get("city") or "").strip(),
                    region=str(data.get("regionName") or "").strip(),
                    timezone=str(data.get("timezone") or "").strip(),
                )
            errors.append(f"ip-api:{data.get('message') or r.status_code}")
        except Exception as e:
            errors.append(f"ip-api:{type(e).__name__}:{_short_proxy_err(str(e), 48)}")

    # 3) Cloudflare trace（IP + 国家码）
    bare_ip = ""
    if _time.time() >= deadline:
        errors.append("egress-budget")
    else:
        try:
            r = _curl_get(
                creq,
                "https://www.cloudflare.com/cdn-cgi/trace",
                proxies=proxies,
                timeout=per,
            )
            kv = {}
            for line in (r.text or "").splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    kv[k.strip()] = v.strip()
            bare_ip = str(kv.get("ip") or "").strip()
            loc = str(kv.get("loc") or "").strip().upper()
            if bare_ip:
                # 有 loc 先用；再尝试 mayips 补城市
                extra = _enrich_geo_with_mayips(bare_ip) or {}
                return _finish(
                    "cloudflare+mayips" if extra.get("city") or extra.get("cc") else "cloudflare",
                    ip=bare_ip,
                    cc=(extra.get("cc") or (loc[:2] if loc else "")),
                    country=extra.get("country") or loc,
                    city=extra.get("city") or "",
                    region=extra.get("region") or "",
                    postal=extra.get("postal") or "",
                    at=extra.get("at") or "",
                )
            errors.append(f"cf:{r.status_code}")
        except Exception as e:
            errors.append(f"cf:{type(e).__name__}:{_short_proxy_err(str(e), 48)}")

    # 4) ipify 裸 IP → mayips 补地区
    if _time.time() >= deadline:
        errors.append("egress-budget")
    else:
        try:
            r = _curl_get(creq, "https://api.ipify.org", proxies=proxies, timeout=min(per, 5.0))
            bare_ip = (r.text or "").strip()
            if r.status_code == 200 and bare_ip and len(bare_ip) < 64:
                extra = _enrich_geo_with_mayips(bare_ip) or {}
                if extra:
                    return _finish("ipify+mayips", **extra)
                return _finish("ipify", ip=bare_ip)
            errors.append(f"ipify:http_{r.status_code}")
        except Exception as e:
            errors.append(f"ipify:{type(e).__name__}:{_short_proxy_err(str(e), 48)}")

    out["ms"] = round((_time.time() - t0) * 1000)
    out["error"] = _short_proxy_err(" | ".join(errors) if errors else "出口探测失败")
    return out


def _format_egress_label(eg: dict) -> str:
    """出口一行：1.2.3.4 · HK Kwai Chung · Kwai Tsing District"""
    if not eg or not eg.get("ok"):
        return ""
    ip = str(eg.get("ip") or "").strip()
    cc = str(eg.get("cc") or eg.get("country") or "").strip().upper()
    city = str(eg.get("city") or "").strip()
    region = str(eg.get("region") or "").strip()
    at = str(eg.get("at") or "").strip()
    tz = str(eg.get("timezone") or "").strip()
    parts = []
    if ip:
        parts.append(ip)
    # 国家 + 城市
    geo_bits = [x for x in (cc, city) if x]
    if geo_bits:
        parts.append(" ".join(geo_bits))
    # 州/区（与城市不同才显示）
    if region and region.lower() not in (city or "").lower():
        parts.append(region)
    if at and at.lower() not in ("", "isp"):
        parts.append(at)
    if tz:
        parts.append(tz)
    return " · ".join(parts)


def _probe_register_proxy(raw: str, timeout: float = 6.0) -> dict:
    """
    测试注册代理，两步：
      1) 出口 IP / 区域（ip-api 等）
      2) accounts.x.ai 连通性
    raw 空 = 直连探测。
    """
    import time as _time

    raw = (raw or "").strip()
    t0 = _time.time()
    result: dict = {
        "ok": False,
        "proxy": raw or "(direct)",
        "mode": "proxy" if raw else "direct",
        "ms": 0,
        "via": "",
        "status": 0,
        "egress_ok": False,
        "egress_ip": "",
        "egress_cc": "",
        "egress_country": "",
        "egress_city": "",
        "egress_region": "",
        "egress_timezone": "",
        "egress_label": "",
        "egress_ms": 0,
        "xai_ok": False,
        "xai_status": 0,
        "xai_ms": 0,
        "message": "",
        "error": "",
    }
    try:
        from g.proxy_pool import ProxyConfigError, parse_proxy_line
    except Exception as e:  # pragma: no cover
        result["error"] = f"parse_proxy_line 不可用: {e}"
        result["message"] = result["error"]
        result["ms"] = round((_time.time() - t0) * 1000)
        return result

    proxies = None
    server_show = "(direct)"
    if raw:
        try:
            parsed = parse_proxy_line(raw)
        except ProxyConfigError:
            result["error"] = "代理格式无法解析"
            result["message"] = (
                "格式错误。支持 host:port · http/socks5:// · "
                "user:pass@host:port · host:port:user:pass"
            )
            result["ms"] = round((_time.time() - t0) * 1000)
            return result
        url = parsed["spec"]
        if not url:
            result["error"] = "解析结果无 server"
            result["message"] = result["error"]
            result["ms"] = round((_time.time() - t0) * 1000)
            return result
        proxies = {"http": url, "https": url}
        # 展示时打码密码
        server_show = f"{parsed['host']}:{parsed['port']}"
        if parsed.get("username"):
            u = str(parsed.get("username") or "")
            u_show = u if len(u) <= 24 else (u[:12] + "…" + u[-8:])
            server_show = f"{parsed['scheme']}://{u_show}:***@{parsed['host']}:{parsed['port']}"
        result["proxy"] = server_show
        result["scheme"] = parsed["scheme"] or ""

    try:
        from curl_cffi import requests as creq
    except Exception as e:
        result["error"] = f"curl_cffi 不可用: {e}"
        result["message"] = result["error"]
        result["ms"] = round((_time.time() - t0) * 1000)
        return result

    to = max(3.0, min(30.0, float(timeout or 12.0)))
    mode = "代理" if raw else "直连"

    # ── ① 先测出口 IP / 区域（主源 mayips.com）──
    eg = _probe_egress_via_proxy(creq, proxies=proxies, timeout=min(to, 4.0))
    result["egress_ok"] = bool(eg.get("ok"))
    result["egress_ip"] = str(eg.get("ip") or "")
    result["egress_cc"] = str(eg.get("cc") or "")
    result["egress_country"] = str(eg.get("country") or "")
    result["egress_city"] = str(eg.get("city") or "")
    result["egress_region"] = str(eg.get("region") or "")
    result["egress_timezone"] = str(eg.get("timezone") or "")
    result["egress_postal"] = str(eg.get("postal") or "")
    result["egress_at"] = str(eg.get("at") or "")
    result["egress_source"] = str(eg.get("source") or "")
    result["egress_ms"] = int(eg.get("ms") or 0)
    result["egress_label"] = _format_egress_label(eg)
    if not eg.get("ok"):
        result["egress_error"] = str(eg.get("error") or "出口探测失败")

    # ── ② 再测 x.ai 连通性 ──
    xai_err = ""
    xai_t0 = _time.time()
    try:
        r = _curl_get(
            creq,
            "https://accounts.x.ai/sign-up",
            proxies=proxies,
            timeout=to,
            allow_redirects=True,
        )
        status = int(getattr(r, "status_code", 0) or 0)
        result["status"] = status
        result["xai_status"] = status
        result["xai_ms"] = round((_time.time() - xai_t0) * 1000)
        result["via"] = "accounts.x.ai"
        if status and status < 500:
            result["xai_ok"] = True
        else:
            xai_err = f"http_{status}"
    except Exception as e:
        result["xai_ms"] = round((_time.time() - xai_t0) * 1000)
        xai_err = f"{type(e).__name__}:{e}"

    result["ms"] = round((_time.time() - t0) * 1000)

    # 拼展示文案：出口 + xAI
    eg_part = ""
    if result.get("egress_ok") and result.get("egress_label"):
        eg_part = f"出口 {result['egress_label']}"
        if result.get("egress_ms"):
            eg_part += f" ({result['egress_ms']}ms)"
    elif result.get("egress_error"):
        eg_part = f"出口失败 · {_short_proxy_err(result['egress_error'])}"
    else:
        eg_part = "出口未知"

    if result.get("xai_ok") and result.get("egress_ok"):
        result["ok"] = True
        xai_part = f"xAI OK · HTTP {result.get('xai_status') or result.get('status')} · {result.get('xai_ms') or 0}ms"
        result["message"] = f"{eg_part}  →  {xai_part}"
        return result

    if result.get("xai_ok") and not result.get("egress_ok"):
        result["error"] = _short_proxy_err(result.get("egress_error") or "出口探测失败")
        result["message"] = f"{eg_part}  →  xAI OK，但出口未通过"
        return result

    short = _short_proxy_err(xai_err or "xAI 不通")
    result["error"] = short
    result["error_raw"] = str(xai_err)[:240]
    result["via"] = "fail" if not result.get("via") else result["via"]
    if result.get("egress_ok"):
        result["message"] = f"{eg_part}  →  xAI 不通 · {short} · 总 {result['ms']}ms"
    else:
        result["message"] = f"{mode}失败 · {eg_part}  →  xAI · {short} · 总 {result['ms']}ms"
    return result


def _probe_saved_proxy(proxy_id: str, *, timeout: float = 6.0) -> dict:
    template = proxy_pool.secret_spec(proxy_id)
    probe_spec = expand_proxy_template(
        template, account="health-check", session=uuid.uuid4().hex[:16]
    )
    return _probe_register_proxy(probe_spec, timeout=timeout)


@app.post("/api/proxy/test")
def proxy_test():
    """
    测试注册代理：先出口 IP/区域，再 accounts.x.ai 连通性。
    body.proxy：可传临时值；不传则测试直连。
    空字符串 = 直连探测。
    """
    body = request.get_json(silent=True) or {}
    if "proxy" in body:
        raw = str(body.get("proxy") or "").strip()
    else:
        raw = ""
    try:
        timeout = float(body.get("timeout") or 6)
    except (TypeError, ValueError):
        timeout = 6.0
    result = _probe_register_proxy(raw, timeout=timeout)
    # 写一条主日志，方便对照
    try:
        level = "success" if result.get("ok") else "warn"
        logs.emit(f"代理测试: {result.get('message') or result.get('error')}", level)
    except Exception:
        pass
    code = 200 if result.get("ok") else 502
    return jsonify(result), code


@app.get("/api/proxies")
def proxy_pool_list():
    try:
        data = proxy_pool.list_public(
            page=request.args.get("page", 1, type=int),
            per_page=request.args.get("per_page", 50, type=int),
            query=request.args.get("q", "", type=str),
            status=request.args.get("status", "", type=str),
        )
        return jsonify({"ok": True, **data})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400


@app.patch("/api/proxies/settings")
def proxy_pool_settings():
    body = request.get_json(silent=True) or {}
    try:
        settings = proxy_pool.update_settings(body)
        return jsonify({"ok": True, "settings": settings})
    except (ProxyConfigError, TypeError, ValueError) as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400


def _proxy_import_payload() -> tuple[str, str]:
    if request.files:
        upload = request.files.get("file")
        if upload is None:
            raise ProxyConfigError("缺少上传文件")
        payload = upload.read(MAX_UPLOAD_BYTES + 1)
        if len(payload) > MAX_UPLOAD_BYTES:
            raise ProxyConfigError("代理文件超过 5 MB")
        try:
            text = payload.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ProxyConfigError("代理文件必须是 UTF-8 文本") from exc
        mode = str(request.form.get("mode") or "append")
        return text, mode
    body = request.get_json(silent=True) or {}
    return str(body.get("text") or ""), str(body.get("mode") or "append")


@app.post("/api/proxies/preview")
def proxy_pool_preview():
    try:
        text, mode = _proxy_import_payload()
        rows, errors, duplicates = parse_proxy_lines(
            text,
            default_scheme=proxy_pool.settings().get("default_scheme", "http"),
        )
        return jsonify({
            "ok": not errors,
            "mode": mode,
            "valid": len(rows),
            "duplicates": duplicates,
            "errors": errors[:200],
            "preview": [
                {
                    "line": idx + 1,
                    "proxy": mask_proxy(row["spec"]),
                }
                for idx, row in enumerate(rows[:20])
            ],
        }), (200 if not errors else 400)
    except (ProxyConfigError, TypeError, ValueError) as exc:
        return jsonify({"ok": False, "message": str(exc), "errors": []}), 400


@app.post("/api/proxies/import")
def proxy_pool_import():
    try:
        text, mode = _proxy_import_payload()
        result = proxy_pool.import_text(text, mode=mode)
        if not result.get("ok"):
            return jsonify(result), 400
        added_ids = list(result.pop("added_ids", []))
        if added_ids:
            _start_proxy_pool_health_checks(added_ids)
        logs.emit(f"注册代理池已导入 {result.get('added', 0)} 条", "success")
        return jsonify(result)
    except (ProxyConfigError, TypeError, ValueError) as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400


@app.patch("/api/proxies/<proxy_id>")
def proxy_pool_update_entry(proxy_id: str):
    try:
        item = proxy_pool.update_entry(proxy_id, request.get_json(silent=True) or {})
        return jsonify({"ok": True, "item": item})
    except KeyError:
        return jsonify({"ok": False, "message": "代理不存在"}), 404
    except (ProxyConfigError, TypeError, ValueError) as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400


@app.post("/api/proxies/delete")
def proxy_pool_delete():
    body = request.get_json(silent=True) or {}
    ids = body.get("ids") or []
    if not isinstance(ids, list) or not ids:
        return jsonify({"ok": False, "message": "请选择要删除的代理"}), 400
    result = proxy_pool.delete(ids)
    return jsonify({"ok": True, **result})


@app.post("/api/proxies/<proxy_id>/move")
def proxy_pool_move(proxy_id: str):
    direction = str((request.get_json(silent=True) or {}).get("direction") or "")
    if direction not in ("up", "down"):
        return jsonify({"ok": False, "message": "direction 必须是 up/down"}), 400
    try:
        proxy_pool.move(proxy_id, direction)
        return jsonify({"ok": True})
    except KeyError:
        return jsonify({"ok": False, "message": "代理不存在"}), 404


@app.post("/api/proxies/test")
def proxy_pool_test_many():
    body = request.get_json(silent=True) or {}
    ids = body.get("ids") or []
    if not isinstance(ids, list) or not ids:
        return jsonify({"ok": False, "message": "请选择要测试的代理"}), 400
    ids = [str(x) for x in ids[:2000]]

    def _one(proxy_id: str) -> dict:
        try:
            result = _probe_saved_proxy(proxy_id, timeout=6)
            proxy_pool.set_health(proxy_id, result)
            return {
                "id": proxy_id,
                "ok": bool(result.get("ok")),
                "message": result.get("message") or result.get("error") or "",
            }
        except KeyError:
            return {"id": proxy_id, "ok": False, "message": "代理不存在"}
        except Exception as exc:
            proxy_pool.set_health(proxy_id, {"ok": False, "error": str(exc)})
            return {"id": proxy_id, "ok": False, "message": str(exc)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(ids))) as pool:
        results = list(pool.map(_one, ids))
    passed = sum(1 for x in results if x["ok"])
    return jsonify({"ok": True, "all_passed": passed == len(results), "passed": passed, "total": len(results), "results": results})


@app.post("/api/proxies/bulk")
def proxy_pool_bulk():
    body = request.get_json(silent=True) or {}
    ids = [str(x) for x in (body.get("ids") or [])][:2000]
    action = str(body.get("action") or "")
    if not ids:
        return jsonify({"ok": False, "message": "请选择代理"}), 400
    if action not in {"enable", "disable"}:
        return jsonify({"ok": False, "message": "批量操作无效"}), 400
    if action == "disable":
        changed = failed = 0
        errors = []
        for proxy_id in ids:
            try:
                proxy_pool.update_entry(proxy_id, {"enabled": False})
                changed += 1
            except Exception as exc:
                failed += 1
                errors.append({"id": proxy_id, "message": str(exc)})
        return jsonify({"ok": True, "all_passed": failed == 0, "changed": changed, "failed": failed, "errors": errors[:100]})

    def _test_and_enable(proxy_id: str) -> dict:
        try:
            result = _probe_saved_proxy(proxy_id, timeout=6)
            proxy_pool.set_health(proxy_id, result)
            if not result.get("ok"):
                return {"id": proxy_id, "ok": False, "message": result.get("message") or result.get("error") or "测试失败"}
            proxy_pool.update_entry(proxy_id, {"enabled": True})
            return {"id": proxy_id, "ok": True, "message": "测试通过并已启用"}
        except Exception as exc:
            return {"id": proxy_id, "ok": False, "message": str(exc)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(ids))) as pool:
        results = list(pool.map(_test_and_enable, ids))
    changed = sum(1 for x in results if x["ok"])
    return jsonify({
        "ok": True,
        "all_passed": changed == len(results),
        "changed": changed,
        "failed": len(results) - changed,
        "results": results,
    })


_proxy_health_lock = threading.Lock()
_proxy_health_stop: threading.Event | None = None
_proxy_health_thread: threading.Thread | None = None


def _stop_proxy_pool_health_checks() -> None:
    global _proxy_health_stop, _proxy_health_thread
    with _proxy_health_lock:
        stop_event = _proxy_health_stop
        thread = _proxy_health_thread
    if stop_event is not None:
        stop_event.set()
    if thread is not None and thread is not threading.current_thread() and thread.is_alive():
        # A probe has a 12s timeout. Wait long enough for the only in-flight
        # generation to finish, otherwise the next batch could overlap it.
        thread.join(timeout=15.0)
    with _proxy_health_lock:
        if _proxy_health_thread is thread and (thread is None or not thread.is_alive()):
            _proxy_health_stop = None
            _proxy_health_thread = None


def _start_proxy_pool_health_checks(selected_ids: list[str] | None = None) -> int:
    """每批启动时后台并行预检；worker 只会领取已完成预检的条目。"""
    global _proxy_health_stop, _proxy_health_thread
    # stop_event 不再复用 engine.stop_event，避免下一批 clear() 后旧线程复活。
    _stop_proxy_pool_health_checks()
    with _proxy_health_lock:
        if _proxy_health_thread is not None and _proxy_health_thread.is_alive():
            logs.emit("上一轮代理健康检查尚未退出，本批不重复启动", "warn")
            return 0
    ids = proxy_pool.begin_health_check(selected_ids)
    if not ids:
        return 0
    stop_event = threading.Event()

    def _run() -> None:
        try:
            def _check(batch: list[str]) -> int:
                def _one(proxy_id: str) -> bool:
                    if stop_event.is_set():
                        return False
                    try:
                        result = _probe_saved_proxy(proxy_id, timeout=6)
                    except Exception as exc:
                        result = {"ok": False, "error": str(exc)}
                    proxy_pool.set_health(proxy_id, result)
                    return bool(result.get("ok"))

                with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(batch))) as checks:
                    return sum(1 for ok in checks.map(_one, batch) if ok)

            passed = _check(ids)
            if not stop_event.is_set():
                logs.emit(f"代理池预检完成：{passed}/{len(ids)} 可用", "success" if passed else "warn")
            while not stop_event.is_set() and runner.is_running():
                if stop_event.wait(timeout=5):
                    break
                due = proxy_pool.begin_due_health_checks()
                if due:
                    recovered = _check(due)
                    if not stop_event.is_set():
                        logs.emit(f"冷却代理复检：{recovered}/{len(due)} 恢复", "info")
        finally:
            global _proxy_health_stop, _proxy_health_thread
            with _proxy_health_lock:
                if _proxy_health_thread is threading.current_thread():
                    _proxy_health_stop = None
                    _proxy_health_thread = None

    thread = threading.Thread(target=_run, daemon=True, name="proxy-pool-health")
    with _proxy_health_lock:
        _proxy_health_stop = stop_event
        _proxy_health_thread = thread
    thread.start()
    return len(ids)


def _on_registration_start() -> None:
    proxy_checks = _start_proxy_pool_health_checks()
    if proxy_checks:
        logs.emit(f"代理池后台预检已启动：{proxy_checks} 条", "info")
    else:
        logs.emit("代理池为空，本批注册直连", "warn")


runner.on_run_start = _on_registration_start


@app.get("/api/proxies/export")
def proxy_pool_export():
    # 导出只用于运维审计，服务端永不读出凭据。分页拉取全量脱敏条目。
    items = []
    page = 1
    while True:
        chunk = proxy_pool.list_public(page=page, per_page=200, query=request.args.get("q", ""))
        items.extend(chunk["items"])
        if len(items) >= chunk["total"]:
            break
        page += 1
    return jsonify({"ok": True, "exported_at": datetime.now(timezone.utc).isoformat(), "items": items})


@app.post("/api/upstream/test")
def upstream_test():
    """测试 sub2api HTTP 登录与 Grok 分组（可用临时参数覆盖已保存配置）。"""
    body = request.get_json(silent=True) or {}
    base = body.get("SUB2API_URL") or body.get("UPSTREAM_URL") or body.get("url")
    admin_email = body.get("UPSTREAM_ADMIN_EMAIL") or body.get("email")
    pwd = body.get("UPSTREAM_ADMIN_PASSWORD") or body.get("password")
    group_id = body.get("SUB2API_GROK_GROUP_ID") or body.get("group_id")
    group_name = body.get("SUB2API_GROK_GROUP_NAME") or body.get("group_name")
    # 空字符串表示“用已保存值”
    if base is not None and str(base).strip() == "":
        base = None
    if admin_email is not None and str(admin_email).strip() == "":
        admin_email = None
    if pwd is not None and str(pwd).strip() == "":
        pwd = None
    if group_id is not None and str(group_id).strip() == "":
        group_id = None
    if group_name is not None and str(group_name).strip() == "":
        group_name = None
    result = test_upstream_connectivity(
        base_url=str(base).strip() if base is not None else None,
        password=str(pwd) if pwd is not None else None,
        email=str(admin_email).strip() if admin_email is not None else None,
        group_id=str(group_id).strip() if group_id is not None else None,
        group_name=str(group_name).strip() if group_name is not None else None,
    )
    code = 200 if result.get("ok") else 502
    return jsonify(result), code


def _safe_keys_file(name: str) -> Path | None:
    """仅允许读取 keys/ 下的 .txt，防止路径穿越。"""
    raw = (name or "").strip().replace("\\", "/")
    if not raw or raw.startswith("/") or ".." in raw.split("/"):
        return None
    # 允许传 "keys/xxx.txt" 或 "xxx.txt"
    if raw.lower().startswith("keys/"):
        raw = raw[5:]
    if not raw.lower().endswith(".txt"):
        return None
    keys_dir = (BASE_DIR / "keys").resolve()
    path = (keys_dir / Path(raw).name).resolve()
    try:
        path.relative_to(keys_dir)
    except ValueError:
        return None
    if not path.is_file():
        return None
    return path


def _read_sso_file_lines(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def _safe_register_json(name: str) -> Path | None:
    raw = str(name or "").strip().replace("\\", "/")
    if not raw or raw.startswith("/") or ".." in raw.split("/"):
        return None
    if raw.lower().startswith("register_sso/"):
        raw = raw[len("register_sso/") :]
    if not raw.lower().endswith(".json"):
        return None
    root = (BASE_DIR / "register_sso").resolve()
    path = (root / Path(raw).name).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return None
    return path if path.is_file() else None


def _account_from_json(data: dict, *, source: str = "") -> dict | None:
    if not isinstance(data, dict):
        return None
    sso = str(data.get("sso") or data.get("sso_cookie") or data.get("sso_token") or "").strip()
    if not sso:
        return None
    risk = data.get("risk") if isinstance(data.get("risk"), dict) else {}
    clean = data.get("clean")
    if clean is None:
        clean = risk.get("clean")
    token = data.get("auth_token") or data.get("token")
    return {
        "id": str(data.get("id") or data.get("session_id") or uuid.uuid4().hex),
        "email": str(data.get("email") or "").strip(),
        "sso": sso,
        "auth_token": token if isinstance(token, dict) else None,
        "clean": clean if isinstance(clean, bool) else None,
        "risk_status": str(data.get("risk_status") or (data.get("account_check") or {}).get("state") or ""),
        "source": source,
    }


def _accounts_from_text(text: str, *, source: str) -> tuple[list[dict], list[dict]]:
    accounts: list[dict] = []
    errors: list[dict] = []
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip() and not line.strip().startswith("#")]
    for index, (email, sso) in enumerate(_parse_sso_import_lines(lines), start=1):
        if not sso:
            errors.append({"row": index, "error": "缺少 SSO"})
            continue
        accounts.append({
            "id": uuid.uuid4().hex,
            "email": str(email or "").strip(),
            "sso": str(sso).strip(),
            "auth_token": None,
            "clean": None,
            "source": source,
        })
    return accounts, errors


def _accounts_from_json_payload(payload: object, *, source: str) -> tuple[list[dict], list[dict]]:
    if isinstance(payload, dict) and isinstance(payload.get("accounts"), list):
        rows = payload["accounts"]
    elif isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = [payload]
    else:
        return [], [{"error": "JSON 顶层必须是账号对象、账号数组或 accounts 包装"}]
    accounts: list[dict] = []
    errors: list[dict] = []
    for index, raw in enumerate(rows, start=1):
        account = _account_from_json(raw, source=source) if isinstance(raw, dict) else None
        if account:
            accounts.append(account)
        else:
            errors.append({"row": index, "error": "缺少 sso/sso_cookie/sso_token"})
    return accounts, errors


def _dedupe_preview(accounts: list[dict]) -> tuple[list[dict], list[dict]]:
    by_sso: dict[str, dict] = {}
    errors: list[dict] = []
    for account in accounts:
        sso = str(account.get("sso") or "").strip()
        if not sso:
            errors.append({"source": account.get("source"), "error": "缺少 SSO"})
            continue
        current = by_sso.get(sso)
        if current is None:
            by_sso[sso] = account
            continue
        # Retain the richer duplicate (email/risk/cached OAuth fields).
        score = lambda item: sum(
            (bool(item.get("email")), item.get("clean") is not None, isinstance(item.get("auth_token"), dict))
        )
        if score(account) > score(current):
            by_sso[sso] = account
        errors.append({"source": account.get("source"), "error": "重复 SSO，已合并"})
    return list(by_sso.values())[:10000], errors


def _resolve_import_retry_source(source: dict, rows: list[dict]) -> list[dict]:
    """Reload a persisted source without ever storing SSO in job history."""
    source_type = str(source.get("type") or "")
    recovered: list[dict] = []
    if source_type == "keys":
        path = _safe_keys_file(str(source.get("file") or ""))
        if path:
            recovered, _ = _accounts_from_text(
                path.read_text(encoding="utf-8", errors="ignore"), source=f"keys/{path.name}"
            )
    elif source_type == "register_sso":
        for file_name in source.get("files") or []:
            path = _safe_register_json(str(file_name))
            if not path:
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                found, _ = _accounts_from_json_payload(payload, source=f"register_sso/{path.name}")
                recovered.extend(found)
            except Exception:
                continue
    elif source_type in ("recent", "automatic"):
        recovered.extend({**item, "source": "recent_success"} for item in list(runner.recent_success) if item.get("sso"))
        if not recovered:
            register_dir = BASE_DIR / "register_sso"
            for path in sorted(register_dir.glob("*.json")) if register_dir.is_dir() else []:
                try:
                    account = _account_from_json(json.loads(path.read_text(encoding="utf-8")), source=f"register_sso/{path.name}")
                    if account:
                        recovered.append(account)
                except Exception:
                    continue
    elif source_type == "retry":
        parent = IMPORT_JOBS.get(str(source.get("job_id") or ""))
        if parent:
            return _resolve_import_retry_source(parent.get("source") or {}, rows)
    if not recovered:
        return []
    recovered, _ = _dedupe_preview(recovered)
    by_id = {str(item.get("id") or ""): item for item in recovered}
    by_email: dict[str, list[dict]] = {}
    for item in recovered:
        by_email.setdefault(str(item.get("email") or "").strip().lower(), []).append(item)
    output: list[dict] = []
    used: set[int] = set()
    for index, row in enumerate(rows):
        match = by_id.get(str(row.get("id") or ""))
        if match is None:
            bucket = by_email.get(str(row.get("email") or "").strip().lower()) or []
            match = next((item for item in bucket if id(item) not in used), None)
        if match is None and index < len(recovered):
            match = recovered[index]
        if match is None:
            continue
        used.add(id(match))
        output.append({**match, "id": str(row.get("id") or match.get("id")), "clean": row.get("clean")})
    return output


def _preview_public(account: dict) -> dict:
    sso = str(account.get("sso") or "")
    return {
        "id": account.get("id"),
        "email": account.get("email") or "",
        "clean": account.get("clean"),
        "risk_status": account.get("risk_status") or "",
        "has_token": isinstance(account.get("auth_token"), dict),
        "sso_preview": (sso[:10] + "…" + sso[-6:]) if len(sso) > 20 else "已读取",
        "source": account.get("source") or "",
    }


def _store_import_preview(accounts: list[dict], source: dict, errors: list[dict]) -> dict:
    preview_id = uuid.uuid4().hex
    now = time.time()
    with IMPORT_PREVIEW_LOCK:
        for key, item in list(IMPORT_PREVIEWS.items()):
            if now - float(item.get("created") or 0) > 1800:
                IMPORT_PREVIEWS.pop(key, None)
        if len(IMPORT_PREVIEWS) >= 20:
            oldest = min(IMPORT_PREVIEWS, key=lambda key: float(IMPORT_PREVIEWS[key].get("created") or 0))
            IMPORT_PREVIEWS.pop(oldest, None)
        IMPORT_PREVIEWS[preview_id] = {
            "created": now,
            "accounts": accounts,
            "source": source,
            "errors": errors,
        }
    return {
        "ok": True,
        "preview_id": preview_id,
        "source": source,
        "total": len(accounts),
        "errors": errors[:200],
        "error_count": len(errors),
        "accounts": [_preview_public(account) for account in accounts],
    }


@app.get("/api/import-services")
def get_import_services():
    cfg = IMPORT_CONFIG.load()
    key_files = []
    keys_dir = BASE_DIR / "keys"
    if keys_dir.is_dir():
        key_files = [path.name for path in sorted(keys_dir.glob("*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)]
    register_files = []
    register_dir = BASE_DIR / "register_sso"
    if register_dir.is_dir():
        register_files = [path.name for path in sorted(register_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)]
    return jsonify({
        "ok": True,
        "config": IMPORT_CONFIG.redacted(cfg),
        "target_labels": TARGET_LABELS,
        "targets": list(TARGETS),
        "sources": {"keys": key_files[:500], "register_sso": register_files[:2000]},
        "recent": [_preview_public(item) for item in list(runner.recent_success)],
        "jobs": IMPORT_JOBS.list_jobs(),
        "note": "密钥只写不读；留空表示保留现有值",
    })


@app.post("/api/import-services/config")
def save_import_services_config():
    body = request.get_json(silent=True) or {}
    try:
        cfg = IMPORT_CONFIG.save(body.get("config") if isinstance(body.get("config"), dict) else body)
        return jsonify({"ok": True, "message": "导入服务配置已保存；变化的服务需重新测试", "config": IMPORT_CONFIG.redacted(cfg)})
    except Exception as exc:
        return jsonify({"ok": False, "message": f"保存失败: {exc}"}), 400


@app.post("/api/import-services/test")
def test_import_service():
    body = request.get_json(silent=True) or {}
    service = str(body.get("service") or "").strip()
    cfg = IMPORT_CONFIG.load()
    register_proxy = ""
    if service == "sub2api":
        sub2 = cfg["services"]["sub2api"]
        _set_sub2_http_options(
            proxy_mode=str(sub2.get("proxy_mode") or "direct"),
            proxy_url=str(sub2.get("proxy_url") or ""),
            register_proxy=register_proxy,
            tls_verify=bool(sub2.get("tls_verify", True)),
        )
        result = test_upstream_connectivity(
            base_url=str(sub2.get("base_url") or ""),
            email=str(sub2.get("email") or ""),
            password=str(sub2.get("password") or ""),
            group_id=str(sub2.get("group_id") or ""),
            group_name=str(sub2.get("group_name") or ""),
        )
    elif service == "cpa":
        result = IMPORT_TARGETS.test_cpa(cfg, register_proxy)
    elif service == "grok2api":
        result = IMPORT_TARGETS.test_grok2api(cfg, register_proxy)
    else:
        return jsonify({"ok": False, "message": "未知导入服务"}), 400
    cfg = IMPORT_CONFIG.update_test_state(service, result)
    code = 200 if result.get("ok") else 502
    return jsonify({**result, "test_state": cfg["test_states"][service]}), code


@app.post("/api/import-services/auto-targets")
def set_import_auto_targets():
    body = request.get_json(silent=True) or {}
    try:
        cfg = IMPORT_CONFIG.set_auto_targets(str(body.get("service") or ""), body.get("targets") or [])
        return jsonify({"ok": True, "message": "自动导入设置已更新", "config": IMPORT_CONFIG.redacted(cfg)})
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 409


@app.post("/api/import-services/preview")
def preview_import_source():
    if request.content_length and request.content_length > 10 * 1024 * 1024:
        return jsonify({"ok": False, "message": "上传文件不能超过 10 MB"}), 413
    body = request.form.to_dict() if request.files else (request.get_json(silent=True) or {})
    source_type = str(body.get("source") or body.get("type") or "recent").strip()
    accounts: list[dict] = []
    errors: list[dict] = []
    source: dict = {"type": source_type}
    try:
        if source_type == "recent":
            ids_provided = "ids" in body
            ids = body.get("ids") or []
            if isinstance(ids, str):
                ids = [x for x in ids.split(",") if x]
            id_set = {str(x) for x in ids}
            for item in list(runner.recent_success):
                if ids_provided and str(item.get("id") or "") not in id_set:
                    continue
                if item.get("sso"):
                    accounts.append({**item, "source": "recent_success"})
        elif source_type == "keys":
            file_name = str(body.get("file") or "")
            path = _safe_keys_file(file_name)
            if not path:
                raise ValueError("无效或不存在的 Keys 文件")
            source["file"] = path.name
            parsed, found_errors = _accounts_from_text(path.read_text(encoding="utf-8", errors="ignore"), source=f"keys/{path.name}")
            accounts.extend(parsed)
            errors.extend(found_errors)
        elif source_type == "register_sso":
            files = body.get("files") or body.get("file") or []
            if isinstance(files, str):
                files = [x for x in files.split(",") if x]
            for file_name in files:
                path = _safe_register_json(str(file_name))
                if not path:
                    errors.append({"file": str(file_name), "error": "无效或不存在"})
                    continue
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    parsed, found_errors = _accounts_from_json_payload(payload, source=f"register_sso/{path.name}")
                    accounts.extend(parsed)
                    errors.extend(found_errors)
                except Exception as exc:
                    errors.append({"file": path.name, "error": str(exc)})
            source["files"] = [Path(str(x)).name for x in files]
        elif source_type == "upload":
            uploaded = request.files.get("file")
            if not uploaded or not uploaded.filename:
                raise ValueError("请选择 TXT 或 JSON 文件")
            raw = uploaded.read(10 * 1024 * 1024 + 1)
            if len(raw) > 10 * 1024 * 1024:
                raise ValueError("上传文件不能超过 10 MB")
            text = raw.decode("utf-8-sig", errors="replace")
            source["file"] = Path(uploaded.filename).name
            if uploaded.filename.lower().endswith(".json"):
                payload = json.loads(text)
                parsed, found_errors = _accounts_from_json_payload(payload, source=f"upload/{source['file']}")
            elif uploaded.filename.lower().endswith(".txt"):
                parsed, found_errors = _accounts_from_text(text, source=f"upload/{source['file']}")
            else:
                raise ValueError("仅支持 .txt 和 .json")
            accounts.extend(parsed)
            errors.extend(found_errors)
        else:
            raise ValueError("未知来源")
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    accounts, duplicate_errors = _dedupe_preview(accounts)
    errors.extend(duplicate_errors)
    if not accounts:
        return jsonify({"ok": False, "message": "没有可导入的有效账号", "errors": errors[:200]}), 400
    return jsonify(_store_import_preview(accounts, source, errors))


@app.post("/api/import-services/jobs")
def create_import_job():
    body = request.get_json(silent=True) or {}
    preview_id = str(body.get("preview_id") or "")
    with IMPORT_PREVIEW_LOCK:
        preview = IMPORT_PREVIEWS.get(preview_id)
    if not preview or time.time() - float(preview.get("created") or 0) > 1800:
        return jsonify({"ok": False, "message": "预览已过期，请重新预览来源"}), 409
    try:
        job = IMPORT_JOBS.create_job(
            preview["accounts"],
            body.get("targets") or [],
            source=preview["source"],
            force_refresh=bool(body.get("force_refresh")),
            allow_marked=bool(body.get("allow_marked")),
            allow_review=bool(body.get("allow_review")),
        )
        return jsonify({"ok": True, "message": "导入任务已创建", "job": job}), 202
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400


@app.get("/api/import-services/jobs")
def list_import_jobs():
    return jsonify({"ok": True, "jobs": IMPORT_JOBS.list_jobs()})


@app.get("/api/import-services/jobs/<job_id>")
def get_import_job(job_id: str):
    job = IMPORT_JOBS.get(job_id)
    if not job:
        return jsonify({"ok": False, "message": "任务不存在"}), 404
    return jsonify({"ok": True, "job": job})


@app.post("/api/import-services/jobs/<job_id>/cancel")
def cancel_import_job(job_id: str):
    try:
        return jsonify({"ok": True, "job": IMPORT_JOBS.cancel(job_id)})
    except KeyError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 404


@app.post("/api/import-services/jobs/<job_id>/retry")
def retry_import_job(job_id: str):
    try:
        return jsonify({"ok": True, "message": "重试任务已创建", "job": IMPORT_JOBS.retry(job_id)}), 202
    except KeyError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 404
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 409


@app.delete("/api/import-services/jobs")
def clear_import_jobs():
    count = IMPORT_JOBS.clear_history()
    return jsonify({"ok": True, "message": f"已清除 {count} 条任务历史", "count": count})


def _mark_recent_imported(selected: list[dict] | None, result: dict) -> None:
    """按导入结果标记 recent_success 中的项为已导入。"""
    if not (result.get("ok") or (result.get("success") or 0) > 0):
        return
    ok_emails = set()
    ok_sso_hints = set()
    for row in result.get("results") or []:
        if row.get("status") != "ok":
            continue
        if row.get("email"):
            ok_emails.add(str(row["email"]).lower())
        hint = row.get("sso_hint") or ""
        if hint:
            ok_sso_hints.add(hint)
    selected = selected or []
    for it in runner.recent_success:
        if not it.get("sso"):
            continue
        email = (it.get("email") or "").lower()
        sso = it.get("sso") or ""
        sso_hint = (sso[:12] + "...") if len(sso) > 12 else sso
        if email and email in ok_emails:
            it["imported"] = True
            it["auth_token"] = None
        elif sso_hint and sso_hint in ok_sso_hints:
            it["imported"] = True
            it["auth_token"] = None
        elif result.get("ok") and selected and any(
            it is x or it.get("id") == x.get("id") for x in selected
        ):
            it["imported"] = True
            it["auth_token"] = None


@app.post("/api/upstream/import")
def upstream_import():
    """将最近成功的 SSO / keys 文件导入 sub2api grok 分组。"""
    body = request.get_json(silent=True) or {}
    merge = body.get("merge", True)
    # 本机 device flow 后写 token：固定串行，忽略客户端并发参数
    try:
        max_workers = int(body.get("max_workers", 1))
    except (TypeError, ValueError):
        max_workers = 1
    max_workers = 1

    # 支持：keys 文件 / 指定 id / 指定 sso 原文 / 当前 output_file / 全部未导入
    ids = body.get("ids")
    if ids is not None and not isinstance(ids, list):
        return jsonify({"ok": False, "message": "ids 必须是数组"}), 400

    raw_ssos = body.get("sso_cookies") or body.get("ssos")
    only_pending = bool(body.get("only_pending", True))
    import_all = bool(body.get("all", False))
    file_name = body.get("file") or body.get("from_file") or body.get("key_file")
    use_output_file = bool(body.get("from_output", False))

    items = list(runner.recent_success)
    selected: list[dict] = []
    sso_lines: list[str] = []
    source = "recent_success"

    if raw_ssos and isinstance(raw_ssos, list) and raw_ssos:
        # 直接导入调用方提供的 SSO 行（无注册缓存 token，走 device flow）
        for line in raw_ssos:
            s = str(line or "").strip()
            if s:
                sso_lines.append(s)
        if not sso_lines:
            return jsonify({"ok": False, "message": "sso_cookies 为空"}), 400
        source = "sso_cookies"
        result = import_sso_to_upstream(
            sso_lines=sso_lines, merge=merge, max_workers=max_workers
        )
        _mark_recent_imported(None, result)
        level = "success" if result.get("ok") else ("warn" if (result.get("success") or 0) > 0 else "error")
        logs.emit(f"sub2api 导入: {result.get('message')}（提交 {len(sso_lines)} 条 · {source}）", level)
        code = 200 if result.get("ok") or (result.get("success") or 0) > 0 else 502
        result["submitted"] = len(sso_lines)
        result["source"] = source
        result["recent_success"] = runner.get_status().get("recent_success", [])
        return jsonify(result), code

    # 从 keys 文件或当前任务 output_file 全量导入（不受 recent_success 截断影响）
    file_path: Path | None = None
    if file_name:
        file_path = _safe_keys_file(str(file_name))
        if not file_path:
            return jsonify({"ok": False, "message": f"无效或不存在的 keys 文件: {file_name}"}), 400
        source = f"file:{file_path.name}"
    elif use_output_file and runner.output_file:
        candidate = Path(runner.output_file)
        if not candidate.is_absolute():
            candidate = BASE_DIR / candidate
        if candidate.is_file():
            file_path = candidate
            source = f"output:{candidate.name}"

    if file_path is not None:
        sso_lines = _read_sso_file_lines(file_path)
        if not sso_lines:
            return jsonify({"ok": False, "message": f"文件无有效 SSO: {file_path.name}"}), 400
        # 有缓存 token 的项尽量带上（同 sso 匹配），加速导入
        token_by_sso = {
            (it.get("sso") or "").strip(): it.get("auth_token")
            for it in items
            if it.get("sso") and isinstance(it.get("auth_token"), dict)
        }
        accounts = []
        for email, sso in _parse_sso_import_lines(sso_lines):
            sso = (sso or "").strip()
            if not sso:
                continue
            accounts.append(
                {
                    "email": email,
                    "sso": sso,
                    "auth_token": token_by_sso.get(sso),
                }
            )
        result = import_sso_to_upstream(
            accounts=accounts, merge=merge, max_workers=max_workers
        )
        _mark_recent_imported(None, result)
        level = "success" if result.get("ok") else ("warn" if (result.get("success") or 0) > 0 else "error")
        logs.emit(
            f"sub2api 导入: {result.get('message')}（提交 {len(accounts)} 条 · {source}）",
            level,
        )
        code = 200 if result.get("ok") or (result.get("success") or 0) > 0 else 502
        result["submitted"] = len(accounts)
        result["source"] = source
        result["file"] = file_path.name
        result["recent_success"] = runner.get_status().get("recent_success", [])
        return jsonify(result), code

    if ids:
        id_set = {str(x) for x in ids}
        for it in items:
            if str(it.get("id") or "") in id_set and it.get("sso"):
                selected.append(it)
    elif import_all:
        # 优先：内存未导入项；若为空且有 output_file，回退读文件（防重启/截断丢号）
        for it in items:
            if not it.get("sso"):
                continue
            if only_pending and it.get("imported"):
                continue
            selected.append(it)
        if not selected and runner.output_file:
            candidate = Path(runner.output_file)
            if not candidate.is_absolute():
                candidate = BASE_DIR / candidate
            if candidate.is_file():
                sso_lines = _read_sso_file_lines(candidate)
                if sso_lines:
                    source = f"output:{candidate.name}"
                    result = import_sso_to_upstream(
                        sso_lines=sso_lines, merge=merge, max_workers=max_workers
                    )
                    _mark_recent_imported(None, result)
                    level = (
                        "success"
                        if result.get("ok")
                        else ("warn" if (result.get("success") or 0) > 0 else "error")
                    )
                    logs.emit(
                        f"sub2api 导入: {result.get('message')}（提交 {len(sso_lines)} 条 · {source}）",
                        level,
                    )
                    code = 200 if result.get("ok") or (result.get("success") or 0) > 0 else 502
                    result["submitted"] = len(sso_lines)
                    result["source"] = source
                    result["file"] = candidate.name
                    result["recent_success"] = runner.get_status().get("recent_success", [])
                    return jsonify(result), code
    else:
        # 默认：全部未导入
        for it in items:
            if it.get("sso") and not it.get("imported"):
                selected.append(it)

    if not selected:
        return jsonify({
            "ok": False,
            "message": "没有可导入的成功账号（请先注册，或选择 keys 文件导入）",
        }), 400

    # 去重 SSO，并带上注册时缓存的 auth_token（有则导入秒级直写）
    seen = set()
    accounts = []
    for it in selected:
        sso = (it.get("sso") or "").strip()
        if not sso or sso in seen:
            continue
        seen.add(sso)
        email = (it.get("email") or "").strip()
        token = it.get("auth_token")
        accounts.append(
            {
                "email": email,
                "sso": sso,
                "auth_token": token if isinstance(token, dict) else None,
            }
        )

    result = import_sso_to_upstream(
        accounts=accounts, merge=merge, max_workers=max_workers
    )
    _mark_recent_imported(selected, result)

    level = "success" if result.get("ok") else ("warn" if (result.get("success") or 0) > 0 else "error")
    logs.emit(f"sub2api 导入: {result.get('message')}（提交 {len(accounts)} 条 · {source}）", level)
    code = 200 if result.get("ok") or (result.get("success") or 0) > 0 else 502
    result["submitted"] = len(accounts)
    result["source"] = source
    # 与 /api/status 一致：不回传完整 sso
    result["recent_success"] = runner.get_status().get("recent_success", [])
    return jsonify(result), code


@app.get("/keys/<path:filename>")
def download_key(filename):
    return send_from_directory(BASE_DIR / "keys", filename, as_attachment=True)


def main():
    cfg = read_env_file()
    apply_env_to_process(cfg)
    host = cfg.get("UI_HOST") or os.getenv("UI_HOST", "127.0.0.1")
    if (os.getenv("RUNNING_IN_DOCKER") or "").strip().lower() in (
        "1",
        "true",
        "yes",
    ):
        host = "0.0.0.0"
    port = int(cfg.get("UI_PORT") or os.getenv("UI_PORT", "3333"))
    print("=" * 60)
    print("Grok 注册机 Web 控制台")
    print(f"打开浏览器: http://{host}:{port}")
    print("=" * 60)
    logs.emit("Web 控制台已启动", "success")
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
