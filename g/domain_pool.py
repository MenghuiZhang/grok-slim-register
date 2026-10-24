"""Persistent Cloudflare Temp base-domain pool.

The pool is deliberately separate from email provider credentials so rotation
and failure counting keep working across registration rounds.  It is safe
for the application's current single-process, multi-threaded deployment.
"""
from __future__ import annotations

import json
import random
import re
import threading

from filelock import FileLock
import time
import uuid
from pathlib import Path
from typing import Any, Iterable, Optional


MAX_DOMAINS = 10_000
# 创邮连续失败 N 次后冷却一段时间：冷却域名只在轮换队列里垫底，
# 不做停用/隔离，任何一次成功即清零。
CREATE_FAIL_COOLDOWN_THRESHOLD = 3
CREATE_FAIL_COOLDOWN_SECONDS = 300
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.I,
)


class DomainPoolError(ValueError):
    pass


def normalize_domain(value: Any) -> str:
    domain = str(value or "").strip().lower().rstrip(".")
    if not domain or not DOMAIN_RE.match(domain):
        raise DomainPoolError(f"域名格式无效: {domain or '空值'}")
    return domain


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class DomainPool:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._data = {"version": 1, "domains": []}
        self.reload()

    def reload(self) -> None:
        with self._lock:
            loaded: dict[str, Any] = {}
            if self.path.exists():
                try:
                    raw = json.loads(self.path.read_text(encoding="utf-8"))
                    if isinstance(raw, dict):
                        loaded = raw
                except Exception:
                    loaded = {}
            clean: list[dict[str, Any]] = []
            seen: set[str] = set()
            changed = False
            for raw in loaded.get("domains") or []:
                if not isinstance(raw, dict):
                    continue
                try:
                    domain = normalize_domain(raw.get("domain"))
                except DomainPoolError:
                    continue
                if domain in seen:
                    continue
                seen.add(domain)
                status = str(
                    raw.get("status") or ("enabled" if raw.get("enabled", True) else "disabled")
                ).lower()
                if status not in {"enabled", "disabled"}:
                    # verifying/archived 是旧隔离机制的遗留状态：
                    # 复验中回滚启用（与原进程重启清理一致），归档回滚停用
                    status = "enabled" if status == "verifying" else "disabled"
                events = list(raw.get("events") or [])[-20:]
                clean.append({
                    "id": str(raw.get("id") or uuid.uuid4().hex),
                    "domain": domain,
                    "status": status,
                    "last_failure_code": str(raw.get("last_failure_code") or ""),
                    "last_failure_message": str(raw.get("last_failure_message") or ""),
                    "last_failure_at": str(raw.get("last_failure_at") or ""),
                    "disabled_reason": str(raw.get("disabled_reason") or ""),
                    "disabled_at": str(raw.get("disabled_at") or ""),
                    "email_health": str(raw.get("email_health") or "untested"),
                    "email_health_message": str(raw.get("email_health_message") or "尚未测试"),
                    "email_tested_at": str(raw.get("email_tested_at") or ""),
                    "success_count": int(raw.get("success_count") or 0),
                    "failure_count": int(raw.get("failure_count") or 0),
                    "consecutive_failures": int(raw.get("consecutive_failures") or 0),
                    "cooldown_until": float(raw.get("cooldown_until") or 0),
                    "events": events[-20:],
                })
            self._data = {"version": 1, "domains": clean[:MAX_DOMAINS]}
            if changed:
                self._save_locked()

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # 跨进程锁：多进程注册时防止并发读-改-写互相覆盖
        with FileLock(str(self.path) + ".lock", timeout=15):
            temp = self.path.with_name(self.path.name + ".tmp")
            persisted = {"version": 1, "domains": []}
            for row in self._data["domains"]:
                persisted["domains"].append(dict(row))
            temp.write_text(json.dumps(persisted, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            temp.replace(self.path)
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def _entry(self, domain_id: str) -> Optional[dict[str, Any]]:
        return next((x for x in self._data["domains"] if x["id"] == domain_id), None)

    def _entry_by_name(self, domain: str) -> Optional[dict[str, Any]]:
        return next((x for x in self._data["domains"] if x["domain"] == domain), None)

    @staticmethod
    def _event(row: dict[str, Any], code: str, message: str, **extra: Any) -> None:
        event = {"at": _now(), "code": code, "message": str(message or "")[:160]}
        event.update({k: v for k, v in extra.items() if v not in (None, "")})
        row["events"] = (list(row.get("events") or []) + [event])[-20:]

    def sync_configured(self, domains: Iterable[str]) -> int:
        """Migrate configured string domains as enabled without removing pool rows."""
        added = 0
        with self._lock:
            for value in domains:
                try:
                    domain = normalize_domain(value)
                except DomainPoolError:
                    continue
                if self._entry_by_name(domain):
                    continue
                row = self._new_entry(domain, status="enabled")
                self._data["domains"].append(row)
                added += 1
            if added:
                self._save_locked()
        return added

    def reconcile_configured(self, domains: Iterable[str]) -> dict[str, Any]:
        """Make a non-empty configured list the active rotation, preserving history.

        Existing rows keep counters/events. Rows absent from the new list are
        disabled instead of deleted; rows that reappear are enabled immediately.
        An empty/invalid result is rejected so an upstream discovery failure
        cannot accidentally clear a working pool.
        """
        normalized: list[str] = []
        invalid_values: list[str] = []
        seen: set[str] = set()
        for value in domains:
            try:
                domain = normalize_domain(value)
            except DomainPoolError:
                invalid_values.append(str(value or "").strip()[:253])
                continue
            if domain not in seen:
                seen.add(domain)
                normalized.append(domain)
        if not normalized:
            raise DomainPoolError("域名列表为空，现有域名池保持不变")
        if len(normalized) > MAX_DOMAINS:
            raise DomainPoolError(f"域名数量超过 {MAX_DOMAINS}")

        added = enabled = disabled = 0
        with self._lock:
            by_name = {row["domain"]: row for row in self._data["domains"]}
            new_count = sum(1 for domain in normalized if domain not in by_name)
            if len(self._data["domains"]) + new_count > MAX_DOMAINS:
                raise DomainPoolError(f"域名数量超过 {MAX_DOMAINS}（旧域历史会保留）")
            ordered: list[dict[str, Any]] = []
            for domain in normalized:
                row = by_name.get(domain)
                if row is None:
                    row = self._new_entry(domain, status="enabled")
                    added += 1
                elif row["status"] != "enabled":
                    row["status"] = "enabled"
                    row["disabled_reason"] = ""
                    row["disabled_at"] = ""
                    self._event(row, "CONFIG_REENABLED", "域名重新进入已保存列表")
                    enabled += 1
                ordered.append(row)

            for row in self._data["domains"]:
                if row["domain"] in seen:
                    continue
                if row["status"] == "enabled":
                    row["status"] = "disabled"
                    row["disabled_reason"] = "CONFIG_REMOVED"
                    row["disabled_at"] = _now()
                    self._event(row, "CONFIG_REMOVED", "域名不在新的已保存列表中")
                    disabled += 1
                ordered.append(row)
            self._data["domains"] = ordered
            self._save_locked()
        return {
            "added": added,
            "enabled": enabled,
            "disabled": disabled,
            "active": len(normalized),
            "invalid": len(invalid_values),
            "invalid_values": invalid_values[:100],
        }

    @staticmethod
    def _new_entry(domain: str, *, status: str = "disabled") -> dict[str, Any]:
        return {
            "id": uuid.uuid4().hex,
            "domain": domain,
            "status": status,
            "last_failure_code": "",
            "last_failure_message": "",
            "last_failure_at": "",
            "disabled_reason": "",
            "disabled_at": "",
            "email_health": "untested",
            "email_health_message": "尚未测试",
            "email_tested_at": "",
            "success_count": 0,
            "failure_count": 0,
            "consecutive_failures": 0,
            "cooldown_until": 0.0,
            "events": [],
        }

    def add(self, domains: Iterable[str], *, enabled: bool = False) -> dict[str, Any]:
        normalized: list[str] = []
        invalid_values: list[str] = []
        for value in domains:
            try:
                normalized.append(normalize_domain(value))
            except DomainPoolError:
                invalid_values.append(str(value or "").strip()[:253])

        added = duplicates = 0
        with self._lock:
            existing = {row["domain"] for row in self._data["domains"]}
            candidates: list[str] = []
            for domain in normalized:
                if domain in existing:
                    duplicates += 1
                    continue
                existing.add(domain)
                candidates.append(domain)
            if len(self._data["domains"]) + len(candidates) > MAX_DOMAINS:
                raise DomainPoolError(f"域名数量超过 {MAX_DOMAINS}")
            for domain in candidates:
                row = self._new_entry(domain, status="enabled" if enabled else "disabled")
                self._data["domains"].append(row)
                added += 1
            if added:
                self._save_locked()
        return {
            "added": added,
            "duplicates": duplicates,
            "invalid": len(invalid_values),
            "invalid_values": invalid_values[:100],
        }

    def _public(self, row: dict[str, Any]) -> dict[str, Any]:
        return dict(row)

    def list_public(self, *, page: int = 1, per_page: int = 50, query: str = "", status: str = "") -> dict[str, Any]:
        with self._lock:
            q = str(query or "").strip().lower()
            rows = [self._public(x) for x in self._data["domains"]]
            if q:
                rows = [x for x in rows if q in (x["domain"] + " " + x.get("last_failure_message", "")).lower()]
            if status:
                rows = [x for x in rows if x["status"] == status]
            page = max(1, int(page))
            per_page = max(1, min(int(per_page), 2000))
            start = (page - 1) * per_page
            return {
                "items": rows[start:start + per_page],
                "total": len(rows),
                "page": page,
                "per_page": per_page,
                "summary": self.summary(),
            }

    def summary(self) -> dict[str, int]:
        with self._lock:
            rows = self._data["domains"]
            return {
                "total": len(rows),
                "enabled": sum(1 for x in rows if x["status"] == "enabled"),
                "disabled": sum(1 for x in rows if x["status"] == "disabled"),
            }

    def active_domains(self) -> list[str]:
        """Domains eligible for new provider leases."""
        with self._lock:
            return [x["domain"] for x in self._data["domains"] if x["status"] == "enabled"]

    def pick_domains(self) -> list[str]:
        """随机打乱启用域名，生成本轮创邮候选队列。

        顺序每轮随机（不再是游标轮换），冷却中的域名垫底（按冷却到期
        时间排序）；全部冷却时仍兜底返回，只影响优先级、不做停用隔离。
        """
        with self._lock:
            rows = [x for x in self._data["domains"] if x["status"] == "enabled"]
            if not rows:
                return []
            fresh = [x["domain"] for x in rows if float(x.get("cooldown_until") or 0) <= time.time()]
            cooling = sorted(
                (x for x in rows if float(x.get("cooldown_until") or 0) > time.time()),
                key=lambda x: float(x.get("cooldown_until") or 0),
            )
            random.shuffle(fresh)
            return fresh + [x["domain"] for x in cooling]

    def record_create_result(self, domain: str, ok: bool, message: str = "") -> None:
        """记录一次创邮结果：失败累计连击与冷却垫底；成功只清连击/冷却，不计成功数。

        成功计数以注册结果为准（record_register_success），创邮成功不代表能走通注册。
        """
        name = str(domain or "").strip().lower().rstrip(".")
        with self._lock:
            row = self._entry_by_name(name)
            if row is None:
                return
            if ok:
                row["consecutive_failures"] = 0
                row["cooldown_until"] = 0.0
                self._event(row, "CREATE_OK", message or "创邮成功")
            else:
                row["failure_count"] = int(row.get("failure_count") or 0) + 1
                row["consecutive_failures"] = int(row.get("consecutive_failures") or 0) + 1
                row["last_failure_code"] = "CREATE_FAIL"
                row["last_failure_message"] = str(message or "创邮失败")[:160]
                row["last_failure_at"] = _now()
                if int(row["consecutive_failures"]) >= CREATE_FAIL_COOLDOWN_THRESHOLD:
                    row["cooldown_until"] = time.time() + CREATE_FAIL_COOLDOWN_SECONDS
                self._event(row, "CREATE_FAIL", row["last_failure_message"])
            self._save_locked()

    def record_register_success(self, domain: str, message: str = "注册成功") -> int:
        """整轮注册拿到 sso 后计一次成功：success_count +1 并清零连击/冷却。

        参数可直接传注册邮箱地址：按池内域名后缀反查归属，匹配不到则忽略。
        返回该域名最新的 (success_count, failure_count)；域名不在池内返回 None。
        """
        name = str(domain or "").strip().lower().rstrip(".")
        with self._lock:
            row = None
            if "@" in name:
                suffix = name.rsplit("@", 1)[-1]
                row = next(
                    (x for x in self._data["domains"] if x["domain"] == suffix),
                    None,
                )
            else:
                row = self._entry_by_name(name)
            if row is None:
                return None
            row["success_count"] = int(row.get("success_count") or 0) + 1
            row["consecutive_failures"] = 0
            row["cooldown_until"] = 0.0
            self._event(row, "REGISTER_OK", message)
            self._save_locked()
            return int(row["success_count"]), int(row["failure_count"])

    def record_register_failure(self, domain: str, message: str = "注册失败") -> int | None:
        """整轮注册失败时给实际使用的域名记 failure_count +1。

        之前只有创邮失败才计数，邮箱能建出来但注册失败的轮次落不到
        任何域名上，前端「成功 / 失败」列一直是 0。参数可传邮箱地址，
        按池内域名后缀反查归属，匹配不到则忽略。
        返回该域名最新的 (success_count, failure_count)。
        """
        name = str(domain or "").strip().lower().rstrip(".")
        with self._lock:
            row = None
            if "@" in name:
                suffix = name.rsplit("@", 1)[-1]
                row = next(
                    (x for x in self._data["domains"] if x["domain"] == suffix),
                    None,
                )
            else:
                row = self._entry_by_name(name)
            if row is None:
                return None
            row["failure_count"] = int(row.get("failure_count") or 0) + 1
            self._event(row, "REGISTER_FAIL", str(message or "注册失败")[:160])
            self._save_locked()
            return int(row["success_count"]), int(row["failure_count"])

    def domain_counts(self, domain: str) -> tuple[int, int] | None:
        """返回域名当前累计 (成功, 失败)；域名不在池内返回 None。"""
        name = str(domain or "").strip().lower().rstrip(".")
        with self._lock:
            row = self._entry_by_name(name)
            if row is None:
                return None
            return int(row.get("success_count") or 0), int(row.get("failure_count") or 0)

    def update(self, domain_id: str, values: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            row = self._entry(domain_id)
            if row is None:
                raise KeyError(domain_id)
            if "enabled" in values:
                enabled = bool(values["enabled"])
                if enabled:
                    row["status"] = "enabled"
                    row["disabled_reason"] = ""
                    row["disabled_at"] = ""
                    self._event(row, "MANUAL_ENABLED", "人工启用")
                else:
                    row["status"] = "disabled"
                    row["disabled_reason"] = "MANUAL"
                    row["disabled_at"] = _now()
                    self._event(row, "MANUAL_DISABLED", "人工停用")
            self._save_locked()
            return self._public(row)

    def set_email_health(self, domain_id: str, *, ok: bool, message: str = "") -> dict[str, Any]:
        with self._lock:
            row = self._entry(domain_id)
            if row is None:
                raise KeyError(domain_id)
            row["email_health"] = "healthy" if ok else "unhealthy"
            row["email_health_message"] = str(message or ("测试通过" if ok else "测试失败"))[:160]
            row["email_tested_at"] = _now()
            self._event(row, "EMAIL_TEST_OK" if ok else "EMAIL_TEST_FAILED", row["email_health_message"])
            self._save_locked()
            return self._public(row)

    def delete(self, ids: Iterable[str]) -> dict[str, int]:
        """Permanently delete selected rows and their embedded history."""
        wanted = {str(x) for x in ids}
        removed = 0
        with self._lock:
            kept: list[dict[str, Any]] = []
            for row in self._data["domains"]:
                if row["id"] not in wanted:
                    kept.append(row)
                    continue
                removed += 1
            self._data["domains"] = kept
            if removed:
                self._save_locked()
        return {"removed": removed}

    def move(self, domain_id: str, direction: str) -> None:
        with self._lock:
            rows = self._data["domains"]
            index = next((i for i, x in enumerate(rows) if x["id"] == domain_id), -1)
            if index < 0:
                raise KeyError(domain_id)
            target = index - 1 if direction == "up" else index + 1
            target = max(0, min(target, len(rows) - 1))
            if target != index:
                rows[index], rows[target] = rows[target], rows[index]
                self._save_locked()

    def get_public(self, domain_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._entry(domain_id)
            if row is None:
                raise KeyError(domain_id)
            return self._public(row)


_POOLS: dict[str, DomainPool] = {}
_POOLS_LOCK = threading.Lock()


def get_domain_pool(base_dir: Path | str | None = None) -> DomainPool:
    root = Path(base_dir or Path(__file__).resolve().parents[1]).resolve()
    path = root / "data" / "domain_pool.json"
    key = str(path)
    with _POOLS_LOCK:
        if key not in _POOLS:
            _POOLS[key] = DomainPool(path)
        return _POOLS[key]
