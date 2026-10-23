"""Persistent Cloudflare Temp base-domain pool.

The pool is deliberately separate from email provider credentials so automatic
isolation can take effect while a registration batch is running.  It is safe
for the application's current single-process, multi-threaded deployment.
"""
from __future__ import annotations

import json
import re
import threading

from filelock import FileLock
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional


MAX_DOMAINS = 10_000
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


@dataclass(frozen=True)
class DomainLease:
    domain_id: str
    domain: str
    logical_id: str


class DomainPool:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._cursor = 0
        self._runtime: dict[str, dict[str, int]] = {}
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
                if status not in {"enabled", "disabled", "verifying", "archived"}:
                    status = "enabled"
                events = list(raw.get("events") or [])[-20:]
                was_archived = status == "archived"
                if was_archived:
                    status = "disabled"
                    changed = True
                    events.append({
                        "at": _now(),
                        "code": "MIGRATED_FROM_ARCHIVE",
                        "message": "旧归档状态已迁移为停用",
                    })
                # A registration attempt cannot be resumed safely after process restart.
                if status == "verifying":
                    status = "enabled"
                    changed = True
                    events.append({
                        "at": _now(),
                        "code": "REVALIDATION_INTERRUPTED",
                        "message": "进程重启，未完成复验已清除",
                    })
                clean.append({
                    "id": str(raw.get("id") or uuid.uuid4().hex),
                    "domain": domain,
                    "status": status,
                    "bot_first_failures": int(raw.get("bot_first_failures") or 0),
                    "bot_second_failures": int(raw.get("bot_second_failures") or 0),
                    "bot_failures": int(raw.get("bot_failures") or 0),
                    "last_failure_code": str(raw.get("last_failure_code") or ""),
                    "last_failure_message": str(raw.get("last_failure_message") or ""),
                    "last_failure_at": str(raw.get("last_failure_at") or ""),
                    "disabled_reason": (
                        "MIGRATED_FROM_ARCHIVE"
                        if was_archived
                        else str(raw.get("disabled_reason") or "")
                    ),
                    "disabled_at": (
                        (str(raw.get("disabled_at") or "") or _now())
                        if was_archived
                        else str(raw.get("disabled_at") or "")
                    ),
                    "email_health": str(raw.get("email_health") or "untested"),
                    "email_health_message": str(raw.get("email_health_message") or "尚未测试"),
                    "email_tested_at": str(raw.get("email_tested_at") or ""),
                    "events": events[-20:],
                    "verification_owner": "",
                })
            self._data = {"version": 1, "domains": clean[:MAX_DOMAINS]}
            self._runtime = {row["id"]: {"in_use": 0} for row in clean}
            if changed:
                self._save_locked()

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # 跨进程锁：多进程注册时防止并发读-改-写互相覆盖
        with FileLock(str(self.path) + ".lock", timeout=15):
            temp = self.path.with_name(self.path.name + ".tmp")
            persisted = {"version": 1, "domains": []}
            for row in self._data["domains"]:
                item = dict(row)
                item.pop("verification_owner", None)
                persisted["domains"].append(item)
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
                self._runtime[row["id"]] = {"in_use": 0}
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
                    self._runtime[row["id"]] = {"in_use": 0}
                    added += 1
                elif row["status"] != "enabled":
                    row["status"] = "enabled"
                    row["disabled_reason"] = ""
                    row["disabled_at"] = ""
                    row["verification_owner"] = ""
                    self._event(row, "CONFIG_REENABLED", "域名重新进入已保存列表")
                    enabled += 1
                ordered.append(row)

            for row in self._data["domains"]:
                if row["domain"] in seen:
                    continue
                if row["status"] in {"enabled", "verifying"}:
                    row["status"] = "disabled"
                    row["disabled_reason"] = "CONFIG_REMOVED"
                    row["disabled_at"] = _now()
                    row["verification_owner"] = ""
                    self._event(row, "CONFIG_REMOVED", "域名不在新的已保存列表中")
                    disabled += 1
                ordered.append(row)
            self._data["domains"] = ordered
            self._cursor = 0
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
            "bot_first_failures": 0,
            "bot_second_failures": 0,
            "bot_failures": 0,
            "last_failure_code": "",
            "last_failure_message": "",
            "last_failure_at": "",
            "disabled_reason": "",
            "disabled_at": "",
            "email_health": "untested",
            "email_health_message": "尚未测试",
            "email_tested_at": "",
            "events": [],
            "verification_owner": "",
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
                self._runtime[row["id"]] = {"in_use": 0}
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
        out = dict(row)
        out.pop("verification_owner", None)
        out["in_use"] = int(self._runtime.setdefault(row["id"], {"in_use": 0}).get("in_use") or 0)
        return out

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
                "verifying": sum(1 for x in rows if x["status"] == "verifying"),
                "busy": sum(int(x.get("in_use") or 0) for x in self._runtime.values()),
            }

    def active_domains(self) -> list[str]:
        """Domains eligible for new provider leases."""
        with self._lock:
            return [x["domain"] for x in self._data["domains"] if x["status"] == "enabled"]

    def acquire(self, logical_id: str) -> Optional[DomainLease]:
        with self._lock:
            rows = self._data["domains"]
            candidates = [x for x in rows if x["status"] == "enabled"]
            if not candidates:
                return None
            ordered = rows[self._cursor:] + rows[:self._cursor]
            ids = {x["id"] for x in candidates}
            row = next(x for x in ordered if x["id"] in ids)
            self._cursor = (rows.index(row) + 1) % max(1, len(rows))
            self._runtime.setdefault(row["id"], {"in_use": 0})["in_use"] += 1
            return DomainLease(row["id"], row["domain"], str(logical_id or uuid.uuid4().hex))

    def release(self, lease: Optional[DomainLease]) -> None:
        if lease is None:
            return
        with self._lock:
            rt = self._runtime.get(lease.domain_id)
            if rt:
                rt["in_use"] = max(0, int(rt.get("in_use") or 0) - 1)

    def begin_revalidation(self, lease: DomainLease, *, proxy: str = "", message: str = "risk MARKED") -> bool:
        with self._lock:
            row = self._entry(lease.domain_id)
            if row is None or row["status"] != "enabled":
                return False
            row["status"] = "verifying"
            row["verification_owner"] = lease.logical_id
            row["bot_first_failures"] += 1
            row["bot_failures"] += 1
            row["last_failure_code"] = "BOT_MARKED_FIRST"
            row["last_failure_message"] = str(message or "risk MARKED")[:160]
            row["last_failure_at"] = _now()
            self._event(row, "BOT_MARKED_FIRST", message, proxy=proxy, logical_id=lease.logical_id)
            self._save_locked()
            return True

    def complete_revalidation(
        self,
        lease: DomainLease,
        *,
        clean: bool,
        proxy: str = "",
        message: str = "",
    ) -> None:
        with self._lock:
            row = self._entry(lease.domain_id)
            if row is None:
                self.release(lease)
                return
            owns = row.get("verification_owner") == lease.logical_id
            if owns:
                if clean:
                    if row["status"] == "verifying":
                        row["status"] = "enabled"
                    self._event(row, "BOT_REVALIDATION_CLEAN", message or "复验 CLEAN", proxy=proxy, logical_id=lease.logical_id)
                else:
                    row["bot_second_failures"] += 1
                    row["bot_failures"] += 1
                    row["last_failure_code"] = "BOT_MARKED_SECOND"
                    row["last_failure_message"] = str(message or "复验 risk MARKED")[:160]
                    row["last_failure_at"] = _now()
                    row["status"] = "disabled"
                    row["disabled_reason"] = "BOT_MARKED_TWICE"
                    row["disabled_at"] = _now()
                    self._event(row, "BOT_MARKED_SECOND", message or "复验 risk MARKED", proxy=proxy, logical_id=lease.logical_id)
                row["verification_owner"] = ""
                self._save_locked()
            self.release(lease)

    def abort_revalidation(self, lease: DomainLease, *, code: str, message: str) -> None:
        with self._lock:
            row = self._entry(lease.domain_id)
            if row and row.get("verification_owner") == lease.logical_id:
                if row["status"] == "verifying":
                    row["status"] = "enabled"
                row["verification_owner"] = ""
                self._event(row, code, message, logical_id=lease.logical_id)
                self._save_locked()
            self.release(lease)

    def record_parallel_marked(self, lease: DomainLease, *, proxy: str = "", message: str = "risk MARKED") -> None:
        with self._lock:
            row = self._entry(lease.domain_id)
            if row:
                row["bot_failures"] += 1
                row["last_failure_code"] = "BOT_MARKED_PARALLEL"
                row["last_failure_message"] = str(message or "risk MARKED")[:160]
                row["last_failure_at"] = _now()
                self._event(row, "BOT_MARKED_PARALLEL", message, proxy=proxy, logical_id=lease.logical_id)
                self._save_locked()
            self.release(lease)

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
                    row["verification_owner"] = ""
                    self._event(row, "MANUAL_ENABLED", "人工启用")
                else:
                    row["status"] = "disabled"
                    row["disabled_reason"] = "MANUAL"
                    row["disabled_at"] = _now()
                    row["verification_owner"] = ""
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
                self._runtime.pop(row["id"], None)
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

    def recover_incomplete(self, message: str = "任务结束，未完成复验已清除") -> int:
        """Return interrupted verification rows to enabled without erasing history."""
        recovered = 0
        with self._lock:
            for row in self._data["domains"]:
                if row["status"] != "verifying":
                    continue
                row["status"] = "enabled"
                row["verification_owner"] = ""
                self._event(row, "REVALIDATION_INTERRUPTED", message)
                recovered += 1
            if recovered:
                self._save_locked()
        return recovered


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
