"""Bounded on-disk logging and diagnostic capture retention helpers."""
from __future__ import annotations

import io
import os
import shutil
import threading
from pathlib import Path
from typing import Any


DEFAULT_CAPTURE_MAX_GROUPS = 20
DEFAULT_CAPTURE_MAX_MB = 50
DEFAULT_LOG_MAX_MB = 10
DEFAULT_LOG_FILE_COUNT = 3

_WRITE_LOCK = threading.RLock()


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int((os.getenv(name) or str(default)).strip())
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def capture_limits() -> tuple[int, int]:
    return (
        env_int("SOLVER_CAPTURE_MAX_GROUPS", DEFAULT_CAPTURE_MAX_GROUPS, 1, 1000),
        env_int("SOLVER_CAPTURE_MAX_MB", DEFAULT_CAPTURE_MAX_MB, 1, 10240) * 1024 * 1024,
    )


def log_limits() -> tuple[int, int]:
    return (
        env_int("LOG_MAX_MB", DEFAULT_LOG_MAX_MB, 1, 1024) * 1024 * 1024,
        env_int("LOG_ROTATE_FILE_COUNT", DEFAULT_LOG_FILE_COUNT, 1, 20),
    )


def _path_size(path: Path) -> int:
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    if path.is_dir():
        for item in path.rglob("*"):
            if item.is_file():
                try:
                    total += item.stat().st_size
                except OSError:
                    pass
    return total


def capture_stats(capture_root: Path) -> dict[str, int]:
    groups = [p for p in capture_root.iterdir() if p.is_dir()] if capture_root.exists() else []
    return {
        "groups": len(groups),
        "bytes": sum(_path_size(group) for group in groups),
    }


def prune_capture_dirs(capture_root: Path, max_groups: int, max_bytes: int) -> dict[str, int]:
    """Remove oldest complete capture directories until both limits are met."""
    capture_root.mkdir(parents=True, exist_ok=True)
    groups: list[tuple[float, str, Path, int]] = []
    for path in capture_root.iterdir():
        if not path.is_dir():
            continue
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = 0.0
        groups.append((mtime, path.name, path, _path_size(path)))
    groups.sort(key=lambda item: (item[0], item[1]))

    total = sum(item[3] for item in groups)
    removed_groups = 0
    removed_bytes = 0
    while groups and (len(groups) > max_groups or total > max_bytes):
        _, _, path, size = groups.pop(0)
        shutil.rmtree(path, ignore_errors=True)
        if not path.exists():
            removed_groups += 1
            removed_bytes += size
            total = max(0, total - size)
    return {
        "groups": len(groups),
        "bytes": total,
        "removed_groups": removed_groups,
        "removed_bytes": removed_bytes,
    }


def clear_capture_dirs(capture_root: Path) -> dict[str, int]:
    before = capture_stats(capture_root)
    if capture_root.exists():
        for path in capture_root.iterdir():
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            elif path.is_file():
                try:
                    path.unlink()
                except OSError:
                    pass
    capture_root.mkdir(parents=True, exist_ok=True)
    after = capture_stats(capture_root)
    return {
        **after,
        "removed_groups": max(0, before["groups"] - after["groups"]),
        "removed_bytes": max(0, before["bytes"] - after["bytes"]),
    }


def _rotate(path: Path, file_count: int) -> None:
    backups = max(0, file_count - 1)
    if backups == 0:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return
    oldest = path.with_name(f"{path.name}.{backups}")
    try:
        oldest.unlink()
    except FileNotFoundError:
        pass
    for index in range(backups - 1, 0, -1):
        source = path.with_name(f"{path.name}.{index}")
        target = path.with_name(f"{path.name}.{index + 1}")
        if source.exists():
            source.replace(target)
    if path.exists():
        path.replace(path.with_name(f"{path.name}.1"))


def _trim_file_tail(path: Path, max_bytes: int) -> None:
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size <= max_bytes:
        return
    with path.open("rb") as handle:
        handle.seek(-max_bytes, os.SEEK_END)
        payload = handle.read()
    while payload and (payload[0] & 0xC0) == 0x80:
        payload = payload[1:]
    temp_path = path.with_name(f".{path.name}.trim.tmp")
    temp_path.write_bytes(payload)
    temp_path.replace(path)


def enforce_rotated_log(path: str | Path, max_bytes: int, file_count: int) -> None:
    """Trim retained files and remove backups outside the configured count."""
    target = Path(path)
    with _WRITE_LOCK:
        target.parent.mkdir(parents=True, exist_ok=True)
        prefix = f"{target.name}."
        for candidate in target.parent.glob(f"{target.name}.*"):
            suffix = candidate.name[len(prefix):]
            if suffix.isdigit() and int(suffix) >= file_count:
                try:
                    candidate.unlink()
                except OSError:
                    pass
        for index in range(file_count):
            retained = target if index == 0 else target.with_name(f"{target.name}.{index}")
            if retained.exists():
                _trim_file_tail(retained, max_bytes)


def enforce_storage_limits(base_dir: Path) -> dict[str, Any]:
    max_groups, max_capture_bytes = capture_limits()
    captures = prune_capture_dirs(
        base_dir / "logs" / "fo_captures",
        max_groups,
        max_capture_bytes,
    )
    max_log_bytes, file_count = log_limits()
    for name in ("turnstile_solver.log", "standalone_live.log"):
        enforce_rotated_log(base_dir / "logs" / name, max_log_bytes, file_count)
    return {"captures": captures, "logs": storage_stats(base_dir)["logs"]}


def append_rotating_text(
    path: str | Path,
    text: str,
    *,
    max_bytes: int | None = None,
    file_count: int | None = None,
) -> None:
    target = Path(path)
    if max_bytes is None or file_count is None:
        default_bytes, default_count = log_limits()
        max_bytes = default_bytes if max_bytes is None else max_bytes
        file_count = default_count if file_count is None else file_count
    payload = str(text).encode("utf-8", errors="replace")
    if len(payload) > max_bytes:
        payload = payload[-max_bytes:]
        while payload and (payload[0] & 0xC0) == 0x80:
            payload = payload[1:]

    with _WRITE_LOCK:
        target.parent.mkdir(parents=True, exist_ok=True)
        enforce_rotated_log(target, max_bytes, file_count)
        current_size = target.stat().st_size if target.exists() else 0
        if current_size and current_size + len(payload) > max_bytes:
            _rotate(target, file_count)
        with target.open("ab") as handle:
            handle.write(payload)


class RotatingTextStream(io.TextIOBase):
    """A small file-like stream for subprocess/server output with hard rotation."""

    def __init__(self, path: str | Path, max_bytes: int, file_count: int):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.file_count = file_count

    @property
    def encoding(self) -> str:
        return "utf-8"

    def writable(self) -> bool:
        return True

    def write(self, value: str) -> int:
        text = str(value)
        if text:
            append_rotating_text(
                self.path,
                text,
                max_bytes=self.max_bytes,
                file_count=self.file_count,
            )
        return len(text)

    def flush(self) -> None:
        return None

    def isatty(self) -> bool:
        return False


def storage_stats(base_dir: Path) -> dict[str, Any]:
    capture_root = base_dir / "logs" / "fo_captures"
    capture = capture_stats(capture_root)
    max_groups, max_capture_bytes = capture_limits()
    max_log_bytes, file_count = log_limits()
    log_files = {}
    for name in ("turnstile_solver.log", "standalone_live.log"):
        total = 0
        for index in range(file_count):
            suffix = "" if index == 0 else f".{index}"
            total += _path_size(base_dir / "logs" / f"{name}{suffix}")
        log_files[name] = total
    return {
        "captures": capture,
        "logs": log_files,
        "limits": {
            "capture_max_groups": max_groups,
            "capture_max_bytes": max_capture_bytes,
            "log_max_bytes": max_log_bytes,
            "log_file_count": file_count,
        },
    }
