"""线程安全日志缓冲，供控制台与 Web UI 共用（拆自旧 grok.py）。"""

from __future__ import annotations

import threading
from collections import deque
from datetime import datetime


class LogBuffer:
    """线程安全日志缓冲，供控制台与 Web UI 共用。"""

    def __init__(self, maxlen: int = 2000):
        self._lock = threading.Lock()
        self._seq = 0
        self._entries = deque(maxlen=maxlen)

    def emit(self, message: str, level: str = "info"):
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self._seq += 1
            entry = {
                "id": self._seq,
                "time": ts,
                "level": level,
                "message": message,
            }
            self._entries.append(entry)
        print(f"[{ts}] {message}")
        return entry

    def latest_id(self) -> int:
        with self._lock:
            return int(self._seq)

    def since(self, after_id: int = 0, limit: int = 200):
        with self._lock:
            # 服务重启后 seq 从 0 起，浏览器仍可能带着旧 after_id → 永远空结果（日志“卡住”）
            if after_id > self._seq:
                items = list(self._entries)[-limit:]
            else:
                items = [e for e in self._entries if e["id"] > after_id]
                items = items[-limit:]
            return items

    def clear(self):
        with self._lock:
            self._entries.clear()
