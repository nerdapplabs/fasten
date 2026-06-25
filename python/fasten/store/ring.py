"""
In-memory ring buffer — fixed-size deque for syslog and api-log streams.

Thread-safe, never blocks writers. Oldest entries drop off the tail when
the buffer is full. Restarting the process clears it (intentional — these
streams are for live observability, not durable storage).
"""
from __future__ import annotations

import threading
from collections import deque
from typing import Any


class RingBuffer:
    def __init__(self, maxlen: int = 2000) -> None:
        self._buf: deque[dict[str, Any]] = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def push(self, row: dict[str, Any]) -> None:
        with self._lock:
            self._buf.appendleft(row)

    def query(
        self,
        *,
        limit: int = 100,
        level: str | None = None,
        request_id: str | None = None,
        service_id: str | None = None,
        method: str | None = None,
        path: str | None = None,
        event: str | None = None,
        status: int | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            rows: list[dict[str, Any]] = list(self._buf)
        if level:
            rows = [r for r in rows if r.get("level") == level.lower()]
        if request_id:
            rows = [r for r in rows if r.get("request_id") == request_id]
        if service_id:
            rows = [r for r in rows if r.get("service_id") == service_id]
        if method:
            rows = [r for r in rows if r.get("method", "").upper() == method.upper()]
        if path:
            rows = [r for r in rows if path.lower() in r.get("path", "").lower()]
        if event:
            rows = [r for r in rows if r.get("event") == event]
        if status is not None:
            rows = [r for r in rows if r.get("status") == status]
        if since:
            rows = [r for r in rows if str(r.get("timestamp", "")) >= since]
        if until:
            rows = [r for r in rows if str(r.get("timestamp", "")) <= until]
        return rows[:limit]

    def __len__(self) -> int:
        with self._lock:
            return len(self._buf)
