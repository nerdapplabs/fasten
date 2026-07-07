"""
In-memory ring buffer — fixed-size deque for syslog and api-log streams.

Thread-safe, never blocks writers. Oldest entries drop off the tail when
the buffer is full. Restarting the process clears it (intentional — these
streams are for live observability, not durable storage).

Filters are exact-match (including ``level``, matching the Go SDK and the
stream store). The since/until window compares timestamps lexicographically:
correct for the canonical UTC timestamps fasten's own writers stamp, but
mixed formats ("…+00:00" vs "…Z", differing fractional precision) do not
order lexicographically — keep caller-supplied timestamps in one canonical
UTC format.
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

    def _matching(
        self,
        *,
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
            rows = [r for r in rows if r.get("level") == level]
        if request_id:
            rows = [r for r in rows if r.get("request_id") == request_id]
        if service_id:
            rows = [r for r in rows if r.get("service_id") == service_id]
        if method:
            rows = [r for r in rows if r.get("method") == method]
        if path:
            rows = [r for r in rows if r.get("path") == path]
        if event:
            rows = [r for r in rows if r.get("event") == event]
        if status is not None:
            rows = [r for r in rows if r.get("status") == status]
        if since:
            rows = [r for r in rows if str(r.get("timestamp", "")) >= since]
        if until:
            rows = [r for r in rows if str(r.get("timestamp", "")) <= until]
        return rows

    def query(self, *, limit: int = 100, **filters: Any) -> list[dict[str, Any]]:
        return self._matching(**filters)[:limit]

    def count(self, **filters: Any) -> int:
        """Total rows matching the filters in the ring's current window — the
        uncapped counterpart of query(), so capped reads can report
        truncation."""
        return len(self._matching(**filters))

    def __len__(self) -> int:
        with self._lock:
            return len(self._buf)
