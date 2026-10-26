"""Fixed-size in-memory buffer for the sys and api streams.

The oldest rows are dropped when it is full, and it is empty after a restart.
Filters are exact matches, as in the stream stores. since/until compare
timestamps as strings, which only works for the canonical format.
"""
from __future__ import annotations

import threading
from collections import deque
from typing import Any


def _row_ts(row: dict[str, Any]) -> str:
    """The row's timestamp as a string, "" if missing or None, like the
    stores' ``COALESCE(timestamp, '')``."""
    t = row.get("timestamp")
    return "" if t is None else str(t)


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
            rows = [r for r in rows if _row_ts(r) >= since]
        if until:
            rows = [r for r in rows if _row_ts(r) <= until]
        return rows

    def query(self, *, limit: int = 100, **filters: Any) -> list[dict[str, Any]]:
        return self._matching(**filters)[:limit]

    def count(self, **filters: Any) -> int:
        """Number of rows matching the filters, with no limit."""
        return len(self._matching(**filters))

    def __len__(self) -> int:
        with self._lock:
            return len(self._buf)
