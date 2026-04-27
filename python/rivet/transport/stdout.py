"""
Stdout transport — JSON lines to stdout. Docker log driver captures + rotates.

Three shapes:
  {"shape": "sys",   ...}  — structured log lines from rivet.log.*
  {"shape": "api",   ...}  — HTTP request log lines
  {"shape": "audit", ...}  — audit rows (also persisted to SQL store)

Each shape is also buffered in an in-memory ring so /logs/{sys,api,audit}
can serve recent events without reading from disk.

Adopters who manage their own stdout (e.g. structlog, slog, zap) should call
push_syslog / push_api instead of write_syslog / write_api — the push variants
only buffer, they do not write to stdout (avoiding double-output).
"""
from __future__ import annotations

import json
import sys
from typing import Any

from ..store.ring import RingBuffer


class StdoutTransport:
    def __init__(self, maxlen: int = 2000) -> None:
        self._syslog = RingBuffer(maxlen=maxlen)
        self._api = RingBuffer(maxlen=maxlen)

    # ── syslog ──────────────────────────────────────────────────────────────

    def write_syslog(self, row: dict[str, Any]) -> None:
        """Write to stdout AND buffer. Used by rivet's own logger."""
        self._syslog.push(row)
        sys.stdout.write(json.dumps({"shape": "sys", **row}, default=str) + "\n")
        sys.stdout.flush()

    def push_syslog(self, row: dict[str, Any]) -> None:
        """Buffer only — no stdout. Used by adopters that own their stdout."""
        self._syslog.push(row)

    def query_syslog(
        self,
        *,
        limit: int = 100,
        level: str | None = None,
        request_id: str | None = None,
        service_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._syslog.query(limit=limit, level=level,
                                  request_id=request_id, service_id=service_id)

    # ── api log ─────────────────────────────────────────────────────────────

    def write_api(self, row: dict[str, Any]) -> None:
        """Write to stdout AND buffer."""
        self._api.push(row)
        sys.stdout.write(json.dumps({"shape": "api", **row}, default=str) + "\n")
        sys.stdout.flush()

    def push_api(self, row: dict[str, Any]) -> None:
        """Buffer only — no stdout."""
        self._api.push(row)

    def query_api(
        self,
        *,
        limit: int = 100,
        method: str | None = None,
        path: str | None = None,
        request_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._api.query(limit=limit, method=method,
                               path=path, request_id=request_id)

    # ── audit ────────────────────────────────────────────────────────────────

    def write_audit(self, row: dict[str, Any]) -> None:
        """Write to stdout. Audit rows are also persisted to SQL store."""
        sys.stdout.write(json.dumps({"shape": "audit", **row}, default=str) + "\n")
        sys.stdout.flush()
