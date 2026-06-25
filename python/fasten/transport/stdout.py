"""
Stdout transport — JSON lines to stdout. Docker log driver captures + rotates.

Three shapes:
  {"shape": "sys",   ...}  — structured log lines from fasten.log.*
  {"shape": "api",   ...}  — HTTP request log lines
  {"shape": "audit", ...}  — audit rows (also persisted to SQL store)

sys and api are also buffered in an in-memory ring so /logs/sys and /logs/api
can serve recent events without reading from disk. audit is not ring-buffered
here — /logs/audit queries the durable SQL store directly.

Adopters who manage their own stdout (e.g. structlog, slog, zap) should call
push_syslog / push_api instead of write_syslog / write_api — the push variants
only buffer, they do not write to stdout (avoiding double-output).
"""
from __future__ import annotations

import json
import sys
from typing import Any

from ..context import is_sentinel, mint_sentinel
from ..store.ring import RingBuffer
from ..store.stream import StreamStore


class StdoutTransport:
    """Stdout writer + in-memory rings for the ``sys``/``api`` streams.

    When a stream store is supplied (FR1, opt-in persistence) the ring stays
    the hot write path and the store is a write-through sink; reads for that
    stream are served from the store so they reach durable history instead of
    a bounded window. Without a store the stream is ring-only — today's
    backward-compatible behaviour.
    """

    def __init__(
        self,
        maxlen: int = 2000,
        *,
        api_store: StreamStore | None = None,
        syslog_store: StreamStore | None = None,
        service_id: str = "",
        boot_request_id: str | None = None,
    ) -> None:
        self._syslog = RingBuffer(maxlen=maxlen)
        self._api = RingBuffer(maxlen=maxlen)
        self._api_store = api_store
        self._syslog_store = syslog_store
        self._service_id = service_id
        # Sentinel invariant: rows written before the first real request belong
        # to one stable boot window; context-less rows after that are orphans.
        self._boot_request_id = boot_request_id
        self._boot_over = False

    def _stamp_request_id(self, row: dict[str, Any]) -> None:
        """Guarantee a non-empty request_id on every stream row (the sentinel
        invariant). A real id ends the boot window; a missing id is filled with
        the shared boot sentinel during startup, else a unique orphan id."""
        rid = row.get("request_id")
        if rid:
            if not is_sentinel(rid):
                self._boot_over = True
            return
        if self._boot_request_id is not None and not self._boot_over:
            row["request_id"] = self._boot_request_id
        else:
            row["request_id"] = mint_sentinel("orphan", self._service_id)

    # ── syslog ──────────────────────────────────────────────────────────────

    def write_syslog(self, row: dict[str, Any]) -> None:
        """Write to stdout AND buffer (+ persist if configured)."""
        self._stamp_request_id(row)
        self._syslog.push(row)
        if self._syslog_store is not None:
            self._syslog_store.insert(row)
        sys.stdout.write(json.dumps({"shape": "sys", **row}, default=str) + "\n")
        sys.stdout.flush()

    def push_syslog(self, row: dict[str, Any]) -> None:
        """Buffer only — no stdout (+ persist if configured)."""
        self._stamp_request_id(row)
        self._syslog.push(row)
        if self._syslog_store is not None:
            self._syslog_store.insert(row)

    def write_drainer_syslog(self, row: dict[str, Any]) -> None:
        """Drainer self-report path. Buffers + writes to STDERR, never stdout.

        The audit queue drainer cannot share the stdout fd with emit() and
        application logging: under stdout backpressure (slow Docker log
        driver, blocked sidecar tail) writing here would block the drainer
        thread, which would in turn block emit() once the queue fills —
        a textbook capacity-deadlock with no recovery path. stderr lives on
        a separate fd so the drainer keeps making progress; the row is
        also pushed to the in-memory ring so `/logs/sys` and
        `query_syslog()` continue to return drainer events for adopters
        who never look at stderr.
        """
        self._stamp_request_id(row)
        self._syslog.push(row)
        sys.stderr.write(json.dumps({"shape": "sys", **row}, default=str) + "\n")
        sys.stderr.flush()

    def query_syslog(
        self,
        *,
        limit: int = 100,
        level: str | None = None,
        request_id: str | None = None,
        service_id: str | None = None,
    ) -> list[dict[str, Any]]:
        src = self._syslog_store if self._syslog_store is not None else self._syslog
        return src.query(limit=limit, level=level,
                         request_id=request_id, service_id=service_id)

    # ── api log ─────────────────────────────────────────────────────────────

    def write_api(self, row: dict[str, Any]) -> None:
        """Write to stdout AND buffer (+ persist if configured)."""
        self._stamp_request_id(row)
        self._api.push(row)
        if self._api_store is not None:
            self._api_store.insert(row)
        sys.stdout.write(json.dumps({"shape": "api", **row}, default=str) + "\n")
        sys.stdout.flush()

    def push_api(self, row: dict[str, Any]) -> None:
        """Buffer only — no stdout (+ persist if configured)."""
        self._stamp_request_id(row)
        self._api.push(row)
        if self._api_store is not None:
            self._api_store.insert(row)

    def query_api(
        self,
        *,
        limit: int = 100,
        method: str | None = None,
        path: str | None = None,
        request_id: str | None = None,
    ) -> list[dict[str, Any]]:
        src = self._api_store if self._api_store is not None else self._api
        return src.query(limit=limit, method=method,
                         path=path, request_id=request_id)

    # ── audit ────────────────────────────────────────────────────────────────

    def write_audit(self, row: dict[str, Any]) -> None:
        """Write to stdout. Audit rows are also persisted to SQL store."""
        sys.stdout.write(json.dumps({"shape": "audit", **row}, default=str) + "\n")
        sys.stdout.flush()
