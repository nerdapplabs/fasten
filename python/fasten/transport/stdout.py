"""JSON lines on stdout, one per row, with a ``shape`` of sys, api or audit.

sys and api rows are also kept in an in-memory ring (or a stream store, if
configured) for the reader. Audit rows are read from the audit store.

Apps that already write their own log lines should use push_syslog/push_api,
which skip stdout.
"""
from __future__ import annotations

import json
import sys
from typing import Any

from ..context import is_sentinel, mint_sentinel
from ..redact import Redactor
from ..store.ring import RingBuffer
from ..store.stream import StreamStore


class StdoutTransport:
    """Stdout writer with in-memory rings for the sys and api streams.

    With a stream store, rows go to both the ring and the store, and reads
    come from the store. Every sys and api row is redacted before it is
    buffered, stored or written.
    """

    def __init__(
        self,
        maxlen: int = 2000,
        *,
        api_store: StreamStore | None = None,
        syslog_store: StreamStore | None = None,
        service_id: str = "",
        boot_request_id: str | None = None,
        redactor: Redactor | None = None,
    ) -> None:
        self._syslog = RingBuffer(maxlen=maxlen)
        self._api = RingBuffer(maxlen=maxlen)
        self._api_store = api_store
        self._syslog_store = syslog_store
        self._service_id = service_id
        # The engine passes its configured Redactor.
        self._redactor = redactor if redactor is not None else Redactor()
        # Rows without a request_id get the boot id until the first real
        # request, then an orphan id. _boot_over only goes False to True, so
        # it needs no lock; a race stamps at most one extra row with boot.
        self._boot_request_id = boot_request_id
        self._boot_over = False

    def _persist(self, store: StreamStore | None, row: dict[str, Any], stream: str) -> None:
        """Write-through to the durable sink. A sink failure must never break
        the hot logging path (the ring + stdout already hold the row), so it is
        logged to stderr and swallowed — matching the Go transport. But the
        failure is recorded on the store, which degrades the stream's
        completeness flag to ``store-degraded``: reads for a store-backed
        stream never consult the ring, so without that the flag would assert
        durability for rows that were silently lost.

        The stderr line reports the error type only — a Postgres INSERT
        failure message can carry the offending row value (e.g.
        NotNullViolation cites the column), and stderr is not redacted, so
        the raw ``str(exc)`` would leak PII. Operators debug the schema
        mismatch via the (redacted) drainer_sys stream, not stderr."""
        if store is None:
            return
        try:
            store.insert(row)
        except Exception as exc:  # noqa: BLE001 — best-effort durability
            store.note_write_failure()
            sys.stderr.write(f"fasten: {stream} persist failed: {type(exc).__name__}\n")

    def _redact(self, row: dict[str, Any]) -> dict[str, Any]:
        """Redacted copy of a sys or api row. Audit rows are redacted in
        Engine.emit()."""
        return self._redactor.redact(row)

    def _stream_store(self, stream: str) -> StreamStore | None:
        if stream == "api":
            return self._api_store
        if stream == "sys":
            return self._syslog_store
        return None

    def stream_degraded(self, stream: str) -> bool:
        """True if a write to the stream's store has failed. Always False
        without a store."""
        store = self._stream_store(stream)
        return store is not None and store.degraded

    def _stamp_request_id(self, row: dict[str, Any]) -> None:
        """Make sure the row has a request_id: the boot id before the first
        real request, an orphan id after."""
        rid = row.get("request_id")
        # A non-string id (e.g. an int) counts as missing.
        if isinstance(rid, str) and rid:
            if not is_sentinel(rid):
                self._boot_over = True
            return
        if self._boot_request_id is not None and not self._boot_over:
            row["request_id"] = self._boot_request_id
        else:
            row["request_id"] = mint_sentinel("orphan", self._service_id)

    def write_syslog(self, row: dict[str, Any]) -> None:
        """Redact, buffer, store if configured, and write to stdout."""
        self._stamp_request_id(row)
        row = self._redact(row)
        self._syslog.push(row)
        self._persist(self._syslog_store, row, "syslog")
        sys.stdout.write(json.dumps({"shape": "sys", **row}, default=str) + "\n")
        sys.stdout.flush()

    def push_syslog(self, row: dict[str, Any]) -> None:
        """Like write_syslog() but without the stdout line."""
        self._stamp_request_id(row)
        row = self._redact(row)
        self._syslog.push(row)
        self._persist(self._syslog_store, row, "syslog")

    def write_drainer_syslog(self, row: dict[str, Any]) -> None:
        """Like write_syslog() but the line goes to stderr.

        Used for fasten's own events. If the drainer thread wrote to a
        blocked stdout it would stall, and emit() would block once the queue
        filled.
        """
        self._stamp_request_id(row)
        row = self._redact(row)
        self._syslog.push(row)
        self._persist(self._syslog_store, row, "syslog")
        sys.stderr.write(json.dumps({"shape": "sys", **row}, default=str) + "\n")
        sys.stderr.flush()

    def query_syslog(
        self,
        *,
        limit: int = 100,
        level: str | None = None,
        request_id: str | None = None,
        service_id: str | None = None,
        event: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> list[dict[str, Any]]:
        src = self._syslog_store if self._syslog_store is not None else self._syslog
        return src.query(limit=limit, level=level, request_id=request_id,
                         service_id=service_id, event=event, since=since, until=until)

    def count_syslog(self, **filters: Any) -> int:
        """Number of sys rows matching the filters, without query_syslog()'s
        limit."""
        if self._syslog_store is not None:
            return self._syslog_store.count_matching(**filters)
        return self._syslog.count(**filters)

    def search_syslog(
        self, *, q: str, since: str, until: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]] | None:
        """Free-text search of the sys store. None if there is no store."""
        if self._syslog_store is None:
            return None
        return self._syslog_store.search(q=q, since=since, until=until, limit=limit)

    def search_api(
        self, *, q: str, since: str, until: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]] | None:
        """Free-text search of the api store. None if there is no store."""
        if self._api_store is None:
            return None
        return self._api_store.search(q=q, since=since, until=until, limit=limit)

    def write_api(self, row: dict[str, Any]) -> None:
        """Redact, buffer, store if configured, and write to stdout."""
        self._stamp_request_id(row)
        row = self._redact(row)
        self._api.push(row)
        self._persist(self._api_store, row, "api")
        sys.stdout.write(json.dumps({"shape": "api", **row}, default=str) + "\n")
        sys.stdout.flush()

    def push_api(self, row: dict[str, Any]) -> None:
        """Like write_api() but without the stdout line."""
        self._stamp_request_id(row)
        row = self._redact(row)
        self._api.push(row)
        self._persist(self._api_store, row, "api")

    def query_api(
        self,
        *,
        limit: int = 100,
        method: str | None = None,
        path: str | None = None,
        request_id: str | None = None,
        status: int | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> list[dict[str, Any]]:
        src = self._api_store if self._api_store is not None else self._api
        return src.query(limit=limit, method=method, path=path,
                         request_id=request_id, status=status, since=since, until=until)

    def count_api(self, **filters: Any) -> int:
        """Number of api rows matching the filters, without query_api()'s
        limit."""
        if self._api_store is not None:
            return self._api_store.count_matching(**filters)
        return self._api.count(**filters)

    def write_audit(self, row: dict[str, Any]) -> None:
        """Write an audit row to stdout. Storing it is the Engine's job."""
        sys.stdout.write(json.dumps({"shape": "audit", **row}, default=str) + "\n")
        sys.stdout.flush()
