"""
SQLite-backed per-stream store for the ``api`` and ``sys`` streams (FR1).

Unlike the audit store (typed ``AuditRow`` + tamper-evident hash chain),
stream rows are schemaless dicts produced by the logging/HTTP shims. We
persist the full row as a JSON ``payload`` and duplicate the queryable
fields into indexed columns, so the reader can filter by ``request_id`` /
time / structured fields against durable history instead of a bounded ring.

Table per stream — ``api`` and ``sys`` never share rows. Rows are returned
newest-first, reconstructed from the stored JSON payload, so a store read is
equivalent to a ring read in content and ordering. The payload is a JSON
round-trip (``json.dumps(..., default=str)`` on the way in), so JSON-native
scalars are preserved but non-JSON values (e.g. ``datetime``) are coerced to
their ``str()`` form — not type-identical to the original object.

Write cost: persistence is write-through — every pushed row is one
synchronous INSERT + commit on the caller's thread. With WAL +
``synchronous=NORMAL`` (set on every connection) a commit is a WAL append
without a per-commit fsync, which keeps a hot api/sys stream viable. Even so
this is a per-row disk write: for very hot streams prefer ring-only mode, or
expect stream persistence to grow an async drainer in a later phase (the
audit path already has one).

Connection handling mirrors ``SQLiteStore``: one connection per thread for
file-backed stores (WAL — many readers + one writer), and a single
lock-guarded connection for ``:memory:`` (which cannot be shared across
connections).
"""
from __future__ import annotations

import contextlib
import json
import re
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Columns lifted out of the row for indexed filtering. The rest of the row
# survives in `payload`. `api` populates method/path/status; `sys` populates
# level/service_id/event; request_id/timestamp are common to both.
_INDEXED_FIELDS = ("request_id", "timestamp", "level", "service_id",
                   "event", "method", "path", "status")

_DDL = """
CREATE TABLE IF NOT EXISTS {table} (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id   TEXT,
    timestamp    TEXT,
    level        TEXT,
    service_id   TEXT,
    event        TEXT,
    method       TEXT,
    path         TEXT,
    status       INTEGER,
    payload      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_{table}_req ON {table}(request_id);
CREATE INDEX IF NOT EXISTS idx_{table}_ts  ON {table}(timestamp);
CREATE INDEX IF NOT EXISTS idx_{table}_lvl ON {table}(level);
CREATE INDEX IF NOT EXISTS idx_{table}_svc ON {table}(service_id);
CREATE INDEX IF NOT EXISTS idx_{table}_evt ON {table}(event);
CREATE INDEX IF NOT EXISTS idx_{table}_mth ON {table}(method);
CREATE INDEX IF NOT EXISTS idx_{table}_pth ON {table}(path);
CREATE INDEX IF NOT EXISTS idx_{table}_sts ON {table}(status);
"""


class StreamStore:
    """Durable, queryable backing for one ring-buffered stream."""

    def __init__(self, path: str, table: str, wal: bool = True) -> None:
        if not _SAFE_IDENTIFIER.match(table):
            raise ValueError(
                f"fasten StreamStore: table name {table!r} is not a valid SQL "
                "identifier. Use only letters, digits, and underscores."
            )
        self._path = path
        self._table = table
        self._wal = wal
        self._is_memory = path == ":memory:"
        self._tls = threading.local()
        self._mem_conn: sqlite3.Connection | None = None
        self._mem_lock = threading.RLock()
        # Persist attempts swallowed by the transport. Non-zero means durable
        # history has holes, so the reader degrades the stream's completeness
        # flag from "store" to "store-degraded". Sticky for the store's
        # lifetime: a hole in history doesn't heal when the disk recovers.
        # Plain int under the GIL — a lost increment can only undercount, and
        # ``degraded`` only needs "at least one".
        self._write_failures = 0
        bootstrap = self._connect()
        for stmt in _DDL.format(table=table).split(";"):
            if stmt.strip():
                bootstrap.execute(stmt)
        bootstrap.commit()

    def _connect(self) -> sqlite3.Connection:
        if self._is_memory:
            if self._mem_conn is None:
                self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
                self._mem_conn.row_factory = sqlite3.Row
            return self._mem_conn
        conn = getattr(self._tls, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._path)
            conn.row_factory = sqlite3.Row
            if self._wal:
                conn.execute("PRAGMA journal_mode=WAL")
                # The standard WAL pairing, and per-connection (unlike
                # journal_mode, which persists in the file): commits append to
                # the WAL without a per-commit fsync. That matters because
                # insert() runs one commit per pushed row. NORMAL still
                # guarantees database consistency after a crash; the tail of
                # unsynced commits may be lost, acceptable for stream rows
                # (the audit chain has its own store and drainer).
                conn.execute("PRAGMA synchronous=NORMAL")
            self._tls.conn = conn
        return conn

    def _txn(self) -> contextlib.AbstractContextManager[Any]:
        return self._mem_lock if self._is_memory else contextlib.nullcontext()

    def insert(self, row: dict[str, Any]) -> None:
        """Write-through persist of a single stream row. Newest rows sort first."""
        cols = {f: row.get(f) for f in _INDEXED_FIELDS}
        with self._txn():
            conn = self._connect()
            conn.execute(
                f"INSERT INTO {self._table} "
                "(request_id,timestamp,level,service_id,event,method,path,status,payload) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    cols["request_id"], cols["timestamp"], cols["level"],
                    cols["service_id"], cols["event"], cols["method"],
                    cols["path"], cols["status"],
                    # ensure_ascii=False keeps non-ASCII characters as UTF-8
                    # bytes in the JSON payload instead of \uXXXX escapes.
                    # With escapes, search(q="prüfung") returns zero matches
                    # against a row containing "prüfung" while the ASCII half
                    # of the same row matches fine — and Go's json.Marshal
                    # (the sibling SDK sharing the table) never escapes, so a
                    # mixed-writer table would return different rows per SDK.
                    json.dumps(row, default=str, ensure_ascii=False),
                ),
            )
            conn.commit()

    def note_write_failure(self) -> None:
        """Record that a persist attempt for this store was swallowed. Called
        by the transport at the swallow point, so callers that handle an
        insert() error themselves don't mark the store degraded."""
        self._write_failures += 1

    @property
    def write_failures(self) -> int:
        """How many persist attempts were swallowed."""
        return self._write_failures

    @property
    def degraded(self) -> bool:
        """True when durable history has known holes (at least one swallowed
        persist failure). Drives the ``store-degraded`` completeness flag."""
        return self._write_failures > 0

    def _build_where(
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
    ) -> tuple[str, list[Any]]:
        """Shared WHERE for query()/count_matching(): exact-match equality on
        the indexed columns plus an optional [since, until] timestamp window."""
        conds: list[str] = []
        params: list[Any] = []
        if level:
            conds.append("level = ?")
            params.append(level)
        if request_id:
            conds.append("request_id = ?")
            params.append(request_id)
        if service_id:
            conds.append("service_id = ?")
            params.append(service_id)
        if method:
            conds.append("method = ?")
            params.append(method)
        if path:
            conds.append("path = ?")
            params.append(path)
        if event:
            conds.append("event = ?")
            params.append(event)
        if status is not None:
            conds.append("status = ?")
            params.append(status)
        # COALESCE so a NULL (timestamp-less) row sorts as "" — matching the
        # ring, which treats a missing timestamp as empty string. Without this
        # a NULL row is excluded by `<= until` in SQL but included in the ring.
        # The window compares lexicographically (as does the ring): correct for
        # fasten's own canonical UTC timestamps, but mixed formats mis-compare.
        if since:
            conds.append("COALESCE(timestamp, '') >= ?")
            params.append(since)
        if until:
            conds.append("COALESCE(timestamp, '') <= ?")
            params.append(until)
        where = (" WHERE " + " AND ".join(conds)) if conds else ""
        return where, params

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
        """Return up to ``limit`` rows newest-first, applying the same
        exact-match filter semantics as the in-memory ring so store and ring
        reads agree (and match the Go SDK; every filter — including ``level``
        — is exact, not case-folded or substring)."""
        where, params = self._build_where(
            level=level, request_id=request_id, service_id=service_id,
            method=method, path=path, event=event, status=status,
            since=since, until=until,
        )
        sql = f"SELECT payload FROM {self._table}{where} ORDER BY seq DESC LIMIT ?"
        params.append(limit)
        with self._txn():
            conn = self._connect()
            rows = conn.execute(sql, params).fetchall()
        return [json.loads(r["payload"]) for r in rows]

    def count_matching(
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
    ) -> int:
        """Total rows matching the same filters as query(), without a limit —
        so a capped read can report how much history it truncated (the
        /correlate totals)."""
        where, params = self._build_where(
            level=level, request_id=request_id, service_id=service_id,
            method=method, path=path, event=event, status=status,
            since=since, until=until,
        )
        with self._txn():
            conn = self._connect()
            row = conn.execute(
                f"SELECT COUNT(*) FROM {self._table}{where}", params
            ).fetchone()
        return int(row[0])

    def count(self) -> int:
        with self._txn():
            conn = self._connect()
            return int(conn.execute(f"SELECT COUNT(*) FROM {self._table}").fetchone()[0])

    def purge(self, *, before: str) -> int:
        """Delete rows older than ``before`` (a canonical UTC ISO-8601 string),
        returning the number removed. Per-stream retention pruning (FR1): api/sys
        run 10–100× audit volume, so their history is trimmed by age. Unlike
        audit, stream rows have no ship/replication lifecycle, so this is an
        unconditional age-based delete, backed by ``idx_{table}_ts``.

        Rows with a NULL/absent timestamp are never purged (``timestamp < ?`` is
        never true for NULL) — the age of a timestamp-less row is unknown, so it
        is kept rather than silently dropped. The comparison is lexicographic,
        matching the read window; keep ``before`` in the same canonical UTC form
        as the stored timestamps."""
        with self._txn():
            conn = self._connect()
            cur = conn.execute(
                f"DELETE FROM {self._table} WHERE timestamp < ?", (before,)
            )
            conn.commit()
            return cur.rowcount

    def search(
        self,
        *,
        q: str,
        since: str,
        until: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Case-insensitive substring search over the persisted row text, inside
        a mandatory ``[since, until]`` window, newest-first, hard-capped.

        The FR3 escape hatch for "I only have an error string" — deliberately
        constrained (§4.1): it is a linear ``LIKE`` scan bounded by the ``since``
        floor and the ``limit`` cap, with **no relevance ranking**. Callers reach
        it only when structured discovery (indexed fields) can't. ``q`` is
        matched against the full serialized row (``payload``), which for a sys
        row is the event name plus its fields — small, unlike a typed audit row.

        ``%`` / ``_`` / ``\\`` in ``q`` are escaped so they match literally
        rather than acting as LIKE wildcards."""
        esc = q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        conds = ["COALESCE(timestamp, '') >= ?", "lower(payload) LIKE ? ESCAPE '\\'"]
        params: list[Any] = [since, f"%{esc}%"]
        if until:
            conds.append("COALESCE(timestamp, '') <= ?")
            params.append(until)
        sql = (
            f"SELECT payload FROM {self._table} WHERE {' AND '.join(conds)} "
            "ORDER BY seq DESC LIMIT ?"
        )
        params.append(limit)
        with self._txn():
            conn = self._connect()
            rows = conn.execute(sql, params).fetchall()
        return [json.loads(r["payload"]) for r in rows]

    @staticmethod
    def _utc_iso(dt: datetime) -> str:
        """Canonical UTC form for lex-safe cross-SDK compares (spec §4.3)."""
        from ..canonical_ts import canonical_ts
        return canonical_ts(dt)
