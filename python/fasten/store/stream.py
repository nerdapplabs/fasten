"""SQLite store for the api or sys stream, one table per stream.

Each row is stored whole as JSON in ``payload``, with the filterable fields
copied into indexed columns. Reads return the decoded payloads newest first,
like the ring. Values that are not JSON types come back as their ``str()``.

Every insert commits on the caller's thread. With WAL and
``synchronous=NORMAL`` that is an append without an fsync, but it is still a
disk write per row.

File databases use one connection per thread; ``:memory:`` uses one shared
connection behind a lock.
"""
from __future__ import annotations

import contextlib
import json
import re
import sqlite3
import threading
from datetime import datetime
from typing import Any

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Copied out of the row for filtering. api rows set method/path/status, sys
# rows level/service_id/event.
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
    """SQLite table backing one stream."""

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
        # Inserts that failed and were dropped by the transport. Any at all
        # makes the reader report "store-degraded". No lock: a lost increment
        # only undercounts.
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
                # Per connection, unlike journal_mode. No fsync per commit;
                # a crash can lose the last few rows but not corrupt the
                # database, which is fine for stream rows.
                conn.execute("PRAGMA synchronous=NORMAL")
            self._tls.conn = conn
        return conn

    def _txn(self) -> contextlib.AbstractContextManager[Any]:
        return self._mem_lock if self._is_memory else contextlib.nullcontext()

    def insert(self, row: dict[str, Any]) -> None:
        """Store one row."""
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
                    # Keep non-ASCII text unescaped so search() can match it,
                    # and so rows match what Go's json.Marshal writes.
                    json.dumps(row, default=str, ensure_ascii=False),
                ),
            )
            conn.commit()

    def note_write_failure(self) -> None:
        """Count a failed insert that was dropped. Called by the transport,
        not by insert(), so callers handling the error themselves don't mark
        the store degraded."""
        self._write_failures += 1

    @property
    def write_failures(self) -> int:
        """Number of failed inserts that were dropped."""
        return self._write_failures

    @property
    def degraded(self) -> bool:
        """True if any insert has failed and been dropped."""
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
        """WHERE clause for query() and count_matching(): exact matches plus an
        optional [since, until] window."""
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
        # A missing timestamp compares as "", as in the ring. Timestamps are
        # compared as strings, which works for the canonical form only.
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
        """Up to ``limit`` rows, newest first. Every filter, ``level``
        included, is an exact match, as in the ring and the Go SDK."""
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
        """Number of rows matching the same filters as query(), with no limit."""
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

    def purge(self, *, before: "datetime | str") -> int:
        """Delete rows older than ``before`` and return how many were deleted.

        ``before`` may be a datetime (as the audit stores take) or a canonical
        timestamp string. Rows without a timestamp are kept.
        """
        if not isinstance(before, str):
            from ..canonical_ts import canonical_ts
            before = canonical_ts(before)
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
        """Case-insensitive substring search of the stored JSON within
        ``[since, until]``, newest first, at most ``limit`` rows.

        This is a linear ``LIKE`` scan. ``%``, ``_`` and ``\\`` in ``q`` match
        literally."""
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
        """``dt`` as a canonical timestamp string."""
        from ..canonical_ts import canonical_ts
        return canonical_ts(dt)
