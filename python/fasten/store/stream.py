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
        bootstrap = self._connect()
        if wal and not self._is_memory:
            bootstrap.execute("PRAGMA journal_mode=WAL")
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
                    cols["path"], cols["status"], json.dumps(row, default=str),
                ),
            )
            conn.commit()

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
        """Return up to ``limit`` rows newest-first, applying the same filter
        intent as the in-memory ring so store and ring reads agree. Caveat:
        ``path`` uses SQL ``LIKE``, so ``%``/``_`` in the path argument act as
        wildcards here while the ring does a literal substring match."""
        conds: list[str] = []
        params: list[Any] = []
        if level:
            conds.append("level = ?")
            params.append(level.lower())
        if request_id:
            conds.append("request_id = ?")
            params.append(request_id)
        if service_id:
            conds.append("service_id = ?")
            params.append(service_id)
        if method:
            conds.append("upper(method) = ?")
            params.append(method.upper())
        if path:
            conds.append("lower(path) LIKE ?")
            params.append(f"%{path.lower()}%")
        if event:
            conds.append("event = ?")
            params.append(event)
        if status is not None:
            conds.append("status = ?")
            params.append(status)
        # COALESCE so a NULL (timestamp-less) row sorts as "" — matching the
        # ring, which treats a missing timestamp as empty string. Without this
        # a NULL row is excluded by `<= until` in SQL but included in the ring.
        if since:
            conds.append("COALESCE(timestamp, '') >= ?")
            params.append(since)
        if until:
            conds.append("COALESCE(timestamp, '') <= ?")
            params.append(until)
        where = (" WHERE " + " AND ".join(conds)) if conds else ""
        sql = f"SELECT payload FROM {self._table}{where} ORDER BY seq DESC LIMIT ?"
        params.append(limit)
        with self._txn():
            conn = self._connect()
            rows = conn.execute(sql, params).fetchall()
        return [json.loads(r["payload"]) for r in rows]

    def count(self) -> int:
        with self._txn():
            conn = self._connect()
            return int(conn.execute(f"SELECT COUNT(*) FROM {self._table}").fetchone()[0])

    @staticmethod
    def _utc_iso(dt: datetime) -> str:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
