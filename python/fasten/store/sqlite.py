"""
SQLite implementation of AuditRepository.

Parses `sqlite:///path?table=X&wal=true` DSN, creates the table on first use,
and uses WAL mode by default.
"""
from __future__ import annotations

import contextlib
import json
import re
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..attrs import AuditRow

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _utc_iso(dt: datetime) -> str:
    """Serialise to UTC ISO-8601, treating naive datetimes as UTC.

    SQLite stores timestamps as ISO strings with the +00:00 offset.
    A naive datetime calling `.isoformat()` would produce a string
    *without* an offset, so lexicographic ordering against existing
    rows ('2026-05-04T10:00:00' vs '2026-05-04T10:00:00+00:00')
    silently mis-orders. Always normalise to UTC-aware before
    serialising so query()/since/until are correct under all inputs.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()

_DDL = """
CREATE TABLE IF NOT EXISTS {table} (
    id               TEXT PRIMARY KEY,
    origin_id        TEXT NOT NULL,
    monotonic_seq    INTEGER NOT NULL,
    timestamp        TEXT NOT NULL,
    code             TEXT NOT NULL,
    action           TEXT NOT NULL,
    severity         TEXT NOT NULL,
    service_id       TEXT NOT NULL,
    source_node_id   TEXT NOT NULL,
    tenant_id        TEXT,
    actor            TEXT NOT NULL,
    actor_kind       TEXT NOT NULL,
    target           TEXT NOT NULL,
    category         TEXT NOT NULL,
    domain           TEXT NOT NULL,
    method           TEXT NOT NULL,
    request_id       TEXT NOT NULL,
    detail           TEXT NOT NULL,
    pii_in_detail    INTEGER NOT NULL DEFAULT 0,
    shipped_at       TEXT
);
CREATE INDEX IF NOT EXISTS idx_{table}_req  ON {table}(request_id);
CREATE INDEX IF NOT EXISTS idx_{table}_code ON {table}(code);
CREATE INDEX IF NOT EXISTS idx_{table}_ts   ON {table}(timestamp);
CREATE INDEX IF NOT EXISTS idx_{table}_unshipped ON {table}(shipped_at) WHERE shipped_at IS NULL;
"""

# Index on pii_in_detail is created after the migration step (legacy tables
# don't have the column when the DDL above runs).
_PII_INDEX = (
    "CREATE INDEX IF NOT EXISTS idx_{table}_pii "
    "ON {table}(pii_in_detail) WHERE pii_in_detail = 1"
)


class SQLiteStore:
    """Thread-safe SQLite-backed AuditRepository.

    For file-backed stores: one connection PER THREAD via
    threading.local. The earlier "single connection shared via
    check_same_thread=False" pattern only silenced sqlite3's safety
    assertion — it did not make concurrent drainer + reader access
    actually safe, and operations on the same connection from multiple
    threads can interleave statements and corrupt the cursor protocol.
    WAL mode (the default) is designed around per-thread connections:
    many readers + one writer can progress in parallel without blocking
    each other.

    For ``:memory:``: every sqlite3 ``:memory:`` connection is a
    SEPARATE private database, so per-thread connections would each
    see an empty schema. We fall back to a single connection guarded
    by an RLock — the pattern is correct for tests / dev, but file
    storage is the right choice for any production load.
    """

    def __init__(self, path: str, table: str = "audit_log", wal: bool = True) -> None:
        if not _SAFE_IDENTIFIER.match(table):
            raise ValueError(
                f"fasten SQLiteStore: table name {table!r} is not a valid SQL identifier. "
                "Use only letters, digits, and underscores."
            )
        self._path = path
        self._table = table
        self._wal = wal
        # `:memory:` databases cannot be shared across connections, so
        # the per-thread model breaks. Detect once at init and route
        # subsequent calls accordingly.
        self._is_memory = path == ":memory:"
        self._tls = threading.local()
        self._mem_conn: sqlite3.Connection | None = None
        self._mem_lock = threading.RLock()
        # Run the DDL once on the constructor's thread so the table /
        # indexes / pii migration exist before any other thread opens
        # its own connection. Subsequent threads see the table already
        # present and skip straight to insert/query.
        bootstrap = self._connect()
        if wal and not self._is_memory:
            # WAL is meaningless for `:memory:` (no journal file).
            bootstrap.execute("PRAGMA journal_mode=WAL")
        for stmt in _DDL.format(table=table).split(";"):
            if stmt.strip():
                bootstrap.execute(stmt)
        # Idempotent migration for existing tables that pre-date pii_in_detail.
        cur = bootstrap.execute(f"PRAGMA table_info({table})")
        cols = {r[1] for r in cur.fetchall()}
        if "pii_in_detail" not in cols:
            bootstrap.execute(
                f"ALTER TABLE {table} "
                "ADD COLUMN pii_in_detail INTEGER NOT NULL DEFAULT 0"
            )
        # Index runs after migration so it exists on both fresh + legacy tables.
        bootstrap.execute(_PII_INDEX.format(table=table))
        bootstrap.commit()

    def _connect(self) -> sqlite3.Connection:
        """Return this thread's sqlite3 connection, opening it on first call.

        For `:memory:` returns the single shared connection (sqlite3
        cannot share an in-memory database across multiple connections).
        Callers MUST hold ``self._mem_lock`` for the duration of any
        compound operation against the in-memory store.
        """
        if self._is_memory:
            if self._mem_conn is None:
                self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            return self._mem_conn
        conn = getattr(self._tls, "conn", None)
        if conn is None:
            # check_same_thread=True (default) is correct now — every
            # thread gets its own connection, so the cross-thread guard
            # never trips and we get the safety assertion for free.
            conn = sqlite3.connect(self._path)
            if self._wal:
                # Each connection sets its own journal_mode pragma.
                conn.execute("PRAGMA journal_mode=WAL")
            self._tls.conn = conn
        return conn

    def _txn(self) -> contextlib.AbstractContextManager[Any]:
        """Lock context for a compound operation.

        File-backed: per-thread connection means no inter-thread
        contention; nullcontext() is correct.
        In-memory: every thread shares the single connection, so we
        serialise with the RLock to avoid sqlite3-on-shared-conn
        statement interleaving.
        """
        return self._mem_lock if self._is_memory else contextlib.nullcontext()

    @classmethod
    def from_dsn(cls, dsn: str) -> "SQLiteStore":
        u = urlparse(dsn)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        path = u.path.lstrip("/")
        if not path:
            raise ValueError(
                f"fasten SQLiteStore: DSN {dsn!r} has no path. "
                "Audit storage must be durable — use sqlite:///./audit.db or similar."
            )
        return cls(
            path=path,
            table=q.get("table", "audit_log"),
            wal=q.get("wal", "true") != "false",
        )

    def insert(self, row: AuditRow) -> None:
        with self._txn():
            conn = self._connect()
            conn.execute(
                f"INSERT OR IGNORE INTO {self._table} VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    row.id, row.origin_id, row.monotonic_seq,
                    _utc_iso(row.timestamp),
                    row.code, row.action, row.severity,
                    row.service_id, row.source_node_id, row.tenant_id,
                    row.actor, row.actor_kind,
                    row.target, row.category, row.domain,
                    row.method, row.request_id,
                    json.dumps(row.detail),
                    int(row.pii_in_detail),
                    _utc_iso(row.shipped_at) if row.shipped_at else None,
                ),
            )
            conn.commit()

    def list_unshipped(self, limit: int = 100) -> list[AuditRow]:
        with self._txn():
            cur = self._connect().execute(
                f"SELECT * FROM {self._table} WHERE shipped_at IS NULL "
                "ORDER BY monotonic_seq ASC LIMIT ?",
                (limit,),
            )
            return [self._row(r) for r in cur.fetchall()]

    def mark_shipped(self, ids: list[str]) -> None:
        with self._txn():
            conn = self._connect()
            now = _utc_iso(datetime.now(timezone.utc))
            conn.executemany(
                f"UPDATE {self._table} SET shipped_at=? WHERE id=?",
                [(now, i) for i in ids],
            )
            conn.commit()

    def purge(self, *, before: datetime, respect_unshipped: bool = True) -> int:
        with self._txn():
            conn = self._connect()
            sql = f"DELETE FROM {self._table} WHERE timestamp < ?"
            params: tuple = (_utc_iso(before),)
            if respect_unshipped:
                sql += " AND shipped_at IS NOT NULL"
            cur = conn.execute(sql, params)
            conn.commit()
            return cur.rowcount

    def _build_where(
        self,
        *,
        request_id: str | None = None,
        code: str | None = None,
        domain: str | None = None,
        source_node_id: str | None = None,
        actor: str | None = None,
        target: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> tuple[str, list[object]]:
        conds: list[str] = []
        params: list[object] = []
        if request_id:
            conds.append("request_id = ?")
            params.append(request_id)
        if code:
            conds.append("code = ?")
            params.append(code)
        if domain:
            conds.append("domain = ?")
            params.append(domain)
        if source_node_id:
            conds.append("source_node_id = ?")
            params.append(source_node_id)
        if actor:
            conds.append("actor = ?")
            params.append(actor)
        if target:
            conds.append("target = ?")
            params.append(target)
        if since:
            conds.append("timestamp >= ?")
            params.append(_utc_iso(since))
        if until:
            conds.append("timestamp <= ?")
            params.append(_utc_iso(until))
        where = f"WHERE {' AND '.join(conds)}" if conds else ""
        return where, params

    def query(
        self,
        *,
        request_id: str | None = None,
        code: str | None = None,
        domain: str | None = None,
        source_node_id: str | None = None,
        actor: str | None = None,
        target: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditRow]:
        where, params = self._build_where(
            request_id=request_id, code=code, domain=domain,
            source_node_id=source_node_id, actor=actor, target=target,
            since=since, until=until,
        )
        with self._txn():
            cur = self._connect().execute(
                f"SELECT * FROM {self._table} {where} "
                "ORDER BY monotonic_seq DESC LIMIT ? OFFSET ?",
                (*params, limit, offset),
            )
            return [self._row(r) for r in cur.fetchall()]

    def count(
        self,
        *,
        request_id: str | None = None,
        code: str | None = None,
        domain: str | None = None,
        source_node_id: str | None = None,
        actor: str | None = None,
        target: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> int:
        where, params = self._build_where(
            request_id=request_id, code=code, domain=domain,
            source_node_id=source_node_id, actor=actor, target=target,
            since=since, until=until,
        )
        with self._txn():
            cur = self._connect().execute(
                f"SELECT COUNT(*) FROM {self._table} {where}",
                params,
            )
            return int(cur.fetchone()[0])

    def _row(self, r: tuple) -> AuditRow:
        return AuditRow(
            id=r[0], origin_id=r[1], monotonic_seq=r[2],
            timestamp=datetime.fromisoformat(r[3]),
            code=r[4], action=r[5], severity=r[6],
            service_id=r[7], source_node_id=r[8], tenant_id=r[9],
            actor=r[10], actor_kind=r[11],
            target=r[12], category=r[13], domain=r[14],
            method=r[15], request_id=r[16],
            detail=json.loads(r[17]),
            pii_in_detail=bool(r[18]),
            shipped_at=datetime.fromisoformat(r[19]) if r[19] else None,
        )
