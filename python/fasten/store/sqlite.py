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
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

from ..attrs import AuditRow

if TYPE_CHECKING:
    from .repo import IngestResult

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
    shipped_at       TEXT,
    canonical_form_id TEXT NOT NULL DEFAULT '1',
    prev_hash        TEXT NOT NULL DEFAULT 'genesis',
    hash             TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_{table}_req  ON {table}(request_id);
CREATE INDEX IF NOT EXISTS idx_{table}_code ON {table}(code);
CREATE INDEX IF NOT EXISTS idx_{table}_ts   ON {table}(timestamp);
CREATE INDEX IF NOT EXISTS idx_{table}_unshipped ON {table}(shipped_at) WHERE shipped_at IS NULL;
"""


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
        # Swallowed persist-failure counter (mirrors StreamStore). At least one
        # means durable audit history has a known hole, so the reader degrades
        # the audit completeness flag from "store" to "store-degraded". Sticky
        # for the store's lifetime: a hole doesn't heal when the disk recovers.
        self._write_failures = 0
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
        bootstrap.commit()
        # Migration: add hash chain columns to pre-existing tables.
        try:
            bootstrap.execute(f"SELECT prev_hash FROM {table} LIMIT 0")
        except sqlite3.OperationalError:
            bootstrap.execute(
                f"ALTER TABLE {table} ADD COLUMN prev_hash TEXT NOT NULL DEFAULT 'genesis'"
            )
            bootstrap.execute(
                f"ALTER TABLE {table} ADD COLUMN hash TEXT NOT NULL DEFAULT ''"
            )
            bootstrap.commit()
        # Migration: add the canonical_form_id column (item 6) to pre-existing
        # tables. Additive — existing rows default to form "1".
        try:
            bootstrap.execute(f"SELECT canonical_form_id FROM {table} LIMIT 0")
        except sqlite3.OperationalError:
            bootstrap.execute(
                f"ALTER TABLE {table} ADD COLUMN canonical_form_id TEXT NOT NULL DEFAULT '1'"
            )
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
                self._mem_conn.row_factory = sqlite3.Row
            return self._mem_conn
        conn = getattr(self._tls, "conn", None)
        if conn is None:
            # check_same_thread=True (default) is correct now — every
            # thread gets its own connection, so the cross-thread guard
            # never trips and we get the safety assertion for free.
            conn = sqlite3.connect(self._path)
            conn.row_factory = sqlite3.Row
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

    def _insert_row_core(self, conn: Any, row: AuditRow) -> None:
        """Execute the idempotent INSERT OR IGNORE on ``conn`` WITHOUT committing.

        The transaction boundary is owned by the caller: ``_insert_row`` commits
        per row, while the batch path in ``ingest_replicated`` executes many of
        these and commits once. Shared by the originated and replicated entry
        points — the intent split is enforced by the wrappers, not here."""
        conn.execute(
            f"INSERT OR IGNORE INTO {self._table} "
            "(id,origin_id,monotonic_seq,timestamp,code,action,severity,"
            "service_id,source_node_id,tenant_id,actor,actor_kind,"
            "target,category,domain,method,request_id,detail,shipped_at,"
            "canonical_form_id,prev_hash,hash) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                row.id, row.origin_id, row.monotonic_seq,
                _utc_iso(row.timestamp),
                row.code, row.action, row.severity,
                row.service_id, row.source_node_id, row.tenant_id,
                row.actor, row.actor_kind,
                row.target, row.category, row.domain,
                row.method, row.request_id,
                json.dumps(row.detail),
                _utc_iso(row.shipped_at) if row.shipped_at else None,
                row.canonical_form_id,
                row.prev_hash,
                row.hash,
            ),
        )

    def _insert_row(self, row: AuditRow) -> None:
        """Idempotent INSERT OR IGNORE of a single row, committed immediately."""
        with self._txn():
            conn = self._connect()
            self._insert_row_core(conn, row)
            conn.commit()

    def insert_originated(self, row: AuditRow) -> None:
        """Insert a row this node ORIGINATED (origin_id == id). Used by the
        engine's own emit path."""
        if row.origin_id != row.id:
            raise ValueError(
                "insert_originated requires origin_id == id "
                f"(got origin_id={row.origin_id!r}, id={row.id!r}); "
                "use insert_replicated for rows from another origin"
            )
        self._insert_row(row)

    def insert_replicated(self, row: AuditRow) -> None:
        """Insert a row replicated from another origin. Used by
        ingest_replicated after the chain verifies; the row must be sealed."""
        if not row.hash:
            raise ValueError(
                "insert_replicated requires a sealed row (non-empty hash); "
                f"row {row.id!r} has no hash"
            )
        self._insert_row(row)

    def insert(self, row: AuditRow) -> None:
        """Thin alias for insert_originated — the engine emit/drainer path. Kept
        so the AuditRepository protocol and the drainer callback stay stable."""
        self.insert_originated(row)

    def note_write_failure(self) -> None:
        """Record a persist failure the caller swallowed on the hot path, so
        durable history has a known hole. Callers that surface (raise) the
        insert() error themselves don't mark the store degraded."""
        self._write_failures += 1

    @property
    def write_failures(self) -> int:
        return self._write_failures

    @property
    def degraded(self) -> bool:
        """True once at least one persist failure was swallowed (durable
        history has holes). Drives the ``store-degraded`` completeness flag."""
        return self._write_failures > 0

    def list_unshipped(
        self,
        limit: int = 100,
        service_id: str | None = None,
        source_node_id: str | None = None,
    ) -> list[AuditRow]:
        """Unshipped rows oldest-first.

        When ``service_id`` and ``source_node_id`` are both given the result is
        scoped to rows this engine ORIGINATED — ``origin_id = id`` AND the
        matching identity. Replicated rows (ingested from another origin) are
        excluded: re-shipping them upstream would duplicate another node's
        sub-chain. With neither argument the legacy unscoped behaviour is kept
        for direct adopter use.
        """
        scoped = service_id is not None and source_node_id is not None
        with self._txn():
            if scoped:
                cur = self._connect().execute(
                    f"SELECT * FROM {self._table} WHERE shipped_at IS NULL "
                    "AND service_id = ? AND source_node_id = ? AND origin_id = id "
                    "ORDER BY monotonic_seq ASC LIMIT ?",
                    (service_id, source_node_id, limit),
                )
            else:
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

    def ingest_replicated(self, rows: list[AuditRow]) -> "IngestResult":
        """Verify the chain of replicated rows, then insert the verified prefix.

        The longest verified prefix (rows before the first chain break) is
        inserted in ONE SQL transaction: every INSERT OR IGNORE runs on the same
        connection and a single ``conn.commit()`` seals them, so a crash mid-batch
        rolls the whole prefix back (real all-or-nothing, unlike per-row commits).
        Never raises on a chain break — rejected rows surface via
        ``rejected_from_seq`` so the sender resyncs from the break. Idempotent
        (INSERT OR IGNORE on the id PK): a retry after a successful commit is a
        no-op; a retry after a rolled-back failure re-inserts cleanly.
        """
        from .repo import IngestResult, verified_prefix

        prefix, rejected_from_seq, reason = verified_prefix(rows)
        for row in prefix:
            if not row.hash:
                raise ValueError(
                    "ingest_replicated requires sealed rows (non-empty hash); "
                    f"row {row.id!r} has no hash"
                )
        inserted = 0
        with self._txn():
            conn = self._connect()
            try:
                for row in prefix:
                    self._insert_row_core(conn, row)
                    inserted += 1
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return IngestResult(
            inserted=inserted,
            rejected_from_seq=rejected_from_seq,
            reason=reason or None,
        )

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
        tenant_id: str | None = None,
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
        if tenant_id:
            conds.append("tenant_id = ?")
            params.append(tenant_id)
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
        tenant_id: str | None = None,
        actor: str | None = None,
        target: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
        after_seq: int = 0,
    ) -> list[AuditRow]:
        where, params = self._build_where(
            request_id=request_id, code=code, domain=domain,
            source_node_id=source_node_id, tenant_id=tenant_id,
            actor=actor, target=target,
            since=since, until=until,
        )
        # Cursor pagination (canonical): rows are newest-first, so paging forward
        # means older rows — monotonic_seq < after_seq. Applied here, not in
        # _build_where, so count()/total stays the full filtered count
        # independent of the cursor. Mirrors the Go audit store.
        #
        # Accepted limitation on multi-origin stores (A1 in PR #59 review):
        # the query orders by (timestamp, monotonic_seq) but the cursor is
        # monotonic_seq alone, which is a per-(service_id, source_node_id)
        # counter (see the tie-breaker note below). Paging to exhaustion
        # across rows from more than one origin can skip or repeat rows
        # because a lower seq in origin B can appear at a newer timestamp
        # than a higher seq in origin A. Single-origin stores are unaffected.
        # A composite (timestamp, seq) cursor would fix this but changes the
        # wire contract; keeping the simpler cursor is the deliberate call.
        if after_seq > 0:
            where = f"{where} AND monotonic_seq < ?" if where else "WHERE monotonic_seq < ?"
            params = [*params, after_seq]
        with self._txn():
            cur = self._connect().execute(
                # Wall-clock first: monotonic_seq is a per-(service_id,
                # source_node_id) counter, meaningless across sub-chains —
                # it stays as the same-timestamp tie-breaker only (#68).
                f"SELECT * FROM {self._table} {where} "
                "ORDER BY timestamp DESC, monotonic_seq DESC LIMIT ? OFFSET ?",
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
        tenant_id: str | None = None,
        actor: str | None = None,
        target: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> int:
        where, params = self._build_where(
            request_id=request_id, code=code, domain=domain,
            source_node_id=source_node_id, tenant_id=tenant_id,
            actor=actor, target=target,
            since=since, until=until,
        )
        with self._txn():
            cur = self._connect().execute(
                f"SELECT COUNT(*) FROM {self._table} {where}",
                params,
            )
            return int(cur.fetchone()[0])

    def sources(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Fleet topology, aggregated from the rows already recorded.

        Groups by ``(source_node_id, service_id, tenant_id)`` and returns
        one entry per distinct emitting source with its row count and
        first/last-seen timestamps. There is no separate topology table —
        this is the honest "what nodes/services/tenants are represented in
        this store" view, derived from the audit rows themselves. Ordered
        by row count, busiest first.
        """
        where, params = self._build_where(since=since, until=until)
        with self._txn():
            cur = self._connect().execute(
                "SELECT source_node_id, service_id, tenant_id, "
                "COUNT(*) AS n, MIN(timestamp) AS first_seen, "
                "MAX(timestamp) AS last_seen "
                f"FROM {self._table} {where} "
                "GROUP BY source_node_id, service_id, tenant_id "
                "ORDER BY n DESC",
                params,
            )
            return [
                {
                    "source_node_id": r["source_node_id"],
                    "service_id": r["service_id"],
                    "tenant_id": r["tenant_id"],
                    "rows": int(r["n"]),
                    "first_seen": r["first_seen"],
                    "last_seen": r["last_seen"],
                }
                for r in cur.fetchall()
            ]

    def max_monotonic_seq(
        self,
        service_id: str | None = None,
        source_node_id: str | None = None,
    ) -> int:
        """Return MAX(monotonic_seq) for seeding _seq at init; 0 if no rows.

        The tamper chain is per ``(service_id, source_node_id)`` and
        ``monotonic_seq`` is a per-node counter, so seeding MUST be scoped to
        the engine's OWN identity. An unscoped MAX() across all origins would,
        after this node ingested replicated rows from another origin, seed the
        engine's seq from a foreign sub-chain and break this node's own chain
        (its next row would skip ahead of its own last seq). When both
        arguments are given the query is scoped; called with no arguments it
        falls back to the legacy global MAX (used only where identity is
        unavailable).
        """
        scoped = service_id is not None and source_node_id is not None
        with self._txn():
            if scoped:
                cur = self._connect().execute(
                    f"SELECT COALESCE(MAX(monotonic_seq), 0) FROM {self._table} "
                    "WHERE service_id = ? AND source_node_id = ?",
                    (service_id, source_node_id),
                )
            else:
                cur = self._connect().execute(
                    f"SELECT COALESCE(MAX(monotonic_seq), 0) FROM {self._table}"
                )
            return int(cur.fetchone()[0])

    def _row(self, r: sqlite3.Row) -> AuditRow:
        keys = r.keys()
        return AuditRow(
            id=r["id"], origin_id=r["origin_id"], monotonic_seq=r["monotonic_seq"],
            timestamp=datetime.fromisoformat(r["timestamp"]),
            code=r["code"], action=r["action"], severity=r["severity"],
            service_id=r["service_id"], source_node_id=r["source_node_id"],
            tenant_id=r["tenant_id"],
            actor=r["actor"], actor_kind=r["actor_kind"],
            target=r["target"], category=r["category"], domain=r["domain"],
            method=r["method"], request_id=r["request_id"],
            detail=json.loads(r["detail"]),
            shipped_at=datetime.fromisoformat(r["shipped_at"]) if r["shipped_at"] else None,
            canonical_form_id=r["canonical_form_id"] if "canonical_form_id" in keys else "1",
            prev_hash=r["prev_hash"] if "prev_hash" in keys else "genesis",
            hash=r["hash"] if "hash" in keys else "",
        )
