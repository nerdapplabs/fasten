"""SQLite AuditRepository. DSN: ``sqlite:///path?table=X&wal=true``. The table
is created on first use; WAL is on by default."""
from __future__ import annotations

import contextlib
import dataclasses
import json
import logging
import re
import sqlite3
import threading
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Sequence
from urllib.parse import parse_qs, urlparse

from ..attrs import AuditRow

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from .repo import IngestResult

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _utc_iso(dt: datetime) -> str:
    """Canonical timestamp string (naive datetimes are UTC), so stored
    timestamps compare correctly as strings."""
    from ..canonical_ts import canonical_ts
    return canonical_ts(dt)

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
    -- Form "2" columns (spec 1.4). NULL on form "1" rows, and detail_salt is
    -- cleared on redaction.
    detail_salt       TEXT,
    detail_commitment TEXT,
    prev_hash        TEXT NOT NULL DEFAULT 'genesis',
    hash             TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_{table}_req  ON {table}(request_id);
CREATE INDEX IF NOT EXISTS idx_{table}_code ON {table}(code);
CREATE INDEX IF NOT EXISTS idx_{table}_ts   ON {table}(timestamp);
CREATE INDEX IF NOT EXISTS idx_{table}_unshipped ON {table}(shipped_at) WHERE shipped_at IS NULL;
"""


class SQLiteStore:
    """Thread-safe SQLite AuditRepository.

    A file database gets one connection per thread, since statements from
    several threads on one connection can interleave. ``:memory:`` gets a
    single connection behind an RLock, because each in-memory connection is
    its own database. Use a file for anything but tests.
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
        # Failed inserts the caller dropped (see note_write_failure). Any
        # makes the reader report "store-degraded"; it never resets.
        self._write_failures = 0
        self._is_memory = path == ":memory:"
        self._tls = threading.local()
        self._mem_conn: sqlite3.Connection | None = None
        self._mem_lock = threading.RLock()
        # Create the table and run migrations before other threads connect.
        bootstrap = self._connect()
        if wal and not self._is_memory:
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
        # Migration: canonical_form_id; existing rows are form "1".
        try:
            bootstrap.execute(f"SELECT canonical_form_id FROM {table} LIMIT 0")
        except sqlite3.OperationalError:
            bootstrap.execute(
                f"ALTER TABLE {table} ADD COLUMN canonical_form_id TEXT NOT NULL DEFAULT '1'"
            )

        # Migration: form "2" columns. Nullable, so existing rows are unchanged.
        for _col in ("detail_salt", "detail_commitment"):
            try:
                bootstrap.execute(f"SELECT {_col} FROM {table} LIMIT 0")
            except Exception:
                bootstrap.execute(f"ALTER TABLE {table} ADD COLUMN {_col} TEXT")
            bootstrap.commit()

    def _connect(self) -> sqlite3.Connection:
        """This thread's connection, or the shared one for ``:memory:``.
        Compound operations on ``:memory:`` must hold ``self._mem_lock``
        (use ``_txn()``)."""
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
        """The RLock for ``:memory:`` (one shared connection), else a no-op."""
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
        """INSERT OR IGNORE one row on ``conn`` without committing; the caller
        owns the transaction. The public insert methods do the checks."""
        conn.execute(
            f"INSERT OR IGNORE INTO {self._table} "
            "(id,origin_id,monotonic_seq,timestamp,code,action,severity,"
            "service_id,source_node_id,tenant_id,actor,actor_kind,"
            "target,category,domain,method,request_id,detail,shipped_at,"
            "canonical_form_id,prev_hash,hash,detail_salt,detail_commitment) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                row.detail_salt,
                row.detail_commitment,
            ),
        )

    def _insert_row(self, row: AuditRow) -> None:
        """Idempotent INSERT OR IGNORE of a single row, committed immediately."""
        with self._txn():
            conn = self._connect()
            self._insert_row_core(conn, row)
            conn.commit()

    def insert_originated(self, row: AuditRow) -> None:
        """Insert a row this node originated (origin_id == id)."""
        if row.origin_id != row.id:
            raise ValueError(
                "insert_originated requires origin_id == id "
                f"(got origin_id={row.origin_id!r}, id={row.id!r}); "
                "use insert_replicated for rows from another origin"
            )
        self._insert_row(row)

    def allocate_and_insert_originated(self, row: AuditRow) -> AuditRow:
        """Allocate monotonic_seq and prev_hash, seal, and insert in one
        transaction (spec 2.1). Returns the sealed row.

        The seq is unique per source_node_id across every engine and process
        writing to the store. ``BEGIN IMMEDIATE`` takes the write lock before
        reading MAX(seq), so two writers cannot read the same value.
        """
        from ..chain import seal

        if row.origin_id != row.id:
            raise ValueError(
                "allocate_and_insert_originated requires origin_id == id "
                f"(got origin_id={row.origin_id!r}, id={row.id!r})"
            )
        with self._txn():
            conn = self._connect()
            conn.execute("BEGIN IMMEDIATE")
            try:
                # Two queries: the seq counts every row on the node, sealed or
                # not, while prev_hash may only come from a sealed row.
                cur = conn.execute(
                    f"SELECT COALESCE(MAX(monotonic_seq), 0) FROM {self._table} "
                    "WHERE source_node_id = ?",
                    (row.source_node_id,),
                )
                next_seq = int(cur.fetchone()[0]) + 1
                cur = conn.execute(
                    f"SELECT hash FROM {self._table} "
                    "WHERE source_node_id = ? AND hash != '' "
                    "ORDER BY monotonic_seq DESC LIMIT 1",
                    (row.source_node_id,),
                )
                tip = cur.fetchone()
                prev_hash = tip[0] if tip else "genesis"
                sealed = seal(prev_hash, dataclasses.replace(
                    row, monotonic_seq=next_seq))
                self._insert_row_core(conn, sealed)
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
        return sealed

    def insert_replicated(self, row: AuditRow) -> None:
        """Insert a sealed row replicated from another origin."""
        if not row.hash:
            raise ValueError(
                "insert_replicated requires a sealed row (non-empty hash); "
                f"row {row.id!r} has no hash"
            )
        self._insert_row(row)

    def insert(self, row: AuditRow) -> None:
        """Same as insert_originated(). Used by the drainer."""
        self.insert_originated(row)

    def note_write_failure(self) -> None:
        """Record an insert failure the caller dropped instead of raising."""
        self._write_failures += 1

    @property
    def write_failures(self) -> int:
        return self._write_failures

    @property
    def degraded(self) -> bool:
        """True once any write failure has been recorded."""
        return self._write_failures > 0

    def list_unshipped(
        self,
        limit: int = 100,
        service_id: str | None = None,
        source_node_id: str | None = None,
    ) -> list[AuditRow]:
        """Unshipped rows, oldest first.

        With both ``service_id`` and ``source_node_id``, only rows originated
        by that identity are returned, so replicated rows are not shipped
        again. Without them, all unshipped rows are returned.
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
        """Verify a replicated batch and insert its verified prefix in one
        transaction. A chain break does not raise; it is reported in
        ``rejected_from_seq``. Rows are inserted with INSERT OR IGNORE, so
        retries are safe.
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

    def list_redaction_candidates(
        self, *, before: datetime, codes: "Sequence[str]",
    ) -> "list[tuple[str, int]]":
        """``(id, monotonic_seq)`` of the rows redact_rows() should destroy.

        Separate from redact_rows() so the caller can record each redaction
        first (spec 7.2). The seq is returned for the ``redacted_seq`` field.

        Skips form-"1" rows: their ``detail`` IS hashed, so redacting one would
        change its hash and cascade a re-seal down the rest of the chain. They
        are counted and logged at WARNING rather than skipped quietly — on a
        store written before the form-"2" upgrade, silence here would let an
        operator watch redaction "succeed" while the personal data it was
        supposed to destroy survives untouched.
        """
        if not codes:
            return []
        placeholders = ",".join("?" for _ in codes)
        conn = self._connect()
        skipped = conn.execute(
            f"SELECT COUNT(*) FROM {self._table} "
            f"WHERE timestamp < ? AND code IN ({placeholders}) "
            "AND canonical_form_id <> '2' AND detail <> 'null'",
            (_utc_iso(before), *codes),
        ).fetchone()[0]
        if skipped:
            logger.warning(
                "fasten redact_expired: %d row(s) past the PII horizon were "
                "NOT redacted because canonical_form_id != '2' — their "
                "detail is inside the hash, so redacting would break the "
                "chain. Personal data in these rows still exists. "
                "Re-seal under form '2' or erase the chain segment.",
                skipped,
            )
        rows = conn.execute(
            f"SELECT id, monotonic_seq FROM {self._table} "
            f"WHERE timestamp < ? AND code IN ({placeholders}) "
            "AND canonical_form_id = '2' AND detail <> 'null' "
            "ORDER BY monotonic_seq",
            (_utc_iso(before), *codes),
        ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def redact_rows(self, *, ids: "Sequence[str]") -> "list[str]":
        """Destroy ``detail`` and ``detail_salt`` on the given form "2" rows.
        Ids that are not form "2" are left alone but still returned. Returns
        ``ids`` as given, so a retry returns the same list."""
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        with self._txn():
            conn = self._connect()
            conn.execute(
                # The JSON literal 'null', since detail is NOT NULL and
                # changing that needs a table rebuild. It reads back as None.
                f"UPDATE {self._table} SET detail = 'null', detail_salt = NULL "
                f"WHERE id IN ({placeholders}) AND canonical_form_id = '2'",
                tuple(ids),
            )
            conn.commit()
            return list(ids)

    def redact_expired(self, *, before: datetime,
                       codes: "Sequence[str]") -> "list[str]":
        """Destroy ``detail`` on rows of ``codes`` older than ``before`` (spec 7.1).

        Rows are not deleted: that would break the chain. Form "2" hashes
        ``detail_commitment`` rather than ``detail``, so the chain still
        verifies afterwards.

        Writes no AUDIT_ROW_REDACTED records; ``Engine.redact_expired`` does
        (spec 7.2).
        """
        candidates = self.list_redaction_candidates(before=before, codes=codes)
        return self.redact_rows(ids=[cid for cid, _ in candidates])

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
        # `is not None`, not truthiness: an empty tenant_id must filter to
        # nothing, never silently widen the query to every tenant. Matches the
        # convention already used elsewhere in this file.
        if tenant_id is not None:
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
        # Cursor paging: rows are newest first, so the next page is
        # monotonic_seq < after_seq. Not in _build_where so count() ignores
        # the cursor. Same as the Go store.
        #
        # Known limitation: the seq is per node but rows are ordered by
        # timestamp, so paging through rows from several nodes can skip or
        # repeat rows. Fixing it needs a (timestamp, seq) cursor, which would
        # change the wire format.
        if after_seq > 0:
            where = f"{where} AND monotonic_seq < ?" if where else "WHERE monotonic_seq < ?"
            params = [*params, after_seq]
        with self._txn():
            cur = self._connect().execute(
                # Timestamp first: monotonic_seq is per node, so it only
                # breaks ties (#68).
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

    def search(
        self,
        *,
        q: str,
        since: str,
        until: str | None = None,
        limit: int = 50,
        tenant_id: str | None = None,
    ) -> list[AuditRow]:
        """Case-insensitive substring search of the ``detail`` JSON, newest
        first, at most ``limit`` rows. ``since`` bounds the scan. ``%``, ``_``
        and ``\\`` in ``q`` match literally.

        ``tenant_id`` scopes the search to one tenant when supplied — the
        reader wires the caller's authenticated tenant into this arg so a
        multi-tenant shared store doesn't leak substring matches across
        tenant boundaries."""
        esc = q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        conds = ["COALESCE(timestamp, '') >= ?", "lower(detail) LIKE ? ESCAPE '\\'"]
        params: list[Any] = [since, f"%{esc}%"]
        if until:
            conds.append("COALESCE(timestamp, '') <= ?")
            params.append(until)
        if tenant_id is not None:
            conds.append("tenant_id = ?")
            params.append(tenant_id)
        params.append(limit)
        sql = (
            f"SELECT * FROM {self._table} WHERE {' AND '.join(conds)} "
            "ORDER BY timestamp DESC, monotonic_seq DESC LIMIT ?"
        )
        with self._txn():
            cur = self._connect().execute(sql, params)
            return [self._row(r) for r in cur.fetchall()]

    def sources(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Row count and first/last seen time per ``(source_node_id,
        service_id, tenant_id)``, busiest first."""
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
        """MAX(monotonic_seq), or 0 with no rows. Scoped to the given
        ``service_id`` and ``source_node_id`` when both are passed, otherwise
        over the whole table. The engine does not use this; the store
        allocates seq on insert."""
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
        from ..canonical_ts import parse_canonical
        keys = r.keys()
        return AuditRow(
            id=r["id"], origin_id=r["origin_id"], monotonic_seq=r["monotonic_seq"],
            # Strict: every row was written by _utc_iso().
            timestamp=parse_canonical(r["timestamp"]),
            code=r["code"], action=r["action"], severity=r["severity"],
            service_id=r["service_id"], source_node_id=r["source_node_id"],
            tenant_id=r["tenant_id"],
            actor=r["actor"], actor_kind=r["actor_kind"],
            target=r["target"], category=r["category"], domain=r["domain"],
            method=r["method"], request_id=r["request_id"],
            detail=json.loads(r["detail"]),
            shipped_at=parse_canonical(r["shipped_at"]) if r["shipped_at"] else None,
            canonical_form_id=r["canonical_form_id"] if "canonical_form_id" in keys else "1",
            detail_salt=r["detail_salt"] if "detail_salt" in keys else None,
            detail_commitment=(
                r["detail_commitment"] if "detail_commitment" in keys else None),
            prev_hash=r["prev_hash"] if "prev_hash" in keys else "genesis",
            hash=r["hash"] if "hash" in keys else "",
        )
