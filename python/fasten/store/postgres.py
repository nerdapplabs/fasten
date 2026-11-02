"""PostgreSQL AuditRepository (psycopg 3). Needs ``pip install "fasten[postgres]"``.

DSN: ``postgres[ql]://user:pass@host/db?table=X``. The table is created on
first use.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import re
import threading
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Sequence, cast
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..attrs import AuditRow

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from .repo import IngestResult

# Bare name ("audit_log") or schema-qualified ("fasten.audit_log").
_SAFE_IDENTIFIER = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$"
)


def _utc_iso(dt: datetime) -> str:
    """Canonical timestamp string; see canonical_ts."""
    from ..canonical_ts import canonical_ts
    return canonical_ts(dt)


_DDL = """
CREATE TABLE IF NOT EXISTS {table} (
    id               TEXT PRIMARY KEY,
    origin_id        TEXT NOT NULL,
    monotonic_seq    BIGINT NOT NULL,
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
    prev_hash        TEXT NOT NULL DEFAULT 'genesis',
    hash             TEXT NOT NULL DEFAULT '',
    canonical_form_id TEXT NOT NULL DEFAULT '1',
    -- Form "2" columns (spec 1.4). NULL on form "1" rows, and detail_salt is
    -- cleared on redaction.
    detail_salt       TEXT,
    detail_commitment TEXT
)
"""

_MIGRATION_HASH_CHAIN = """
ALTER TABLE {table} ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT 'genesis';
ALTER TABLE {table} ADD COLUMN IF NOT EXISTS hash      TEXT NOT NULL DEFAULT '';
ALTER TABLE {table} ADD COLUMN IF NOT EXISTS canonical_form_id TEXT NOT NULL DEFAULT '1';
-- Form "2" columns. Nullable, so existing rows are unchanged.
ALTER TABLE {table} ADD COLUMN IF NOT EXISTS detail_salt TEXT;
ALTER TABLE {table} ADD COLUMN IF NOT EXISTS detail_commitment TEXT;
"""

_INDEXES = [
    # {p} = bare table name used for the index identifier (no dots allowed).
    # {t} = fully-qualified table name used in ON clause (may be schema.table).
    "CREATE INDEX IF NOT EXISTS idx_{p}_req       ON {t}(request_id)",
    "CREATE INDEX IF NOT EXISTS idx_{p}_code      ON {t}(code)",
    "CREATE INDEX IF NOT EXISTS idx_{p}_ts        ON {t}(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_{p}_unshipped ON {t}(shipped_at) WHERE shipped_at IS NULL",
]


class PostgresStore:
    """Thread-safe PostgreSQL AuditRepository with one connection per thread.

    Chain allocation is serialised with an advisory lock per node; see
    allocate_and_insert_originated.
    """

    def __init__(self, dsn: str, table: str = "audit_log") -> None:
        if not _SAFE_IDENTIFIER.match(table):
            raise ValueError(
                f"fasten PostgresStore: table name {table!r} is not a valid SQL identifier. "
                "Use only letters, digits, underscores, and an optional 'schema.' prefix."
            )
        self._dsn = dsn
        self._table = table  # full ref used in SQL (may be "schema.table")
        # Failed inserts the caller dropped. Any makes the reader report
        # "store-degraded"; it never resets.
        self._write_failures = 0
        # Bare table name for index names, which cannot contain dots.
        self._idx_prefix = table.split(".")[-1]
        self._schema = table.split(".")[0] if "." in table else None
        self._tls = threading.local()
        # Create the table before other threads connect.
        conn = self._connect()
        with conn.cursor() as cur:
            # Serialise bootstrap across processes: workers starting together
            # each take AccessExclusiveLock for CREATE TABLE/INDEX and can
            # deadlock, IF NOT EXISTS notwithstanding. Session-scoped so it
            # covers the whole block; keyed on the table name.
            cur.execute("SELECT pg_advisory_lock(hashtextextended(%s, 0))",
                        (f"fasten.bootstrap.{self._table}",))
            if self._schema:
                cur.execute(f"CREATE SCHEMA IF NOT EXISTS {self._schema}")
            cur.execute(_DDL.format(table=self._table))
            for sql in _INDEXES:
                cur.execute(sql.format(t=self._table, p=self._idx_prefix))
            # Add columns missing from older tables.
            for stmt in _MIGRATION_HASH_CHAIN.format(table=self._table).strip().split(";"):
                if stmt.strip():
                    cur.execute(stmt)
            cur.execute("SELECT pg_advisory_unlock(hashtextextended(%s, 0))",
                        (f"fasten.bootstrap.{self._table}",))
        conn.commit()

    def _connect(self) -> Any:
        import psycopg

        conn = getattr(self._tls, "conn", None)
        if conn is None or conn.closed:
            conn = psycopg.connect(self._dsn)
            self._tls.conn = conn
        return conn

    def _connect_fresh(self) -> Any:
        """Force-close the current thread connection and open a new one."""
        import psycopg

        old = getattr(self._tls, "conn", None)
        if old and not old.closed:
            try:
                old.close()
            except Exception:
                pass
        conn = psycopg.connect(self._dsn)
        self._tls.conn = conn
        return conn

    def _execute_with_retry(self, fn: Callable[[Any], Any]) -> Any:
        """Run fn(conn), reconnecting and retrying once on a dropped connection.

        Afterwards any open transaction is rolled back. Writes commit
        themselves, but a plain read leaves the connection idle in
        transaction (or in error, if it raised), still holding ACCESS SHARE
        locks that would block another process's ALTER TABLE at startup.
        The rollback ignores errors from a dead connection so the original
        error reaches the retry."""
        import psycopg

        def _call(conn: Any) -> Any:
            try:
                return fn(conn)
            finally:
                if conn.info.transaction_status != psycopg.pq.TransactionStatus.IDLE:
                    try:
                        conn.rollback()
                    except (psycopg.OperationalError, psycopg.InterfaceError):
                        pass  # dead conn; don't mask the in-flight error

        try:
            return _call(self._connect())
        except (psycopg.OperationalError, psycopg.InterfaceError) as exc:
            logger.warning(
                "fasten audit store connection lost (%s); reconnecting and retrying once",
                exc,
            )
            return _call(self._connect_fresh())

    def close(self) -> None:
        """Close the calling thread's connection."""
        conn = getattr(self._tls, "conn", None)
        if conn and not conn.closed:
            conn.close()
        self._tls.conn = None

    @classmethod
    def from_dsn(cls, dsn: str) -> "PostgresStore":
        """Build a store from a ``postgres[ql]://...?table=X`` DSN. ``table`` is
        removed before connecting, since libpq rejects unknown parameters."""
        u = urlparse(dsn)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        table = q.pop("table", "audit_log")
        pg_dsn = urlunparse(u._replace(query=urlencode(q)))
        return cls(dsn=pg_dsn, table=table)

    _INSERT_SQL = (
        "INSERT INTO {table} "
        "(id,origin_id,monotonic_seq,timestamp,code,action,severity,"
        "service_id,source_node_id,tenant_id,actor,actor_kind,"
        "target,category,domain,method,request_id,detail,shipped_at,"
        "prev_hash,hash,canonical_form_id,detail_salt,detail_commitment) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
        "ON CONFLICT (id) DO NOTHING"
    )

    def _insert_params(self, row: AuditRow) -> tuple:
        """Positional params for _INSERT_SQL, in column order."""
        return (
            row.id, row.origin_id, row.monotonic_seq,
            _utc_iso(row.timestamp),
            row.code, row.action, row.severity,
            row.service_id, row.source_node_id, row.tenant_id,
            row.actor, row.actor_kind,
            row.target, row.category, row.domain,
            row.method, row.request_id,
            json.dumps(row.detail),
            _utc_iso(row.shipped_at) if row.shipped_at else None,
            row.prev_hash,
            row.hash,
            row.canonical_form_id,
            row.detail_salt,
            row.detail_commitment,
        )

    def _insert_row_core(self, cur: Any, row: AuditRow) -> None:
        """Insert one row on ``cur`` (ON CONFLICT DO NOTHING) without
        committing; the caller owns the transaction."""
        cur.execute(self._INSERT_SQL.format(table=self._table), self._insert_params(row))

    def _insert_row(self, row: AuditRow) -> None:
        """Insert and commit one row. The public insert methods do the checks."""
        def _run(conn: Any) -> None:
            with conn.cursor() as cur:
                self._insert_row_core(cur, row)
            conn.commit()

        self._execute_with_retry(_run)

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
        transaction (spec 2.1). Returns the sealed row as stored.

        Writers for a node are serialised with ``pg_advisory_xact_lock`` on
        the node id. ``SELECT ... FOR UPDATE`` on the latest row would not
        work for the first row, when there is nothing to lock.
        """
        from ..chain import seal

        if row.origin_id != row.id:
            raise ValueError(
                "allocate_and_insert_originated requires origin_id == id "
                f"(got origin_id={row.origin_id!r}, id={row.id!r})"
            )

        def _run(conn: Any) -> AuditRow:
            try:
                with conn.cursor() as cur:
                    # _execute_with_retry may rerun this after a commit whose
                    # ack was lost. If the row is already there, return it as
                    # stored rather than sealing a new seq that never lands.
                    cur.execute(
                        f"SELECT monotonic_seq, prev_hash, hash, canonical_form_id "
                        f"FROM {self._table} WHERE id = %s",
                        (row.id,),
                    )
                    existing = cur.fetchone()
                    if existing is not None:
                        conn.commit()
                        return dataclasses.replace(
                            row, monotonic_seq=int(existing[0]),
                            prev_hash=existing[1], hash=existing[2],
                            canonical_form_id=existing[3],
                        )
                    cur.execute(
                        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                        (row.source_node_id,),
                    )
                    # The seq counts every row on the node, sealed or not;
                    # prev_hash may only come from a sealed row.
                    cur.execute(
                        f"SELECT COALESCE(MAX(monotonic_seq), 0) FROM {self._table} "
                        "WHERE source_node_id = %s",
                        (row.source_node_id,),
                    )
                    next_seq = int(cur.fetchone()[0]) + 1
                    cur.execute(
                        f"SELECT hash FROM {self._table} "
                        "WHERE source_node_id = %s AND hash <> '' "
                        "ORDER BY monotonic_seq DESC LIMIT 1",
                        (row.source_node_id,),
                    )
                    tip = cur.fetchone()
                    prev_hash = tip[0] if tip else "genesis"
                    sealed = seal(prev_hash, dataclasses.replace(
                        row, monotonic_seq=next_seq))
                    self._insert_row_core(cur, sealed)
                conn.commit()
                return sealed
            except BaseException:
                conn.rollback()
                raise

        return cast(AuditRow, self._execute_with_retry(_run))

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
        """Unshipped rows, oldest first. With both ``service_id`` and
        ``source_node_id``, only rows originated by that identity."""
        scoped = service_id is not None and source_node_id is not None

        def _run(conn: Any) -> list[AuditRow]:
            with conn.cursor() as cur:
                if scoped:
                    cur.execute(
                        f"SELECT * FROM {self._table} WHERE shipped_at IS NULL "
                        "AND service_id = %s AND source_node_id = %s AND origin_id = id "
                        "ORDER BY monotonic_seq ASC LIMIT %s",
                        (service_id, source_node_id, limit),
                    )
                else:
                    cur.execute(
                        f"SELECT * FROM {self._table} WHERE shipped_at IS NULL "
                        "ORDER BY monotonic_seq ASC LIMIT %s",
                        (limit,),
                    )
                return [self._row(r) for r in cur.fetchall()]

        return self._execute_with_retry(_run)

    def mark_shipped(self, ids: list[str]) -> None:
        now = _utc_iso(datetime.now(timezone.utc))

        def _run(conn: Any) -> None:
            with conn.cursor() as cur:
                cur.executemany(
                    f"UPDATE {self._table} SET shipped_at=%s WHERE id=%s",
                    [(now, i) for i in ids],
                )
            conn.commit()

        self._execute_with_retry(_run)

    def ingest_replicated(self, rows: list[AuditRow]) -> "IngestResult":
        """Verify a replicated batch and insert its verified prefix in one
        transaction. A chain break does not raise; it is reported in
        ``rejected_from_seq``. Inserts use ON CONFLICT DO NOTHING, so retries
        are safe.
        """
        from .repo import IngestResult, verified_prefix

        prefix, rejected_from_seq, reason = verified_prefix(rows)
        for row in prefix:
            if not row.hash:
                raise ValueError(
                    "ingest_replicated requires sealed rows (non-empty hash); "
                    f"row {row.id!r} has no hash"
                )

        def _run(conn: Any) -> int:
            inserted = 0
            try:
                with conn.cursor() as cur:
                    for row in prefix:
                        self._insert_row_core(cur, row)
                        inserted += 1
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            return inserted

        inserted = self._execute_with_retry(_run)
        return IngestResult(
            inserted=inserted,
            rejected_from_seq=rejected_from_seq,
            reason=reason or None,
        )

    def redact_expired(self, *, before: datetime,
                       codes: "Sequence[str]") -> "list[str]":
        """Destroy ``detail`` on rows of ``codes`` older than ``before`` (spec 7.1).

        Same as SQLiteStore.redact_expired: rows are kept and ``detail`` is set
        to the JSON literal ``'null'`` (the column is NOT NULL). Writes no
        AUDIT_ROW_REDACTED records; ``Engine.redact_expired`` does.
        """
        candidates = self.list_redaction_candidates(before=before, codes=codes)
        return self.redact_rows(ids=[cid for cid, _ in candidates])

    def list_redaction_candidates(
        self, *, before: datetime, codes: "Sequence[str]",
    ) -> "list[tuple[str, int]]":
        """``(id, monotonic_seq)`` of the rows redact_rows() should destroy.
        See SQLiteStore.list_redaction_candidates."""
        if not codes:
            return []

        def _run(conn: Any) -> "list[tuple[str, int]]":
            with conn.cursor() as cur:
                # Count what we are about to NOT redact. Silence here would let
                # an operator on a pre-form-"2" store watch redaction "succeed"
                # while the personal data survives. See the SQLite store.
                cur.execute(
                    f"SELECT COUNT(*) FROM {self._table} "
                    "WHERE timestamp < %s AND code = ANY(%s) "
                    "AND canonical_form_id <> '2' AND detail <> 'null'",
                    (_utc_iso(before), list(codes)),
                )
                skipped = cur.fetchone()[0]
                if skipped:
                    logger.warning(
                        "fasten redact_expired: %d row(s) past the PII horizon "
                        "were NOT redacted because canonical_form_id != '2' — "
                        "their detail is inside the hash, so redacting would "
                        "break the chain. Personal data in these rows still "
                        "exists. Re-seal under form '2' or erase the chain "
                        "segment.",
                        skipped,
                    )
                cur.execute(
                    f"SELECT id, monotonic_seq FROM {self._table} "
                    "WHERE timestamp < %s AND code = ANY(%s) "
                    "AND canonical_form_id = '2' AND detail <> 'null' "
                    "ORDER BY monotonic_seq",
                    (_utc_iso(before), list(codes)),
                )
                return [(r[0], r[1]) for r in cur.fetchall()]

        return cast("list[tuple[str, int]]", self._execute_with_retry(_run))

    def redact_rows(self, *, ids: "Sequence[str]") -> "list[str]":
        """Destroy ``detail`` and ``detail_salt`` on the given form "2" rows.
        Ids that are not form "2" are left alone but still returned. Returns
        ``ids`` as given, so a retry after a lost commit returns the same
        list."""
        if not ids:
            return []

        def _run(conn: Any) -> "list[str]":
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE {self._table} "
                    "SET detail = 'null', detail_salt = NULL "
                    "WHERE id = ANY(%s) AND canonical_form_id = '2'",
                    (list(ids),),
                )
            conn.commit()
            return list(ids)

        return cast("list[str]", self._execute_with_retry(_run))

    def purge(self, *, before: datetime, respect_unshipped: bool = True) -> int:
        sql = f"DELETE FROM {self._table} WHERE timestamp < %s"
        params: list[Any] = [_utc_iso(before)]
        if respect_unshipped:
            sql += " AND shipped_at IS NOT NULL"

        def _run(conn: Any) -> int:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                deleted = cur.rowcount
            conn.commit()
            return deleted

        return self._execute_with_retry(_run)

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
    ) -> tuple[str, list[Any]]:
        conds: list[str] = []
        params: list[Any] = []
        if request_id:
            conds.append("request_id = %s")
            params.append(request_id)
        if code:
            conds.append("code = %s")
            params.append(code)
        if domain:
            conds.append("domain = %s")
            params.append(domain)
        if source_node_id:
            conds.append("source_node_id = %s")
            params.append(source_node_id)
        if tenant_id is not None:
            conds.append("tenant_id = %s")
            params.append(tenant_id)
        if actor:
            conds.append("actor = %s")
            params.append(actor)
        if target:
            conds.append("target = %s")
            params.append(target)
        if since:
            conds.append("timestamp >= %s")
            params.append(_utc_iso(since))
        if until:
            conds.append("timestamp <= %s")
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
        # Cursor paging; see SQLiteStore.query.
        if after_seq > 0:
            where = f"{where} AND monotonic_seq < %s" if where else "WHERE monotonic_seq < %s"
            params = [*params, after_seq]

        def _run(conn: Any) -> list[AuditRow]:
            with conn.cursor() as cur:
                cur.execute(
                    # Timestamp first: monotonic_seq is per node, so it only
                    # breaks ties (#68).
                    f"SELECT * FROM {self._table} {where} "
                    "ORDER BY timestamp DESC, monotonic_seq DESC LIMIT %s OFFSET %s",
                    (*params, limit, offset),
                )
                return [self._row(r) for r in cur.fetchall()]

        return self._execute_with_retry(_run)

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

        def _run(conn: Any) -> int:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) FROM {self._table} {where}", params)
                return int(cur.fetchone()[0])

        return self._execute_with_retry(_run)

    def search(
        self,
        *,
        q: str,
        since: str,
        until: str | None = None,
        limit: int = 50,
        tenant_id: str | None = None,
    ) -> list[AuditRow]:
        """Case-insensitive substring search of the ``detail`` JSON (ILIKE),
        newest first, at most ``limit`` rows. ``%``, ``_`` and ``\\`` in
        ``q`` match literally.

        ``tenant_id`` scopes the search to one tenant when supplied — see
        SQLiteStore.search for the reasoning."""
        esc = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        conds = ["timestamp >= %s", "detail::text ILIKE %s ESCAPE E'\\\\'"]
        params: list[Any] = [since, f"%{esc}%"]
        if until:
            conds.append("timestamp <= %s")
            params.append(until)
        if tenant_id is not None:
            conds.append("tenant_id = %s")
            params.append(tenant_id)
        params.append(limit)
        sql = (
            f"SELECT * FROM {self._table} WHERE {' AND '.join(conds)} "
            "ORDER BY timestamp DESC, monotonic_seq DESC LIMIT %s"
        )

        def _run(conn: Any) -> list[AuditRow]:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return [self._row(r) for r in cur.fetchall()]

        return self._execute_with_retry(_run)

    def sources(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Row count and first/last seen time per ``(source_node_id,
        service_id, tenant_id)``, busiest first."""
        where, params = self._build_where(since=since, until=until)

        def _run(conn: Any) -> list[dict[str, Any]]:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT source_node_id, service_id, tenant_id, "
                    "COUNT(*) AS n, MIN(timestamp) AS first_seen, "
                    "MAX(timestamp) AS last_seen "
                    f"FROM {self._table} {where} "
                    "GROUP BY source_node_id, service_id, tenant_id "
                    "ORDER BY n DESC",
                    params,
                )
                out: list[dict[str, Any]] = []
                for r in cur.fetchall():
                    first_seen, last_seen = r[4], r[5]
                    out.append({
                        "source_node_id": r[0],
                        "service_id": r[1],
                        "tenant_id": r[2],
                        "rows": int(r[3]),
                        "first_seen": first_seen.isoformat() if hasattr(first_seen, "isoformat") else first_seen,
                        "last_seen": last_seen.isoformat() if hasattr(last_seen, "isoformat") else last_seen,
                    })
                return out

        return self._execute_with_retry(_run)

    def max_monotonic_seq(
        self,
        service_id: str | None = None,
        source_node_id: str | None = None,
    ) -> int:
        """MAX(monotonic_seq), or 0 with no rows. See
        SQLiteStore.max_monotonic_seq."""
        scoped = service_id is not None and source_node_id is not None

        def _run(conn: Any) -> int:
            with conn.cursor() as cur:
                if scoped:
                    cur.execute(
                        f"SELECT COALESCE(MAX(monotonic_seq), 0) FROM {self._table} "
                        "WHERE service_id = %s AND source_node_id = %s",
                        (service_id, source_node_id),
                    )
                else:
                    cur.execute(f"SELECT COALESCE(MAX(monotonic_seq), 0) FROM {self._table}")
                return int(cur.fetchone()[0])

        return self._execute_with_retry(_run)

    def _row(self, r: tuple) -> AuditRow:
        from ..canonical_ts import parse_canonical
        return AuditRow(
            id=r[0], origin_id=r[1], monotonic_seq=r[2],
            # Strict: every row was written by _utc_iso().
            timestamp=parse_canonical(r[3]),
            code=r[4], action=r[5], severity=r[6],
            service_id=r[7], source_node_id=r[8], tenant_id=r[9],
            actor=r[10], actor_kind=r[11],
            target=r[12], category=r[13], domain=r[14],
            method=r[15], request_id=r[16],
            detail=json.loads(r[17]),
            shipped_at=parse_canonical(r[18]) if r[18] else None,
            prev_hash=r[19] if len(r) > 19 else "genesis",
            hash=r[20] if len(r) > 20 else "",
            canonical_form_id=r[21] if len(r) > 21 else "1",
            # SELECT * is positional. The new DDL and the migrations both put
            # detail_salt and detail_commitment after canonical_form_id.
            detail_salt=r[22] if len(r) > 22 else None,
            detail_commitment=r[23] if len(r) > 23 else None,
        )
