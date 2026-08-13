"""
PostgreSQL implementation of AuditRepository (psycopg v3).

Parses ``postgres[ql]://user:pass@host/db?table=X`` DSN, strips the
``table`` query-param before handing the DSN to psycopg (libpq rejects
unknown params), and creates the table on first use.

Install the optional dep:  pip install "fasten[postgres]"
"""
from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable
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
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()


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
    canonical_form_id TEXT NOT NULL DEFAULT '1'
)
"""

_MIGRATION_HASH_CHAIN = """
ALTER TABLE {table} ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT 'genesis';
ALTER TABLE {table} ADD COLUMN IF NOT EXISTS hash      TEXT NOT NULL DEFAULT '';
ALTER TABLE {table} ADD COLUMN IF NOT EXISTS canonical_form_id TEXT NOT NULL DEFAULT '1';
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
    """Thread-safe PostgreSQL-backed AuditRepository (psycopg v3).

    Opens one connection per thread via threading.local. Each connection
    is independent; Postgres serialises concurrent writers at the server
    level, so no additional locking is needed here.
    """

    def __init__(self, dsn: str, table: str = "audit_log") -> None:
        if not _SAFE_IDENTIFIER.match(table):
            raise ValueError(
                f"fasten PostgresStore: table name {table!r} is not a valid SQL identifier. "
                "Use only letters, digits, underscores, and an optional 'schema.' prefix."
            )
        self._dsn = dsn
        self._table = table  # full ref used in SQL (may be "schema.table")
        # Swallowed persist-failure counter (mirrors StreamStore). At least one
        # means durable audit history has a known hole → "store-degraded". Sticky.
        self._write_failures = 0
        # Bare table name for index identifiers — dots are not allowed there.
        self._idx_prefix = table.split(".")[-1]
        self._schema = table.split(".")[0] if "." in table else None
        self._tls = threading.local()
        # Bootstrap DDL once on the calling thread; every other thread that
        # subsequently opens its own connection will see the table already present.
        conn = self._connect()
        with conn.cursor() as cur:
            if self._schema:
                cur.execute(f"CREATE SCHEMA IF NOT EXISTS {self._schema}")
            cur.execute(_DDL.format(table=self._table))
            for sql in _INDEXES:
                cur.execute(sql.format(t=self._table, p=self._idx_prefix))
            # Migration: add hash chain columns to pre-existing tables (no-op on new tables).
            for stmt in _MIGRATION_HASH_CHAIN.format(table=self._table).strip().split(";"):
                if stmt.strip():
                    cur.execute(stmt)
        conn.commit()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

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
        """Run fn(conn) once; on stale-connection error reconnect and retry once.

        Whether fn returns or raises, release any transaction it left open so the
        connection is never parked holding locks. A write fn ``commit()``s itself
        (leaving the connection IDLE — untouched here). A read fn runs a bare
        ``SELECT`` and returns, leaving the connection *idle in transaction*
        (INTRANS); a read that *raises* (e.g. a bad column during a concurrent
        ``ALTER``) leaves it INERROR — both still hold any lock the statement
        took (``ACCESS SHARE``) until the transaction ends, and INERROR also
        poisons the connection for reuse. Either would let the engine's startup
        hash-chain seed reads block a concurrent store-init ``ALTER TABLE``
        (``ACCESS EXCLUSIVE``) indefinitely — the audit-store deadlock. The
        cleanup rollback is itself guarded so that, on an already-dead
        connection, it can't mask the in-flight stale-connection error the retry
        below needs to see."""
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

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_dsn(cls, dsn: str) -> "PostgresStore":
        """Parse a ``postgres[ql]://...?table=X`` DSN.

        Strips the fasten-specific ``table`` param before handing the DSN
        to psycopg — libpq raises an error on unrecognised parameters.
        """
        u = urlparse(dsn)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        table = q.pop("table", "audit_log")
        pg_dsn = urlunparse(u._replace(query=urlencode(q)))
        return cls(dsn=pg_dsn, table=table)

    # ------------------------------------------------------------------
    # AuditRepository protocol
    # ------------------------------------------------------------------

    _INSERT_SQL = (
        "INSERT INTO {table} "
        "(id,origin_id,monotonic_seq,timestamp,code,action,severity,"
        "service_id,source_node_id,tenant_id,actor,actor_kind,"
        "target,category,domain,method,request_id,detail,shipped_at,"
        "prev_hash,hash,canonical_form_id) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
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
        )

    def _insert_row_core(self, cur: Any, row: AuditRow) -> None:
        """Execute the idempotent insert on ``cur`` WITHOUT committing — the
        transaction boundary belongs to the caller (per-row in _insert_row, one
        BEGIN/COMMIT in ingest_replicated)."""
        cur.execute(self._INSERT_SQL.format(table=self._table), self._insert_params(row))

    def _insert_row(self, row: AuditRow) -> None:
        """Idempotent ON CONFLICT DO NOTHING insert of a single row, committed
        immediately. Shared by the originated and replicated entry points —
        identical SQL; the intent split is enforced by the wrappers."""
        def _run(conn: Any) -> None:
            with conn.cursor() as cur:
                self._insert_row_core(cur, row)
            conn.commit()

        self._execute_with_retry(_run)

    def insert_originated(self, row: AuditRow) -> None:
        """Insert a row this node ORIGINATED (origin_id == id). Engine emit path."""
        if row.origin_id != row.id:
            raise ValueError(
                "insert_originated requires origin_id == id "
                f"(got origin_id={row.origin_id!r}, id={row.id!r}); "
                "use insert_replicated for rows from another origin"
            )
        self._insert_row(row)

    def insert_replicated(self, row: AuditRow) -> None:
        """Insert a row replicated from another origin. ingest_replicated path;
        the row must be sealed."""
        if not row.hash:
            raise ValueError(
                "insert_replicated requires a sealed row (non-empty hash); "
                f"row {row.id!r} has no hash"
            )
        self._insert_row(row)

    def insert(self, row: AuditRow) -> None:
        """Thin alias for insert_originated — the engine emit/drainer path."""
        self.insert_originated(row)

    def note_write_failure(self) -> None:
        """Record a swallowed persist failure (durable history has a hole).
        Callers that surface the insert() error don't mark the store degraded."""
        self._write_failures += 1

    @property
    def write_failures(self) -> int:
        return self._write_failures

    @property
    def degraded(self) -> bool:
        """True once at least one persist failure was swallowed. Drives the
        ``store-degraded`` completeness flag."""
        return self._write_failures > 0

    def list_unshipped(
        self,
        limit: int = 100,
        service_id: str | None = None,
        source_node_id: str | None = None,
    ) -> list[AuditRow]:
        """Unshipped rows oldest-first.

        Scoped to rows this engine ORIGINATED (``origin_id = id`` AND matching
        identity) when both ``service_id`` and ``source_node_id`` are given, so
        replicated rows from another origin are never re-shipped upstream. See
        SQLiteStore.list_unshipped for the rationale.
        """
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
        """Verify the chain of replicated rows, then insert the verified prefix.

        The longest verified prefix (rows before the first chain break) is
        inserted in ONE transaction: all inserts run on a single connection and a
        single ``conn.commit()`` seals them, with ``conn.rollback()`` on any
        error, so a failure mid-batch commits nothing (real all-or-nothing).
        Never raises on a chain break — rejected rows surface via
        ``rejected_from_seq`` so the sender resyncs from the break. Idempotent
        (ON CONFLICT (id) DO NOTHING): a retry after a successful commit is a
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
        if tenant_id:
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
        # Cursor pagination (canonical): rows are newest-first, so paging forward
        # means older rows — monotonic_seq < after_seq. Applied here, not in
        # _build_where, so count()/total stays the full filtered count
        # independent of the cursor. Mirrors the Go audit store.
        if after_seq > 0:
            where = f"{where} AND monotonic_seq < %s" if where else "WHERE monotonic_seq < %s"
            params = [*params, after_seq]

        def _run(conn: Any) -> list[AuditRow]:
            with conn.cursor() as cur:
                cur.execute(
                    # Wall-clock first: monotonic_seq is a per-(service_id,
                    # source_node_id) counter, meaningless across sub-chains —
                    # it stays as the same-timestamp tie-breaker only (#68).
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

    def sources(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Fleet topology, aggregated from the rows already recorded.

        Groups by ``(source_node_id, service_id, tenant_id)`` and returns
        one entry per distinct emitting source with its row count and
        first/last-seen timestamps. Mirrors ``SQLiteStore.sources``; see
        that method for the rationale.
        """
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
        """Return MAX(monotonic_seq); 0 if no rows.

        Scoped to ``(service_id, source_node_id)`` when both are provided —
        the tamper chain is per-node and ``monotonic_seq`` is a per-node
        counter, so seeding the engine's seq from an unscoped global MAX would
        break this node's own chain once it has ingested replicated rows from
        another origin. See SQLiteStore.max_monotonic_seq for the full
        rationale.
        """
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

    # ------------------------------------------------------------------
    # Row deserialisation
    # ------------------------------------------------------------------

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
            shipped_at=datetime.fromisoformat(r[18]) if r[18] else None,
            prev_hash=r[19] if len(r) > 19 else "genesis",
            hash=r[20] if len(r) > 20 else "",
            canonical_form_id=r[21] if len(r) > 21 else "1",
        )
