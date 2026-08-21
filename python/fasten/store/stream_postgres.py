"""PostgreSQL-backed per-stream store for the ``api`` and ``sys`` streams (FR1),
psycopg v3.

The Postgres sibling of :class:`fasten.store.stream.StreamStore`. It carries the
same schema form ``"1"`` columns and indexes and the same query / filter /
window / completeness / search semantics, so a stream table is portable across
backends and the SQLite and Postgres paths agree (and match the Go SDK). Chosen
for high-volume ``api``/``sys`` persistence, where SQLite's single-writer lock
becomes the bottleneck.

Connection handling mirrors :class:`fasten.store.postgres.PostgresStore`: one
psycopg connection per thread via ``threading.local``, with a one-shot reconnect
on a stale connection. Install the optional dep: ``pip install "fasten[postgres]"``.
"""
from __future__ import annotations

import json
import re
import threading
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

# Bare name ("syslog") or schema-qualified ("fasten.syslog").
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$")

_DDL = """
CREATE TABLE IF NOT EXISTS {table} (
    seq          BIGSERIAL PRIMARY KEY,
    request_id   TEXT,
    timestamp    TEXT,
    level        TEXT,
    service_id   TEXT,
    event        TEXT,
    method       TEXT,
    path         TEXT,
    status       INTEGER,
    payload      TEXT NOT NULL
)
"""

_INDEXES = [
    # {p} = bare table name for the index identifier; {t} = full (maybe schema.table).
    "CREATE INDEX IF NOT EXISTS idx_{p}_req ON {t}(request_id)",
    "CREATE INDEX IF NOT EXISTS idx_{p}_ts  ON {t}(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_{p}_lvl ON {t}(level)",
    "CREATE INDEX IF NOT EXISTS idx_{p}_svc ON {t}(service_id)",
    "CREATE INDEX IF NOT EXISTS idx_{p}_evt ON {t}(event)",
    "CREATE INDEX IF NOT EXISTS idx_{p}_mth ON {t}(method)",
    "CREATE INDEX IF NOT EXISTS idx_{p}_pth ON {t}(path)",
    "CREATE INDEX IF NOT EXISTS idx_{p}_sts ON {t}(status)",
]

_INDEXED_FIELDS = ("request_id", "timestamp", "level", "service_id",
                   "event", "method", "path", "status")


class PostgresStreamStore:
    """Durable, queryable Postgres backing for one ring-buffered stream."""

    def __init__(self, dsn: str, table: str = "syslog") -> None:
        if not _SAFE_IDENTIFIER.match(table):
            raise ValueError(
                f"fasten PostgresStreamStore: table name {table!r} is not a valid SQL "
                "identifier. Use only letters, digits, underscores, and an optional "
                "'schema.' prefix."
            )
        self._dsn = dsn
        self._table = table
        self._idx_prefix = table.split(".")[-1]
        self._schema = table.split(".")[0] if "." in table else None
        self._tls = threading.local()
        # Swallowed persist attempts — see StreamStore for the semantics; drives
        # the reader's ``store-degraded`` completeness flag.
        self._write_failures = 0
        conn = self._connect()
        with conn.cursor() as cur:
            if self._schema:
                cur.execute(f"CREATE SCHEMA IF NOT EXISTS {self._schema}")
            cur.execute(_DDL.format(table=self._table))
            for sql in _INDEXES:
                cur.execute(sql.format(t=self._table, p=self._idx_prefix))
        conn.commit()

    # ── Connection management ─────────────────────────────────────────────

    def _connect(self) -> Any:
        import psycopg

        conn = getattr(self._tls, "conn", None)
        if conn is None or conn.closed:
            conn = psycopg.connect(self._dsn)
            self._tls.conn = conn
        return conn

    def _connect_fresh(self) -> Any:
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
        poisons the connection for reuse.

        Without this guard, a non-Operational error in a write fn (e.g.
        ``UndefinedTable``, ``NotNullViolation``) is swallowed one level up,
        leaves the thread-local connection ``INERROR``, and every subsequent
        statement raises ``InFailedSqlTransaction`` — which is
        ``psycopg.InternalError``, **not** ``OperationalError`` — so the
        reconnect branch never fires. Every api/sys row on that thread then
        fails to persist forever while the flag stays green. Mirrors
        ``PostgresStore._execute_with_retry`` in ``postgres.py``."""
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
        except (psycopg.OperationalError, psycopg.InterfaceError):
            return _call(self._connect_fresh())

    def close(self) -> None:
        conn = getattr(self._tls, "conn", None)
        if conn and not conn.closed:
            conn.close()
        self._tls.conn = None

    @classmethod
    def from_dsn(cls, dsn: str, default_table: str = "syslog") -> "PostgresStreamStore":
        """Parse ``postgres[ql]://...?table=X`` — strip the fasten-specific
        ``table`` param before handing the DSN to psycopg (libpq rejects
        unknown params)."""
        u = urlparse(dsn)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        table = q.pop("table", default_table)
        pg_dsn = urlunparse(u._replace(query=urlencode(q)))
        return cls(dsn=pg_dsn, table=table)

    # ── Write path ────────────────────────────────────────────────────────

    def insert(self, row: dict[str, Any]) -> None:
        cols = {f: row.get(f) for f in _INDEXED_FIELDS}

        def _run(conn: Any) -> None:
            with conn.cursor() as cur:
                cur.execute(
                    f"INSERT INTO {self._table} "
                    "(request_id,timestamp,level,service_id,event,method,path,status,payload) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        cols["request_id"], cols["timestamp"], cols["level"],
                        cols["service_id"], cols["event"], cols["method"],
                        cols["path"], cols["status"],
                        # ensure_ascii=False — see stream.py for why (parity
                        # with Go's json.Marshal, otherwise q= over non-ASCII
                        # text returns zero matches).
                        json.dumps(row, default=str, ensure_ascii=False),
                    ),
                )
            conn.commit()

        self._execute_with_retry(_run)

    def note_write_failure(self) -> None:
        self._write_failures += 1

    @property
    def write_failures(self) -> int:
        return self._write_failures

    @property
    def degraded(self) -> bool:
        return self._write_failures > 0

    # ── Read path ─────────────────────────────────────────────────────────

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
        conds: list[str] = []
        params: list[Any] = []
        for col, val in (
            ("level", level), ("request_id", request_id), ("service_id", service_id),
            ("method", method), ("path", path), ("event", event),
        ):
            if val:
                conds.append(f"{col} = %s")
                params.append(val)
        if status is not None:
            conds.append("status = %s")
            params.append(status)
        if since:
            conds.append("COALESCE(timestamp, '') >= %s")
            params.append(since)
        if until:
            conds.append("COALESCE(timestamp, '') <= %s")
            params.append(until)
        where = (" WHERE " + " AND ".join(conds)) if conds else ""
        return where, params

    def query(self, *, limit: int = 100, **filters: Any) -> list[dict[str, Any]]:
        where, params = self._build_where(**filters)
        sql = f"SELECT payload FROM {self._table}{where} ORDER BY seq DESC LIMIT %s"

        def _run(conn: Any) -> list[dict[str, Any]]:
            with conn.cursor() as cur:
                cur.execute(sql, (*params, limit))
                return [json.loads(r[0]) for r in cur.fetchall()]

        return self._execute_with_retry(_run)

    def count_matching(self, **filters: Any) -> int:
        where, params = self._build_where(**filters)

        def _run(conn: Any) -> int:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) FROM {self._table}{where}", params)
                return int(cur.fetchone()[0])

        return self._execute_with_retry(_run)

    def count(self) -> int:
        def _run(conn: Any) -> int:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) FROM {self._table}")
                return int(cur.fetchone()[0])

        return self._execute_with_retry(_run)

    def purge(self, *, before: str) -> int:
        """Age-based retention delete (FR1). NULL timestamps are never purged."""
        def _run(conn: Any) -> int:
            with conn.cursor() as cur:
                cur.execute(f"DELETE FROM {self._table} WHERE timestamp < %s", (before,))
                deleted = cur.rowcount
            conn.commit()
            return deleted

        return self._execute_with_retry(_run)

    def search(
        self, *, q: str, since: str, until: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """FR3 bounded substring search (§4.1). Case-insensitive via ILIKE; %/_/\\
        in ``q`` are escaped so they match literally."""
        esc = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        # ESCAPE E'\\' (explicit escape-string) always means one backslash,
        # independent of standard_conforming_strings; plain '\' would break if a
        # deployment turned that off (FR3-4).
        conds = ["COALESCE(timestamp, '') >= %s", "payload ILIKE %s ESCAPE E'\\\\'"]
        params: list[Any] = [since, f"%{esc}%"]
        if until:
            conds.append("COALESCE(timestamp, '') <= %s")
            params.append(until)
        sql = (
            f"SELECT payload FROM {self._table} WHERE {' AND '.join(conds)} "
            "ORDER BY seq DESC LIMIT %s"
        )

        def _run(conn: Any) -> list[dict[str, Any]]:
            with conn.cursor() as cur:
                cur.execute(sql, (*params, limit))
                return [json.loads(r[0]) for r in cur.fetchall()]

        return self._execute_with_retry(_run)
