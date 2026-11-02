"""Postgres store for the api or sys stream (psycopg 3).

Same columns, indexes and query behaviour as
:class:`fasten.store.stream.StreamStore`, for streams too busy for SQLite's
single writer. One connection per thread, reconnecting once if it has gone
stale. Needs ``pip install "fasten[postgres]"``.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
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
    # {p}: table name without schema, for index names. {t}: full table name.
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
    """Postgres table backing one stream."""

    def __init__(self, dsn: str, table: str) -> None:
        # No default table, so api rows can't end up in the syslog table by
        # accident.
        if not table:
            raise ValueError(
                "fasten PostgresStreamStore: table name is required "
                "(no default: pass \"api_log\" / \"syslog\" explicitly to "
                "avoid api rows landing in the syslog table)."
            )
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
        # See StreamStore._write_failures.
        self._write_failures = 0
        conn = self._connect()
        with conn.cursor() as cur:
            if self._schema:
                cur.execute(f"CREATE SCHEMA IF NOT EXISTS {self._schema}")
            cur.execute(_DDL.format(table=self._table))
            for sql in _INDEXES:
                cur.execute(sql.format(t=self._table, p=self._idx_prefix))
        conn.commit()

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
        """Run fn(conn), reconnecting and retrying once on a connection error.

        Afterwards any open transaction is rolled back. Reads leave one open
        (holding locks), and a failed statement leaves the connection in an
        error state where every later statement raises InFailedSqlTransaction,
        which is not an OperationalError and so would never trigger the
        reconnect. Same as PostgresStore._execute_with_retry.
        """
        import psycopg

        def _call(conn: Any) -> Any:
            try:
                return fn(conn)
            finally:
                if conn.info.transaction_status != psycopg.pq.TransactionStatus.IDLE:
                    try:
                        conn.rollback()
                    except (psycopg.OperationalError, psycopg.InterfaceError):
                        pass  # dead connection; keep the original error

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
    def from_dsn(cls, dsn: str, default_table: str) -> "PostgresStreamStore":
        """Build a store from ``postgres[ql]://...?table=X``. ``table`` is
        removed before connecting, since libpq rejects unknown parameters;
        ``default_table`` is used when it is absent."""
        u = urlparse(dsn)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        table = q.pop("table", default_table)
        pg_dsn = urlunparse(u._replace(query=urlencode(q)))
        return cls(dsn=pg_dsn, table=table)

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
                        # Unescaped non-ASCII; see StreamStore.insert.
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

    def purge(self, *, before: "datetime | str") -> int:
        """Delete rows older than ``before`` (a datetime or canonical string)
        and return how many were deleted. Rows without a timestamp are kept."""
        if not isinstance(before, str):
            from ..canonical_ts import canonical_ts
            before = canonical_ts(before)

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
        """Case-insensitive substring search (ILIKE) of the stored JSON within
        ``[since, until]``. ``%``, ``_`` and ``\\`` in ``q`` match literally."""
        esc = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        # E'\\' is one backslash whatever standard_conforming_strings is set
        # to; a plain '\' would not be.
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
