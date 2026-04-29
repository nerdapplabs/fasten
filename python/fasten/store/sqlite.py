"""
SQLite implementation of AuditRepository.

Parses `sqlite:///path?table=X&wal=true` DSN, creates the table on first use,
and uses WAL mode by default.
"""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import parse_qs, urlparse

from ..attrs import AuditRow

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

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
    shipped_at       TEXT
);
CREATE INDEX IF NOT EXISTS idx_{table}_req  ON {table}(request_id);
CREATE INDEX IF NOT EXISTS idx_{table}_code ON {table}(code);
CREATE INDEX IF NOT EXISTS idx_{table}_ts   ON {table}(timestamp);
CREATE INDEX IF NOT EXISTS idx_{table}_unshipped ON {table}(shipped_at) WHERE shipped_at IS NULL;
"""


class SQLiteStore:
    def __init__(self, path: str, table: str = "audit_log", wal: bool = True) -> None:
        if not _SAFE_IDENTIFIER.match(table):
            raise ValueError(
                f"fasten SQLiteStore: table name {table!r} is not a valid SQL identifier. "
                "Use only letters, digits, and underscores."
            )
        self._path = path
        self._table = table
        self._conn = sqlite3.connect(path, check_same_thread=False)
        if wal:
            self._conn.execute("PRAGMA journal_mode=WAL")
        for stmt in _DDL.format(table=table).split(";"):
            if stmt.strip():
                self._conn.execute(stmt)
        self._conn.commit()

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
        self._conn.execute(
            f"INSERT OR IGNORE INTO {self._table} VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                row.id, row.origin_id, row.monotonic_seq,
                row.timestamp.isoformat(),
                row.code, row.action, row.severity,
                row.service_id, row.source_node_id, row.tenant_id,
                row.actor, row.actor_kind,
                row.target, row.category, row.domain,
                row.method, row.request_id,
                json.dumps(row.detail),
                row.shipped_at.isoformat() if row.shipped_at else None,
            ),
        )
        self._conn.commit()

    def list_unshipped(self, limit: int = 100) -> list[AuditRow]:
        cur = self._conn.execute(
            f"SELECT * FROM {self._table} WHERE shipped_at IS NULL "
            "ORDER BY monotonic_seq ASC LIMIT ?",
            (limit,),
        )
        return [self._row(r) for r in cur.fetchall()]

    def mark_shipped(self, ids: list[str]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._conn.executemany(
            f"UPDATE {self._table} SET shipped_at=? WHERE id=?",
            [(now, i) for i in ids],
        )
        self._conn.commit()

    def purge(self, *, before: datetime, respect_unshipped: bool = True) -> int:
        sql = f"DELETE FROM {self._table} WHERE timestamp < ?"
        params: tuple = (before.isoformat(),)
        if respect_unshipped:
            sql += " AND shipped_at IS NOT NULL"
        cur = self._conn.execute(sql, params)
        self._conn.commit()
        return cur.rowcount

    def query(
        self,
        *,
        request_id: str | None = None,
        code: str | None = None,
        domain: str | None = None,
        source_node_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditRow]:
        conds: list[str] = []
        params: list[object] = []
        if request_id:
            conds.append("request_id = ?");     params.append(request_id)
        if code:
            conds.append("code = ?");           params.append(code)
        if domain:
            conds.append("domain = ?");         params.append(domain)
        if source_node_id:
            conds.append("source_node_id = ?"); params.append(source_node_id)
        if since:
            conds.append("timestamp >= ?");     params.append(since.isoformat())
        if until:
            conds.append("timestamp <= ?");     params.append(until.isoformat())
        where = f"WHERE {' AND '.join(conds)}" if conds else ""
        cur = self._conn.execute(
            f"SELECT * FROM {self._table} {where} ORDER BY monotonic_seq DESC LIMIT ?",
            (*params, limit),
        )
        return [self._row(r) for r in cur.fetchall()]

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
        )
