"""
The Python stores on a table the Go SDK created.

Go makes detail_salt and detail_commitment NOT NULL DEFAULT '', puts
pii_in_detail and wire_version among the columns, and on Postgres stores
timestamp and shipped_at as TIMESTAMPTZ. The DDL below is copied from
go/store.go and go/store_postgres.go.

Postgres is skipped unless FASTEN_TEST_POSTGRES_DSN is set.
"""
from __future__ import annotations

import dataclasses
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone

import pytest

from fasten.attrs import AuditRow
from fasten.chain import seal, verify_chain
from fasten.context import mint_id
from fasten.store.sqlite import SQLiteStore

_GO_COLUMNS = """
    id             TEXT PRIMARY KEY,
    origin_id      TEXT NOT NULL,
    monotonic_seq  {seq} NOT NULL,
    timestamp      {ts} NOT NULL,
    code           TEXT NOT NULL,
    action         TEXT NOT NULL,
    severity       TEXT NOT NULL,
    service_id     TEXT NOT NULL,
    source_node_id TEXT NOT NULL,
    tenant_id      TEXT,
    actor          TEXT NOT NULL,
    actor_kind     TEXT NOT NULL,
    target         TEXT NOT NULL,
    category       TEXT NOT NULL,
    domain         TEXT NOT NULL,
    method         TEXT NOT NULL,
    request_id     TEXT NOT NULL,
    detail         TEXT NOT NULL,
    pii_in_detail  {pii} NOT NULL DEFAULT 0,
    shipped_at     {ts},
    wire_version   TEXT NOT NULL DEFAULT '1',
    hash           TEXT NOT NULL DEFAULT '',
    prev_hash      TEXT NOT NULL DEFAULT '',
    canonical_form_id TEXT NOT NULL DEFAULT '1',
    detail_salt       TEXT NOT NULL DEFAULT '',
    detail_commitment TEXT NOT NULL DEFAULT ''
"""

_GO_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_{t}_req ON {t}(request_id);
CREATE INDEX IF NOT EXISTS idx_{t}_code ON {t}(code);
CREATE INDEX IF NOT EXISTS idx_{t}_ts ON {t}(timestamp);
CREATE INDEX IF NOT EXISTS idx_{t}_seq ON {t}(monotonic_seq);
CREATE UNIQUE INDEX IF NOT EXISTS uq_{t}_node_seq ON {t}(source_node_id, monotonic_seq);
CREATE INDEX IF NOT EXISTS idx_{t}_unshipped ON {t}(shipped_at) WHERE shipped_at IS NULL;
"""


def _go_ddl(table: str, postgres: bool) -> str:
    cols = _GO_COLUMNS.format(
        seq="BIGINT" if postgres else "INTEGER",
        ts="TIMESTAMPTZ" if postgres else "TEXT",
        pii="SMALLINT" if postgres else "INTEGER",
    )
    return f"CREATE TABLE {table} ({cols});" + _GO_INDEXES.format(t=table)


def _row(**overrides) -> AuditRow:
    row_id = f"evt-{uuid.uuid4().hex[:20]}"
    fields = dict(
        id=row_id, origin_id=row_id, monotonic_seq=0,
        timestamp=datetime.now(timezone.utc),
        code="USER_CREATED", action="create", severity="info",
        service_id="svc", source_node_id="node-1",
        actor="system", actor_kind="service", target="u-1",
        category="account", domain="user", method="sdk",
        request_id=mint_id(), detail={"email": "a@b.com"},
    )
    fields.update(overrides)
    return AuditRow(**fields)


@pytest.fixture(params=["sqlite", "postgres"])
def go_table(request, tmp_path):
    """(store, insert_as_go): a Python store opened on a table Go created,
    and a function that writes a row the way Go does."""
    table = f"go_{uuid.uuid4().hex[:12]}"
    if request.param == "sqlite":
        path = str(tmp_path / "go.db")
        with sqlite3.connect(path) as conn:
            conn.executescript(_go_ddl(table, postgres=False))

        def insert_as_go(row: AuditRow) -> None:
            with sqlite3.connect(path) as conn:
                conn.execute(_GO_INSERT.format(t=table).replace("%s", "?"),
                             _go_params(row, row.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")))

        yield SQLiteStore(path, table=table), insert_as_go
        return

    dsn = os.getenv("FASTEN_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("FASTEN_TEST_POSTGRES_DSN not set — skipping Postgres tests")
    import psycopg
    from fasten.store.postgres import PostgresStore

    with psycopg.connect(dsn) as conn:
        conn.execute(_go_ddl(table, postgres=True))

    def insert_as_go(row: AuditRow) -> None:
        with psycopg.connect(dsn) as conn:
            conn.execute(_GO_INSERT.format(t=table), _go_params(row, row.timestamp))

    s = PostgresStore(dsn, table=table)
    yield s, insert_as_go
    s.close()
    with psycopg.connect(dsn) as conn:
        conn.execute(f"DROP TABLE IF EXISTS {table}")


_GO_INSERT = (
    "INSERT INTO {t} (id, origin_id, monotonic_seq, timestamp, code, action, severity,"
    " service_id, source_node_id, tenant_id, actor, actor_kind, target, category, domain,"
    " method, request_id, detail, pii_in_detail, shipped_at, wire_version, hash, prev_hash,"
    " canonical_form_id, detail_salt, detail_commitment)"
    " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
)


def _go_params(row: AuditRow, ts) -> tuple:
    return (row.id, row.origin_id, row.monotonic_seq, ts, row.code, row.action,
            row.severity, row.service_id, row.source_node_id, row.tenant_id,
            row.actor, row.actor_kind, row.target, row.category, row.domain,
            row.method, row.request_id, json.dumps(row.detail), 1, None, "1",
            row.hash, row.prev_hash, row.canonical_form_id,
            row.detail_salt or "", row.detail_commitment or "")


def test_unsealed_row_inserts(go_table):
    store, _ = go_table
    row = _row()
    store.insert(row)
    [got] = store.query(request_id=row.request_id)
    assert got.id == row.id
    assert got.detail_salt is None
    assert got.detail_commitment is None


def test_sealed_rows_read_back_and_verify(go_table):
    store, _ = go_table
    written = [store.allocate_and_insert_originated(_row(target=f"u-{i}")) for i in range(3)]
    got = store.query(source_node_id="node-1", limit=10)
    by_id = {r.id: r for r in got}
    for w in written:
        r = by_id[w.id]
        assert (r.monotonic_seq, r.timestamp, r.target) == (w.monotonic_seq, w.timestamp, w.target)
        assert (r.prev_hash, r.hash, r.canonical_form_id) == (w.prev_hash, w.hash, w.canonical_form_id)
        assert (r.detail_salt, r.detail_commitment) == (w.detail_salt, w.detail_commitment)
        assert r.shipped_at is None
    result = verify_chain(sorted(got, key=lambda r: r.monotonic_seq))
    assert result.ok, result.reason


def test_row_go_wrote_reads_back(go_table):
    store, insert_as_go = go_table
    row = seal("", dataclasses.replace(_row(), monotonic_seq=1))
    insert_as_go(row)
    [got] = store.query(request_id=row.request_id)
    assert (got.id, got.monotonic_seq, got.timestamp) == (row.id, 1, row.timestamp)
    assert (got.prev_hash, got.hash, got.canonical_form_id) == (row.prev_hash, row.hash, row.canonical_form_id)
    assert (got.detail_salt, got.detail_commitment) == (row.detail_salt, row.detail_commitment)
    assert got.detail == row.detail
    assert verify_chain([got]).ok



def test_chain_tail_reads_back(go_table):
    store, _ = go_table
    written = [store.allocate_and_insert_originated(_row(target=f"u-{i}")) for i in range(4)]
    tail = store.chain_tail("node-1", 3)
    assert [(r.id, r.monotonic_seq, r.target, r.hash) for r in tail] == [
        (w.id, w.monotonic_seq, w.target, w.hash) for w in written[1:]]
    assert verify_chain(tail).ok


def test_redact_ship_and_sources(go_table):
    store, _ = go_table
    old = datetime(2026, 1, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)
    w = [store.allocate_and_insert_originated(_row(timestamp=old.replace(second=i)))
         for i in range(2)]
    redacted = store.redact_expired(before=datetime(2026, 2, 1, tzinfo=timezone.utc),
                                    codes=["USER_CREATED"])
    assert sorted(redacted) == sorted(r.id for r in w)
    got = store.query(source_node_id="node-1", limit=10)
    assert all(r.detail is None and r.detail_salt is None for r in got)
    assert verify_chain(sorted(got, key=lambda r: r.monotonic_seq)).ok
    store.mark_shipped([w[0].id])
    assert [r.id for r in store.list_unshipped(limit=10)] == [w[1].id]
    [src] = store.sources()
    assert (src["first_seen"], src["last_seen"]) == (
        "2026-01-01T12:00:00.123456Z", "2026-01-01T12:00:01.123456Z")
