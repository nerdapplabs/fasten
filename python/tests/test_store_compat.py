"""
Backend-compatibility suite: same tests run against SQLite and PostgreSQL.

The ``store`` fixture is parametrized over ``["sqlite", "postgres"]``.
Postgres is skipped at collection time unless FASTEN_TEST_POSTGRES_DSN is set:

    FASTEN_TEST_POSTGRES_DSN=postgresql://fasten:fasten@localhost:5432/fasten_test \
        pytest python/tests/test_store_compat.py -v
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone, timedelta

import pytest

from fasten.attrs import AuditRow
from fasten.context import mint_id
from fasten.store.sqlite import SQLiteStore


def _unique_id() -> str:
    return f"evt-{uuid.uuid4().hex}"


def make_row(**overrides):
    # origin_id defaults to id (originated semantics) so store.insert — a thin
    # alias for insert_originated — accepts these rows. Tests that need a
    # replicated row (origin_id != id) override origin_id explicitly.
    row_id = overrides.get("id", _unique_id())
    defaults = dict(
        id=row_id,
        origin_id=row_id,
        monotonic_seq=1,
        timestamp=datetime.now(timezone.utc),
        code="USER_CREATED",
        action="create",
        severity="info",
        service_id="svc",
        source_node_id="node-1",
        actor="system",
        actor_kind="service",
        target="u-1",
        category="account",
        domain="user",
        method="sdk",
        request_id=mint_id(),
        detail={"email": "a@b.com"},
    )
    defaults.update(overrides)
    return AuditRow(**defaults)


@pytest.fixture(params=["sqlite", "postgres"])
def store(request):
    if request.param == "postgres":
        dsn = os.getenv("FASTEN_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("FASTEN_TEST_POSTGRES_DSN not set — skipping Postgres tests")
        from fasten.store.postgres import PostgresStore
        import psycopg

        table = f"t_{uuid.uuid4().hex[:12]}"
        s = PostgresStore(dsn, table=table)
        yield s
        s.close()
        with psycopg.connect(dsn) as conn:
            conn.execute(f"DROP TABLE IF EXISTS {table}")
    else:
        yield SQLiteStore(":memory:")


# ---------------------------------------------------------------------------
# INSERT / QUERY
# ---------------------------------------------------------------------------

def test_insert_and_query_by_request_id(store):
    rid = mint_id()
    row = make_row(request_id=rid)
    store.insert(row)
    results = store.query(request_id=rid)
    assert len(results) == 1
    assert results[0].id == row.id
    assert results[0].code == "USER_CREATED"


def test_insert_idempotent(store):
    row = make_row()
    store.insert(row)
    store.insert(row)
    assert store.count() == 1


def test_query_by_code(store):
    store.insert(make_row(code="USER_CREATED"))
    store.insert(make_row(code="USER_DELETED"))
    created = store.query(code="USER_CREATED")
    deleted = store.query(code="USER_DELETED")
    assert all(r.code == "USER_CREATED" for r in created)
    assert all(r.code == "USER_DELETED" for r in deleted)


def test_query_naive_datetime_normalised_to_utc(store):
    aware_now = datetime.now(timezone.utc)
    store.insert(make_row(timestamp=aware_now))
    naive_now = aware_now.replace(tzinfo=None)
    assert len(store.query(
        since=naive_now - timedelta(seconds=10),
        until=naive_now + timedelta(seconds=10),
    )) == 1
    assert len(store.query(
        since=aware_now - timedelta(seconds=10),
        until=aware_now + timedelta(seconds=10),
    )) == 1


def test_round_trip_detail_json(store):
    detail = {"nested": {"k": [1, 2, 3]}, "flag": True, "n": None}
    row = make_row(detail=detail)
    store.insert(row)
    back = store.query()[0]
    assert back.detail == detail


# ---------------------------------------------------------------------------
# COUNT
# ---------------------------------------------------------------------------

def test_count_empty(store):
    assert store.count() == 0


def test_count_filtered(store):
    store.insert(make_row(code="USER_CREATED"))
    store.insert(make_row(code="USER_CREATED"))
    store.insert(make_row(code="USER_DELETED"))
    assert store.count() == 3
    assert store.count(code="USER_CREATED") == 2
    assert store.count(code="USER_DELETED") == 1


# ---------------------------------------------------------------------------
# OUTBOX (list_unshipped / mark_shipped)
# ---------------------------------------------------------------------------

def test_list_unshipped(store):
    row = make_row()
    store.insert(row)
    unshipped = store.list_unshipped(limit=10)
    assert len(unshipped) == 1
    assert unshipped[0].id == row.id


def test_mark_shipped_removes_from_unshipped(store):
    row = make_row()
    store.insert(row)
    store.mark_shipped([row.id])
    assert store.list_unshipped(limit=10) == []


def test_mark_shipped_sets_timestamp(store):
    row = make_row()
    store.insert(row)
    store.mark_shipped([row.id])
    back = store.query()[0]
    assert back.shipped_at is not None


# ---------------------------------------------------------------------------
# PURGE
# ---------------------------------------------------------------------------

def test_purge_respects_unshipped(store):
    old = make_row(timestamp=datetime.now(timezone.utc) - timedelta(days=31))
    store.insert(old)
    deleted = store.purge(before=datetime.now(timezone.utc), respect_unshipped=True)
    assert deleted == 0
    assert store.count() == 1


def test_purge_shipped(store):
    old = make_row(timestamp=datetime.now(timezone.utc) - timedelta(days=31))
    store.insert(old)
    store.mark_shipped([old.id])
    deleted = store.purge(before=datetime.now(timezone.utc), respect_unshipped=True)
    assert deleted == 1
    assert store.count() == 0


def test_purge_force(store):
    old = make_row(timestamp=datetime.now(timezone.utc) - timedelta(days=31))
    store.insert(old)
    deleted = store.purge(before=datetime.now(timezone.utc), respect_unshipped=False)
    assert deleted == 1


# ---------------------------------------------------------------------------
# max_monotonic_seq
# ---------------------------------------------------------------------------

def test_max_monotonic_seq_empty(store):
    assert store.max_monotonic_seq() == 0


def test_max_monotonic_seq_returns_max(store):
    store.insert(make_row(monotonic_seq=7))
    store.insert(make_row(monotonic_seq=3))
    assert store.max_monotonic_seq() == 7


# ---------------------------------------------------------------------------
# Table naming flexibility (Postgres-only)
# ---------------------------------------------------------------------------

def test_postgres_schema_qualified_table():
    """fasten.audit_log — table lives in a dedicated 'fasten' schema."""
    dsn = os.getenv("FASTEN_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("FASTEN_TEST_POSTGRES_DSN not set")
    import psycopg
    from fasten.store.postgres import PostgresStore

    table = f"fasten.t_{uuid.uuid4().hex[:10]}"
    s = PostgresStore(dsn, table=table)
    row = make_row()
    s.insert(row)
    assert s.count() == 1
    assert s.query()[0].id == row.id
    s.close()
    with psycopg.connect(dsn) as conn:
        conn.execute(f"DROP TABLE IF EXISTS {table}")
        conn.execute("DROP SCHEMA IF EXISTS fasten CASCADE")


def test_postgres_fasten_prefix_table():
    """fasten_audit_log — user's DB, no new schema, fasten_ prefix avoids clashes."""
    dsn = os.getenv("FASTEN_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("FASTEN_TEST_POSTGRES_DSN not set")
    import psycopg
    from fasten.store.postgres import PostgresStore

    table = f"fasten_{uuid.uuid4().hex[:10]}"
    s = PostgresStore(dsn, table=table)
    row = make_row()
    s.insert(row)
    assert s.count() == 1
    s.close()
    with psycopg.connect(dsn) as conn:
        conn.execute(f"DROP TABLE IF EXISTS {table}")


# ---------------------------------------------------------------------------
# QUERY ORDERING ACROSS SUB-CHAINS (#68)
# ---------------------------------------------------------------------------

def test_query_orders_by_time_across_sub_chains(store):
    """monotonic_seq is a per-(service_id, source_node_id) counter — comparing
    it across sub-chains is meaningless. Global query() must order by
    wall-clock first, so a chatty old chain's high counters cannot bury a
    quieter chain's newer rows below the page limit (#68)."""
    now = datetime.now(timezone.utc)
    # Chain A: an older, chattier writer — high seq, day-old timestamps.
    for i in range(5):
        store.insert(make_row(service_id="svc-a", source_node_id="node-a",
                              monotonic_seq=100 + i,
                              timestamp=now - timedelta(days=1, minutes=5 - i)))
    # Chain B: a fresh writer — counter restarted at 1, current timestamps.
    for i in range(3):
        store.insert(make_row(service_id="svc-b", source_node_id="node-b",
                              monotonic_seq=1 + i,
                              timestamp=now - timedelta(minutes=3 - i)))

    page = store.query(limit=4)
    # Newest wall-clock rows come first: all of chain B precedes any of chain A.
    assert [r.source_node_id for r in page[:3]] == ["node-b"] * 3
    stamps = [r.timestamp for r in page]
    assert stamps == sorted(stamps, reverse=True)


def test_query_same_millisecond_ties_break_by_seq(store):
    """Within one sub-chain, seq stays the same-timestamp tie-breaker."""
    t = datetime.now(timezone.utc)
    store.insert(make_row(monotonic_seq=1, timestamp=t))
    store.insert(make_row(monotonic_seq=2, timestamp=t))
    assert [r.monotonic_seq for r in store.query(limit=2)] == [2, 1]
