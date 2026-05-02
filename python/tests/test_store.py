"""SQLiteStore: insert, query, list_unshipped, mark_shipped, purge."""
from datetime import datetime, timezone, timedelta
import pytest
from fasten.store.sqlite import SQLiteStore
from fasten.attrs import AuditRow
from fasten.context import mint_id


def make_row(**overrides):
    defaults = dict(
        id=f"evt-{'a' * 20}",
        origin_id=f"evt-{'a' * 20}",
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


@pytest.fixture
def store():
    return SQLiteStore(":memory:")


def test_insert_and_query_by_request_id(store):
    row = make_row(id="evt-" + "b" * 20, origin_id="evt-" + "b" * 20, request_id="abc123def456")
    store.insert(row)
    results = store.query(request_id="abc123def456")
    assert len(results) == 1
    assert results[0].id == row.id
    assert results[0].code == "USER_CREATED"


def test_insert_idempotent(store):
    row = make_row()
    store.insert(row)
    store.insert(row)  # duplicate — INSERT OR IGNORE
    assert len(store.query()) == 1


def test_list_unshipped(store):
    row = make_row()
    store.insert(row)
    unshipped = store.list_unshipped(limit=10)
    assert len(unshipped) == 1
    assert unshipped[0].id == row.id


def test_mark_shipped(store):
    row = make_row()
    store.insert(row)
    store.mark_shipped([row.id])
    assert store.list_unshipped(limit=10) == []


def test_purge_respects_unshipped(store):
    row = make_row(timestamp=datetime.now(timezone.utc) - timedelta(days=31))
    store.insert(row)
    deleted = store.purge(before=datetime.now(timezone.utc), respect_unshipped=True)
    assert deleted == 0
    assert len(store.query()) == 1


def test_purge_shipped(store):
    row = make_row(timestamp=datetime.now(timezone.utc) - timedelta(days=31))
    store.insert(row)
    store.mark_shipped([row.id])
    deleted = store.purge(before=datetime.now(timezone.utc), respect_unshipped=True)
    assert deleted == 1


def test_query_by_code(store):
    store.insert(make_row(id="evt-" + "c" * 20, origin_id="evt-" + "c" * 20, code="USER_CREATED"))
    store.insert(make_row(id="evt-" + "d" * 20, origin_id="evt-" + "d" * 20, code="USER_DELETED"))
    results = store.query(code="USER_CREATED")
    assert all(r.code == "USER_CREATED" for r in results)
