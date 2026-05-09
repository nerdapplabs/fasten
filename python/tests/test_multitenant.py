"""Multi-tenant isolation tests (P1-3).

Verifies that audit rows emitted under tenant_id=A are not returned when
querying for tenant_id=B, and vice versa.
"""
import uuid
from datetime import datetime, timezone

import pytest
from fasten.attrs import AuditRow
from fasten.store.sqlite import SQLiteStore


def _row(tenant: str, seq: int, code: str = "USER_CREATED") -> AuditRow:
    rid = str(uuid.uuid4())
    return AuditRow(
        id=rid, origin_id=rid, monotonic_seq=seq,
        timestamp=datetime.now(timezone.utc),
        code=code, action="create", severity="info",
        service_id="svc", source_node_id="node",
        tenant_id=tenant,
        actor="svc", actor_kind="service",
        target="res", category="test", domain="test",
        method="sdk", request_id=rid, detail={},
    )


@pytest.fixture
def shared_store():
    return SQLiteStore(":memory:")


# ── Store-level isolation ─────────────────────────────────────────────────────

def test_tenant_a_rows_invisible_to_tenant_b(shared_store):
    for i in range(3):
        shared_store.insert(_row("tenant-a", i))
    for i in range(3):
        shared_store.insert(_row("tenant-b", 10 + i))

    a_rows = shared_store.query(tenant_id="tenant-a")
    b_rows = shared_store.query(tenant_id="tenant-b")

    assert len(a_rows) == 3
    assert len(b_rows) == 3
    assert all(r.tenant_id == "tenant-a" for r in a_rows)
    assert all(r.tenant_id == "tenant-b" for r in b_rows)


def test_tenant_b_rows_invisible_to_tenant_a(shared_store):
    shared_store.insert(_row("tenant-a", 1))
    shared_store.insert(_row("tenant-b", 2))

    a_rows = shared_store.query(tenant_id="tenant-a")
    assert len(a_rows) == 1
    assert a_rows[0].tenant_id == "tenant-a"


def test_unfiltered_query_returns_all_tenants(shared_store):
    shared_store.insert(_row("tenant-a", 1))
    shared_store.insert(_row("tenant-b", 2))

    all_rows = shared_store.query()
    tenants = {r.tenant_id for r in all_rows}
    assert tenants == {"tenant-a", "tenant-b"}


def test_count_scoped_per_tenant(shared_store):
    for i in range(5):
        shared_store.insert(_row("tenant-a", i))
    for i in range(2):
        shared_store.insert(_row("tenant-b", 10 + i))

    assert shared_store.count(tenant_id="tenant-a") == 5
    assert shared_store.count(tenant_id="tenant-b") == 2
    assert shared_store.count() == 7


def test_unknown_tenant_returns_empty(shared_store):
    shared_store.insert(_row("tenant-a", 1))

    assert shared_store.query(tenant_id="tenant-z") == []
    assert shared_store.count(tenant_id="tenant-z") == 0


def test_tenant_filter_combined_with_code(shared_store):
    shared_store.insert(_row("tenant-a", 1, "USER_CREATED"))
    shared_store.insert(_row("tenant-a", 2, "USER_DELETED"))
    shared_store.insert(_row("tenant-b", 3, "USER_CREATED"))

    rows = shared_store.query(tenant_id="tenant-a", code="USER_CREATED")
    assert len(rows) == 1
    assert rows[0].code == "USER_CREATED"
    assert rows[0].tenant_id == "tenant-a"


# ── Engine-level: init(tenant_id=...) stamps rows ─────────────────────────────

def test_engine_stamps_tenant_id_on_rows(mem_store):
    import fasten
    fasten.init(
        service_id="svc", node_id="node",
        tenant_id="engine-tenant-a",
        audit_store=mem_store,
        audit_store_failure_strategy="raise",
    )
    fasten.emit("USER_CREATED", target="res-1", actor="svc", actor_kind="service")
    rows = mem_store.query()
    assert len(rows) == 1
    assert rows[0].tenant_id == "engine-tenant-a"
