"""Topology aggregation — store.sources() + reader /topology route.

The fleet topology is derived from the audit rows already recorded
(grouped by source_node_id / service_id / tenant_id), so it can never
drift from reality. These tests pin the aggregation and the endpoint.
"""
from datetime import datetime, timezone

import pytest

import fasten  # noqa: F401
from fasten.attrs import AuditRow


def _row(seq, *, node, service, tenant, when=None):
    return AuditRow(
        id=f"evt-{seq:020x}",
        origin_id=f"evt-{seq:020x}",
        monotonic_seq=seq,
        timestamp=when or datetime.now(timezone.utc),
        code="USER_CREATED",
        action="create",
        severity="info",
        service_id=service,
        source_node_id=node,
        tenant_id=tenant,
        actor="alice",
        actor_kind="service",
        target=f"u-{seq}",
        category="account",
        domain="user",
        method="sdk",
        request_id="req-1",
        detail={},
    )


# ── store.sources() aggregation ───────────────────────────────────────────

def test_sources_groups_by_node_service_tenant(mem_store):
    # node-a/svc-x/acme: 3 rows, node-b/svc-y/acme: 1, node-a/svc-x/beta: 1
    mem_store.insert(_row(1, node="node-a", service="svc-x", tenant="acme"))
    mem_store.insert(_row(2, node="node-a", service="svc-x", tenant="acme"))
    mem_store.insert(_row(3, node="node-a", service="svc-x", tenant="acme"))
    mem_store.insert(_row(4, node="node-b", service="svc-y", tenant="acme"))
    mem_store.insert(_row(5, node="node-a", service="svc-x", tenant="beta"))

    sources = mem_store.sources()

    # three distinct (node, service, tenant) combinations
    assert len(sources) == 3
    # busiest first
    assert sources[0]["source_node_id"] == "node-a"
    assert sources[0]["service_id"] == "svc-x"
    assert sources[0]["tenant_id"] == "acme"
    assert sources[0]["rows"] == 3
    assert {s["rows"] for s in sources} == {3, 1, 1}
    # every entry carries first/last-seen
    for s in sources:
        assert s["first_seen"] and s["last_seen"]


def test_sources_empty_store(mem_store):
    assert mem_store.sources() == []


def test_sources_first_last_seen_span(mem_store):
    early = datetime(2026, 5, 1, 10, 0, 0, tzinfo=timezone.utc)
    late = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
    mem_store.insert(_row(1, node="n", service="s", tenant="t", when=early))
    mem_store.insert(_row(2, node="n", service="s", tenant="t", when=late))

    (one,) = mem_store.sources()
    assert one["rows"] == 2
    assert one["first_seen"] < one["last_seen"]


def test_sources_window_filters_by_time(mem_store):
    early = datetime(2026, 5, 1, 10, 0, 0, tzinfo=timezone.utc)
    late = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
    mem_store.insert(_row(1, node="n", service="s", tenant="t", when=early))
    mem_store.insert(_row(2, node="n", service="s", tenant="t", when=late))

    windowed = mem_store.sources(since=datetime(2026, 5, 1, 11, tzinfo=timezone.utc))
    assert len(windowed) == 1
    assert windowed[0]["rows"] == 1


# ── reader /topology route ────────────────────────────────────────────────

def _client(build_router):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(build_router(), prefix="/api/v1/logs")
    return TestClient(app)


def test_topology_endpoint_summarises_sources(initialized):
    pytest.importorskip("fastapi")
    from fasten.reader.router import router as build_router

    # initialized fixture → service_id="test-svc", source_node_id="test-node"
    fasten.emit(code="USER_CREATED", target="u-1", actor="alice")
    fasten.emit(code="USER_CREATED", target="u-2", actor="bob")

    body = _client(build_router).get("/api/v1/logs/topology").json()

    assert body["nodes"] == 1
    assert body["services"] == 1
    assert len(body["sources"]) == 1
    src = body["sources"][0]
    assert src["source_node_id"] == "test-node"
    assert src["service_id"] == "test-svc"
    assert src["rows"] == 2
    assert src["first_seen"] and src["last_seen"]


def test_topology_endpoint_uninitialised_returns_empty():
    pytest.importorskip("fastapi")
    from fasten.reader.router import router as build_router

    # fresh_state autouse fixture leaves the engine pre-init → store is None.
    body = _client(build_router).get("/api/v1/logs/topology").json()
    assert body == {
        "sources": [], "nodes": 0, "services": 0, "tenants": 0,
        "error": "audit store not initialised — call fasten.init() first",
    }
