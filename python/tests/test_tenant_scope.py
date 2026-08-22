"""P1-44 — cross-tenant isolation on reader endpoints.

Pins the enforcement contract: when ``router(tenant_scope=...)`` is
wired, every reader endpoint (`/audit`, `/correlate`, `/search`,
`/sys`, `/api`, `/topology`) IGNORES any caller-supplied ``?tenant_id=``
AND scopes the result to the resolved tenant. Tenant B cannot see
tenant A's rows via any known attack:

- passing ``?tenant_id=A``
- passing ``X-Request-ID: <known-A-request-id>`` to /correlate
- searching for a substring that only exists in A's rows
- topology enumeration of A's service_id / node_id values

The single-tenant baseline (``tenant_scope=None``) is untouched.
"""
from __future__ import annotations

import pytest

import fasten
from fasten.context import with_request_id
from fasten.store.sqlite import SQLiteStore
from fasten.store.stream import StreamStore


def _client(*, tenant_scope=None, enforce=False):
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from fasten.reader.router import router as build_router

    app = FastAPI()
    app.include_router(
        build_router(dependencies=[], tenant_scope=tenant_scope,
                     enforce_tenant_isolation=enforce),
        prefix="/api/v1/logs",
    )
    return TestClient(app)


def _init_shared_store():
    """Init fasten with one shared audit store + stream stores, then emit
    rows for two different tenants A and B by re-initing the Engine per
    tenant (keeping the same store). Mirrors a hosted multi-tenant
    deployment where each tenant's process has its own Engine.tenant_id
    but all write into the shared physical store."""
    audit = SQLiteStore(":memory:")
    api_s = StreamStore(":memory:", table="api_shared")
    sys_s = StreamStore(":memory:", table="sys_shared")
    for tid, rid, marker in (("tenant-a", "req-a1", "aliceA@corp"),
                             ("tenant-b", "req-b1", "bobB@corp")):
        fasten.init(
            service_id="svc", node_id="n", tenant_id=tid,
            audit_store=audit,
            api_store=api_s, syslog_store=sys_s,
            audit_store_failure_strategy="raise",
            search_enabled=True,
        )
        with with_request_id(rid):
            fasten.emit(
                code="USER_CREATED", target=f"u-{tid}", actor="op",
                detail={"marker": marker},
            )
        t = fasten.transport()
        t.push_syslog({"event": "auth", "message": marker, "tenant_id": tid,
                       "request_id": rid,
                       "timestamp": "2026-08-22T10:00:00.000000Z"})
        t.push_api({"method": "GET", "path": f"/{tid}", "status": 200,
                    "tenant_id": tid, "request_id": rid,
                    "timestamp": "2026-08-22T10:00:00.000000Z"})
    # Re-init once more without a tenant_id so /audit/doctor and helpers
    # that read `_default._tenant_id` don't stick on tenant-b — the shared
    # store already holds tagged rows for both.
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=audit,
        api_store=api_s, syslog_store=sys_s,
        audit_store_failure_strategy="raise",
        search_enabled=True,
    )
    return audit


# ── baseline: no scope hook, behaviour unchanged ─────────────────────────

def test_no_scope_hook_keeps_current_behaviour():
    _init_shared_store()
    body = _client().get("/api/v1/logs/audit?limit=10").json()
    # Sees both tenants' rows — single-tenant / legacy baseline.
    tenants = {r["tenant_id"] for r in body["rows"]}
    assert tenants == {"tenant-a", "tenant-b"}


# ── enforce_tenant_isolation refuses to construct without hook ───────────

def test_enforce_without_hook_refuses_construction():
    from fasten.reader.router import router as build_router
    with pytest.raises(RuntimeError, match="tenant_scope"):
        build_router(dependencies=[], enforce_tenant_isolation=True)


# ── with scope: audit endpoint filters ───────────────────────────────────

def test_audit_endpoint_scopes_to_resolved_tenant():
    _init_shared_store()
    c = _client(tenant_scope=lambda _req: "tenant-a")
    body = c.get("/api/v1/logs/audit?limit=10").json()
    assert body["rows"]
    for r in body["rows"]:
        assert r["tenant_id"] == "tenant-a"


def test_audit_endpoint_ignores_caller_tenant_id_override():
    """Attack: tenant A caller passes ?tenant_id=tenant-b hoping to
    read B's rows. Scope hook must OVERRIDE the query param."""
    _init_shared_store()
    c = _client(tenant_scope=lambda _req: "tenant-a")
    body = c.get("/api/v1/logs/audit?tenant_id=tenant-b&limit=10").json()
    for r in body["rows"]:
        assert r["tenant_id"] == "tenant-a", (
            "?tenant_id= must not override the resolved scope"
        )


def test_audit_endpoint_401s_when_scope_returns_none():
    _init_shared_store()
    c = _client(tenant_scope=lambda _req: None)
    resp = c.get("/api/v1/logs/audit?limit=10")
    assert resp.status_code == 401


# ── /correlate: X-Request-ID pivot attack blocked ────────────────────────

def test_correlate_cannot_pivot_across_tenants_via_request_id():
    """The known attack: tenant B knows tenant A's request_id (leaked
    log, header sniff), calls /correlate?request_id=<A's id>. Result
    must be empty for B — scope filter blocks cross-tenant read."""
    _init_shared_store()
    c = _client(tenant_scope=lambda _req: "tenant-b")
    body = c.get("/api/v1/logs/correlate?request_id=req-a1&limit=10").json()
    # audit block empty for B when the scope filter fires
    assert body["audit"] == []
    # api/sys post-filter drops any A-tenant rows
    for r in body["api"] + body["sys"]:
        assert r["tenant_id"] == "tenant-b"


def test_correlate_scoped_returns_own_tenant_rows():
    _init_shared_store()
    c = _client(tenant_scope=lambda _req: "tenant-a")
    body = c.get("/api/v1/logs/correlate?request_id=req-a1&limit=10").json()
    assert len(body["audit"]) >= 1
    for r in body["audit"] + body["api"] + body["sys"]:
        assert r["tenant_id"] == "tenant-a"


# ── /search: substring-across-tenants blocked ───────────────────────────

def test_search_audit_stream_scoped_to_tenant():
    _init_shared_store()
    # A's audit row contains "aliceA@corp"; B searching for it must
    # get zero even though the substring exists in the store.
    c = _client(tenant_scope=lambda _req: "tenant-b")
    body = c.get(
        "/api/v1/logs/search",
        params={"q": "aliceA@corp", "since": "2026-01-01T00:00:00Z",
                "streams": "audit"},
    ).json()
    assert body["counts"]["audit"] == 0


def test_search_sys_stream_scoped_to_tenant():
    _init_shared_store()
    c = _client(tenant_scope=lambda _req: "tenant-b")
    body = c.get(
        "/api/v1/logs/search",
        params={"q": "aliceA@corp", "since": "2026-01-01T00:00:00Z",
                "streams": "sys"},
    ).json()
    assert body["counts"]["sys"] == 0


# ── /sys and /api: post-filter blocks cross-tenant rows ──────────────────

def test_sys_endpoint_scoped_post_filter():
    _init_shared_store()
    c = _client(tenant_scope=lambda _req: "tenant-a")
    body = c.get("/api/v1/logs/sys?limit=10").json()
    for r in body["rows"]:
        assert r["tenant_id"] == "tenant-a"


def test_api_endpoint_scoped_post_filter():
    _init_shared_store()
    c = _client(tenant_scope=lambda _req: "tenant-a")
    body = c.get("/api/v1/logs/api?limit=10").json()
    for r in body["rows"]:
        assert r["tenant_id"] == "tenant-a"


# ── /topology: fleet enumeration blocked ────────────────────────────────

def test_topology_scoped_to_tenant():
    _init_shared_store()
    c = _client(tenant_scope=lambda _req: "tenant-a")
    body = c.get("/api/v1/logs/topology").json()
    for src in body["sources"]:
        assert src["tenant_id"] == "tenant-a"
    # tenants count must be 1 for a scoped read.
    assert body["tenants"] <= 1
