"""Tests for the public-API parity additions in P1-8.

Covers:
  #1 — fasten.transport() accessor
  #2 — fasten.redactor() accessor
  #4 — reader.router() lazy-fetches store + transport from fasten.init()
  #7 — reader docstring auth pattern (read-only assertion that example mentions Depends)
  #8 — actor / target filters + offset / total on /audit
  #9 — fasten.init() docstring lists FASTEN_AUDIT_DSN
"""
import pytest

import fasten  # noqa: F401  (used by fixtures)
from fasten.codes import Meta, Severity, RetentionClass, register
from fasten.emit import _default
from fasten.redact import Redactor
from fasten.store.sqlite import SQLiteStore
from fasten.transport.stdout import StdoutTransport


# ── #1 transport() ────────────────────────────────────────────────────────

def test_transport_returns_active_stdout(initialized):
    t = fasten.transport()
    assert t is _default._stdout
    assert isinstance(t, StdoutTransport)


def test_transport_pre_init_returns_none():
    # fresh_state resets the engine, so _stdout is None pre-init.
    assert fasten.transport() is None


# ── #2 redactor() ─────────────────────────────────────────────────────────

def test_redactor_returns_active_instance(initialized):
    r = fasten.redactor()
    assert r is _default._redactor
    assert isinstance(r, Redactor)


def test_redactor_round_trip(initialized):
    r = fasten.redactor()
    out = r.redact({"email": "a@b.com", "api_key": "sk-x"})
    assert out["email"] == "a@b.com"
    assert out["api_key"] == "***"


# ── #4 reader auto-init from globals ──────────────────────────────────────

def test_router_lazy_fetches_store_from_globals(initialized, mem_store):
    """router() must work without a separate init_reader(store, transport)."""
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from fasten.reader.router import router as build_router

    fasten.emit(code="USER_CREATED", target="u-42", actor="alice")
    fasten.emit(code="USER_CREATED", target="u-99", actor="bob")

    app = FastAPI()
    app.include_router(build_router(), prefix="/api/v1/logs")
    client = TestClient(app)

    resp = client.get("/api/v1/logs/audit?limit=10")
    assert resp.status_code == 200
    body = resp.json()
    assert "rows" in body
    assert body["total"] >= 2  # the two emits above
    assert "limit" in body and body["limit"] == 10
    assert "offset" in body and body["offset"] == 0


# ── #7 reader docstring shows Depends pattern as the lead-with example ────

def test_router_docstring_leads_with_depends_example():
    from fasten.reader import router as router_mod
    doc = router_mod.__doc__ or ""
    # The recommended (gated) usage block must mention Depends.
    assert "Depends" in doc, "router docstring must show Depends auth example"
    # And must call out the no-auth case as the secondary path.
    assert "trusted-network" in doc.lower() or "no-auth" in doc.lower()


# ── #8 /audit filters + pagination ────────────────────────────────────────

def test_audit_filter_by_actor(initialized):
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from fasten.reader.router import router as build_router

    fasten.emit(code="USER_CREATED", target="u-1", actor="alice")
    fasten.emit(code="USER_CREATED", target="u-2", actor="bob")
    fasten.emit(code="USER_CREATED", target="u-3", actor="alice")

    app = FastAPI()
    app.include_router(build_router(), prefix="/api/v1/logs")
    client = TestClient(app)

    resp = client.get("/api/v1/logs/audit?actor=alice")
    body = resp.json()
    assert body["total"] == 2
    assert all(r["actor"] == "alice" for r in body["rows"])


def test_audit_filter_by_target(initialized):
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from fasten.reader.router import router as build_router

    fasten.emit(code="USER_CREATED", target="u-7", actor="x")
    fasten.emit(code="USER_CREATED", target="u-9", actor="y")

    app = FastAPI()
    app.include_router(build_router(), prefix="/api/v1/logs")
    client = TestClient(app)

    resp = client.get("/api/v1/logs/audit?target=u-7")
    body = resp.json()
    assert body["total"] == 1
    assert body["rows"][0]["target"] == "u-7"


def test_audit_pagination_offset_and_total(initialized):
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from fasten.reader.router import router as build_router

    for i in range(7):
        fasten.emit(code="USER_CREATED", target=f"u-{i}", actor="alice")

    app = FastAPI()
    app.include_router(build_router(), prefix="/api/v1/logs")
    client = TestClient(app)

    page1 = client.get("/api/v1/logs/audit?limit=3&offset=0").json()
    page2 = client.get("/api/v1/logs/audit?limit=3&offset=3").json()
    page3 = client.get("/api/v1/logs/audit?limit=3&offset=6").json()

    assert page1["total"] == 7 and len(page1["rows"]) == 3
    assert page2["total"] == 7 and len(page2["rows"]) == 3
    assert page3["total"] == 7 and len(page3["rows"]) == 1
    # Pages must be disjoint by id.
    ids = {r["id"] for r in page1["rows"] + page2["rows"] + page3["rows"]}
    assert len(ids) == 7


# ── #9 init() docstring lists FASTEN_AUDIT_DSN ────────────────────────────

def test_init_docstring_documents_required_env_vars():
    doc = fasten.init.__doc__ or ""
    for name in ("FASTEN_SERVICE_ID", "FASTEN_NODE_ID", "FASTEN_AUDIT_DSN"):
        assert name in doc, f"init() docstring must mention {name}"


# ── SQLiteStore.query / count: filter parity ──────────────────────────────

def test_sqlite_query_actor_target_offset(mem_store):
    from datetime import datetime, timezone
    from fasten.attrs import AuditRow

    def make(seq, actor, target):
        return AuditRow(
            id=f"evt-{seq:020x}",
            origin_id=f"evt-{seq:020x}",
            monotonic_seq=seq,
            timestamp=datetime.now(timezone.utc),
            code="USER_CREATED",
            action="create",
            severity="info",
            service_id="svc",
            source_node_id="node",
            tenant_id=None,
            actor=actor,
            actor_kind="service",
            target=target,
            category="account",
            domain="user",
            method="sdk",
            request_id="abc123",
            detail={},
        )

    for i in range(5):
        mem_store.insert(make(i + 1, "alice" if i % 2 == 0 else "bob", f"u-{i}"))

    assert mem_store.count(actor="alice") == 3
    assert mem_store.count(target="u-2") == 1
    rows = mem_store.query(actor="alice", limit=2, offset=0)
    assert len(rows) == 2
    rows2 = mem_store.query(actor="alice", limit=2, offset=2)
    assert len(rows2) == 1
