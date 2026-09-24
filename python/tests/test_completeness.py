"""Per-stream completeness flags on every /logs read.

Each reader response declares, per stream, whether that stream is backed by
the durable ``store`` or a bounded ``ring``. With persistence still off (the
default), audit is classified as store-backed and api/sys as ring-backed. The
flag is additive — existing response keys are untouched — so consumers can
adopt it now; Phase 1 only flips the value once api/sys can persist.
"""
import pytest

import fasten  # noqa: F401


def _client(**router_kwargs):
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from fasten.reader.router import router as build_router

    app = FastAPI()
    router_kwargs.setdefault("dependencies", [])
    app.include_router(build_router(**router_kwargs), prefix="/api/v1/logs")
    return TestClient(app)


def test_audit_reports_store(initialized):
    client = _client()
    fasten.emit(code="USER_CREATED", target="u-1", actor="alice")

    body = client.get("/api/v1/logs/audit").json()
    assert body["completeness"] == {"audit": "store"}
    # Additive only — existing pagination keys must survive.
    for key in ("rows", "total", "limit", "offset"):
        assert key in body, f"audit response lost {key!r}"


def test_sys_reports_ring(initialized):
    client = _client()
    body = client.get("/api/v1/logs/sys").json()
    assert body["completeness"] == {"sys": "ring"}
    assert "rows" in body


def test_api_reports_ring(initialized):
    client = _client()
    body = client.get("/api/v1/logs/api").json()
    assert body["completeness"] == {"api": "ring"}
    assert "rows" in body


def test_persist_streams_override_flips_to_store(initialized):
    """The resolver seam Phase 1 flips: marking a stream persisted makes its
    reads report ``store`` instead of ``ring``."""
    client = _client(persist_streams=frozenset({"audit", "api", "sys"}))

    assert client.get("/api/v1/logs/sys").json()["completeness"] == {"sys": "store"}
    assert client.get("/api/v1/logs/api").json()["completeness"] == {"api": "store"}
    assert client.get("/api/v1/logs/audit").json()["completeness"] == {"audit": "store"}


def test_request_id_filter_coexists_with_completeness(initialized):
    """The added completeness field must not shadow the pre-existing
    request_id query param: filtering the api ring still narrows rows, and the
    flag is still present on the filtered read."""
    transport = fasten.transport()
    transport.push_api({"method": "GET", "path": "/a", "request_id": "req-A"})
    transport.push_api({"method": "GET", "path": "/b", "request_id": "req-B"})

    body = _client().get("/api/v1/logs/api?request_id=req-A").json()
    assert len(body["rows"]) == 1, body["rows"]
    assert body["rows"][0]["request_id"] == "req-A"
    assert body["completeness"] == {"api": "ring"}


def test_empty_persist_streams_makes_audit_ring(initialized):
    """`_source` is purely set-driven — with an empty persist set even audit
    reports ``ring``, proving there is no hardcoded audit special-case."""
    body = _client(persist_streams=frozenset()).get("/api/v1/logs/audit").json()
    assert body["completeness"] == {"audit": "ring"}


def test_stdout_only_audit_reports_ring():
    """Initialised without an audit store (stdout-only mode): audit is not
    durable, so its completeness is ``ring``. The reader must not advertise a
    ``store`` that was never configured."""
    fasten.init(service_id="test-svc", node_id="test-node")  # no audit_store

    body = _client().get("/api/v1/logs/audit").json()
    assert body["completeness"] == {"audit": "ring"}
    assert "error" in body  # no store to read from — but honestly flagged ring


def test_completeness_present_on_uninitialised_reads():
    """Even the not-initialised error paths carry the flag, so consumers can
    parse one uniform shape on every response. With no audit store configured,
    audit is honestly ``ring`` — it must not claim a durable ``store`` while
    simultaneously erroring that nothing is stored."""
    client = _client()  # no `initialized` fixture → globals are unset

    sys_body = client.get("/api/v1/logs/sys").json()
    assert sys_body["completeness"] == {"sys": "ring"}
    assert "error" in sys_body

    audit_body = client.get("/api/v1/logs/audit").json()
    assert audit_body["completeness"] == {"audit": "ring"}
    assert "error" in audit_body
    # Uniform shape: the audit error path carries the same pagination keys as
    # its success path, not just rows/total.
    for key in ("rows", "total", "limit", "offset"):
        assert key in audit_body, f"audit error path lost {key!r}"
