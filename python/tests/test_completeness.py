"""Per-stream completeness flags on every /logs read.

Each reader response declares, per stream, whether that stream is backed by
the durable ``store`` or a bounded ``ring``. By default audit is store-backed
and api/sys are ring-backed. The field sits alongside the existing response
keys.
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
    # Pagination keys are still present.
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
    """Marking a stream persisted makes its reads report ``store``."""
    client = _client(persist_streams=frozenset({"audit", "api", "sys"}))

    assert client.get("/api/v1/logs/sys").json()["completeness"] == {"sys": "store"}
    assert client.get("/api/v1/logs/api").json()["completeness"] == {"api": "store"}
    assert client.get("/api/v1/logs/audit").json()["completeness"] == {"audit": "store"}


def test_request_id_filter_coexists_with_completeness(initialized):
    """Filtering the api ring by request_id still narrows rows, and the flag
    is present on the filtered read."""
    transport = fasten.transport()
    transport.push_api({"method": "GET", "path": "/a", "request_id": "req-A"})
    transport.push_api({"method": "GET", "path": "/b", "request_id": "req-B"})

    body = _client().get("/api/v1/logs/api?request_id=req-A").json()
    assert len(body["rows"]) == 1, body["rows"]
    assert body["rows"][0]["request_id"] == "req-A"
    assert body["completeness"] == {"api": "ring"}


def test_empty_persist_streams_makes_audit_ring(initialized):
    """With an empty persist set even audit reports ``ring``; there is no
    special case for audit."""
    body = _client(persist_streams=frozenset()).get("/api/v1/logs/audit").json()
    assert body["completeness"] == {"audit": "ring"}


def test_stdout_only_audit_reports_ring():
    """Without an audit store (stdout-only mode) audit is not durable, so it
    reports ``ring``."""
    fasten.init(service_id="test-svc", node_id="test-node")  # no audit_store

    body = _client().get("/api/v1/logs/audit").json()
    assert body["completeness"] == {"audit": "ring"}
    assert "error" in body  # no store to read from


def test_completeness_present_on_uninitialised_reads():
    """Not-initialised error responses carry the flag too, so every response
    has the same shape. With no audit store, audit reports ``ring``."""
    client = _client()  # no `initialized` fixture, so globals are unset

    sys_body = client.get("/api/v1/logs/sys").json()
    assert sys_body["completeness"] == {"sys": "ring"}
    assert "error" in sys_body

    audit_body = client.get("/api/v1/logs/audit").json()
    assert audit_body["completeness"] == {"audit": "ring"}
    assert "error" in audit_body
    # The error path carries the same pagination keys as the success path.
    for key in ("rows", "total", "limit", "offset"):
        assert key in audit_body, f"audit error path lost {key!r}"
