"""FR4 (Phase 0): per-stream completeness flags on every /logs read.

Each reader response declares, per stream, whether its rows came from the
durable ``store`` or a bounded ``ring``. With persistence still off (the
default), audit is served from the store and api/sys from rings. The flag is
additive — existing response keys are untouched — so consumers can adopt it
now and Phase 1 (FR1) only flips the value once api/sys can persist.
"""
import pytest

import fasten  # noqa: F401


def _client(**router_kwargs):
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from fasten.reader.router import router as build_router

    app = FastAPI()
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
    """The resolver seam Phase 1 (FR1) flips: marking a stream persisted
    makes its reads report ``store`` instead of ``ring``."""
    client = _client(persist_streams=frozenset({"audit", "api", "sys"}))

    assert client.get("/api/v1/logs/sys").json()["completeness"] == {"sys": "store"}
    assert client.get("/api/v1/logs/api").json()["completeness"] == {"api": "store"}
    assert client.get("/api/v1/logs/audit").json()["completeness"] == {"audit": "store"}


def test_completeness_present_on_uninitialised_reads():
    """Even the not-initialised error paths carry the flag, so consumers can
    parse one uniform shape on every response."""
    client = _client()  # no `initialized` fixture → globals are unset

    sys_body = client.get("/api/v1/logs/sys").json()
    assert sys_body["completeness"] == {"sys": "ring"}
    assert "error" in sys_body

    audit_body = client.get("/api/v1/logs/audit").json()
    assert audit_body["completeness"] == {"audit": "store"}
    assert "error" in audit_body
