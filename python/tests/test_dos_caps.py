"""Size and depth caps:

  1) Per-row byte cap (FASTEN_MAX_DETAIL_BYTES, default 64 KiB). Oversize
     payloads are replaced with a `_truncated: true` marker.
  2) A dict nested 129+ deep does not crash emit(); it is stored as
     `<unredactable>`.
  3) `q=` max_length on /sys, /api, /search: 422 above 1024 chars.
"""
from __future__ import annotations

import pytest

import fasten
from fasten.redact import Redactor


# 1) byte cap

def test_redact_returns_truncated_marker_for_oversize_dict():
    r = Redactor()
    big = {"blob": "x" * 100_000}  # > 64 KiB default
    out = r.redact(big)
    assert out.get("_truncated") is True
    assert out.get("_max_detail_bytes") == 64 * 1024
    assert "blob" not in out  # original PII-suspect payload dropped


def test_redact_respects_env_override(monkeypatch):
    monkeypatch.setenv("FASTEN_MAX_DETAIL_BYTES", "256")
    r = Redactor()
    out = r.redact({"x": "y" * 500})
    assert out["_truncated"] is True
    assert out["_max_detail_bytes"] == 256


def test_redact_leaves_small_payload_alone():
    r = Redactor()
    out = r.redact({"user": "alice", "action": "login"})
    assert out.get("_truncated") is not True
    assert out == {"user": "alice", "action": "login"}


# 2) deep nesting

def _nested(depth: int) -> dict:
    root = {}
    cur = root
    for _ in range(depth):
        nxt = {}
        cur["n"] = nxt
        cur = nxt
    cur["leaf"] = True
    return root


def test_redact_returns_unredactable_on_deep_nesting():
    r = Redactor()
    # 200 > serde_json's 128 recursion limit, so fasten-core returns an error.
    out = r.redact(_nested(200))
    assert out.get("_redact_failed") is True
    assert out.get("_summary") == "<unredactable>"


def test_emit_survives_deep_nesting_and_stores_marker():
    from fasten.store.sqlite import SQLiteStore
    store = SQLiteStore(":memory:")
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=store,
        audit_store_failure_strategy="raise",
    )
    row = fasten.emit(
        code="USER_CREATED", target="u-1", actor="op",
        detail=_nested(200),
    )
    # emit does not raise, and the row carries the marker instead of the payload.
    assert row.detail.get("_redact_failed") is True


# 3) q= max_length on reader endpoints

def _client_search_enabled():
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from fasten.store.sqlite import SQLiteStore
    from fasten.store.stream import StreamStore
    from fasten.reader.router import router as build_router

    fasten.init(
        service_id="svc", node_id="n",
        audit_store=SQLiteStore(":memory:"),
        api_store=StreamStore(":memory:", table="api_dos"),
        syslog_store=StreamStore(":memory:", table="sys_dos"),
        audit_store_failure_strategy="raise",
        search_enabled=True,
    )
    app = FastAPI()
    app.include_router(build_router(dependencies=[]), prefix="/api/v1/logs")
    return TestClient(app)


def test_sys_q_over_1024_returns_422():
    c = _client_search_enabled()
    q = "x" * 1025
    r = c.get(f"/api/v1/logs/sys?q={q}&since=2020-01-01T00:00:00Z")
    assert r.status_code == 422


def test_search_q_over_1024_returns_422():
    c = _client_search_enabled()
    q = "x" * 1025
    r = c.get(f"/api/v1/logs/search?q={q}&since=2020-01-01T00:00:00Z")
    assert r.status_code == 422


def test_api_q_over_1024_returns_422():
    # /api rejects any q= with 400, but FastAPI's query validation runs
    # first, so an oversized q gets 422.
    c = _client_search_enabled()
    q = "x" * 1025
    r = c.get(f"/api/v1/logs/api?q={q}")
    assert r.status_code == 422


def test_sys_q_at_limit_accepted():
    c = _client_search_enabled()
    q = "x" * 1024
    r = c.get(f"/api/v1/logs/sys?q={q}&since=2020-01-01T00:00:00Z")
    # 200 with no matches. The cap includes 1024.
    assert r.status_code == 200
