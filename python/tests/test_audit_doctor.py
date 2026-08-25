"""Regression tests for /audit/doctor chain verification:

- Rows are traversed oldest-first (verify_chain requires it; s.query returns
  newest-first). Without the reverse(), a tampered row's seq is misreported
  or the whole chain reads clean when it isn't.
- A failed check reports breaks: null with error/reason fields, not the
  previous silent collapse to breaks: 0 that reads as green on a status
  page (finding #10 in the PR #59 review).
"""
from unittest.mock import patch

import pytest

import fasten
from fasten.store.sqlite import SQLiteStore


def _client():
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from fasten.reader.router import router as build_router

    app = FastAPI()
    app.include_router(build_router(dependencies=[]), prefix="/api/v1/logs")
    return TestClient(app)


def _init():
    fasten.init(
        service_id="svc", node_id="node",
        audit_store=SQLiteStore(":memory:"),
        audit_store_failure_strategy="raise",
    )


def _emit_n(n: int, code: str = "USER_CREATED"):
    for i in range(n):
        fasten.emit(
            code=code,
            target=f"u_{i}",
            actor="tester",
            actor_kind="service",
            detail={"i": i},
        )


# ── verify oldest-first ────────────────────────────────────────────────────
def test_doctor_verifies_chain_oldest_first_clean_chain():
    """Clean chain of 3 rows must verify OK. Without reverse(), depending on
    seq/hash semantics this could false-negative."""
    _init()
    _emit_n(3)
    resp = _client().get("/api/v1/logs/audit/doctor")
    assert resp.status_code == 200
    chain = resp.json()["chain"]
    assert chain["verified"] is True
    assert chain["breaks"] == 0


def test_doctor_pinpoints_tampered_row_at_correct_seq():
    """Tamper row seq=2 (middle) in a 3-row chain. verify_chain must report
    first_break_at=2. With newest-first ordering it would report the wrong
    seq or false-negative entirely."""
    _init()
    _emit_n(3)

    # Tamper directly in SQLite so verify_chain sees the change on next read.
    store = fasten.audit_store()
    conn = getattr(store, "_mem_conn", None)
    if conn is None:
        pytest.skip("cannot reach underlying connection for tamper")
    conn.execute("UPDATE audit_log SET detail = '{\"i\": 99}' WHERE monotonic_seq = 2")
    conn.commit()

    resp = _client().get("/api/v1/logs/audit/doctor")
    assert resp.status_code == 200
    chain = resp.json()["chain"]
    assert chain["verified"] is False
    assert chain["breaks"] == 1
    assert chain["first_break_at"] == 2


# ── surface errors instead of collapsing to breaks:0 ───────────────────────
def test_doctor_reports_error_when_verify_raises():
    """If verify_chain raises, chain block must include error/reason and
    keep breaks: null. Prior behaviour returned breaks: 0 which reads as
    green on status pages."""
    _init()
    _emit_n(1)

    with patch("fasten.engine.verify_chain", side_effect=RuntimeError("simulated failure")):
        resp = _client().get("/api/v1/logs/audit/doctor")

    assert resp.status_code == 200
    chain = resp.json()["chain"]
    assert chain["verified"] is None
    assert chain["breaks"] is None
    assert chain["error"] == "RuntimeError"
    assert "simulated failure" in chain["reason"]


def test_doctor_reports_breaks_null_when_no_rows_to_verify():
    """Empty store: verification didn't run, so breaks must be null (not 0).
    0 would mean "verified clean"; null means "didn't verify"."""
    _init()
    resp = _client().get("/api/v1/logs/audit/doctor")
    assert resp.status_code == 200
    chain = resp.json()["chain"]
    assert chain["verified"] is None
    assert chain["breaks"] is None
