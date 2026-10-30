"""Regression tests for /audit/doctor chain verification:

- Rows are traversed oldest-first (verify_chain requires it; s.query returns
  newest-first). Without the reverse(), a tampered row's seq is misreported
  or the whole chain reads clean when it isn't.
- A failed check reports breaks: null with error/reason fields, not the
  previous silent collapse to breaks: 0 that reads as green on a status
  page (finding #10 in the PR #59 review).
"""
from datetime import datetime, timedelta, timezone
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
    assert "simulated failure" not in chain["reason"]


def test_doctor_reports_breaks_null_when_no_rows_to_verify():
    """Empty store: verification didn't run, so breaks must be null (not 0).
    0 would mean "verified clean"; null means "didn't verify"."""
    _init()
    resp = _client().get("/api/v1/logs/audit/doctor")
    assert resp.status_code == 200
    chain = resp.json()["chain"]
    assert chain["verified"] is None
    assert chain["breaks"] is None


# ── clock step back ────────────────────────────────────────────────────────
def test_doctor_samples_by_seq_after_a_clock_step_back():
    """Seq 2 is stamped 90 s before seq 1. A newest-by-timestamp sample of 2
    rows is [3, 1], which skips seq 2 and reads as a break."""
    _init()
    t0 = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
    stamps = iter([t0, t0 - timedelta(seconds=90), t0 + timedelta(seconds=1)])

    class _Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return next(stamps)

    with patch("fasten.engine.datetime", _Clock):
        _emit_n(3)
    store = fasten.audit_store()
    with patch.object(store, "chain_tail", wraps=store.chain_tail) as tail:
        resp = _client().get("/api/v1/logs/audit/doctor")
    tail.assert_called_once()
    chain = resp.json()["chain"]
    assert chain["verified"] is True, chain
    assert chain["breaks"] == 0


def test_chain_tail_keeps_the_newest_rows_in_seq_order():
    _init()
    _emit_n(5)
    rows = fasten.audit_store().chain_tail("node", 3)
    assert [r.monotonic_seq for r in rows] == [3, 4, 5]


# ── store errors stay out of the response ──────────────────────────────────
def test_doctor_logs_store_errors_by_type_only():
    _init()
    _emit_n(1)
    secret = "connection to host=db.internal user=svc failed"
    store = fasten.audit_store()
    with patch.object(store, "count", side_effect=RuntimeError(secret)), \
            patch.object(store, "chain_tail", side_effect=RuntimeError(secret)), \
            patch.object(fasten.emitter._default, "_drainer_sys_log") as log:
        resp = _client().get("/api/v1/logs/audit/doctor")
    body = resp.json()
    assert secret not in resp.text
    assert body["store"]["last_error"] == "store check failed; see the service log"
    assert body["chain"]["reason"] == "chain check failed; see the service log"
    logged = [c.args for c in log.call_args_list]
    assert ("error", "doctor_check_failed",
            {"check": "store", "error_type": "RuntimeError"}) in logged
    assert ("error", "doctor_check_failed",
            {"check": "chain", "error_type": "RuntimeError"}) in logged


def test_reinit_with_a_sealing_store_clears_chain_unavailable():
    class _Unchained(SQLiteStore):
        allocate_and_insert_originated = None

    fasten.init(service_id="svc", node_id="node", audit_store=_Unchained(":memory:"),
                audit_store_failure_strategy="raise")
    _emit_n(1)
    assert _client().get("/api/v1/logs/audit/doctor").json()["chain"]["verified"] is False
    _init()
    _emit_n(1)
    assert _client().get("/api/v1/logs/audit/doctor").json()["chain"]["verified"] is True
