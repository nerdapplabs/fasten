"""Engine.init() error paths and accessors not covered by the conftest fixture."""
from __future__ import annotations

import logging

import pytest

import fasten
from fasten.emitter import _default


# init() error paths


def test_init_raises_when_service_id_missing(mem_store):
    with pytest.raises(RuntimeError, match="FASTEN_SERVICE_ID"):
        fasten.init(service_id="", node_id="n", audit_store=mem_store)


def test_init_raises_when_node_id_missing(mem_store):
    with pytest.raises(RuntimeError, match="FASTEN_NODE_ID"):
        fasten.init(service_id="svc", node_id="", audit_store=mem_store)


def test_init_stdout_only_when_no_audit_store_and_no_dsn(monkeypatch):
    """No store and no DSN: stdout-only mode, init() succeeds without persisting."""
    monkeypatch.delenv("FASTEN_AUDIT_DSN", raising=False)
    fasten.init(service_id="svc", node_id="n")
    assert _default._audit_store is None


def test_init_raises_on_invalid_strategy(mem_store):
    with pytest.raises(RuntimeError, match="audit_store_failure_strategy"):
        fasten.init(
            service_id="svc",
            node_id="n",
            audit_store=mem_store,
            audit_store_failure_strategy="bad",
        )


# init() with env-based DSN


def test_init_reads_dsn_from_env(monkeypatch):
    monkeypatch.setenv("FASTEN_AUDIT_DSN", "sqlite:///:memory:")
    fasten.init(service_id="svc", node_id="n")
    assert _default._audit_store is not None


# init() seq seeding from store


def test_post_restart_rows_continue_the_node_sequence(mem_store):
    """Post-restart rows never reuse a pre-restart monotonic_seq.

    The store allocates seq inside the insert transaction (spec §2.1).
    """
    from datetime import datetime, timezone
    from fasten.attrs import AuditRow
    from fasten.chain import verify_chain

    existing = AuditRow(
        id="evt-" + "0" * 16,
        origin_id="evt-" + "0" * 16,
        monotonic_seq=42,
        timestamp=datetime.now(timezone.utc),
        code="USER_CREATED", action="create", severity="info",
        service_id="svc", source_node_id="n", tenant_id=None,
        actor="sys", actor_kind="service", target="t",
        category="account", domain="user",
        method="sdk", request_id="r", detail={},
    )
    mem_store.insert(existing)

    fasten.init(
        service_id="svc",
        node_id="n",
        audit_store=mem_store,
        audit_store_failure_strategy="raise",
    )
    row = fasten.emit(code="USER_CREATED", target="after-restart")
    assert row.monotonic_seq > 42, (
        f"post-restart row reused seq {row.monotonic_seq}; the node sequence "
        "did not continue"
    )
    # A different service on the same node must also continue it, not restart.
    fasten.init(
        service_id="other-svc",
        node_id="n",
        audit_store=mem_store,
        audit_store_failure_strategy="raise",
    )
    second = fasten.emit(code="USER_CREATED", target="other-service")
    assert second.monotonic_seq > row.monotonic_seq

    sealed = [r for r in mem_store.query(limit=100) if r.hash]
    assert verify_chain(sealed).ok


# accessors


def test_audit_store_accessor_returns_store(initialized, mem_store):
    assert fasten.audit_store() is mem_store


def test_last_init_at_is_none_before_init():
    from fasten.emitter import last_init_at
    assert last_init_at() is None


def test_last_init_at_is_set_after_init(initialized):
    from fasten.emitter import last_init_at
    ts = last_init_at()
    assert ts is not None


# re-init flushes old drainer


def test_reinit_flushes_old_drainer_before_replacing(mem_store):
    """A second init() in queue mode flushes and stops the first drainer
    before installing the new one, so no rows are dropped."""
    import threading
    received = []
    lock = threading.Lock()

    class _RecStore:
        def insert(self, row) -> None:
            with lock:
                received.append(row)
        def count(self, **_) -> int:
            return len(received)
        def max_monotonic_seq(self, service_id=None, source_node_id=None) -> int:
            return 0

    store = _RecStore()
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=store,
        audit_store_failure_strategy="queue",
    )
    fasten.emit(code="USER_CREATED", target="u-1")

    # Re-init: old drainer should be flushed (row lands) then replaced.
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=store,
        audit_store_failure_strategy="queue",
    )
    assert fasten.flush(timeout=2.0)
    assert len(received) >= 1


# atexit flush


def test_atexit_flush_noop_when_no_drainer():
    """_atexit_flush must not raise when called with no drainer installed."""
    _default.reset_for_tests()
    _default._atexit_flush()  # must not raise


def test_atexit_flush_drains_pending(mem_store):
    """_atexit_flush must flush pending rows when a drainer is active."""
    import threading
    flushed = threading.Event()

    class _SlowStore:
        def __init__(self):
            self.rows = []
        def insert(self, row):
            self.rows.append(row)
            flushed.set()
        def count(self, **_):
            return len(self.rows)
        def max_monotonic_seq(self, service_id=None, source_node_id=None):
            return 0

    store = _SlowStore()
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=store,
        audit_store_failure_strategy="queue",
    )
    fasten.emit(code="USER_CREATED", target="u-1")
    _default._atexit_flush()
    assert len(store.rows) >= 1


# stdlib logger fallback


def test_log_falls_back_to_stdlib_before_init(caplog):
    """fasten.log.info() before init() must emit via stdlib (not stdout)."""
    with caplog.at_level(logging.INFO, logger="fasten"):
        fasten.log.info("startup_probe", component="test")
    assert any("startup_probe" in r.message for r in caplog.records)


# Datetime round-trip through the drainer (#36)


def test_issue_36_drainer_reconstructs_datetime_from_json_roundtrip():
    """In queue mode a row goes emit -> JSON -> fasten-core queue ->
    ``_insert_cb``, so ``timestamp`` arrives as a string. ``_insert_cb`` must
    turn it back into a datetime before building the AuditRow, or the store's
    ``_utc_iso(row.timestamp)`` fails and the row is dead-lettered.
    """
    from datetime import datetime as _datetime

    received: list = []

    class _CapturingStore:
        def insert(self, row) -> None:
            received.append(row)
        def count(self, **_) -> int:
            return len(received)
        def max_monotonic_seq(self, service_id=None, source_node_id=None) -> int:
            return 0

    fasten.init(
        service_id="svc", node_id="n",
        audit_store=_CapturingStore(),
        audit_store_failure_strategy="queue",
    )
    fasten.emit(code="USER_CREATED", target="u-1")
    assert fasten.flush(timeout=2.0), "flush should drain the row"

    assert len(received) == 1, (
        "row should land via the drainer's _insert_cb; if zero, the "
        "drainer dead-lettered the row after an exception"
    )
    row = received[0]
    assert isinstance(row.timestamp, _datetime), (
        f"row.timestamp must be a datetime after the drainer round-trip "
        f"(got {type(row.timestamp).__name__!r}); downstream "
        "_utc_iso(row.timestamp) reads .tzinfo and crashes on a str"
    )
    assert row.timestamp.tzinfo is not None, (
        "reconstructed timestamp must be tz-aware so PostgresStore / "
        "SQLiteStore can serialise it without a naive-datetime detour"
    )


# sync fallback with no drainer


def test_sync_fallback_emits_sys_event_on_queue_mode_no_drainer():
    """Queue mode with no drainer: emit() falls back to a sync insert, and a
    store failure writes audit_sync_fallback_failed to the drainer syslog."""
    from fasten.emitter import _default as eng

    class _BrokenStore:
        def insert(self, row) -> None:
            raise RuntimeError("store down")
        def count(self, **_) -> int:
            return 0
        def max_monotonic_seq(self, service_id=None, source_node_id=None) -> int:
            return 0

    fasten.init(
        service_id="svc", node_id="n",
        audit_store=_BrokenStore(),
        audit_store_failure_strategy="queue",
    )
    # Uninstall drainer to force the sync fallback path.
    eng._uninstall_drainer()

    captured: list = []
    t = fasten.transport()
    assert t is not None
    orig = t.write_drainer_syslog
    t.write_drainer_syslog = lambda r: (captured.append(r), orig(r))[-1]  # type: ignore[assignment,attr-defined]

    # emit() must not raise even though the store is broken.
    fasten.emit(code="USER_CREATED", target="u-1")

    events = [r.get("event") for r in captured]
    assert "audit_sync_fallback_failed" in events


def test_sync_fallback_marks_engine_degraded_even_for_adopter_store_without_notifier():
    """An adopter AuditRepository need not implement note_write_failure. A
    swallowed write still sets the engine flag, so completeness reports
    'store-degraded'."""
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from fasten.reader.router import router as build_router
    from fasten.emitter import _default as eng

    class _AdopterStore:
        """AuditRepository shape without note_write_failure / degraded."""
        def insert(self, row) -> None:
            raise RuntimeError("adopter store down")
        def count(self, **_) -> int:
            return 0
        def query(self, **_) -> list:
            return []
        def max_monotonic_seq(self, service_id=None, source_node_id=None) -> int:
            return 0

    fasten.init(
        service_id="svc", node_id="n",
        audit_store=_AdopterStore(),
        audit_store_failure_strategy="queue",
    )
    eng._uninstall_drainer()

    assert eng.audit_write_swallowed() is False
    fasten.emit(code="USER_CREATED", target="u-adopter")
    assert eng.audit_write_swallowed() is True

    app = FastAPI()
    app.include_router(build_router(dependencies=[]), prefix="/api/v1/logs")
    resp = TestClient(app).get("/api/v1/logs/audit?limit=1")
    assert resp.status_code == 200
    # The engine-side flag reaches the reader.
    assert resp.json()["completeness"] == {"audit": "store-degraded"}
