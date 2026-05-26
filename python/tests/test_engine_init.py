"""Coverage for Engine.init() error paths and accessor methods.

Tests in this file target the lines that fall outside the happy-path
fixture in conftest.py.
"""
from __future__ import annotations

import logging

import pytest

import fasten
from fasten.emitter import _default
from fasten.store.sqlite import SQLiteStore


# ── init() error paths ────────────────────────────────────────────────────


def test_init_raises_when_service_id_missing(mem_store):
    with pytest.raises(RuntimeError, match="FASTEN_SERVICE_ID"):
        fasten.init(service_id="", node_id="n", audit_store=mem_store)


def test_init_raises_when_node_id_missing(mem_store):
    with pytest.raises(RuntimeError, match="FASTEN_NODE_ID"):
        fasten.init(service_id="svc", node_id="", audit_store=mem_store)


def test_init_stdout_only_when_no_audit_store_and_no_dsn(monkeypatch):
    """No store and no DSN → stdout-only mode: init() succeeds without persisting.
    AuditStore is optional here, matching Go/JS/Rust."""
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


# ── init() with env-based DSN ─────────────────────────────────────────────


def test_init_reads_dsn_from_env(monkeypatch):
    monkeypatch.setenv("FASTEN_AUDIT_DSN", "sqlite:///:memory:")
    fasten.init(service_id="svc", node_id="n")
    assert _default._audit_store is not None


# ── init() seq seeding from store ─────────────────────────────────────────


def test_init_seeds_seq_from_store_max(mem_store):
    """Engine seeds _seq from max_monotonic_seq() so post-restart rows
    never duplicate (timestamp, seq) with pre-restart rows."""
    from datetime import datetime, timezone
    from fasten.attrs import AuditRow

    row = AuditRow(
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
    mem_store.insert(row)

    fasten.init(
        service_id="svc",
        node_id="n",
        audit_store=mem_store,
        audit_store_failure_strategy="raise",
    )
    assert _default._seq >= 42


# ── accessors ─────────────────────────────────────────────────────────────


def test_audit_store_accessor_returns_store(initialized, mem_store):
    assert fasten.audit_store() is mem_store


def test_last_init_at_is_none_before_init():
    from fasten.emitter import last_init_at
    assert last_init_at() is None


def test_last_init_at_is_set_after_init(initialized):
    from fasten.emitter import last_init_at
    ts = last_init_at()
    assert ts is not None


# ── re-init flushes old drainer ───────────────────────────────────────────


def test_reinit_flushes_old_drainer_before_replacing(mem_store):
    """Calling init() twice in queue mode must flush + stop the first drainer
    before installing the second one — no rows dropped."""
    import threading
    received = []
    lock = threading.Lock()

    class _RecStore:
        def insert(self, row) -> None:
            with lock:
                received.append(row)
        def count(self, **_) -> int:
            return len(received)
        def max_monotonic_seq(self) -> int:
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


# ── atexit flush ──────────────────────────────────────────────────────────


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
        def max_monotonic_seq(self):
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


# ── stdlib logger fallback ────────────────────────────────────────────────


def test_log_falls_back_to_stdlib_before_init(caplog):
    """fasten.log.info() before init() must emit via stdlib (not stdout)."""
    with caplog.at_level(logging.INFO, logger="fasten"):
        fasten.log.info("startup_probe", component="test")
    assert any("startup_probe" in r.message for r in caplog.records)


# ── issue #36: datetime round-trip through the drainer ───────────────────


def test_issue_36_drainer_reconstructs_datetime_from_json_roundtrip():
    """Regression for #36.

    fasten.emit -> JSON -> Rust queue -> Python _insert_cb is the
    audit row's round-trip through the drainer. After json.loads(),
    ``timestamp`` arrives as an ISO string, not a ``datetime``. Any
    store implementation that calls ``_utc_iso(row.timestamp)`` (both
    PostgresStore and SQLiteStore do) then crashes on
    ``AttributeError: 'str' has no attribute 'tzinfo'`` — and because
    ``_insert_cb`` swallows exceptions and returns 1, the row is
    silently dead-lettered after retry-exhaustion.

    The fix reconstructs the two datetime fields in ``_insert_cb``
    before constructing ``AuditRow``. This test exercises the
    queue-mode path end-to-end and asserts the store receives the
    row with a real datetime instance (not a str).
    """
    from datetime import datetime as _datetime

    received: list = []

    class _CapturingStore:
        def insert(self, row) -> None:
            received.append(row)
        def count(self, **_) -> int:
            return len(received)
        def max_monotonic_seq(self) -> int:
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
        "drainer dead-lettered the row after exception (the #36 bug)"
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


# ── sync fallback with no drainer ─────────────────────────────────────────


def test_sync_fallback_emits_sys_event_on_queue_mode_no_drainer():
    """Queue mode + drainer uninstalled → emit() falls back to sync insert.
    A sink failure must emit audit_sync_fallback_failed via drainer syslog."""
    from fasten.emitter import _default as eng

    class _BrokenStore:
        def insert(self, row) -> None:
            raise RuntimeError("store down")
        def count(self, **_) -> int:
            return 0
        def max_monotonic_seq(self) -> int:
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
