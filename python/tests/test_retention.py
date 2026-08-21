"""FR1 retention (spec §1) — background age-based purger for stream stores.

Tests the standalone driver + the engine wiring. The driver is deterministic
(injected clock + inline wait); the engine test is a smoke that init()
actually spawns and shuts a purger down for a configured stream store.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

import fasten
from fasten.retention import (
    RetentionConfigError,
    parse_duration,
    start_purger,
)
from fasten.store.sqlite import SQLiteStore
from fasten.store.stream import StreamStore


# ── duration parser ──────────────────────────────────────────────────────

@pytest.mark.parametrize("s, want", [
    ("1s", timedelta(seconds=1)),
    ("30s", timedelta(seconds=30)),
    ("15m", timedelta(minutes=15)),
    ("24h", timedelta(hours=24)),
    ("7d", timedelta(days=7)),
    ("90d", timedelta(days=90)),
    (" 7d ", timedelta(days=7)),  # whitespace tolerated
])
def test_parse_duration_ok(s, want):
    assert parse_duration(s) == want


@pytest.mark.parametrize("s", [
    "", "7", "d", "0d", "-1d", "7x", "1d12h", "week", None,
    "3.5d",  # no fractional support in v1
])
def test_parse_duration_rejects(s):
    with pytest.raises((RetentionConfigError, TypeError)):
        parse_duration(s)


# ── purger loop ──────────────────────────────────────────────────────────

class _FakeStore:
    """Minimal stream-store shim capturing purge() invocations."""
    def __init__(self, raise_on_calls: list[int] | None = None):
        self.calls: list[str] = []
        self._raise_on = set(raise_on_calls or [])

    def purge(self, *, before: str) -> int:
        idx = len(self.calls)
        self.calls.append(before)
        if idx in self._raise_on:
            raise RuntimeError("simulated purge failure")
        return 0


def test_purger_runs_immediately_and_uses_now_minus_retention():
    """First tick fires without waiting the interval — operators must see the
    purge take effect on init, not an hour later. Cutoff must be exactly
    now - retention (checked to ms via the injected clock)."""
    store = _FakeStore()
    fixed_now = datetime(2026, 8, 21, 10, 0, 0, tzinfo=timezone.utc)
    stop = threading.Event()

    t = start_purger(
        store=store, stream="api",
        retention=timedelta(days=7),
        check_interval=timedelta(seconds=60),
        stop_event=stop,
        now_fn=lambda: fixed_now,
    )
    # Loop must have fired once by the time the process reaches this line —
    # small polling avoids a race without needing a long sleep.
    for _ in range(50):
        if store.calls:
            break
        time.sleep(0.01)
    stop.set()
    t.join(timeout=1.0)

    assert store.calls, "purger must fire the first purge before waiting"
    # Cutoff = now - 7d = 2026-08-14T10:00:00.000+00:00
    assert store.calls[0].startswith("2026-08-14T10:00:00")


def test_purger_errors_do_not_stop_the_loop():
    """A store.purge() raise on the first tick must not kill the thread —
    the next tick must still run. Piped through on_error so the caller can
    log the miss (Engine wires this into drainer_sys_log)."""
    store = _FakeStore(raise_on_calls=[0])  # first call raises
    stop = threading.Event()
    errors: list[tuple[str, str]] = []

    def _err(stream, e):
        errors.append((stream, f"{type(e).__name__}: {e}"))

    t = start_purger(
        store=store, stream="sys",
        retention=timedelta(hours=1),
        check_interval=timedelta(milliseconds=50),
        stop_event=stop, on_error=_err,
    )
    # Wait for at least a second call (the recovery).
    for _ in range(100):
        if len(store.calls) >= 2:
            break
        time.sleep(0.02)
    stop.set()
    t.join(timeout=1.0)

    assert len(store.calls) >= 2, "loop must survive a purge failure"
    assert errors and errors[0][0] == "sys"


def test_purger_shuts_down_within_interval_on_stop():
    """stop_event.set() must wake the sleep before the interval fires; a
    long interval must not delay shutdown."""
    store = _FakeStore()
    stop = threading.Event()
    t = start_purger(
        store=store, stream="api",
        retention=timedelta(hours=1),
        check_interval=timedelta(seconds=60),
        stop_event=stop,
    )
    time.sleep(0.05)  # let it run the first purge
    stop.set()
    t.join(timeout=1.0)
    assert not t.is_alive(), "stop must terminate the purger promptly"


# ── engine wiring ────────────────────────────────────────────────────────

def test_engine_init_spawns_purger_thread_for_configured_stream():
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=SQLiteStore(":memory:"),
        syslog_store=StreamStore(":memory:", table="syslog"),
        audit_store_failure_strategy="raise",
        retention_syslog="7d",
    )
    from fasten.emitter import _default as eng
    assert any(
        t.name == "fasten-retention-sys" and t.is_alive()
        for t in eng._retention_threads
    ), "retention_syslog=7d should spawn a sys purger thread"


def test_engine_init_no_retention_spawns_no_thread():
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=SQLiteStore(":memory:"),
        syslog_store=StreamStore(":memory:", table="syslog"),
        audit_store_failure_strategy="raise",
        # no retention_syslog / retention_api → no purger
    )
    from fasten.emitter import _default as eng
    assert eng._retention_threads == [], (
        "with no retention configured, no purger threads must be spawned"
    )


def test_engine_reinit_stops_previous_purgers(monkeypatch):
    """Repeat init on the same Engine must join the old threads before
    starting new ones — an orphan thread hammering a closed store is a
    real failure mode."""
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=SQLiteStore(":memory:"),
        syslog_store=StreamStore(":memory:", table="s1"),
        audit_store_failure_strategy="raise",
        retention_syslog="1h",
    )
    from fasten.emitter import _default as eng
    old_threads = list(eng._retention_threads)
    assert old_threads and old_threads[0].is_alive()

    # Re-init with a fresh store; the old thread must be joined.
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=SQLiteStore(":memory:"),
        syslog_store=StreamStore(":memory:", table="s2"),
        audit_store_failure_strategy="raise",
        retention_syslog="1h",
    )
    for t in old_threads:
        t.join(timeout=1.0)
        assert not t.is_alive(), "old retention thread must stop on re-init"

    # And a new one is now running.
    assert any(
        t.name == "fasten-retention-sys" and t.is_alive()
        for t in eng._retention_threads
    )


def test_engine_reads_retention_from_env(monkeypatch):
    monkeypatch.setenv("FASTEN_RETENTION_SYSLOG", "3d")
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=SQLiteStore(":memory:"),
        syslog_store=StreamStore(":memory:", table="env_syslog"),
        audit_store_failure_strategy="raise",
    )
    from fasten.emitter import _default as eng
    assert any(
        t.name == "fasten-retention-sys" and t.is_alive()
        for t in eng._retention_threads
    ), "FASTEN_RETENTION_SYSLOG=3d env var must wire the sys purger"
