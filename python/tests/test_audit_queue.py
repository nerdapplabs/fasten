"""Queue mode: rows go through the fasten-core drainer and the store seals them.

Vectors from spec/drainer-conformance.md §7.
"""
import faulthandler
import json
import os
import signal
import sqlite3
import sys
import threading
import time
import warnings

import pytest

import fasten
from fasten.emitter import _default
from fasten.store.sqlite import SQLiteStore
from fasten.store.stream import StreamStore


class FlakyStore:
    """SQLiteStore that fails its first ``fail`` allocating inserts."""

    def __init__(self, path, fail=0, delay=0.0):
        self.inner = SQLiteStore(path)
        self.fail = fail
        self.delay = delay
        self.attempts = 0
        self.lock = threading.Lock()

    def allocate_and_insert_originated(self, row):
        with self.lock:
            self.attempts += 1
            failing = self.attempts <= self.fail
        if self.delay:
            time.sleep(self.delay)
        if failing:
            raise OSError("store down")
        return self.inner.allocate_and_insert_originated(row)

    def __getattr__(self, name):
        return getattr(self.inner, name)


def _init(store, **kw):
    kw = {"queue_retry_jitter": False, "queue_retry_initial_ms": 10,
          "queue_retry_max_ms": 50, **kw}
    fasten.init(service_id="svc", node_id="node", audit_store=store,
                audit_store_failure_strategy="queue", **kw)


def _rows(store):
    return store.inner.query(limit=100)


def _signal_drainer_close(monkeypatch):
    """Return an event set once fasten-core's drainer_close has returned."""
    from fasten import core_ffi
    closed, close = threading.Event(), core_ffi.drainer_close

    def signalling(handle):
        close(handle)
        closed.set()
    monkeypatch.setattr(core_ffi, "drainer_close", signalling)
    return closed


def _hold_first_insert(store):
    """Block the store's first insert until the returned event is set, so
    the queue fills to a known depth."""
    gate, insert = threading.Event(), store.allocate_and_insert_originated
    first = [True]

    def held(row):
        if first[0]:
            first[0] = False
            assert gate.wait(5)
        return insert(row)
    store.allocate_and_insert_originated = held
    return gate


def _wait_for_attempts(store, n):
    deadline = time.monotonic() + 5
    while store.attempts < n and time.monotonic() < deadline:
        time.sleep(0.005)
    assert store.attempts >= n


def _wait_in_backoff():
    """Wait until a failed row is in backoff, not still inside its attempt."""
    deadline = time.monotonic() + 5
    while fasten.queue_stats()["retry_count_active"] < 1 and time.monotonic() < deadline:
        time.sleep(0.005)
    assert fasten.queue_stats()["retry_count_active"] >= 1


def test_v1_happy_path(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"))
    _init(store)
    fasten.emit(code="USER_CREATED", target="u-1")
    fasten.emit(code="USER_CREATED", target="u-2")
    assert fasten.flush(timeout=1.0)
    assert len(_rows(store)) == 2


def test_v4_outage_then_recovery(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"), fail=2)
    _init(store)
    fasten.emit(code="USER_CREATED", target="u-1")
    assert fasten.flush(timeout=2.0)
    assert len(_rows(store)) == 1
    assert store.attempts >= 3
    assert fasten.queue_stats()["dead_lettered_total"] == 0


def test_v5_queue_stats_after_drain(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"))
    _init(store, queue_capacity=100)
    fasten.emit(code="USER_CREATED", target="u-1")
    assert fasten.flush(timeout=1.0)
    s = fasten.queue_stats()
    assert s["depth"] == 0 and s["capacity"] == 100 and s["high_water"] >= 1
    assert s["drained_total"] == 1 and s["retry_count_active"] == 0
    assert s["last_error"] is None


def test_v7_high_water_never_decreases(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"))
    gate = _hold_first_insert(store)
    _init(store, queue_capacity=10)
    for i in range(5):
        fasten.emit(code="USER_CREATED", target=f"u-{i}")
    gate.set()
    assert fasten.flush(timeout=1.0)
    hw1 = fasten.queue_stats()["high_water"]
    assert hw1 == 5
    fasten.emit(code="USER_CREATED", target="u-5")
    assert fasten.flush(timeout=1.0)
    assert fasten.queue_stats()["high_water"] >= hw1


def test_full_queue_loses_nothing_under_concurrent_emits(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"), delay=0.02)
    _init(store, queue_capacity=2)
    threads = [threading.Thread(target=fasten.emit,
                                kwargs={"code": "USER_CREATED", "target": f"u-{i}"})
               for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
    assert fasten.flush(timeout=5.0)
    assert len(_rows(store)) == 8
    assert fasten.queue_stats()["high_water"] <= 2


def test_v10_dead_letter_after_max_attempts(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"), fail=10**6)
    _init(store, queue_drain_max_attempts=3)
    fasten.emit(code="USER_CREATED", target="u-1")
    fasten.flush(timeout=2.0)
    s = fasten.queue_stats()
    assert s["dead_lettered_total"] == 1 and s["depth"] == 0
    assert store.attempts == 3
    assert _default._drainer.pending == {}
    assert _default.audit_write_swallowed()


def test_drained_rows_are_sealed_and_verify(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"), fail=1)
    _init(store)
    emitted = [fasten.emit(code="USER_CREATED", target=f"u-{i}") for i in range(3)]
    assert fasten.flush(timeout=2.0)
    rows = sorted(_rows(store), key=lambda r: r.monotonic_seq)
    assert [r.monotonic_seq for r in rows] == [1, 2, 3]
    assert [r.id for r in rows] == [r.id for r in emitted]  # emit order
    assert all(r.hash for r in rows)
    assert fasten.verify_chain(rows).ok
    # emit() cannot know the seal yet (spec §8).
    assert all(r.hash == "" for r in emitted)


def test_sealed_line_reaches_stdout(tmp_path, capsys):
    store = FlakyStore(str(tmp_path / "a.db"))
    _init(store)
    row = fasten.emit(code="USER_CREATED", target="u-1")
    assert fasten.flush(timeout=1.0)
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()
             if line.startswith("{")]
    audit = [e for e in lines if e.get("shape") == "audit" and e.get("id") == row.id]
    assert [bool(e["hash"]) for e in audit] == [False, True]  # phase 1, then phase 2


def test_raise_mode_is_unchanged(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"), fail=1)
    fasten.init(service_id="svc", node_id="node", audit_store=store,
                audit_store_failure_strategy="raise")
    with pytest.raises(fasten.AuditStoreError, match="store down"):          # V-2
        fasten.emit(code="USER_CREATED", target="u-1")
    assert fasten.queue_stats() is None                                        # V-3
    assert fasten.flush(timeout=0.1)                                           # V-6
    row = fasten.emit(code="USER_CREATED", target="u-2")
    assert row.hash


def _emit_concurrently(n):
    threads = [threading.Thread(target=fasten.emit,
                                kwargs={"code": "USER_CREATED", "target": f"u-{i}"})
               for i in range(n)]
    for t in threads:
        t.start()
    return threads


def test_stopping_the_drainer_stores_rows_still_waiting(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"), delay=0.2)
    _init(store, queue_capacity=1)
    threads = _emit_concurrently(4)
    _wait_for_attempts(store, 1)    # one row draining, the rest blocked
    _default._uninstall_drainer()
    for t in threads:
        t.join(timeout=5)
    assert len(_rows(store)) == 4
    assert not _default.audit_write_swallowed()


def test_rows_failing_at_shutdown_mark_the_engine_degraded(tmp_path):
    # At stop, rows queued behind a retrying row get one attempt each.
    store = FlakyStore(str(tmp_path / "a.db"), fail=1)
    good = store.allocate_and_insert_originated

    def insert(row):
        if row.target.startswith("bad"):
            raise OSError("store down")
        return good(row)
    store.allocate_and_insert_originated = insert
    _init(store, queue_retry_initial_ms=10_000, queue_retry_max_ms=10_000)
    for target in ("good", "bad-1", "bad-2"):
        fasten.emit(code="USER_CREATED", target=target)
    _wait_for_attempts(store, 1)    # "good" failed once and is in backoff
    _default._uninstall_drainer()
    assert [r.target for r in _rows(store)] == ["good"]
    assert _default.audit_write_swallowed()


class _StoreAborted(BaseException):
    pass


def test_base_exception_from_the_store_is_a_failed_insert(tmp_path):
    # Escaping the ctypes callback, it would make the callback return 0,
    # which fasten-core reads as stored.
    store = FlakyStore(str(tmp_path / "a.db"))
    good, calls = store.allocate_and_insert_originated, []

    def insert(row):
        calls.append(row.id)
        if len(calls) == 1:
            raise _StoreAborted()
        return good(row)
    store.allocate_and_insert_originated = insert
    _init(store)
    row = fasten.emit(code="USER_CREATED", target="u-1")
    assert fasten.flush(timeout=2.0)
    assert calls == [row.id, row.id]
    assert [r.id for r in _rows(store)] == [row.id]


def test_stdout_failure_after_store_is_not_a_failed_insert(tmp_path, monkeypatch):
    store = FlakyStore(str(tmp_path / "a.db"))
    _init(store)
    fasten.emit(code="USER_CREATED", target="u-1")   # phase 1 before the patch
    def broken(row):
        raise OSError("stdout closed")
    monkeypatch.setattr(_default._stdout, "write_audit", broken)
    assert fasten.flush(timeout=2.0)
    assert len(_rows(store)) == 1
    assert fasten.queue_stats()["dead_lettered_total"] == 0
    assert not _default.audit_write_swallowed()


def test_v12_emit_after_drainer_stopped_is_stored(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"))
    _init(store)
    _default._uninstall_drainer()
    row = fasten.emit(code="USER_CREATED", target="u-1")
    assert row.hash                 # stored synchronously
    assert len(_rows(store)) == 1
    events = _sys_events()
    assert "audit_drain_abandoned" in events and "audit_drain_stored_inline" in events


def test_max_attempts_zero_uses_the_default(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"), fail=2)
    _init(store, queue_drain_max_attempts=0)
    fasten.emit(code="USER_CREATED", target="u-1")
    assert fasten.flush(timeout=2.0)
    assert len(_rows(store)) == 1
    assert not _default.audit_write_swallowed()


def test_emits_racing_uninstall_are_all_stored(tmp_path):
    for n in range(20):
        store = FlakyStore(str(tmp_path / f"{n}.db"), delay=0.001)
        _init(store, queue_capacity=2)
        threads = _emit_concurrently(16)
        _default._uninstall_drainer()
        for t in threads:
            t.join(timeout=5)
        assert len(_rows(store)) == 16, f"round {n}"
        assert not _default.audit_write_swallowed()


def test_old_store_losing_rows_does_not_degrade_the_new_one(tmp_path):
    old = FlakyStore(str(tmp_path / "old.db"), fail=10**6)
    _init(old, queue_retry_initial_ms=10_000, queue_retry_max_ms=10_000)
    fasten.emit(code="USER_CREATED", target="u-1")
    _wait_for_attempts(old, 1)      # first attempt failed, now in backoff
    new = FlakyStore(str(tmp_path / "new.db"))
    _init(new)
    assert not _default.audit_write_swallowed()
    assert _rows(new) == [] and old.attempts >= 3   # the row stayed with the old store



def test_uninstall_waits_for_an_emit_still_using_the_handle(tmp_path, monkeypatch):
    from fasten import core_ffi
    store = FlakyStore(str(tmp_path / "a.db"))
    _init(store)
    entered, release, closed_early = threading.Event(), threading.Event(), []
    enqueue, store_close = core_ffi.drainer_enqueue, core_ffi.store_close

    def slow_enqueue(handle, row_json):
        entered.set()
        release.wait(5)
        return enqueue(handle, row_json)

    def recording_close(handle):
        closed_early.append(not release.is_set())
        store_close(handle)

    monkeypatch.setattr(core_ffi, "drainer_enqueue", slow_enqueue)
    monkeypatch.setattr(core_ffi, "store_close", recording_close)
    emitter = threading.Thread(target=fasten.emit,
                               kwargs={"code": "USER_CREATED", "target": "u-1"})
    emitter.start()
    assert entered.wait(5)
    closed = _signal_drainer_close(monkeypatch)
    closer = threading.Thread(target=_default._uninstall_drainer)
    closer.start()
    assert closed.wait(5)           # retire now waits for the emit
    time.sleep(0.05)                # let it reach the wait; store_close must not run yet
    release.set()
    emitter.join(timeout=5)
    closer.join(timeout=5)
    assert closed_early == [False]
    assert len(_rows(store)) == 1


@pytest.mark.parametrize("name, bad", [
    ("queue_capacity", -1), ("queue_capacity", 2**64),
    ("queue_retry_initial_ms", -1), ("queue_retry_max_ms", -1),
    ("queue_drain_max_attempts", -1), ("queue_drain_max_attempts", 2**32),
])
def test_out_of_range_queue_settings_are_rejected(name, bad):
    with pytest.raises(RuntimeError, match=name):
        fasten.init_config(service_id="svc", node_id="node", **{name: bad})


def test_row_emitted_during_reinit_goes_to_the_new_store(tmp_path, monkeypatch):
    # An emit while init() is still running must not reach the old drainer
    # once the engine has switched to the new store and cleared its flag;
    # with no drainer installed yet it is stored inline.
    import fasten.engine as engine_mod
    old = FlakyStore(str(tmp_path / "old.db"))
    _init(old)
    new = FlakyStore(str(tmp_path / "new.db"), fail=10**6)
    transport = engine_mod.StdoutTransport

    def emit_during_init(*args, **kwargs):
        fasten.emit(code="USER_CREATED", target="during-reinit")
        return transport(*args, **kwargs)

    monkeypatch.setattr(engine_mod, "StdoutTransport", emit_during_init)
    _init(new, queue_drain_max_attempts=2)
    monkeypatch.setattr(engine_mod, "StdoutTransport", transport)
    fasten.flush(timeout=2.0)
    assert _rows(old) == []
    assert new.attempts >= 1
    assert _default.audit_write_swallowed()


def test_rows_stored_at_stop_are_reported(tmp_path, capsys):
    store = FlakyStore(str(tmp_path / "a.db"), fail=2)
    _init(store, queue_retry_initial_ms=10_000, queue_retry_max_ms=10_000)
    row = fasten.emit(code="USER_CREATED", target="u-1")
    _wait_in_backoff()              # first attempt failed
    _default._uninstall_drainer()   # one more attempt fails; stored inline
    assert len(_rows(store)) == 1
    err = [json.loads(line) for line in capsys.readouterr().err.splitlines()
           if line.startswith("{")]
    assert [e["row_ids"] for e in err if e.get("event") == "audit_drain_recovered_at_stop"] == [
        [row.id]]
    # Stored after all, so not also reported as dead-lettered or lost.
    assert not [e for e in err if e.get("event") in ("audit_drain_dead_letter",
                                                     "audit_drain_lost_at_stop")]



def test_refused_enqueue_during_reinit_stays_with_the_old_store(tmp_path, monkeypatch):
    from fasten import core_ffi
    old = FlakyStore(str(tmp_path / "old.db"))
    _init(old)
    entered, release = threading.Event(), threading.Event()
    enqueue = core_ffi.drainer_enqueue

    def slow_enqueue(handle, row_json):
        entered.set()
        release.wait(5)
        return enqueue(handle, row_json)

    monkeypatch.setattr(core_ffi, "drainer_enqueue", slow_enqueue)
    emitter = threading.Thread(target=fasten.emit,
                               kwargs={"code": "USER_CREATED", "target": "u-1"})
    emitter.start()
    assert entered.wait(5)
    new = FlakyStore(str(tmp_path / "new.db"))
    closed = _signal_drainer_close(monkeypatch)
    reinit = threading.Thread(target=_init, args=(new,))
    reinit.start()
    assert closed.wait(5)           # old drainer closed; the emit is still in enqueue
    release.set()
    emitter.join(timeout=5)
    reinit.join(timeout=5)
    assert len(_rows(old)) == 1 and _rows(new) == []


def test_callback_for_a_settled_row_does_not_retry(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"))
    _init(store)
    assert _default._drainer.callback(b'{"id": "evt-not-pending"}', 0) == 0
    assert "audit_drain_row_not_pending" in _sys_events()


def test_refused_enqueue_is_stored_in_the_drainers_store(tmp_path, monkeypatch):
    from fasten import core_ffi
    a = FlakyStore(str(tmp_path / "a.db"))
    _init(a)
    b = FlakyStore(str(tmp_path / "b.db"))
    monkeypatch.setattr(_default, "_audit_store", b)

    def refused(handle, row_json):
        raise RuntimeError("fasten_drainer_enqueue: drainer stopped")

    monkeypatch.setattr(core_ffi, "drainer_enqueue", refused)
    fasten.emit(code="USER_CREATED", target="u-1")
    assert len(_rows(a)) == 1 and _rows(b) == []


def test_row_failing_at_stop_is_reported(tmp_path, capsys):
    store = FlakyStore(str(tmp_path / "a.db"), fail=10**6)
    _init(store, queue_retry_initial_ms=10_000, queue_retry_max_ms=10_000)
    row = fasten.emit(code="USER_CREATED", target="u-1")
    _wait_for_attempts(store, 1)
    _default._uninstall_drainer()
    err = [json.loads(line) for line in capsys.readouterr().err.splitlines()
           if line.startswith("{")]
    assert [e["row_id"] for e in err if e.get("event") == "audit_drain_lost_at_stop"] == [row.id]
    assert not [e for e in err if e.get("event") in ("audit_drain_dead_letter",
                                                     "audit_drain_recovered_at_stop")]
    assert _default.audit_write_swallowed()


def test_queue_mode_without_a_store_installs_no_drainer(tmp_path):
    _init(FlakyStore(str(tmp_path / "a.db")))
    fasten.init(service_id="svc", node_id="node", audit_store_failure_strategy="queue")
    assert _default._drainer is None


def test_reinit_keeps_the_flag_for_the_same_store(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"), fail=10**6)
    _init(store, queue_drain_max_attempts=2)
    fasten.emit(code="USER_CREATED", target="u-1")
    fasten.flush(timeout=2.0)
    _init(store)
    assert _default.audit_write_swallowed()
    _init(FlakyStore(str(tmp_path / "b.db")))
    assert not _default.audit_write_swallowed()


def test_reinit_onto_the_same_database_keeps_the_flag(tmp_path, monkeypatch):
    # FASTEN_AUDIT_DSN builds a new store object on every init.
    monkeypatch.setattr(_default, "_reinit_timeout", 1.0, raising=False)
    path = str(tmp_path / "a.db")
    _init(FlakyStore(path, fail=10**6), queue_retry_initial_ms=10_000, queue_retry_max_ms=10_000)
    fasten.emit(code="USER_CREATED", target="u-1")
    _wait_in_backoff()
    _init(SQLiteStore(path))        # the old drainer loses its row at stop
    assert _default.audit_write_swallowed()


def test_refused_enqueue_stored_inline_is_reported(tmp_path, monkeypatch, capsys):
    from fasten import core_ffi
    store = FlakyStore(str(tmp_path / "a.db"))
    _init(store)

    def refused(handle, row_json):
        raise RuntimeError("fasten_drainer_enqueue: drainer stopped")

    monkeypatch.setattr(core_ffi, "drainer_enqueue", refused)
    row = fasten.emit(code="USER_CREATED", target="u-1")
    err = [json.loads(line) for line in capsys.readouterr().err.splitlines()
           if line.startswith("{")]
    assert any(e.get("event") == "audit_drain_stored_inline" and e.get("row_id") == row.id
               for e in err)


def _sys_events():
    return [r.get("event") for r in reversed(fasten.transport().query_syslog(limit=1000))]  # oldest first


def test_v8_threshold_events_are_debounced(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"))
    gate = _hold_first_insert(store)
    _init(store, queue_capacity=10)
    for t in _emit_concurrently(8):
        t.join(timeout=5)
    gate.set()                      # depth rose 1..8 with no dip below 50 %
    assert fasten.flush(timeout=5.0)
    events = _sys_events()
    assert events.count("audit_queue_high_water") == 1
    assert events.count("audit_queue_near_full") == 1


def test_v10_dead_letter_reaches_the_sys_stream(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"), fail=10**6)
    _init(store, queue_drain_max_attempts=3, queue_retry_initial_ms=1, queue_retry_max_ms=5)
    fasten.emit(code="USER_CREATED", target="u-1")
    fasten.flush(timeout=2.0)
    assert "audit_drain_dead_letter" in _sys_events()


def test_v11_drain_state_events_fire_in_order(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"), fail=5)
    _init(store, queue_retry_initial_ms=10, queue_retry_max_ms=20)
    fasten.emit(code="USER_CREATED", target="u-1")
    assert fasten.flush(timeout=5.0)
    drain = [e for e in _sys_events() if e in
             ("audit_drain_failed", "audit_drain_degraded", "audit_drain_recovered")]
    assert drain == ["audit_drain_failed", "audit_drain_degraded", "audit_drain_recovered"]


def test_v12_emit_racing_stop_is_reported(tmp_path, monkeypatch):
    from fasten import core_ffi
    store = FlakyStore(str(tmp_path / "a.db"))
    _init(store)
    enqueue = core_ffi.drainer_enqueue
    d = _default._drainer

    def after_close(handle, row_json):
        core_ffi.drainer_close(d.handle)   # stop lands between lookup and enqueue
        return enqueue(handle, row_json)

    monkeypatch.setattr(core_ffi, "drainer_enqueue", after_close)
    fasten.emit(code="USER_CREATED", target="u-1")
    monkeypatch.setattr(core_ffi, "drainer_enqueue", enqueue)
    assert len(_rows(store)) == 1
    events = _sys_events()
    assert "audit_drain_abandoned" in events and "audit_drain_stored_inline" in events


def test_enqueue_refused_without_core_event_is_reported(tmp_path, monkeypatch):
    from fasten import core_ffi
    store = FlakyStore(str(tmp_path / "a.db"))
    _init(store)

    def not_installed(handle, row_json):
        raise core_ffi.EnqueueError(4, "drainer not installed")

    monkeypatch.setattr(core_ffi, "drainer_enqueue", not_installed)
    fasten.emit(code="USER_CREATED", target="u-1")
    events = _sys_events()
    assert "audit_drain_abandoned" in events and "audit_drain_stored_inline" in events


def test_doctor_queue_block_reports_the_dead_letter(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from fasten.reader.router import router as build_router
    app = FastAPI()
    app.include_router(build_router(dependencies=[]), prefix="/api/v1/logs")
    store = FlakyStore(str(tmp_path / "a.db"), fail=10**6)
    _init(store, queue_drain_max_attempts=2, queue_retry_initial_ms=1, queue_retry_max_ms=5)
    fasten.emit(code="USER_CREATED", target="u-1")
    fasten.flush(timeout=2.0)
    queue = TestClient(app).get("/api/v1/logs/audit/doctor").json()["queue"]
    assert queue["dead_lettered_total"] == 1 and queue["drained_total"] == 0



def test_old_drainer_events_keep_the_old_config(tmp_path, capsys):
    old = FlakyStore(str(tmp_path / "old.db"), fail=10**6)
    _init(old, queue_retry_initial_ms=10_000, queue_retry_max_ms=10_000)
    fasten.emit(code="USER_CREATED", target="u-1")
    _wait_for_attempts(old, 1)
    fasten.init(service_id="svc-b", node_id="node", audit_store=FlakyStore(str(tmp_path / "b.db")),
                audit_store_failure_strategy="queue")
    err = [json.loads(line) for line in capsys.readouterr().err.splitlines()
           if line.startswith("{")]
    lost = [e for e in err if e.get("event") == "audit_drain_lost_at_stop"]
    assert lost and all(e["service_id"] == "svc" for e in lost)
    assert "audit_drain_lost_at_stop" not in _sys_events()   # not in the new stream


def test_emits_while_the_old_drainer_retires_are_queued(tmp_path, monkeypatch):
    # init swaps in the new drainer before it retires the old one, so a row
    # emitted while the old one drains is retried, not written once inline.
    from fasten import core_ffi
    _init(FlakyStore(str(tmp_path / "old.db")))
    new = FlakyStore(str(tmp_path / "new.db"), fail=2)
    flush, emitted = core_ffi.drainer_flush, []

    def emit_while_retiring(handle, timeout_ms):
        emitted.append(fasten.emit(code="USER_CREATED", target="during-retire"))
        return flush(handle, timeout_ms)

    monkeypatch.setattr(core_ffi, "drainer_flush", emit_while_retiring)
    _init(new)
    monkeypatch.setattr(core_ffi, "drainer_flush", flush)
    assert fasten.flush(timeout=2.0)
    assert [r.id for r in _rows(new)] == [r.id for r in emitted]
    assert not _default.audit_write_swallowed()


def _reinit_in_background(store):
    """Start re-init onto ``store``; return its thread once the old drainer
    is swapped out and retiring."""
    old = _default._drainer
    t = threading.Thread(target=_init, args=(store,))
    t.start()
    deadline = time.monotonic() + 5
    while _default._drainer is old and time.monotonic() < deadline:
        time.sleep(0.005)
    assert _default._drainer is not old
    return t


def test_flush_during_reinit_waits_for_the_old_drainer(tmp_path):
    old = FlakyStore(str(tmp_path / "old.db"))
    gate = _hold_first_insert(old)
    _init(old)
    row = fasten.emit(code="USER_CREATED", target="u-1")
    reinit = _reinit_in_background(FlakyStore(str(tmp_path / "new.db")))
    try:
        assert not fasten.flush(timeout=0.3)
    finally:
        gate.set()
    assert fasten.flush(timeout=5.0)
    assert [r.id for r in _rows(old)] == [row.id]
    reinit.join(timeout=5)


def _install_incomplete(capsys):
    return [{k: e[k] for k in ("flushed", "unstored")}
            for e in (json.loads(line) for line in capsys.readouterr().err.splitlines()
                      if line.startswith("{"))
            if e.get("event") == "audit_drain_install_incomplete"]


def test_reinit_reports_rows_the_old_drainer_did_not_store(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(_default, "_reinit_timeout", 1.0, raising=False)
    old = FlakyStore(str(tmp_path / "old.db"), fail=10**6)
    _init(old, queue_retry_initial_ms=10_000, queue_retry_max_ms=10_000)
    _init(old)                      # nothing pending: complete
    assert _install_incomplete(capsys) == []
    fasten.emit(code="USER_CREATED", target="u-1")
    _wait_in_backoff()
    _init(FlakyStore(str(tmp_path / "new.db")))
    assert _install_incomplete(capsys) == [{"flushed": False, "unstored": 1}]


def test_close_waits_for_a_drainer_reinit_is_retiring(tmp_path):
    old = FlakyStore(str(tmp_path / "old.db"))
    gate = _hold_first_insert(old)
    _init(old)
    row = fasten.emit(code="USER_CREATED", target="u-1")
    reinit = _reinit_in_background(FlakyStore(str(tmp_path / "new.db")))
    threading.Timer(0.3, gate.set).start()
    assert fasten.close(timeout=5.0)
    assert [r.id for r in _rows(old)] == [row.id]
    reinit.join(timeout=5)


def test_close_waits_for_its_drainer_when_reinit_swaps_it_out(tmp_path, monkeypatch):
    old = FlakyStore(str(tmp_path / "old.db"))
    gate = _hold_first_insert(old)
    _init(old)
    row = fasten.emit(code="USER_CREATED", target="u-1")
    flush, reinits = _default.flush, []

    def reinit_then_flush(timeout):
        reinits.append(_reinit_in_background(FlakyStore(str(tmp_path / "new.db"))))
        threading.Timer(1.3, gate.set).start()   # after this flush gives up
        return flush(timeout)

    monkeypatch.setattr(_default, "flush", reinit_then_flush)
    assert fasten.close(timeout=2.0)
    assert [r.id for r in _rows(old)] == [row.id]
    reinits[0].join(timeout=5)


def test_close_reports_rows_a_retiring_drainer_still_holds(tmp_path, capsys):
    old = HangingStore(str(tmp_path / "old.db"))
    _init(old)
    try:
        row = fasten.emit(code="USER_CREATED", target="u-1")
        _wait_for_attempts(old, 1)
        reinit = _reinit_in_background(FlakyStore(str(tmp_path / "new.db")))
        start = time.monotonic()
        assert not fasten.close(timeout=0.4)
        assert time.monotonic() - start < 1.5
        reinit.join(timeout=5)
        assert not reinit.is_alive()
        err = [json.loads(line) for line in capsys.readouterr().err.splitlines()
               if line.startswith("{")]
    finally:
        _release_hung_store(old)
    lost = [e["row_id"] for e in err if e.get("event") == "audit_drain_lost_at_stop"]
    assert lost == [row.id]


def test_concurrent_inits_retire_every_drainer(tmp_path, monkeypatch):
    from fasten import core_ffi
    opened, closed = [], []
    open_, close = core_ffi.store_from_callback, core_ffi.store_close
    monkeypatch.setattr(core_ffi, "store_from_callback", lambda cb: opened.append(1) or open_(cb))
    monkeypatch.setattr(core_ffi, "store_close", lambda h: closed.append(1) or close(h))
    store = FlakyStore(str(tmp_path / "a.db"))
    threads = [threading.Thread(target=_init, args=(store,)) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    _default._uninstall_drainer()
    assert len(opened) == len(closed) == 4


def test_row_refused_at_stop_gets_one_abandoned_event(tmp_path):
    # fasten-core reports a row it refuses at stop (rc 10); the engine must
    # not report it again.
    store = FlakyStore(str(tmp_path / "a.db"))
    gate = _hold_first_insert(store)
    _init(store, queue_capacity=1)
    fasten.emit(code="USER_CREATED", target="held")          # takes the only slot
    blocked = threading.Thread(target=fasten.emit,
                               kwargs={"code": "USER_CREATED", "target": "blocked"})
    blocked.start()
    deadline = time.monotonic() + 5
    while _default._drainer.users == 0 and time.monotonic() < deadline:
        time.sleep(0.005)
    closer = threading.Thread(target=_default._uninstall_drainer)
    closer.start()
    while "audit_drain_abandoned" not in _sys_events() and time.monotonic() < deadline:
        time.sleep(0.005)
    gate.set()
    blocked.join(timeout=5)
    closer.join(timeout=5)
    abandoned = [e for e in reversed(fasten.transport().query_syslog(limit=1000))
                 if e.get("event") == "audit_drain_abandoned"]
    assert [e["reason"] for e in abandoned] == ["drainer_stopped"]
    assert len(_rows(store)) == 2


class RejectingStore(FlakyStore):
    """Raises the DB-API IntegrityError, as a real store does for a row it
    will never accept, for rows targeting "bad"."""

    rejects = 0

    def allocate_and_insert_originated(self, row):
        if row.target == "bad":
            self.rejects += 1
            raise sqlite3.IntegrityError("constraint failed")
        return super().allocate_and_insert_originated(row)


def test_rejected_row_is_dead_lettered_without_holding_up_the_queue(tmp_path):
    store = RejectingStore(str(tmp_path / "a.db"))
    _init(store, queue_retry_initial_ms=10_000, queue_retry_max_ms=10_000)
    fasten.emit(code="USER_CREATED", target="bad")
    fasten.emit(code="USER_CREATED", target="good")
    assert fasten.flush(timeout=2.0)
    assert [r.target for r in _rows(store)] == ["good"]
    assert store.rejects == 1
    assert fasten.queue_stats()["dead_lettered_total"] == 1
    assert "audit_drain_dead_letter" in _sys_events()
    assert _default.audit_write_swallowed()


def test_flush_with_no_time_left_does_not_wait(tmp_path):
    # fasten-core reads 0 ms as no timeout.
    store = FlakyStore(str(tmp_path / "a.db"), fail=10**6)
    _init(store, queue_retry_initial_ms=10_000, queue_retry_max_ms=10_000)
    fasten.emit(code="USER_CREATED", target="u-1")
    start = time.monotonic()
    assert not fasten.flush(timeout=0)
    assert not fasten.flush(timeout=0.0004)
    assert time.monotonic() - start < 1


def test_large_queue_capacity_is_accepted(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"))
    _init(store, queue_capacity=10**12)
    fasten.emit(code="USER_CREATED", target="u-1")
    assert fasten.flush(timeout=1.0)
    assert len(_rows(store)) == 1


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_forked_child_gets_its_own_drainer(tmp_path):
    # gunicorn --preload / Celery prefork: the child inherits the drainer but
    # not its thread. Before the child reinstalled, it hung once the queue
    # filled and stored nothing.
    store = FlakyStore(str(tmp_path / "a.db"))
    _init(store, queue_capacity=3)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)  # fork with threads
        pid = os.fork()
    if pid == 0:
        code = 1
        try:
            for i in range(6):
                fasten.emit(code="USER_CREATED", target=f"child-{i}")
            code = 0 if fasten.flush(timeout=5.0) else 2
        finally:
            os._exit(code)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            break
        time.sleep(0.05)
    else:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        pytest.fail("forked child hung emitting")
    assert os.waitstatus_to_exitcode(status) == 0
    assert sorted(r.target for r in _rows(store)) == [f"child-{i}" for i in range(6)]


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_fork_never_lands_mid_insert(tmp_path):
    # Forked while the parent's drain thread was inside SQLite, a child
    # inherited its global mutex or file lock state and never stored a row.
    store = SQLiteStore(str(tmp_path / "a.db"))
    _init(store)
    # A child still running at the deadline gets SIGABRT, so its stack
    # shows where it hung.
    if not faulthandler.is_enabled():
        faulthandler.enable()
    pids = []
    for rnd in range(3):
        for i in range(300):
            fasten.emit(code="USER_CREATED", target=f"parent-{rnd}-{i}")
        for k in range(8):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)  # fork with threads
                pid = os.fork()
            if pid == 0:
                code = 1
                try:
                    fasten.emit(code="USER_CREATED", target=f"child-{rnd}-{k}")
                    code = 0 if fasten.flush(timeout=5.0) else 2
                finally:
                    os._exit(code)
            pids.append(pid)
    deadline = time.monotonic() + 20
    failed = []
    for pid in pids:
        while True:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                if os.waitstatus_to_exitcode(status) != 0:
                    failed.append(f"exit {os.waitstatus_to_exitcode(status)}")
                break
            if time.monotonic() > deadline:
                os.kill(pid, signal.SIGABRT)
                os.waitpid(pid, 0)
                failed.append("hung")
                break
            time.sleep(0.02)
    assert not failed, f"{len(failed)} of {len(pids)} forked children did not store: {failed}"
    assert fasten.flush(timeout=10.0)
    targets = sorted(r.target for r in store.query(limit=10000))
    assert targets == sorted([f"parent-{r}-{i}" for r in range(3) for i in range(300)]
                             + [f"child-{r}-{k}" for r in range(3) for k in range(8)])



class HangingStore(FlakyStore):
    """Every insert polls in short steps, as psycopg does on its socket,
    until ``release`` is set, then fails (or stores the row if ``recovers``)."""

    def __init__(self, path, recovers=False):
        super().__init__(path)
        self.release = threading.Event()
        self.recovers = recovers

    def allocate_and_insert_originated(self, row):
        with self.lock:
            self.attempts += 1
        deadline = time.monotonic() + 10
        while not self.release.is_set() and time.monotonic() < deadline:
            time.sleep(0.01)
        if self.recovers:
            return self.inner.allocate_and_insert_originated(row)
        raise OSError("store hung")


def _release_hung_store(store):
    store.release.set()
    installed = _default._drainer
    for t in threading.enumerate():
        if t.name == "fasten-retire" or (
                t.name == "fasten-store" and (installed is None or t is not installed.worker)):
            t.join(timeout=5)


def test_close_returns_by_its_timeout_when_the_store_hangs(tmp_path):
    store = HangingStore(str(tmp_path / "a.db"))
    _init(store)
    try:
        rows = [fasten.emit(code="USER_CREATED", target=f"u-{i}") for i in range(3)]
        _wait_for_attempts(store, 1)
        start = time.monotonic()
        assert not fasten.close(timeout=0.3)
        assert time.monotonic() - start < 1.5
        lost = [e for e in fasten.transport().query_syslog(limit=1000)
                if e.get("event") == "audit_drain_lost_at_stop"]
        assert sorted(e["row_id"] for e in lost) == sorted(r.id for r in rows)
        assert _default.audit_write_swallowed()
    finally:
        _release_hung_store(store)
    # No store call starts after the deadline, and nothing is reported twice.
    assert store.attempts == 1
    events = _sys_events()
    assert events.count("audit_drain_lost_at_stop") == 3
    assert "audit_drain_dead_letter" not in events
    assert "audit_drain_row_not_pending" not in events


def test_row_stored_after_close_gave_up_is_reported_recovered(tmp_path):
    store = HangingStore(str(tmp_path / "a.db"), recovers=True)
    _init(store)
    try:
        row = fasten.emit(code="USER_CREATED", target="u-1")
        _wait_for_attempts(store, 1)
        assert not fasten.close(timeout=0.3)
    finally:
        _release_hung_store(store)
    assert [r.id for r in _rows(store)] == [row.id]
    recovered = [e for e in fasten.transport().query_syslog(limit=1000)
                 if e.get("event") == "audit_drain_recovered_at_stop"]
    assert [e["row_ids"] for e in recovered] == [[row.id]]


class BlockingSyslogStore(StreamStore):
    """Syslog store whose inserts hang once ``armed`` is set."""

    def __init__(self):
        super().__init__(":memory:", table="syslog")
        self.armed = threading.Event()
        self.release = threading.Event()

    def insert(self, row):
        if self.armed.is_set():
            self.release.wait(10)
        return super().insert(row)


def test_close_does_not_wait_on_a_hung_syslog_store(tmp_path, capsys):
    # FASTEN_SYSLOG_DSN on the same stuck Postgres as the audit store.
    store = HangingStore(str(tmp_path / "a.db"))
    syslog = BlockingSyslogStore()
    _init(store, syslog_store=syslog)
    try:
        rows = [fasten.emit(code="USER_CREATED", target=f"u-{i}") for i in range(3)]
        _wait_for_attempts(store, 1)
        syslog.armed.set()
        start = time.monotonic()
        assert not fasten.close(timeout=0.3)
        assert time.monotonic() - start < 1.5
        # On stderr while the syslog store still hangs.
        err = [json.loads(line) for line in capsys.readouterr().err.splitlines()
               if line.startswith("{")]
    finally:
        syslog.release.set()
        _release_hung_store(store)
    lost = [e["row_id"] for e in err if e.get("event") == "audit_drain_lost_at_stop"]
    assert sorted(lost) == sorted(r.id for r in rows)


def test_close_does_not_wait_on_a_hung_syslog_store_after_a_fast_failure(tmp_path, capsys):
    # The retire thread's own try fails at once, before the deadline, and
    # its lost_at_stop event hangs in the syslog store.
    store = FlakyStore(str(tmp_path / "a.db"), fail=10**6)
    syslog = BlockingSyslogStore()
    _init(store, syslog_store=syslog, queue_retry_initial_ms=10_000, queue_retry_max_ms=10_000)
    try:
        rows = [fasten.emit(code="USER_CREATED", target=f"u-{i}") for i in range(2)]
        _wait_in_backoff()
        syslog.armed.set()
        start = time.monotonic()
        assert not fasten.close(timeout=0.5)
        assert time.monotonic() - start < 1.0
        # On stderr while the syslog store still hangs.
        err = [json.loads(line) for line in capsys.readouterr().err.splitlines()
               if line.startswith("{")]
    finally:
        syslog.release.set()
        for t in threading.enumerate():
            if t.name == "fasten-retire":
                t.join(timeout=5)
    lost = [e["row_id"] for e in err if e.get("event") == "audit_drain_lost_at_stop"]
    assert sorted(lost) == sorted(r.id for r in rows)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_fork_does_not_wait_on_a_hung_insert(tmp_path):
    store = HangingStore(str(tmp_path / "a.db"))
    _init(store)
    lock = _default._drainer.insert_lock
    try:
        fasten.emit(code="USER_CREATED", target="u-1")
        _wait_for_attempts(store, 1)
        start = time.monotonic()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)  # fork with threads
            pid = os.fork()
        if pid == 0:
            os._exit(0)
        assert time.monotonic() - start < 3
        assert os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]) == 0
    finally:
        _release_hung_store(store)
    # The parent did not release the lock the stuck insert held.
    assert lock.acquire(timeout=5)
    lock.release()
    assert "audit_drain_fork_during_insert" in _sys_events()


def test_forks_from_two_threads_do_not_leak_the_insert_lock(tmp_path):
    # One thread holds the lock across its fork while another gives up
    # waiting for it.
    _init(FlakyStore(str(tmp_path / "a.db")))
    _default._insert_lock_before_fork()
    other = threading.Thread(target=lambda: (_default._insert_lock_before_fork(),
                                             _default._insert_lock_after_fork()))
    other.start()
    other.join(timeout=5)
    _default._insert_lock_after_fork()
    assert _default._drainer.insert_lock.acquire(timeout=1)
    _default._drainer.insert_lock.release()


class SlowRetireStore(FlakyStore):
    """Fails the drain thread's two tries, then holds the retire thread's
    try until ``release`` is set and stores the row."""

    def __init__(self, path):
        super().__init__(path, fail=2)
        self.release = threading.Event()

    def allocate_and_insert_originated(self, row):
        if self.attempts >= 2:
            assert self.release.wait(10)
        return super().allocate_and_insert_originated(row)


def test_row_retire_stores_after_close_gave_up_is_reported_recovered(tmp_path):
    store = SlowRetireStore(str(tmp_path / "a.db"))
    _init(store, queue_retry_initial_ms=10_000, queue_retry_max_ms=10_000)
    row = fasten.emit(code="USER_CREATED", target="u-1")
    _wait_in_backoff()
    try:
        assert not fasten.close(timeout=0.4)    # retire's try is still running
    finally:
        _release_hung_store(store)
    assert [r.id for r in _rows(store)] == [row.id]
    recovered = [e for e in fasten.transport().query_syslog(limit=1000)
                 if e.get("event") == "audit_drain_recovered_at_stop"]
    assert [e["row_ids"] for e in recovered] == [[row.id]]


def _core_event(d, event, row_id):
    d.sys_callback(json.dumps({"event": event, "level": "error", "row_id": row_id}).encode(), None)


def test_core_event_for_a_row_close_did_not_report_still_goes_out(tmp_path):
    store = HangingStore(str(tmp_path / "a.db"))
    _init(store)
    d = _default._drainer
    try:
        fasten.emit(code="USER_CREATED", target="u-1")
        _wait_for_attempts(store, 1)
        assert not fasten.close(timeout=0.3)
        _core_event(d, "audit_drain_dead_letter", "evt-never-reported")
    finally:
        _release_hung_store(store)
    dead = [e for e in fasten.transport().query_syslog(limit=1000)
            if e.get("event") == "audit_drain_dead_letter"]
    assert [e["row_id"] for e in dead] == ["evt-never-reported"]


def test_core_event_past_the_deadline_skips_the_syslog_store(tmp_path):
    store = HangingStore(str(tmp_path / "a.db"))
    syslog = BlockingSyslogStore()
    _init(store, syslog_store=syslog)
    d = _default._drainer
    try:
        fasten.emit(code="USER_CREATED", target="u-1")
        _wait_for_attempts(store, 1)
        assert not fasten.close(timeout=0.3)
        syslog.armed.set()
        t = threading.Thread(target=_core_event, args=(d, "audit_drain_failed", "evt-x"))
        t.start()
        t.join(timeout=2)
        assert not t.is_alive()
    finally:
        syslog.release.set()
        _release_hung_store(store)


def test_core_stop_event_does_not_wait_on_a_hung_syslog_store(tmp_path, monkeypatch, capsys):
    # fasten-core emits audit_drain_stop_slow from inside drainer_close, on
    # the retire thread; stuck in the syslog store there, it would still be
    # in Python above fasten-core's frames at interpreter exit.
    from fasten import core_ffi
    syslog = BlockingSyslogStore()
    _init(FlakyStore(str(tmp_path / "a.db")), syslog_store=syslog)
    d, close = _default._drainer, core_ffi.drainer_close

    def slow_stop(handle):
        close(handle)
        _core_event(d, "audit_drain_stop_slow", None)

    monkeypatch.setattr(core_ffi, "drainer_close", slow_stop)
    syslog.armed.set()
    try:
        start = time.monotonic()
        assert fasten.close(timeout=2.0)
        assert time.monotonic() - start < 1
        err = [json.loads(line) for line in capsys.readouterr().err.splitlines()
               if line.startswith("{")]
        assert [e["event"] for e in err if e.get("event") == "audit_drain_stop_slow"] == [
            "audit_drain_stop_slow"]
        assert fasten.transport().stream_degraded("sys")
    finally:
        syslog.release.set()


def test_row_reported_lost_then_stored_inline_is_reported_recovered(tmp_path, monkeypatch):
    # close gives up on the drainer while an emit is between queueing the
    # row and fasten-core refusing it.
    from fasten import core_ffi
    store = FlakyStore(str(tmp_path / "a.db"))
    _init(store)
    d = _default._drainer

    def refused(handle, row_json):
        _default._report_unstored(d)
        raise core_ffi.EnqueueError(core_ffi.ERR_DRAINER_STOPPED, "drainer stopped")

    monkeypatch.setattr(core_ffi, "drainer_enqueue", refused)
    row = fasten.emit(code="USER_CREATED", target="u-1")
    assert row.hash
    recovered = [e for e in fasten.transport().query_syslog(limit=1000)
                 if e.get("event") == "audit_drain_recovered_at_stop"]
    assert [e["row_ids"] for e in recovered] == [[row.id]]


def test_close_returns_false_when_a_racing_emit_fails_inline(tmp_path, monkeypatch):
    # The drainer refuses the row because close is stopping it, and the
    # inline store fails too.
    from fasten import core_ffi
    store = FlakyStore(str(tmp_path / "a.db"))
    good = store.allocate_and_insert_originated

    def insert(row):
        if row.target == "racing":
            raise OSError("store down")
        return good(row)
    store.allocate_and_insert_originated = insert
    _init(store)
    closed = _signal_drainer_close(monkeypatch)

    def refused(handle, row_json):
        assert closed.wait(5)
        raise core_ffi.EnqueueError(core_ffi.ERR_DRAINER_STOPPED, "drainer stopped")

    monkeypatch.setattr(core_ffi, "drainer_enqueue", refused)
    emitter = threading.Thread(target=fasten.emit,
                               kwargs={"code": "USER_CREATED", "target": "racing"})
    emitter.start()
    deadline = time.monotonic() + 5
    while _default._drainer.users == 0 and time.monotonic() < deadline:
        time.sleep(0.005)
    assert not fasten.close(timeout=2.0)
    emitter.join(timeout=5)
    assert _rows(store) == []
    assert _default.audit_write_swallowed()


def test_lost_at_stop_left_out_of_the_syslog_store_degrades_it(tmp_path):
    store = HangingStore(str(tmp_path / "a.db"))
    _init(store, syslog_store=StreamStore(":memory:", table="syslog"))
    try:
        fasten.emit(code="USER_CREATED", target="u-1")
        _wait_for_attempts(store, 1)
        assert not fasten.transport().stream_degraded("sys")
        assert not fasten.close(timeout=0.3)
        assert fasten.transport().stream_degraded("sys")
    finally:
        _release_hung_store(store)


def _fail_first_lost_event(monkeypatch):
    """Make the first lost_at_stop event raise; return the ids reported."""
    log, reported = _default._drainer_sys_log, []

    def flaky(level, event, fields, via=None, persist=True):
        if event == "audit_drain_lost_at_stop":
            reported.append(fields["row_id"])
            if len(reported) == 1:
                raise OSError("stderr closed")
        return log(level, event, fields, via=via, persist=persist)
    monkeypatch.setattr(_default, "_drainer_sys_log", flaky)
    return reported


def test_a_failed_lost_event_does_not_stop_the_others_at_close(tmp_path, monkeypatch):
    store = HangingStore(str(tmp_path / "a.db"))
    _init(store)
    try:
        rows = [fasten.emit(code="USER_CREATED", target=f"u-{i}") for i in range(3)]
        _wait_for_attempts(store, 1)
        reported = _fail_first_lost_event(monkeypatch)
        assert not fasten.close(timeout=0.3)
    finally:
        _release_hung_store(store)
    assert sorted(reported) == sorted(r.id for r in rows)


def test_a_failed_lost_event_does_not_stop_retire(tmp_path, monkeypatch):
    store = FlakyStore(str(tmp_path / "a.db"), fail=10**6)
    _init(store, queue_retry_initial_ms=10_000, queue_retry_max_ms=10_000)
    rows = [fasten.emit(code="USER_CREATED", target=f"u-{i}") for i in range(3)]
    _wait_in_backoff()
    reported = _fail_first_lost_event(monkeypatch)
    _default._uninstall_drainer()
    assert sorted(reported) == sorted(r.id for r in rows)


def test_drainer_flush_raises_on_an_ffi_error():
    from fasten import core_ffi
    with pytest.raises(RuntimeError, match="fasten_drainer_flush"):
        core_ffi.drainer_flush(None, 10)


def test_flush_failure_is_reported_not_a_timeout(tmp_path, monkeypatch):
    from fasten import core_ffi
    _init(FlakyStore(str(tmp_path / "a.db")))

    def broken(handle, timeout_ms):
        raise RuntimeError("fasten_drainer_flush: null argument")

    monkeypatch.setattr(core_ffi, "drainer_flush", broken)
    assert not fasten.flush(timeout=1.0)
    failed = [e for e in fasten.transport().query_syslog(limit=1000)
              if e.get("event") == "audit_drain_flush_failed"]
    assert [e["error"] for e in failed] == ["fasten_drainer_flush: null argument"]


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_failed_reinstall_after_fork_is_reported(tmp_path, monkeypatch):
    _init(FlakyStore(str(tmp_path / "a.db")))

    def broken(**kwargs):
        raise OSError("no threads")

    monkeypatch.setattr(_default, "_install_drainer", broken)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)  # fork with threads
        pid = os.fork()
    if pid == 0:
        code = 1
        try:
            failed = [e for e in fasten.transport().query_syslog(limit=1000)
                      if e.get("event") == "audit_drain_reinstall_failed"]
            code = 0 if [e["error_type"] for e in failed] == ["OSError"] else 2
        finally:
            os._exit(code)
    assert os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]) == 0


def test_reinit_does_not_wait_forever_on_a_hanging_store(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(_default, "_reinit_timeout", 0.6, raising=False)
    store = HangingStore(str(tmp_path / "a.db"))
    _init(store)
    try:
        row = fasten.emit(code="USER_CREATED", target="u-1")
        _wait_for_attempts(store, 1)
        start = time.monotonic()
        _init(FlakyStore(str(tmp_path / "b.db")))
        assert time.monotonic() - start < 2
        err = capsys.readouterr().err
    finally:
        _release_hung_store(store)
    assert f'"row_id": "{row.id}"' in err and "audit_drain_lost_at_stop" in err
    assert fasten.emit(code="USER_CREATED", target="u-2") and fasten.flush(timeout=2.0)


def test_rows_emitted_while_a_hung_store_retires_reach_the_new_store(tmp_path, monkeypatch):
    # The old store's stuck call must not hold up the new drainer's inserts.
    from fasten import core_ffi
    monkeypatch.setattr(_default, "_reinit_timeout", 0.6, raising=False)
    old = HangingStore(str(tmp_path / "old.db"))
    _init(old)
    try:
        fasten.emit(code="USER_CREATED", target="u-1")
        _wait_for_attempts(old, 1)
        flush, emitted = core_ffi.drainer_flush, []

        def emit_while_retiring(handle, timeout_ms):
            emitted.append(fasten.emit(code="USER_CREATED", target="during-reinit"))
            return flush(handle, timeout_ms)

        monkeypatch.setattr(core_ffi, "drainer_flush", emit_while_retiring)
        new = FlakyStore(str(tmp_path / "new.db"))
        _init(new)
        monkeypatch.setattr(core_ffi, "drainer_flush", flush)
        assert fasten.flush(timeout=2.0)
        assert [r.id for r in _rows(new)] == [r.id for r in emitted]
    finally:
        _release_hung_store(old)


def test_reset_does_not_wait_forever_on_a_hanging_store(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(_default, "_reset_timeout", 0.3, raising=False)
    store = HangingStore(str(tmp_path / "a.db"))
    _init(store)
    try:
        row = fasten.emit(code="USER_CREATED", target="u-1")
        _wait_for_attempts(store, 1)
        start = time.monotonic()
        _default.reset_for_tests()
        assert time.monotonic() - start < 2
        err = capsys.readouterr().err
    finally:
        _release_hung_store(store)
    assert f'"row_id": "{row.id}"' in err and "audit_drain_lost_at_stop" in err


def test_close_returns_true_when_retire_stores_the_row(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"), fail=1)
    _init(store, queue_retry_initial_ms=10_000, queue_retry_max_ms=10_000)
    row = fasten.emit(code="USER_CREATED", target="u-1")
    _wait_in_backoff()
    # The flush times out while the row is in backoff; its try at stop stores it.
    assert fasten.close(timeout=1.0)
    assert [r.id for r in _rows(store)] == [row.id]


def test_close_returns_false_when_a_row_is_lost(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"), fail=10**6)
    _init(store, queue_retry_initial_ms=10_000, queue_retry_max_ms=10_000)
    fasten.emit(code="USER_CREATED", target="u-1")
    _wait_in_backoff()
    assert not fasten.close(timeout=1.0)
    assert "audit_drain_lost_at_stop" in _sys_events()


def test_emit_after_close_is_stored_without_an_abandoned_event(tmp_path):
    store = FlakyStore(str(tmp_path / "a.db"))
    _init(store)
    assert fasten.close(timeout=1.0)
    row = fasten.emit(code="USER_CREATED", target="u-1")
    assert row.hash                 # stored synchronously
    events = _sys_events()
    assert "audit_drain_abandoned" not in events
    assert "audit_drain_stored_inline" not in events
    _init(store)                    # init installs a drainer again
    assert not fasten.emit(code="USER_CREATED", target="u-2").hash




_EXIT_SCRIPT = """
import atexit, sys, time, fasten
from fasten.codes import Meta, RetentionClass, Severity, register
from fasten.store.sqlite import SQLiteStore

atexit.register(print, "earlier hook ran")

class Store(SQLiteStore):
    def allocate_and_insert_originated(self, row):
        until = time.monotonic() + {hang}
        while time.monotonic() < until:
            time.sleep(0.01)
        return super().allocate_and_insert_originated(row)

register("t", {{"USER_CREATED": Meta(domain="t", category="auth", action="create",
    severity=Severity.INFO, description="x", emitter="t",
    retention_class=RetentionClass.LONG)}})
from fasten.store.stream import StreamStore

class Syslog(StreamStore):
    hang = False

    def insert(self, row):
        while self.hang:
            time.sleep(0.01)
        return super().insert(row)

syslog = Syslog({db!r} + ".sys", table="syslog")
fasten.init(service_id="svc", node_id="node", audit_store=Store({db!r}), syslog_store=syslog)
for i in range(3):
    fasten.emit(code="USER_CREATED", target=f"u-{{i}}")
time.sleep(0.2)
print("buffered output")
syslog.hang = {syslog_hangs}
{ending}
"""


def _run_exit_script(tmp_path, hang, ending, syslog_hangs=False):
    import subprocess
    script = _EXIT_SCRIPT.format(hang=hang, db=str(tmp_path / "a.db"), ending=ending,
                                 syslog_hangs=syslog_hangs)
    return subprocess.run([sys.executable, "-c", script], capture_output=True,
                          text=True, timeout=30, env={**os.environ, "PYTHONPATH": os.getcwd()})


def _printed(proc):
    """stdout without the audit rows."""
    return [line for line in proc.stdout.splitlines() if not line.startswith("{")]


def _assert_each_row_once(tmp_path, proc):
    """Every emitted row is either stored or reported lost (and not
    recovered), never both. Returns the rows reported lost."""
    emitted = {e["id"] for e in (json.loads(line) for line in proc.stdout.splitlines()
                                 if line.startswith("{"))
               if e.get("shape") == "audit"}
    events = [json.loads(line) for line in proc.stderr.splitlines() if line.startswith("{")]
    lost = [e["row_id"] for e in events if e.get("event") == "audit_drain_lost_at_stop"]
    recovered = [i for e in events if e.get("event") == "audit_drain_recovered_at_stop"
                 for i in e["row_ids"]]
    stored = [r.id for r in SQLiteStore(str(tmp_path / "a.db")).query(limit=100)]
    assert len(emitted) == 3
    assert len(set(lost)) == len(lost) and len(set(stored)) == len(stored)
    assert set(recovered) <= set(stored)
    unstored = set(lost) - set(recovered)
    assert set(stored).isdisjoint(unstored)
    assert set(stored) | unstored == emitted
    return lost


@pytest.mark.parametrize("ending,status", [
    ("assert not fasten.close(timeout=0.3)", 0),
    ("fasten.close(timeout=0.3); sys.exit(3)", 3),
    ("fasten.close(timeout=0.3); raise SystemExit(4)", 4),
    ("fasten.close(timeout=0.3); raise RuntimeError('boom')", 1),
    pytest.param("fasten.close(timeout=0.3); raise KeyboardInterrupt", -2,
                 marks=pytest.mark.skipif(os.name != "posix", reason="POSIX signal status")),
    ("pass", 0),    # the exit hook's own close gives up
])
def test_exit_is_not_held_by_a_hanging_store(tmp_path, ending, status):
    # On CPython before 3.14 on Linux, a drain thread still inside the
    # insert callback at finalization aborted the process.
    start = time.monotonic()
    proc = _run_exit_script(tmp_path, 3600, ending)
    assert proc.returncode == status, proc.stderr
    assert time.monotonic() - start < 15
    lost = [line for line in proc.stderr.splitlines() if "audit_drain_lost_at_stop" in line]
    assert len(lost) == 3
    assert len(_assert_each_row_once(tmp_path, proc)) == 3
    assert _printed(proc) == ["buffered output", "earlier hook ran"]


def test_exit_is_not_held_by_a_hanging_syslog_store(tmp_path):
    # Nothing on the exit path waits on a store without a bound.
    start = time.monotonic()
    proc = _run_exit_script(tmp_path, 3600, "sys.exit(3)", syslog_hangs=True)
    assert proc.returncode == 3, proc.stderr
    assert time.monotonic() - start < 15
    lost = [line for line in proc.stderr.splitlines() if "audit_drain_lost_at_stop" in line]
    assert len(lost) == 3
    assert len(_assert_each_row_once(tmp_path, proc)) == 3
    assert _printed(proc) == ["buffered output", "earlier hook ran"]


@pytest.mark.parametrize("hang", [0.25, 0.3, 0.35])
def test_exit_as_a_left_behind_store_call_returns(tmp_path, hang):
    # The store call close gave up on returns around the time the
    # interpreter finalizes.
    proc = _run_exit_script(tmp_path, hang, "fasten.close(timeout=0.3)")
    assert proc.returncode == 0, proc.stderr
    _assert_each_row_once(tmp_path, proc)
    assert _printed(proc) == ["buffered output", "earlier hook ran"]


@pytest.mark.parametrize("ending,status", [("pass", 0), ("sys.exit(3)", 3),
                                           ("raise SystemExit(4)", 4),
                                           ("raise RuntimeError('boom')", 1)])
def test_exit_with_a_working_store_finalizes_as_usual(tmp_path, ending, status):
    proc = _run_exit_script(tmp_path, 0, ending)
    assert proc.returncode == status, proc.stderr
    assert _printed(proc) == ["buffered output", "earlier hook ran"]
    assert _assert_each_row_once(tmp_path, proc) == []
