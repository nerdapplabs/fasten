"""Queue mode: rows go through the fasten-core drainer and the store seals them.

Vectors from spec/drainer-conformance.md §7.
"""
import json
import os
import sqlite3
import threading
import time
import warnings

import pytest

import fasten
from fasten.emitter import _default
from fasten.store.sqlite import SQLiteStore


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
    assert any(e.get("event") == "audit_drain_recovered_at_stop" and e.get("row_ids") == [row.id]
               for e in err)
    # Stored after all, so not also reported as dead-lettered.
    assert not any(e.get("event") == "audit_drain_dead_letter" for e in err)



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
    assert any(e.get("event") == "audit_drain_lost_at_stop" and e.get("row_id") == row.id
               for e in err)
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

