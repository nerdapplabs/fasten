"""P0-9 — allocation must serialise across PROCESSES, not just threads.

The reported bug was a forking supervisor / `uvicorn --workers` / two services
sharing a store. Those are separate processes with separate SQLite connections,
so an in-process lock proves nothing. Only `BEGIN IMMEDIATE` taking a RESERVED
lock in the database file makes this correct.

These tests fork real processes.
"""
import multiprocessing as mp
import os
import tempfile
from datetime import datetime, timezone

import pytest

from fasten.attrs import AuditRow
from fasten.chain import verify_chain
from fasten.store.sqlite import SQLiteStore

ROWS_PER_PROC = 40
N_PROCS = 6


def _row(pid: int, i: int) -> AuditRow:
    rid = f"evt-{pid}-{i}"
    return AuditRow(
        id=rid, origin_id=rid, monotonic_seq=0,
        timestamp=datetime(2026, 6, 15, 10, 30, 45, tzinfo=timezone.utc),
        code="USER_CREATED", action="create", severity="info",
        service_id=f"svc-{pid}", source_node_id="node-1", tenant_id=None,
        actor="a", actor_kind="user", target=f"u/{pid}-{i}",
        category="account", domain="user", method="sdk",
        request_id=f"req-{pid}-{i}", detail={"p": pid, "i": i},
    )


def _worker(db: str, pid: int, q: mp.Queue, barrier) -> None:
    """Separate process: its own SQLiteStore, its own connection.

    The barrier makes every process start writing at the same instant, so the
    RESERVED lock is genuinely contended. Without it the workers finish one
    after another and the test passes whether or not the lock works.
    """
    try:
        store = SQLiteStore(path=db, table="fasten_audit")
        barrier.wait(timeout=60)
        for i in range(ROWS_PER_PROC):
            store.allocate_and_insert_originated(_row(pid, i))
        q.put(("ok", pid, None))
    except BaseException as exc:                      # pragma: no cover
        q.put(("err", pid, f"{type(exc).__name__}: {exc}"))


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork")
def test_concurrent_processes_produce_one_verifiable_chain():
    """THE REAL P0-9 GUARD.

    N processes, N service ids, one node, one SQLite file. The chain must come
    out contiguous and verifiable. Before store-allocated sequencing each
    process minted from 1 and verify_chain reported a false tamper signal.
    """
    db = os.path.join(tempfile.mkdtemp(), "audit.db")
    SQLiteStore(path=db, table="fasten_audit")     # create schema once

    ctx = mp.get_context("fork")
    q: mp.Queue = ctx.Queue()
    barrier = ctx.Barrier(N_PROCS)
    procs = [ctx.Process(target=_worker, args=(db, p, q, barrier))
             for p in range(N_PROCS)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)

    results = [q.get() for _ in range(N_PROCS)]
    failures = [(pid, err) for status, pid, err in results if status != "ok"]
    assert not failures, f"worker processes failed: {failures}"
    assert all(p.exitcode == 0 for p in procs), [p.exitcode for p in procs]

    rows = SQLiteStore(path=db, table="fasten_audit").query(limit=1000)
    total = N_PROCS * ROWS_PER_PROC
    assert len(rows) == total, f"expected {total} rows, got {len(rows)}"

    seqs = sorted(r.monotonic_seq for r in rows)
    assert seqs == list(range(1, total + 1)), (
        "monotonic_seq is not contiguous — allocation did not serialise across "
        f"processes. got {seqs}"
    )
    assert len({r.monotonic_seq for r in rows}) == total, "duplicate seq"

    result = verify_chain(rows)
    assert result.ok, result.reason


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork")
def test_no_writer_starves_or_errors_under_simultaneous_start():
    """Contention must not surface as errors to the caller.

    All N processes are released from a barrier at once, so they pile onto the
    RESERVED lock simultaneously. SQLite serialises writers — in practice one
    process tends to run to completion before the next is scheduled, which is
    lock handoff, not absence of contention. What must NOT happen is a worker
    seeing "database is locked" and dropping an audit row on the floor.

    This is the guard for the throughput/robustness side of spec §2.1: the
    allocation is correct, but it IS a serialisation point.
    """
    db = os.path.join(tempfile.mkdtemp(), "audit.db")
    SQLiteStore(path=db, table="fasten_audit")

    ctx = mp.get_context("fork")
    q: mp.Queue = ctx.Queue()
    barrier = ctx.Barrier(N_PROCS)
    procs = [ctx.Process(target=_worker, args=(db, p, q, barrier))
             for p in range(N_PROCS)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=120)

    results = [q.get() for _ in range(N_PROCS)]
    errors = [(pid, err) for status, pid, err in results if status != "ok"]
    assert not errors, f"contention surfaced as errors (lost audit rows): {errors}"

    rows = SQLiteStore(path=db, table="fasten_audit").query(limit=1000)
    total = N_PROCS * ROWS_PER_PROC
    assert len(rows) == total, f"lost rows under contention: {len(rows)}/{total}"
    assert sorted(r.monotonic_seq for r in rows) == list(range(1, total + 1))
    assert verify_chain(rows).ok
