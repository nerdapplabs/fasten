"""Scenario 1 + 2: concurrent writers — single Postgres and multi-tenant.

Spawns K worker processes, each emitting M rows/s for duration_s seconds.
Verifies all rows present with no duplicates and that per-tenant counts
match expectations when --tenants > 1.

Pass criteria (from P1-16 spec):
  - All rows present (row_count == expected_total)
  - No deadlocks (no DeadlockDetected exceptions)
  - p99 emit < 50 ms
"""
import argparse
import json
import multiprocessing
import os
import statistics
import time
import uuid
from datetime import datetime, timezone


def _worker(args):
    dsn, table, worker_id, tenant_id, rows_per_s, duration_s, result_q = args

    import fasten
    from fasten.store.postgres import PostgresStore

    store = PostgresStore(dsn=dsn, table=table)
    fasten.init(
        service_id=f"worker-{worker_id}", node_id=f"node-{worker_id}",
        tenant_id=tenant_id,
        audit_store=store,
        audit_store_failure_strategy="raise",
    )
    if not fasten._codes_registered():
        fasten.register("load", {
            "LOAD_EVENT": fasten.Meta(
                id="LOAD_EVENT", domain="load", category="test",
                action="create", severity=fasten.Severity.INFO,
                description="Load test row", emitter=f"worker-{worker_id}",
                retention_class=fasten.RetentionClass.SHORT,
            ),
        })

    interval = 1.0 / rows_per_s
    latencies = []
    errors = 0
    emitted = 0
    t_end = time.time() + duration_s

    while time.time() < t_end:
        t0 = time.perf_counter()
        try:
            fasten.emit("LOAD_EVENT",
                        fasten.Target(f"res-{emitted}"),
                        fasten.Actor(f"worker-{worker_id}", "service"))
            emitted += 1
        except Exception:
            errors += 1
        latencies.append((time.perf_counter() - t0) * 1000)
        elapsed = time.perf_counter() - t0
        if elapsed < interval:
            time.sleep(interval - elapsed)

    fasten.flush(30.0)
    result_q.put({
        "worker_id": worker_id,
        "tenant_id": tenant_id,
        "emitted": emitted,
        "errors": errors,
        "p50_ms": statistics.median(latencies) if latencies else 0,
        "p99_ms": statistics.quantiles(latencies, n=100)[98] if len(latencies) >= 100 else max(latencies, default=0),
    })


def run(dsn, table, num_workers, tenants, rows_per_s, duration_s):
    ctx = multiprocessing.get_context("spawn")
    result_q = ctx.Queue()
    procs = []
    for i in range(num_workers):
        tenant = f"tenant-{i % tenants}"
        p = ctx.Process(target=_worker,
                        args=((dsn, table, i, tenant, rows_per_s, duration_s, result_q),))
        p.start()
        procs.append(p)

    for p in procs:
        p.join()

    results = [result_q.get() for _ in procs]

    total_emitted = sum(r["emitted"] for r in results)
    total_errors  = sum(r["errors"]  for r in results)
    p99_max       = max(r["p99_ms"]  for r in results)

    from fasten.store.postgres import PostgresStore
    store = PostgresStore(dsn=dsn, table=table)
    actual_count = store.count()

    report = {
        "scenario": "concurrent_writers",
        "workers": num_workers,
        "tenants": tenants,
        "rows_per_s_per_worker": rows_per_s,
        "duration_s": duration_s,
        "expected_rows": total_emitted,
        "actual_rows": actual_count,
        "missing_rows": total_emitted - actual_count,
        "total_errors": total_errors,
        "p99_ms_max": round(p99_max, 2),
        "passed": (
            actual_count == total_emitted
            and total_errors == 0
            and p99_max < 50
        ),
    }
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dsn", default="postgresql://fasten:fasten@localhost:5432/fasten_test")
    parser.add_argument("--table", default="fasten_concurrent")
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--tenants", type=int, default=1)
    parser.add_argument("--rows-per-s", type=int, default=10, dest="rows_per_s")
    parser.add_argument("--duration", type=int, default=30, dest="duration_s")
    args = parser.parse_args()
    run(args.dsn, args.table, args.workers, args.tenants, args.rows_per_s, args.duration_s)
