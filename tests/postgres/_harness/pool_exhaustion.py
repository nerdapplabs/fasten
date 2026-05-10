"""Scenario 3: pool exhaustion — emit under connection saturation.

Holds all pgbouncer connections busy, then verifies that emit() either
succeeds (queued) or raises AuditStoreError (raise mode) — never silently
drops rows.

Pass criteria: no silent drops (emitted == actual_count + queue_depth).
"""
import argparse
import json
import threading
import time


def run(dsn, table, pool_size, burst_writers, duration_s):
    import fasten
    from fasten.store.postgres import PostgresStore

    store = PostgresStore(dsn=dsn, table=table)

    holders = []
    holder_conns = []

    # Hold pool_size connections open to exhaust the pool.
    import psycopg
    for _ in range(pool_size):
        try:
            c = psycopg.connect(dsn)
            c.execute("BEGIN")
            holder_conns.append(c)
        except Exception:
            pass

    fasten.init(
        service_id="exhaust-svc", node_id="exhaust-node",
        audit_store=store,
        audit_store_failure_strategy="queue",
        queue_capacity=burst_writers * 10,
    )
    if not fasten._codes_registered():
        fasten.register("load", {
            "EXHAUST_EVENT": fasten.Meta(
                id="EXHAUST_EVENT", domain="load", category="test",
                action="create", severity=fasten.Severity.INFO,
                description="Exhaustion test row", emitter="exhaust-svc",
                retention_class=fasten.RetentionClass.SHORT,
            ),
        })

    emitted = 0
    errors = 0
    lock = threading.Lock()

    def _emit_burst():
        nonlocal emitted, errors
        t_end = time.time() + duration_s
        while time.time() < t_end:
            try:
                fasten.emit("EXHAUST_EVENT",
                            fasten.Target("res"),
                            fasten.Actor("exhaust-svc", "service"))
                with lock:
                    emitted += 1
            except fasten.AuditStoreError:
                with lock:
                    errors += 1
            time.sleep(0.01)

    threads = [threading.Thread(target=_emit_burst) for _ in range(burst_writers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Release held connections so drainer can flush.
    for c in holder_conns:
        try:
            c.execute("ROLLBACK")
            c.close()
        except Exception:
            pass

    fasten.flush(60.0)
    stats = fasten.queue_stats()
    actual_count = store.count()

    report = {
        "scenario": "pool_exhaustion",
        "pool_size": pool_size,
        "burst_writers": burst_writers,
        "emitted": emitted,
        "emit_errors": errors,
        "actual_rows": actual_count,
        "queue_stats": stats,
        "passed": actual_count + errors == emitted,
    }
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dsn", default="postgresql://fasten:fasten@localhost:5432/fasten_test")
    parser.add_argument("--table", default="fasten_exhaustion")
    parser.add_argument("--pool-size", type=int, default=10, dest="pool_size")
    parser.add_argument("--burst-writers", type=int, default=50, dest="burst_writers")
    parser.add_argument("--duration", type=int, default=15, dest="duration_s")
    args = parser.parse_args()
    run(args.dsn, args.table, args.pool_size, args.burst_writers, args.duration_s)
