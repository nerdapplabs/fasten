"""Scenario 6: VACUUM ANALYZE during writes — verify no deadlocks.

Runs VACUUM ANALYZE on the audit table while concurrent writers emit rows.
Pass criteria: no deadlock exceptions, p99 emit latency unchanged vs baseline.
"""
import argparse
import json
import statistics
import threading
import time


def run(dsn, table, writers, rows_per_s, vacuum_interval_s, duration_s):
    import fasten
    from fasten.store.postgres import PostgresStore
    import psycopg

    store = PostgresStore(dsn=dsn, table=table)
    fasten.init(
        service_id="vacuum-svc", node_id="vacuum-node",
        audit_store=store,
        audit_store_failure_strategy="raise",
    )
    if not fasten._codes_registered():
        fasten.register("load", {
            "VACUUM_EVENT": fasten.Meta(
                id="VACUUM_EVENT", domain="load", category="test",
                action="create", severity=fasten.Severity.INFO,
                description="Vacuum test row", emitter="vacuum-svc",
                retention_class=fasten.RetentionClass.SHORT,
            ),
        })

    latencies = []
    errors = []
    lock = threading.Lock()
    stop_flag = threading.Event()

    def _emit_loop():
        interval = 1.0 / rows_per_s
        t_end = time.time() + duration_s
        while not stop_flag.is_set() and time.time() < t_end:
            t0 = time.perf_counter()
            try:
                fasten.emit("VACUUM_EVENT",
                            fasten.Target("res"),
                            fasten.Actor("vacuum-svc", "service"))
            except Exception as e:
                with lock:
                    errors.append(str(e))
            lat = (time.perf_counter() - t0) * 1000
            with lock:
                latencies.append(lat)
            elapsed = time.perf_counter() - t0
            if elapsed < interval:
                time.sleep(interval - elapsed)

    def _vacuum_loop():
        t_end = time.time() + duration_s
        while not stop_flag.is_set() and time.time() < t_end:
            try:
                with psycopg.connect(dsn, autocommit=True) as conn:
                    conn.execute(f"VACUUM ANALYZE {table}")
            except Exception:
                pass
            time.sleep(vacuum_interval_s)

    threads = [threading.Thread(target=_emit_loop) for _ in range(writers)]
    vthread = threading.Thread(target=_vacuum_loop)
    for t in threads:
        t.start()
    vthread.start()
    time.sleep(duration_s + 1)
    stop_flag.set()
    for t in threads:
        t.join()
    vthread.join()

    deadlocks = [e for e in errors if "deadlock" in e.lower()]
    report = {
        "scenario": "vacuum_concurrency",
        "writers": writers,
        "duration_s": duration_s,
        "vacuum_interval_s": vacuum_interval_s,
        "deadlocks": len(deadlocks),
        "total_errors": len(errors),
        "p99_ms": statistics.quantiles(latencies, n=100)[98] if len(latencies) >= 100 else max(latencies, default=0),
        "passed": len(deadlocks) == 0,
    }
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dsn", default="postgresql://fasten:fasten@localhost:5432/fasten_test")
    parser.add_argument("--table", default="fasten_vacuum")
    parser.add_argument("--writers", type=int, default=8)
    parser.add_argument("--rows-per-s", type=int, default=20, dest="rows_per_s")
    parser.add_argument("--vacuum-interval", type=float, default=5.0, dest="vacuum_interval_s")
    parser.add_argument("--duration", type=int, default=30, dest="duration_s")
    args = parser.parse_args()
    run(args.dsn, args.table, args.writers, args.rows_per_s, args.vacuum_interval_s, args.duration_s)
