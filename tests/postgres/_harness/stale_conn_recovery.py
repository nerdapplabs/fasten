"""Scenario 9: emit after the store's connection has been idle.

Emits a row, idles for idle_s seconds with the server's tcp_keepalives_idle
lowered, then emits again. Only --mode idle is implemented.

Passes when both rows are stored and neither emit raised.
"""
import argparse
import json
import time
import uuid
from datetime import datetime, timezone


def run_idle(dsn, table, idle_s):
    """Emit once, idle for idle_s, emit again; the second emit must succeed."""
    import fasten
    from fasten.store.postgres import PostgresStore
    import psycopg

    store = PostgresStore(dsn=dsn, table=table)
    fasten.init(
        service_id="idle-svc", node_id="idle-node",
        audit_store=store,
        audit_store_failure_strategy="raise",
    )
    if not fasten._codes_registered():
        fasten.register("load", {
            "IDLE_EVENT": fasten.Meta(
                id="IDLE_EVENT", domain="load", category="test",
                action="create", severity=fasten.Severity.INFO,
                description="Idle recovery row", emitter="idle-svc",
                retention_class=fasten.RetentionClass.SHORT,
            ),
        })

    errors = []

    def _emit(label):
        try:
            fasten.emit("IDLE_EVENT",
                        fasten.Target(label),
                        fasten.Actor("idle-svc", "service"))
        except Exception as e:
            errors.append(str(e))

    _emit("before-idle")

    # Lower the server's TCP keepalive idle time for the duration of the test.
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute(f"ALTER SYSTEM SET tcp_keepalives_idle = {max(1, idle_s // 2)}")
        c.execute("SELECT pg_reload_conf()")

    print(f"sleeping {idle_s}s to force stale connection...")
    time.sleep(idle_s)

    _emit("after-idle")

    # Restore.
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute("ALTER SYSTEM RESET tcp_keepalives_idle")
        c.execute("SELECT pg_reload_conf()")

    count = store.count()
    report = {
        "scenario": "stale_conn_recovery",
        "mode": "idle",
        "idle_s": idle_s,
        "errors": errors,
        "actual_rows": count,
        "passed": count == 2 and len(errors) == 0,
    }
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dsn", default="postgresql://fasten:fasten@localhost:5432/fasten_test")
    parser.add_argument("--table", default="fasten_idle")
    parser.add_argument("--mode", choices=["idle"], default="idle")
    parser.add_argument("--idle-s", type=int, default=10, dest="idle_s")
    args = parser.parse_args()
    if args.mode == "idle":
        run_idle(args.dsn, args.table, args.idle_s)
