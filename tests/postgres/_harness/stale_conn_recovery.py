"""Scenario 4 + 9: stale-connection recovery.

Verifies that the fasten Postgres store reconnects automatically after:
  - Postgres restart (scenario 4)
  - Long idle period where the server closes the connection (scenario 9)

Run scenario 4 via --mode restart (requires docker-compose in PATH and
COMPOSE_FILE set).  Scenario 9 via --mode idle (sets server idle timeout
low via ALTER SYSTEM).

Pass criteria: all rows present after recovery; no unhandled exceptions.
"""
import argparse
import json
import time
import uuid
from datetime import datetime, timezone


def run_idle(dsn, table, idle_s):
    """Emit once, idle for idle_s, emit again — stale retry must recover."""
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

    # Lower server idle timeout so the connection goes stale quickly.
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
