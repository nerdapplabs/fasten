"""Seed N rows into the fasten audit store for baseline load testing."""
import argparse
import time
import uuid
from datetime import datetime, timezone

import fasten
from fasten.store.postgres import PostgresStore


def seed(dsn: str, n: int, table: str = "audit_log") -> None:
    store = PostgresStore(dsn=dsn, table=table)
    fasten.init(
        service_id="seed-svc", node_id="seed-node",
        audit_store=store,
        audit_store_failure_strategy="raise",
    )
    fasten.register("load", {
        "SEED_EVENT": fasten.Meta(
            id="SEED_EVENT", domain="load", category="test",
            action="create", severity=fasten.Severity.INFO,
            description="Load seed row", emitter="seed",
            retention_class=fasten.RetentionClass.SHORT,
        ),
    })

    t0 = time.perf_counter()
    for i in range(n):
        fasten.emit("SEED_EVENT",
                    fasten.Target(f"res-{i}"),
                    fasten.Actor("seed", "service"),
                    fasten.WithDetail({"seq": i}))
    fasten.flush(30.0)
    elapsed = time.perf_counter() - t0

    count = store.count()
    print(f"seeded {count} rows in {elapsed:.2f}s ({count/elapsed:.0f} rows/s)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dsn", default="postgresql://fasten:fasten@localhost:5432/fasten_test")
    parser.add_argument("--n", type=int, default=10_000)
    parser.add_argument("--table", default="fasten_seed")
    args = parser.parse_args()
    seed(args.dsn, args.n, args.table)
