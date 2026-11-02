"""P0-9 / #12 — Postgres allocation against a REAL server.

This path was written, reviewed and shipped twice without ever executing.
It is the one place a bug of the same shape as the SQLite unsealed-row defect
would not have been caught. Requires FASTEN_TEST_POSTGRES_DSN (the name CI sets).
"""
import os
from datetime import datetime, timezone

import pytest

from fasten.attrs import AuditRow
from fasten.chain import verify_chain

DSN = os.environ.get("FASTEN_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="set FASTEN_TEST_POSTGRES_DSN")


def _row(i: int, *, service_id: str = "svc-a", node: str = "node-1") -> AuditRow:
    return AuditRow(
        id=f"evt-{service_id}-{i}", origin_id=f"evt-{service_id}-{i}",
        monotonic_seq=0,
        timestamp=datetime(2026, 6, 15, 10, 30, 45, tzinfo=timezone.utc),
        code="USER_CREATED", action="create", severity="info",
        service_id=service_id, source_node_id=node, tenant_id=None,
        actor="a", actor_kind="user", target=f"u/{i}",
        category="account", domain="user", method="sdk",
        request_id=f"req-{i}", detail={"n": i},
    )


@pytest.fixture()
def store():
    from fasten.store.postgres import PostgresStore
    s = PostgresStore.from_dsn(DSN)
    s.purge(before=datetime(2099, 1, 1, tzinfo=timezone.utc), respect_unshipped=False)
    return s


def test_allocates_and_seals(store):
    sealed = store.allocate_and_insert_originated(_row(1))
    assert sealed.monotonic_seq >= 1
    assert sealed.hash and sealed.prev_hash


def test_two_services_share_one_node_sequence(store):
    a = store.allocate_and_insert_originated(_row(1, service_id="svc-a"))
    b = store.allocate_and_insert_originated(_row(1, service_id="svc-b"))
    assert b.monotonic_seq == a.monotonic_seq + 1
    assert b.prev_hash == a.hash


def test_advisory_lock_serialises_concurrent_writers(store):
    """pg_advisory_xact_lock, NOT SELECT ... FOR UPDATE: on an empty table
    there is no tip row to lock, so FOR UPDATE would let every writer through
    to allocate seq 1."""
    import threading
    n, errors = 12, []
    barrier = threading.Barrier(n)
    from fasten.store.postgres import PostgresStore

    def worker(i: int) -> None:
        try:
            s = PostgresStore.from_dsn(DSN)
            barrier.wait(timeout=60)
            s.allocate_and_insert_originated(_row(i, service_id=f"svc-{i % 3}"))
        except BaseException as exc:
            errors.append(exc)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors, errors
    rows = store.query(limit=100)
    seqs = sorted(r.monotonic_seq for r in rows)
    assert seqs == list(range(1, n + 1)), f"duplicate/gapped: {seqs}"
    assert verify_chain(rows).ok


def test_unsealed_rows_still_occupy_their_sequence(store):
    """Same defect the SQLite backend had: filtering MAX(seq) on hash != ''
    restarts the counter against pre-upgrade rows."""
    import dataclasses
    store._insert_row(dataclasses.replace(_row(99), monotonic_seq=42))
    nxt = store.allocate_and_insert_originated(_row(1))
    assert nxt.monotonic_seq == 43


def test_retry_is_idempotent(store):
    """#12: re-running a committed allocation must return the PERSISTED row,
    not a freshly-sealed one with a burned sequence number."""
    first = store.allocate_and_insert_originated(_row(7))
    again = store.allocate_and_insert_originated(_row(7))
    assert again.monotonic_seq == first.monotonic_seq
    assert again.hash == first.hash
    assert len([r for r in store.query(limit=100) if r.id == first.id]) == 1


def test_form_2_commitment_round_trips(store):
    """The commitment columns must survive the store round trip, or the hash
    cannot be recomputed on read."""
    sealed = store.allocate_and_insert_originated(_row(11))
    assert sealed.canonical_form_id == "2"
    assert sealed.detail_salt and sealed.detail_commitment
    (back,) = [r for r in store.query(limit=50) if r.id == sealed.id]
    assert back.detail_salt == sealed.detail_salt
    assert back.detail_commitment == sealed.detail_commitment
    assert verify_chain([back]).ok


def test_redact_expired_destroys_pii_keeps_ops_and_chain(store):
    """#90 on Postgres: PII on a short horizon, ops history on its own."""
    import dataclasses
    from datetime import timedelta
    old = datetime.now(timezone.utc) - timedelta(days=40)

    pii = store.allocate_and_insert_originated(dataclasses.replace(
        _row(21), code="USER_EXPORTED", timestamp=old, detail={"email": "a@b.c"}))
    ops = store.allocate_and_insert_originated(dataclasses.replace(
        _row(22), code="SERVICE_PINGED", timestamp=old, detail={"n": 1}))

    redacted = store.redact_expired(
        before=datetime.now(timezone.utc) - timedelta(days=30),
        codes=["USER_EXPORTED"])
    assert redacted == [pii.id]

    rows = {r.id: r for r in store.query(limit=50)}
    assert rows[pii.id].detail is None
    assert rows[pii.id].detail_salt is None
    assert rows[ops.id].detail == {"n": 1}
    assert rows[pii.id].hash == pii.hash
    assert verify_chain(list(rows.values())).ok


def test_redact_expired_respects_cutoff_and_codes(store):
    import dataclasses
    from datetime import timedelta
    fresh = store.allocate_and_insert_originated(dataclasses.replace(
        _row(31), code="USER_EXPORTED",
        timestamp=datetime.now(timezone.utc), detail={"email": "x@y.z"}))
    assert store.redact_expired(
        before=datetime.now(timezone.utc) - timedelta(days=30),
        codes=["USER_EXPORTED"]) == []
    assert store.redact_expired(before=datetime(2099, 1, 1, tzinfo=timezone.utc),
                                codes=[]) == []
    assert {r.id: r for r in store.query(limit=50)}[fresh.id].detail is not None


def test_sealed_form_1_row_is_counted_and_never_redacted(store, caplog):
    """Spec §7.1: an unsealed row is a candidate; a sealed form "1" row is not,
    is counted in the warning, and survives redact_rows naming it directly."""
    import dataclasses
    import logging
    from datetime import timedelta
    old = datetime.now(timezone.utc) - timedelta(days=40)
    unsealed = dataclasses.replace(
        _row(31), code="USER_EXPORTED", timestamp=old,
        detail={"email": "u@v.w"}, monotonic_seq=900_001)
    legacy = dataclasses.replace(
        _row(32), code="USER_EXPORTED", timestamp=old,
        detail={"email": "l@m.n"}, monotonic_seq=900_002,
        canonical_form_id="1", prev_hash="genesis", hash="f" * 64)
    store._insert_row(unsealed)
    store._insert_row(legacy)

    with caplog.at_level(logging.WARNING, logger="fasten.store.postgres"):
        got = store.list_redaction_candidates(
            before=datetime.now(timezone.utc) - timedelta(days=30),
            codes=["USER_EXPORTED"])
    assert [cid for cid, _ in got] == [unsealed.id]
    warnings = [r.getMessage() for r in caplog.records
                if r.name == "fasten.store.postgres"]
    assert len(warnings) == 1 and " 1 row(s) " in warnings[0], warnings

    store.redact_rows(ids=[legacy.id])
    assert {r.id: r for r in store.query(limit=50)}[legacy.id].detail == {"email": "l@m.n"}


def test_redact_rows_on_a_not_null_salt_column():
    """go/store_postgres.go declares detail_salt NOT NULL DEFAULT '', so
    redaction writes '' like Go does, and '' reads back as no salt. One pass
    blanks the row; a second finds nothing left to redact."""
    import dataclasses

    import psycopg

    from fasten.store.postgres import PostgresStore
    table = "fasten_not_null_salt"
    with psycopg.connect(DSN) as conn:
        conn.execute(f"DROP TABLE IF EXISTS {table}")
    store = PostgresStore(DSN, table=table)
    sealed = store.allocate_and_insert_originated(_row(41))
    with psycopg.connect(DSN) as conn:
        for col in ("detail_salt", "detail_commitment"):
            conn.execute(f"ALTER TABLE {table} ALTER COLUMN {col} SET DEFAULT ''")
            conn.execute(f"ALTER TABLE {table} ALTER COLUMN {col} SET NOT NULL")
    unsealed = dataclasses.replace(
        _row(42), monotonic_seq=sealed.monotonic_seq + 1,
        detail_salt="", detail_commitment="")
    store._insert_row(unsealed)

    assert store.redact_rows(ids=[sealed.id, unsealed.id]) == [sealed.id, unsealed.id]

    rows = {r.id: r for r in store.query(limit=10)}
    for rid in (sealed.id, unsealed.id):
        assert rows[rid].detail is None
        assert rows[rid].detail_salt is None
    assert verify_chain([rows[sealed.id]]).ok
    assert store.list_redaction_candidates(
        before=datetime(2099, 1, 1, tzinfo=timezone.utc),
        codes=["USER_CREATED"]) == []
