"""#90, second half — the PII horizon has to be reachable from configuration.

test_pii_retention_horizon.py proves the MECHANISM: pii_codes() derives the
code set and start_purger(pii_retention=...) redacts. It proves it by calling
start_purger directly with stream="audit", which is a configuration the Engine
could not produce:

  - `pii_retention` was never passed by _start_retention_threads, and the
    parameter appeared nowhere outside retention.py and that one test;
  - the purger loop covered only the api and sys stores, while redact_expired,
    pii_in_detail, canonical_form_id and detail_salt all live on the AUDIT
    store, which got no purger at all;
  - start_purger called store.redact_expired, the raw store method, which does
    not emit AUDIT_ROW_REDACTED. Only Engine.redact_expired does. So even once
    wired, the automatic path would have destroyed data with no spec §7.2
    record — the exact thing that method's own docstring forbids.

So the mechanism was tested against wiring that did not exist. These tests
drive it the way an operator does: configure the Engine, and assert.

The audit purger is REDACTION-ONLY by construction. It never age-deletes,
because removing a row from a hash-chained stream is what spec §7.1 exists to
prevent. test_audit_rows_are_never_age_deleted pins that.
"""
import dataclasses
import os
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from fasten import codes
from fasten.attrs import AuditRow
from fasten.chain import verify_chain
from fasten.codes import Meta, RetentionClass, Severity
from fasten.context import mint_id
from fasten.engine import Engine
from fasten.retention import start_purger
from fasten.store.sqlite import SQLiteStore

PII, OPS = "WIRE_USER_EXPORTED", "WIRE_SERVICE_PINGED"


@pytest.fixture(scope="module", autouse=True)
def _register() -> None:
    codes.register("wiredemo", {
        PII: Meta(id=PII, domain="wiredemo", action="export", category="data",
                  severity=Severity.INFO, description="export", emitter="t",
                  pii_in_detail=True),            # forced to SHORT
        OPS: Meta(id=OPS, domain="wiredemo", action="ping", category="ops",
                  severity=Severity.INFO, description="ping", emitter="t",
                  retention_class=RetentionClass.LONG),
    })


def _db() -> str:
    return os.path.join(tempfile.mkdtemp(), "audit.db")


def _aged(store, code: str, detail: dict, days: int) -> AuditRow:
    """Seal AT the old timestamp.

    Backdating with UPDATE after sealing would rewrite `timestamp`, which is
    inside the hashed field set, and verify_chain correctly calls that
    tampering. Build the row with the timestamp it should have.
    """
    meta = codes.meta_of(code)
    assert meta is not None
    row = AuditRow(
        id=f"evt-{mint_id()}", origin_id="", monotonic_seq=0,
        timestamp=datetime.now(timezone.utc) - timedelta(days=days),
        code=code, action=meta.action, severity=str(meta.severity),
        service_id="svc", source_node_id="node-1", tenant_id=None,
        actor="system", actor_kind="service", target="t",
        category=meta.category, domain=meta.domain, method="sdk",
        request_id="req-1", detail=detail,
    )
    return store.allocate_and_insert_originated(
        dataclasses.replace(row, origin_id=row.id))


def _wait_for(pred, timeout: float = 10.0):
    """Poll until pred() is truthy.

    The purger's first tick runs immediately on start(), so seeding the store
    BEFORE init() means no check_interval knob is needed to observe the effect
    — but the tick is on another thread, so it still has to be awaited.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        got = pred()
        if got:
            return got
        time.sleep(0.05)
    return None


def test_engine_config_destroys_pii_and_records_it() -> None:
    """The whole point of #90, driven from configuration rather than by hand."""
    db = _db()
    seed = SQLiteStore(db)
    pii = _aged(seed, PII, {"email": "a@b.c"}, 40)
    ops = _aged(seed, OPS, {"n": 1}, 40)

    e = Engine()
    e.init(service_id="svc", node_id="node-1", audit_store=SQLiteStore(db),
           audit_store_failure_strategy="raise",
           retention_pii="30d")
    try:
        reader = SQLiteStore(db)
        got = _wait_for(
            lambda: [r for r in reader.query(limit=50)
                     if r.id == pii.id and r.detail is None])
        assert got, "PII detail survived its 30-day horizon under Engine config"

        rows = {r.id: r for r in reader.query(limit=50)}
        assert rows[pii.id].detail_salt is None, \
            "salt survived — the commitment digest stays guessable"
        assert rows[ops.id].detail == {"n": 1}, \
            "a LONG non-PII row was swept up"

        # spec §7.2: the destruction is itself a chained row. Without this an
        # honest erasure and a quiet redaction are indistinguishable, which is
        # most of the reason to redact rather than DELETE.
        redactions = [r for r in rows.values()
                      if r.code == Engine._REDACTION_CODE]
        assert len(redactions) == 1, (
            "no AUDIT_ROW_REDACTED row — the purger reached the raw store "
            "method and bypassed the spec §7.2 event"
        )
        assert redactions[0].detail is not None
        # spec/chain-replication.md:305 specifies
        #   detail = {"redacted_seq": <n>, "reason": <policy>}
        # The code wrote redacted_id and no seq, so this assertion is the one
        # that pins conformance — an earlier version of this test asserted the
        # non-conformant shape and would have shipped it.
        assert redactions[0].detail["redacted_seq"] == pii.monotonic_seq
        assert redactions[0].detail["reason"] == "retention"
        assert redactions[0].detail["redacted_id"] == pii.id

        assert verify_chain(list(rows.values())).ok, \
            "redaction broke the chain it is designed to preserve"
    finally:
        e.reset_for_tests()


def test_audit_rows_are_never_age_deleted() -> None:
    """Redaction-only by construction.

    An audit purger that also age-deleted would remove rows from a hash-chained
    stream — the tampering signature verify_chain is built to detect. The PII
    horizon destroys `detail`; it never removes the row.
    """
    db = _db()
    seed = SQLiteStore(db)
    pii = _aged(seed, PII, {"email": "a@b.c"}, 4000)   # far past any horizon
    ops = _aged(seed, OPS, {"n": 1}, 4000)

    e = Engine()
    e.init(service_id="svc", node_id="node-1", audit_store=SQLiteStore(db),
           audit_store_failure_strategy="raise",
           retention_pii="1d")
    try:
        reader = SQLiteStore(db)
        assert _wait_for(lambda: [r for r in reader.query(limit=50)
                                  if r.id == pii.id and r.detail is None])
        rows = {r.id: r for r in reader.query(limit=50)}
        assert pii.id in rows, "an audit row was DELETED, not redacted"
        assert ops.id in rows, "an audit row was DELETED, not redacted"
        assert verify_chain(list(rows.values())).ok
    finally:
        e.reset_for_tests()


def test_without_retention_pii_nothing_is_touched() -> None:
    """Opt-in. No retention_pii means no audit purger and no redaction."""
    db = _db()
    seed = SQLiteStore(db)
    pii = _aged(seed, PII, {"email": "a@b.c"}, 40)

    e = Engine()
    e.init(service_id="svc", node_id="node-1", audit_store=SQLiteStore(db),
           audit_store_failure_strategy="raise")
    try:
        time.sleep(0.5)   # let any tick that would fire, fire
        rows = {r.id: r for r in SQLiteStore(db).query(limit=50)}
        assert rows[pii.id].detail == {"email": "a@b.c"}, \
            "redaction ran without being configured"
        assert not [r for r in rows.values()
                    if r.code == Engine._REDACTION_CODE]
    finally:
        e.reset_for_tests()


def test_form_1_rows_are_reported_not_skipped_silently(caplog) -> None:
    """A pre-upgrade store must not look like a successful redaction.

    Form-"1" rows hash `detail` directly, so redacting one would change its
    hash and cascade a re-seal down the chain. Skipping them is correct. Doing
    it quietly is not: the operator sees redaction run, sees no error, and
    concludes the personal data is gone when every byte of it is still there.
    """
    import logging
    db = _db()
    store = SQLiteStore(db)
    row = _aged(store, PII, {"email": "a@b.c"}, 40)

    # Reproduce a pre-upgrade row: form "1", detail inside the hash.
    conn = store._connect()
    conn.execute(
        f"UPDATE {store._table} SET canonical_form_id = '1' WHERE id = ?",
        (row.id,))
    conn.commit()

    with caplog.at_level(logging.WARNING, logger="fasten.store.sqlite"):
        redacted = store.redact_expired(
            before=datetime.now(timezone.utc) - timedelta(days=30),
            codes=[PII])

    assert redacted == [], "a form-1 row was redacted — its hash is now wrong"
    assert any("canonical_form_id != '2'" in r.message for r in caplog.records), \
        "form-1 rows were skipped with no warning — silent PII survival"
    # and the data is, correctly, still there: skipping means skipping
    kept = {r.id: r for r in SQLiteStore(db).query(limit=10)}
    assert kept[row.id].detail == {"email": "a@b.c"}


def test_a_failed_event_destroys_nothing() -> None:
    """Record before destroying, so no row dies without its record.

    Destroy-then-emit leaves the data gone and no record if the emit fails,
    and the retry can't find the rows it just emptied.
    """
    db = _db()
    seed = SQLiteStore(db)
    pii = _aged(seed, PII, {"email": "a@b.c"}, 40)

    e = Engine()
    e.init(service_id="svc", node_id="node-1", audit_store=SQLiteStore(db),
           audit_store_failure_strategy="raise")
    try:
        boom = RuntimeError("emit failed")

        def _explode(**_kw):
            raise boom

        e.emit = _explode                      # type: ignore[method-assign]
        with pytest.raises(RuntimeError):
            e.redact_expired(before=datetime.now(timezone.utc) - timedelta(days=30),
                             codes=[PII])

        rows = {r.id: r for r in SQLiteStore(db).query(limit=20)}
        assert rows[pii.id].detail == {"email": "a@b.c"}, \
            "data was destroyed even though its §7.2 record failed to write"
        assert rows[pii.id].detail_salt is not None
    finally:
        e.reset_for_tests()


def test_redact_rows_is_idempotent_under_retry() -> None:
    """A retried redaction must not lose its ids.

    Returning RETURNING ids from a window query guarded by `detail <> 'null'`
    meant a retry after a lost commit ack matched nothing and returned [], so
    the caller wrote no events for rows it had just destroyed.
    """
    db = _db()
    store = SQLiteStore(db)
    pii = _aged(store, PII, {"email": "a@b.c"}, 40)

    first = store.redact_rows(ids=[pii.id])
    again = store.redact_rows(ids=[pii.id])     # the retry
    assert first == [pii.id]
    assert again == first, "retry lost the ids the caller needs for its events"


def test_age_purge_does_not_raise_on_an_audit_store() -> None:
    """The age purge threw on every tick, silently.

    start_purger passed a canonical string while the audit stores declare
    `before: datetime`. The raise landed in the tick's except and went out
    through on_error, so a purge that never once succeeded looked healthy.
    The fake store agreed with the caller and the real stores did not, and
    every fixture row was younger than its retention, so there was nothing to
    delete and the failure was invisible.

    Pins both halves: a row past the horizon, and an on_error hook that fails
    the test if it fires.
    """
    db = _db()
    store = SQLiteStore(db)
    _aged(store, PII, {"email": "a@b.c"}, 400)   # past a 365-day horizon
    _aged(store, OPS, {"n": 1}, 400)

    errors: list[tuple[str, str]] = []
    stop = threading.Event()
    t = start_purger(
        store=store, stream="audit",
        retention=timedelta(days=365),
        pii_retention=timedelta(days=30),
        check_interval=timedelta(milliseconds=50),
        stop_event=stop,
        on_error=lambda label, e: errors.append((label, f"{type(e).__name__}: {e}")),
    )
    for _ in range(100):
        if [r for r in SQLiteStore(db).query(limit=20) if r.detail is None]:
            break
        time.sleep(0.02)
    stop.set()
    t.join(timeout=2.0)

    assert not errors, f"retention tick raised: {errors}"


def test_purger_with_neither_horizon_is_a_config_error() -> None:
    """A thread that ticks forever and does nothing is a bug, not a default."""
    with pytest.raises(ValueError, match="at least one of retention"):
        start_purger(store=SQLiteStore(_db()), stream="audit")


def test_env_var_configures_the_horizon(monkeypatch: pytest.MonkeyPatch) -> None:
    """FASTEN_RETENTION_PII, matching FASTEN_RETENTION_API / _SYSLOG."""
    db = _db()
    seed = SQLiteStore(db)
    pii = _aged(seed, PII, {"email": "a@b.c"}, 40)

    monkeypatch.setenv("FASTEN_RETENTION_PII", "30d")
    e = Engine()
    e.init(service_id="svc", node_id="node-1", audit_store=SQLiteStore(db),
           audit_store_failure_strategy="raise")
    try:
        reader = SQLiteStore(db)
        assert _wait_for(lambda: [r for r in reader.query(limit=50)
                                  if r.id == pii.id and r.detail is None]), \
            "FASTEN_RETENTION_PII did not configure the horizon"
    finally:
        e.reset_for_tests()
