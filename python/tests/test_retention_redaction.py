"""The retention and redaction contract.

What this file guarantees, one class per guarantee:

  PIICodeSet          which codes the horizon acts on, derived from the catalog
  Configuration       how an operator turns the horizon on, and what happens
                      when they configure something impossible
  RedactionSemantics  what redaction destroys, what it preserves, and that the
                      chain still verifies afterwards
  RecordBeforeDestroy no row loses its payload without a durable spec §7.2
                      record — in every failure mode, including the default
  FormCompatibility   form-"1" rows cannot be redacted, and are reported
  AgePurgeContract    the age purge and the PII horizon are independent

Organised by what breaks if it regresses, not by the order the bugs were found.
Provenance appears only where a guard looks arbitrary without it.

Companion files: test_retention.py (purger loop mechanics and duration
parsing), test_canonical_form_2.py (the hashed form itself).
"""
from __future__ import annotations

import dataclasses
import logging
import os
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

import pytest

from fasten import codes
from fasten.attrs import AuditRow
from fasten.chain import verify_chain
from fasten.codes import Meta, RetentionClass, Severity, pii_codes
from fasten.context import mint_id
from fasten.engine import AuditStoreError, Engine
from fasten.retention import start_purger
from fasten.store.sqlite import SQLiteStore

PII = "RR_USER_EXPORTED"
OPS = "RR_SERVICE_PINGED"
REDACTION = Engine._REDACTION_CODE


@pytest.fixture(scope="module", autouse=True)
def _register_codes() -> None:
    """register() raises on a duplicate, so register once per module."""
    codes.register("rrdemo", {
        PII: Meta(id=PII, domain="rrdemo", action="export", category="data",
                  severity=Severity.INFO, description="export", emitter="t",
                  retention_class=RetentionClass.LONG,  # forced to SHORT
                  pii_in_detail=True),
        OPS: Meta(id=OPS, domain="rrdemo", action="ping", category="ops",
                  severity=Severity.INFO, description="ping", emitter="t",
                  retention_class=RetentionClass.LONG),
    })


def new_db() -> str:
    return os.path.join(tempfile.mkdtemp(), "audit.db")


def aged(store: Any, code: str, detail: dict, days: float) -> AuditRow:
    """Seal a row AT a past timestamp.

    Backdating with UPDATE after sealing rewrites `timestamp`, which is inside
    the hashed field set, and verify_chain correctly calls that tampering.
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


def rows_by_id(db: str) -> dict[str, AuditRow]:
    return {r.id: r for r in SQLiteStore(db).query(limit=50)}


def wait_for(pred: Callable[[], Any], timeout: float = 10.0) -> Any:
    """Poll until pred() is truthy. Returns None on timeout.

    The purger's first tick runs immediately, so seeding the store BEFORE
    init() needs no check_interval knob — but the tick is on another thread.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        got = pred()
        if got:
            return got
        time.sleep(0.05)
    return None


def engine_with(db: str, *, store: Optional[Any] = None, **init_kw: Any) -> Engine:
    e = Engine()
    e.init(service_id="svc", node_id="node-1",
           audit_store=store if store is not None else SQLiteStore(db),
           **init_kw)
    return e


def redactions(rows: Any) -> list[AuditRow]:
    return [r for r in rows if r.code == REDACTION]


# ─────────────────────────────────────────────────────────────────────────────

class TestPIICodeSet:
    """Which codes the horizon acts on."""

    def test_derived_from_the_catalog(self) -> None:
        got = pii_codes()
        assert PII in got, "a pii_in_detail code was not derived"
        assert OPS not in got, "a LONG non-PII code was swept up"

    def test_pii_flag_forces_short_retention(self) -> None:
        meta = codes.meta_of(PII)
        assert meta is not None
        assert str(meta.retention_class) == "short", \
            "pii_in_detail must force SHORT even when LONG is declared"


class TestConfiguration:
    """How the horizon is turned on, and what impossible config does."""

    def test_engine_kwarg_enables_it(self) -> None:
        db = new_db()
        pii = aged(SQLiteStore(db), PII, {"email": "a@b.c"}, 40)
        e = engine_with(db, audit_store_failure_strategy="raise",
                        retention_pii="30d")
        try:
            assert wait_for(lambda: rows_by_id(db)[pii.id].detail is None), \
                "retention_pii did not reach the audit store"
        finally:
            e.reset_for_tests()

    def test_env_var_enables_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        db = new_db()
        pii = aged(SQLiteStore(db), PII, {"email": "a@b.c"}, 40)
        monkeypatch.setenv("FASTEN_RETENTION_PII", "30d")
        e = engine_with(db, audit_store_failure_strategy="raise")
        try:
            assert wait_for(lambda: rows_by_id(db)[pii.id].detail is None), \
                "FASTEN_RETENTION_PII was not read"
        finally:
            e.reset_for_tests()

    def test_it_is_opt_in(self) -> None:
        """No horizon configured means no purger and no redaction."""
        db = new_db()
        pii = aged(SQLiteStore(db), PII, {"email": "a@b.c"}, 40)
        e = engine_with(db, audit_store_failure_strategy="raise")
        try:
            time.sleep(0.5)   # let any tick that would fire, fire
            assert rows_by_id(db)[pii.id].detail == {"email": "a@b.c"}
            assert not redactions(rows_by_id(db).values())
        finally:
            e.reset_for_tests()

    def test_purger_with_no_horizon_at_all_is_rejected(self) -> None:
        """A thread that ticks forever doing nothing is a config error."""
        with pytest.raises(ValueError, match="at least one of retention"):
            start_purger(store=SQLiteStore(new_db()), stream="audit")

    def test_store_that_cannot_redact_is_rejected(self) -> None:
        db = new_db()
        e = engine_with(db, audit_store_failure_strategy="raise")
        try:
            e._audit_store = object()
            with pytest.raises(AuditStoreError, match="redact"):
                e.redact_expired(before=datetime.now(timezone.utc), codes=[PII])
        finally:
            e.reset_for_tests()


class TestRedactionSemantics:
    """What redaction destroys, preserves, and leaves verifiable."""

    def test_pii_expires_while_operational_history_survives(self) -> None:
        """The policy that was previously inexpressible: two horizons."""
        store = SQLiteStore(new_db())
        pii = aged(store, PII, {"email": "a@b.c"}, 40)
        ops = aged(store, OPS, {"n": 1}, 40)

        stop = threading.Event()
        t = start_purger(store=store, stream="audit",
                         retention=None,                   # audit: never delete
                         pii_retention=timedelta(days=30),
                         check_interval=timedelta(hours=1), stop_event=stop)
        t.join(timeout=2.0)
        stop.set()

        rows = {r.id: r for r in store.query(limit=20)}
        assert rows[pii.id].detail is None, "PII survived its horizon"
        assert rows[pii.id].detail_salt is None, \
            "salt survived — the commitment digest stays guessable"
        assert rows[ops.id].detail == {"n": 1}, \
            "operational history was destroyed too"

    def test_rows_younger_than_the_horizon_are_untouched(self) -> None:
        store = SQLiteStore(new_db())
        fresh = aged(store, PII, {"email": "n@o.p"}, 1)
        stop = threading.Event()
        t = start_purger(store=store, stream="audit",
                         pii_retention=timedelta(days=30),
                         check_interval=timedelta(hours=1), stop_event=stop)
        t.join(timeout=2.0)
        stop.set()
        assert {r.id: r for r in store.query(limit=20)}[fresh.id].detail is not None

    def test_rows_are_redacted_never_deleted(self) -> None:
        """Deleting from a hash-chained stream is the tamper signature."""
        db = new_db()
        seed = SQLiteStore(db)
        pii = aged(seed, PII, {"email": "a@b.c"}, 4000)
        ops = aged(seed, OPS, {"n": 1}, 4000)
        e = engine_with(db, audit_store_failure_strategy="raise",
                        retention_pii="1d")
        try:
            assert wait_for(lambda: rows_by_id(db)[pii.id].detail is None)
            rows = rows_by_id(db)
            assert pii.id in rows, "an audit row was DELETED, not redacted"
            assert ops.id in rows, "an audit row was DELETED, not redacted"
            assert verify_chain(list(rows.values())).ok
        finally:
            e.reset_for_tests()

    def test_the_chain_still_verifies_after_redaction(self) -> None:
        db = new_db()
        store = SQLiteStore(db)
        aged(store, PII, {"email": "a@b.c"}, 40)
        aged(store, OPS, {"n": 1}, 40)
        e = engine_with(db, store=store, audit_store_failure_strategy="raise")
        try:
            e.redact_expired(
                before=datetime.now(timezone.utc) - timedelta(days=30),
                codes=[PII])
            rows = store.query(limit=50)
            assert verify_chain(rows).ok, \
                "redaction broke the chain it is designed to preserve"
        finally:
            e.reset_for_tests()

    def test_retry_destroys_the_same_rows_and_reports_them(self) -> None:
        """Idempotent by targeting ids rather than a time window.

        Deriving the return value from RETURNING on a window query guarded by
        `detail <> 'null'` meant a retry after a lost commit ack matched
        nothing and returned [], so the caller wrote no events for rows it had
        just destroyed.
        """
        store = SQLiteStore(new_db())
        pii = aged(store, PII, {"email": "a@b.c"}, 40)
        first = store.redact_rows(ids=[pii.id])
        again = store.redact_rows(ids=[pii.id])
        assert first == [pii.id]
        assert again == first, "the retry lost the ids the caller needs"


class TestRecordBeforeDestroy:
    """Spec §7.2 — no payload dies without a durable record.

    Without the record an honest erasure and a quiet unauthorised redaction are
    indistinguishable, which is most of the reason to redact rather than DELETE.
    """

    def test_redaction_emits_a_chained_event(self) -> None:
        db = new_db()
        store = SQLiteStore(db)
        pii = aged(store, PII, {"email": "a@b.c"}, 40)
        ops = aged(store, OPS, {"n": 1}, 40)
        e = engine_with(db, store=store, audit_store_failure_strategy="raise")
        try:
            got = e.redact_expired(
                before=datetime.now(timezone.utc) - timedelta(days=30),
                codes=[PII], reason="gdpr-30d")
            assert got == [pii.id]

            rows = store.query(limit=50)
            by_id = {r.id: r for r in rows}
            assert by_id[pii.id].detail is None
            assert by_id[pii.id].detail_salt is None
            assert by_id[ops.id].detail == {"n": 1}

            events = redactions(rows)
            assert len(events) == 1, "the redaction was not recorded"
            assert events[0].target == pii.id
            assert events[0].detail is not None
            assert events[0].detail["reason"] == "gdpr-30d"
            assert events[0].hash and events[0].prev_hash, \
                "the record must itself be chained"
            assert verify_chain(rows).ok
        finally:
            e.reset_for_tests()

    def test_event_carries_the_spec_detail_shape(self) -> None:
        """spec/chain-replication.md §7.2: {"redacted_seq": n, "reason": ...}.

        The implementation wrote redacted_id and no seq.
        """
        db = new_db()
        store = SQLiteStore(db)
        pii = aged(store, PII, {"email": "a@b.c"}, 40)
        e = engine_with(db, store=store, audit_store_failure_strategy="raise")
        try:
            e.redact_expired(
                before=datetime.now(timezone.utc) - timedelta(days=30),
                codes=[PII])
            ev = redactions(store.query(limit=50))[0]
            assert ev.detail is not None
            assert ev.detail["redacted_seq"] == pii.monotonic_seq
            assert ev.detail["reason"] == "retention"
            assert ev.detail["redacted_id"] == pii.id
        finally:
            e.reset_for_tests()

    def test_one_event_per_row_redacted(self) -> None:
        db = new_db()
        store = SQLiteStore(db)
        ids = [aged(store, PII, {"email": f"{i}@x.y"}, 40).id for i in range(3)]
        e = engine_with(db, store=store, audit_store_failure_strategy="raise")
        try:
            got = e.redact_expired(
                before=datetime.now(timezone.utc) - timedelta(days=30),
                codes=[PII])
            assert sorted(got) == sorted(ids)
            events = redactions(store.query(limit=50))
            assert len(events) == 3
            assert sorted(ev.target for ev in events) == sorted(ids)
            assert verify_chain(store.query(limit=50)).ok
        finally:
            e.reset_for_tests()

    def test_nothing_expired_means_no_event(self) -> None:
        db = new_db()
        store = SQLiteStore(db)
        e = engine_with(db, store=store, audit_store_failure_strategy="raise")
        try:
            e.emit(code=PII, target="u/2", detail={"email": "x@y.z"})
            assert e.redact_expired(
                before=datetime.now(timezone.utc) - timedelta(days=30),
                codes=[PII]) == []
            assert not redactions(store.query(limit=50))
        finally:
            e.reset_for_tests()

    def test_the_event_code_exists_before_any_store_call(self) -> None:
        """Registering it afterwards meant a failure there destroyed data with
        no record, and a retry could not repair it."""
        seen: list[bool] = []

        class Probe(SQLiteStore):
            def list_redaction_candidates(self, *, before, codes):  # type: ignore[no-untyped-def]
                seen.append(codes_module_has_redaction_code())
                return []

        def codes_module_has_redaction_code() -> bool:
            return codes.meta_of(REDACTION) is not None

        db = new_db()
        e = engine_with(db, store=Probe(db),
                        audit_store_failure_strategy="raise")
        try:
            e.redact_expired(before=datetime.now(timezone.utc), codes=[PII])
            assert seen == [True], \
                "the code was not registered before the store was touched"
        finally:
            e.reset_for_tests()

    def test_a_retry_after_a_failed_destroy_does_not_duplicate_events(self) -> None:
        """Record and destroy per row, so a retry re-records at most one.

        Emitting the whole batch and then destroying it in one call left every
        row still a candidate when the destroy failed, so the next tick
        re-recorded all of them.
        """
        db = new_db()
        seed = SQLiteStore(db)
        ids = [aged(seed, PII, {"email": f"{i}@x.y"}, 40).id for i in range(3)]

        fail = {"on": True}

        class DestroyFailsOnce(SQLiteStore):
            def redact_rows(self, *, ids):  # type: ignore[no-untyped-def]
                if fail["on"]:
                    raise RuntimeError("destroy unavailable")
                return super().redact_rows(ids=ids)

        e = engine_with(db, store=DestroyFailsOnce(db),
                        audit_store_failure_strategy="raise")
        try:
            with pytest.raises(RuntimeError):
                e.redact_expired(
                    before=datetime.now(timezone.utc) - timedelta(days=30),
                    codes=[PII])
            # The first row was recorded, then its destroy failed; the loop
            # stopped there rather than recording the other two.
            after_failure = redactions(rows_by_id(db).values())
            assert len(after_failure) == 1, (
                "a failed destroy recorded rows it never reached: "
                f"{len(after_failure)} events for 3 candidates"
            )

            fail["on"] = False
            e.redact_expired(
                before=datetime.now(timezone.utc) - timedelta(days=30),
                codes=[PII])

            events = redactions(rows_by_id(db).values())
            targets = [ev.target for ev in events]
            assert sorted(set(targets)) == sorted(ids), "not every row recorded"
            dupes = [t for t in set(targets) if targets.count(t) > 1]
            assert len(dupes) <= 1, \
                f"retry duplicated records for {len(dupes)} rows: {dupes}"
            assert verify_chain(list(rows_by_id(db).values())).ok
        finally:
            e.reset_for_tests()

    def test_a_failed_event_destroys_nothing_in_raise_mode(self) -> None:
        db = new_db()
        pii = aged(SQLiteStore(db), PII, {"email": "a@b.c"}, 40)
        e = engine_with(db, audit_store_failure_strategy="raise")
        try:
            def explode(**_kw: Any) -> None:
                raise RuntimeError("emit failed")

            e.emit = explode                      # type: ignore[method-assign]
            with pytest.raises(RuntimeError):
                e.redact_expired(
                    before=datetime.now(timezone.utc) - timedelta(days=30),
                    codes=[PII])
            assert rows_by_id(db)[pii.id].detail == {"email": "a@b.c"}, \
                "data was destroyed though its record failed to write"
        finally:
            e.reset_for_tests()

    def test_a_failed_event_destroys_nothing_in_queue_mode(self) -> None:
        """Queue mode is the DEFAULT, and it swallows store failures.

        emit() in queue mode catches the insert error, flags the engine
        degraded, logs, and returns normally — so the redaction loop saw no
        exception and destroyed rows whose record had never been persisted.
        Testing only raise mode missed this entirely.
        """
        db = new_db()
        pii = aged(SQLiteStore(db), PII, {"email": "a@b.c"}, 40)

        class RejectsTheRecord(SQLiteStore):
            def allocate_and_insert_originated(self, row):  # type: ignore[no-untyped-def]
                if row.code == REDACTION:
                    raise RuntimeError("store rejected the redaction event")
                return super().allocate_and_insert_originated(row)

        e = engine_with(db, store=RejectsTheRecord(db))   # default: queue
        try:
            with pytest.raises(Exception):
                e.redact_expired(
                    before=datetime.now(timezone.utc) - timedelta(days=30),
                    codes=[PII])
            rows = rows_by_id(db)
            assert rows[pii.id].detail == {"email": "a@b.c"}, \
                "queue mode destroyed a row whose record was swallowed"
            assert rows[pii.id].detail_salt is not None
            assert not redactions(rows.values()), \
                "an event persisted though the store rejected it"
        finally:
            e.reset_for_tests()


class TestFormCompatibility:
    """Form-"1" rows hash `detail` directly, so they cannot be redacted."""

    def test_form_1_rows_are_skipped_and_reported(self) -> None:
        """Skipping is correct; doing it silently is not.

        On a pre-upgrade store the operator sees redaction run, sees no error,
        and concludes the personal data is gone when every byte is still there.
        """
        db = new_db()
        store = SQLiteStore(db)
        row = aged(store, PII, {"email": "a@b.c"}, 40)
        conn = store._connect()
        conn.execute(
            f"UPDATE {store._table} SET canonical_form_id = '1' WHERE id = ?",
            (row.id,))
        conn.commit()

        records: list[logging.LogRecord] = []

        class Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        logger = logging.getLogger("fasten.store.sqlite")
        handler = Capture()
        logger.addHandler(handler)
        try:
            got = store.redact_expired(
                before=datetime.now(timezone.utc) - timedelta(days=30),
                codes=[PII])
        finally:
            logger.removeHandler(handler)

        assert got == [], "a form-1 row was redacted — its hash is now wrong"
        assert any("canonical_form_id != '2'" in r.getMessage() for r in records), \
            "form-1 rows were skipped with no warning"
        assert rows_by_id(db)[row.id].detail == {"email": "a@b.c"}


class TestAgePurgeContract:
    """The age purge and the PII horizon are independent policies."""

    def test_age_purge_accepts_a_datetime_on_an_audit_store(self) -> None:
        """It used to raise on every tick, invisibly.

        start_purger passed a canonical string while the audit stores declare
        `before: datetime`. The raise landed in the tick's except and went out
        through on_error, so a purge that never once succeeded looked healthy:
        the fake store in test_retention.py agreed with the caller, the real
        stores did not, and every fixture row was younger than its retention.
        """
        db = new_db()
        store = SQLiteStore(db)
        aged(store, PII, {"email": "a@b.c"}, 400)   # past a 365-day horizon
        aged(store, OPS, {"n": 1}, 400)

        errors: list[tuple[str, str]] = []
        stop = threading.Event()
        t = start_purger(
            store=store, stream="audit",
            retention=timedelta(days=365),
            pii_retention=timedelta(days=30),
            check_interval=timedelta(milliseconds=50), stop_event=stop,
            on_error=lambda label, e: errors.append((label, f"{type(e).__name__}: {e}")),
        )
        wait_for(lambda: [r for r in store.query(limit=20) if r.detail is None])
        stop.set()
        t.join(timeout=2.0)
        assert not errors, f"a retention tick raised: {errors}"

    def test_a_redaction_failure_does_not_skip_the_age_purge(self) -> None:
        """Separate try blocks, separate labels. One shared try let a
        redaction failure suppress the age purge for the rest of the tick."""
        purged: list[Any] = []

        class RedactionFails:
            def redact_expired(self, *, before, codes):  # type: ignore[no-untyped-def]
                raise RuntimeError("redaction down")

            def purge(self, *, before):  # type: ignore[no-untyped-def]
                purged.append(before)
                return 0

        errors: list[str] = []
        stop = threading.Event()
        t = start_purger(
            store=RedactionFails(), stream="api",
            retention=timedelta(days=365),
            pii_retention=timedelta(days=30),
            check_interval=timedelta(milliseconds=50), stop_event=stop,
            on_error=lambda label, e: errors.append(label),
        )
        wait_for(lambda: purged)
        stop.set()
        t.join(timeout=2.0)

        assert purged, "the age purge was skipped because redaction failed"
        assert "api/pii-redaction" in errors, \
            "the redaction failure was not reported under its own label"
        assert "api/age-purge" not in errors, \
            "the age purge was reported as failing when it succeeded"
