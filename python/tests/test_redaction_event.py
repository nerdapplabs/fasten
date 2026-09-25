"""P1-47 / spec §7.2 — redaction must itself be a chained event.

Destroying `detail` leaves a row whose detail is null. So does a quiet,
unauthorised redaction. Without an AUDIT_ROW_REDACTED row recording who did it
and under which policy, the two are indistinguishable — which is most of the
reason to redact rather than DELETE.
"""
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

import fasten
from fasten.chain import verify_chain
from fasten.engine import AuditStoreError, Engine
from fasten.store.sqlite import SQLiteStore


@pytest.fixture(scope="session", autouse=True)
def _register_redaction_codes():
    """register() raises on a duplicate code, so register once per session."""
    from fasten import codes
    from fasten.codes import Meta, Severity
    codes.register("redactdemo", {
        "REDACT_USER_EXPORTED": Meta(
            id="REDACT_USER_EXPORTED", domain="redactdemo", category="data",
            action="export", severity=list(Severity)[0],
            description="export", emitter="test"),
        "REDACT_SERVICE_PINGED": Meta(
            id="REDACT_SERVICE_PINGED", domain="redactdemo", category="ops",
            action="ping", severity=list(Severity)[0],
            description="ping", emitter="test"),
    })


@pytest.fixture()
def eng():
    db = os.path.join(tempfile.mkdtemp(), "audit.db")
    e = Engine()
    e.init(service_id="svc", node_id="node-1", audit_store=SQLiteStore(db),
           audit_store_failure_strategy="raise")
    return e, SQLiteStore(db)


def _emit_aged(e, store, code, target, detail, days):
    """Seal a row AT an old timestamp.

    The obvious approach — emit now, then UPDATE the timestamp — does not work
    and it is instructive why: `timestamp` is inside the hashed field set, so
    rewriting it after sealing IS tampering, and verify_chain correctly reports
    a hash mismatch. Build the row with the timestamp it should have and let
    the store seal it once.
    """
    import dataclasses
    from fasten.attrs import AuditRow
    from fasten.codes import meta_of
    from fasten.context import mint_id

    meta = meta_of(code)
    row = AuditRow(
        id=f"evt-{mint_id()}", origin_id="", monotonic_seq=0,
        timestamp=datetime.now(timezone.utc) - timedelta(days=days),
        code=code, action=meta.action, severity=str(meta.severity),
        service_id="svc", source_node_id="node-1", tenant_id=None,
        actor="system", actor_kind="service", target=target,
        category=meta.category, domain=meta.domain, method="sdk",
        request_id=f"req-{target}", detail=detail,
    )
    row = dataclasses.replace(row, origin_id=row.id)
    return store.allocate_and_insert_originated(row)


def test_redaction_emits_a_chained_event(eng):
    e, store = eng
    pii = _emit_aged(e, store, "REDACT_USER_EXPORTED", "u/1", {"email": "a@b.c"}, 40)
    ops = _emit_aged(e, store, "REDACT_SERVICE_PINGED", "svc/1", {"n": 1}, 40)

    redacted = e.redact_expired(
        before=datetime.now(timezone.utc) - timedelta(days=30),
        codes=["REDACT_USER_EXPORTED"], reason="gdpr-30d")
    assert redacted == [pii.id]

    rows = store.query(limit=50)
    by_id = {r.id: r for r in rows}
    # the data is gone
    assert by_id[pii.id].detail is None
    assert by_id[pii.id].detail_salt is None
    # operational history survived
    assert by_id[ops.id].detail == {"n": 1}
    # and the destruction is on the record
    events = [r for r in rows if r.code == "AUDIT_ROW_REDACTED"]
    assert len(events) == 1, "redaction was not recorded"
    assert events[0].target == pii.id
    assert events[0].detail["reason"] == "gdpr-30d"
    # the event is itself chained, and the chain still verifies end to end
    assert events[0].hash and events[0].prev_hash
    assert verify_chain(rows).ok


def test_no_rows_means_no_event(eng):
    e, store = eng
    e.emit(code="REDACT_USER_EXPORTED", target="u/2", detail={"email": "x@y.z"})
    assert e.redact_expired(
        before=datetime.now(timezone.utc) - timedelta(days=30),
        codes=["REDACT_USER_EXPORTED"]) == []
    assert not [r for r in store.query(limit=50) if r.code == "AUDIT_ROW_REDACTED"]


def test_event_count_matches_rows_redacted(eng):
    e, store = eng
    ids = [_emit_aged(e, store, "REDACT_USER_EXPORTED", f"u/{i}",
                      {"email": f"{i}@x.y"}, 40).id for i in range(3)]
    redacted = e.redact_expired(
        before=datetime.now(timezone.utc) - timedelta(days=30),
        codes=["REDACT_USER_EXPORTED"])
    assert sorted(redacted) == sorted(ids)
    events = [r for r in store.query(limit=50) if r.code == "AUDIT_ROW_REDACTED"]
    assert len(events) == 3
    assert sorted(ev.target for ev in events) == sorted(ids)
    assert verify_chain(store.query(limit=50)).ok


def test_store_without_redact_support_raises(eng):
    e, _ = eng
    e._audit_store = object()
    with pytest.raises(AuditStoreError, match="redact_expired"):
        e.redact_expired(before=datetime.now(timezone.utc), codes=["REDACT_USER_EXPORTED"])


def test_redaction_code_is_registered_before_any_data_is_destroyed():
    """The event code must exist BEFORE the delete.

    Registering after meant a failure there destroyed data with no record, and
    a retry could not repair it — the rows were already gone.
    """
    from fasten.codes import meta_of
    from fasten.store.sqlite import SQLiteStore

    calls = []

    class Probe(SQLiteStore):
        def redact_expired(self, *, before, codes):
            # By the time any data is touched, the code must be registered.
            calls.append(meta_of("AUDIT_ROW_REDACTED") is not None)
            return []

    db = os.path.join(tempfile.mkdtemp(), "audit.db")
    e = Engine()
    e.init(service_id="svc", node_id="node-1", audit_store=Probe(db),
           audit_store_failure_strategy="raise")
    e.redact_expired(before=datetime.now(timezone.utc), codes=["X"])
    assert calls == [True], "code was not registered before the redaction ran"
