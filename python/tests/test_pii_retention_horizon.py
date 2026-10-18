"""#90 — pii_in_detail must mean something at runtime, not just reclassify.

The flag forces retention_class to SHORT at registration. Nothing acted on
that: purge() filters on age alone, so an operator had to hand-pass a list of
codes and the flag was effectively a comment.

The issue's own use case: personal data gone at 30 days, operational history
kept for a year. Previously inexpressible — a 30-day purge deleted the year of
history too, a 365-day purge kept the personal data for a year.
"""
import os
import tempfile
import threading
from datetime import datetime, timedelta, timezone

import pytest

from fasten import codes
from fasten.chain import seal, verify_chain
from fasten.codes import Meta, RetentionClass, Severity, pii_codes
from fasten.retention import start_purger
from fasten.store.sqlite import SQLiteStore

PII, OPS = "RET_USER_EXPORTED", "RET_SERVICE_PINGED"


@pytest.fixture(scope="module", autouse=True)
def _codes():
    codes.register("retdemo", {
        PII: Meta(id=PII, domain="retdemo", action="export", category="data",
                  severity=Severity.INFO, description="export", emitter="t",
                  retention_class=RetentionClass.LONG,   # forced to SHORT
                  pii_in_detail=True),
        OPS: Meta(id=OPS, domain="retdemo", action="ping", category="ops",
                  severity=Severity.INFO, description="ping", emitter="t",
                  retention_class=RetentionClass.LONG),
    })


def _store():
    return SQLiteStore(path=os.path.join(tempfile.mkdtemp(), "audit.db"),
                       table="fasten_audit")


def _aged(store, code, detail, days):
    """Seal AT the old timestamp. Backdating with UPDATE would change a hashed
    field, which verify_chain correctly reports as tampering."""
    import dataclasses
    from fasten.attrs import AuditRow
    from fasten.context import mint_id
    meta = codes.meta_of(code)
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


def test_pii_codes_is_derived_from_the_catalog():
    """THE MISSING LINK. Nothing derived the code set, so the flag was inert."""
    got = pii_codes()
    assert PII in got, "pii_in_detail=True code not derived from the catalog"
    assert OPS not in got, "a LONG non-PII code must not be swept up"


def test_pii_goes_at_30_days_while_history_survives_a_year():
    """The issue's use case, end to end."""
    store = _store()
    pii = _aged(store, PII, {"email": "a@b.c"}, 40)
    ops = _aged(store, OPS, {"n": 1}, 40)

    stop = threading.Event()
    t = start_purger(
        store=store, stream="audit",
        retention=timedelta(days=365),       # history kept a year
        pii_retention=timedelta(days=30),    # personal data gone at 30
        check_interval=timedelta(hours=1), stop_event=stop,
    )
    t.join(timeout=10)
    stop.set()

    rows = {r.id: r for r in store.query(limit=20)}
    assert rows[pii.id].detail is None, "PII survived its 30-day horizon"
    assert rows[pii.id].detail_salt is None, "salt survived — digest still guessable"
    assert rows[ops.id].detail == {"n": 1}, "operational history was destroyed too"
    # redaction, not deletion: both rows still present, chain intact
    assert len(rows) == 2
    assert verify_chain(list(rows.values())).ok


def test_without_pii_retention_behaviour_is_unchanged():
    """Opt-in. Omitting pii_retention keeps the old age-only purge."""
    store = _store()
    pii = _aged(store, PII, {"email": "x@y.z"}, 40)
    stop = threading.Event()
    t = start_purger(store=store, stream="audit", retention=timedelta(days=365),
                     check_interval=timedelta(hours=1), stop_event=stop)
    t.join(timeout=10)
    stop.set()
    assert {r.id: r for r in store.query(limit=20)}[pii.id].detail is not None


def test_fresh_pii_rows_are_untouched():
    store = _store()
    fresh = _aged(store, PII, {"email": "n@o.p"}, 1)
    stop = threading.Event()
    t = start_purger(store=store, stream="audit", retention=timedelta(days=365),
                     pii_retention=timedelta(days=30),
                     check_interval=timedelta(hours=1), stop_event=stop)
    t.join(timeout=10)
    stop.set()
    assert {r.id: r for r in store.query(limit=20)}[fresh.id].detail is not None
