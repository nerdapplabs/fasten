"""#58 persist_streams — explicit stream allowlist that must match the set of
stream stores actually attached. Both directions fail loudly: a stream named
in persist_streams without a store, or an attached store not in
persist_streams. Preserves the current "store means store" honesty when the
knob is unset."""
from __future__ import annotations

import pytest

import fasten
from fasten.store.sqlite import SQLiteStore
from fasten.store.stream import StreamStore


def _audit():
    return SQLiteStore(":memory:")


def _stream(table: str = "s"):
    return StreamStore(":memory:", table=table)


# ── happy paths ──────────────────────────────────────────────────────────

def test_persist_streams_none_falls_back_to_derivation():
    """Unset knob = old behaviour: persistence is derived from attachment."""
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=_audit(),
        syslog_store=_stream("s_none"),
        audit_store_failure_strategy="raise",
    )
    assert fasten.persisted_streams() == frozenset({"audit", "sys"})


def test_persist_streams_matches_attached_stores():
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=_audit(),
        syslog_store=_stream("s_match"),
        audit_store_failure_strategy="raise",
        persist_streams=["sys"],
    )
    assert fasten.persisted_streams() == frozenset({"audit", "sys"})


def test_persist_streams_both_api_and_sys():
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=_audit(),
        api_store=_stream("api_both"),
        syslog_store=_stream("sys_both"),
        audit_store_failure_strategy="raise",
        persist_streams={"api", "sys"},
    )
    assert fasten.persisted_streams() == frozenset({"audit", "api", "sys"})


def test_persist_streams_empty_set_with_no_stores_is_ok():
    """persist_streams=[] plus no stream stores is a consistent (vacuous)
    match — not an error."""
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=_audit(),
        audit_store_failure_strategy="raise",
        persist_streams=[],
    )
    assert fasten.persisted_streams() == frozenset({"audit"})


# ── mismatch: fail loudly, both directions ───────────────────────────────

def test_persist_streams_named_but_no_store_errors():
    """persist_streams=["sys"] with no syslog_store must fail — otherwise
    completeness would say "store" over durable history the store never
    got."""
    with pytest.raises(RuntimeError, match="no store attached"):
        fasten.init(
            service_id="svc", node_id="n",
            audit_store=_audit(),
            audit_store_failure_strategy="raise",
            persist_streams=["sys"],
        )


def test_persist_streams_store_attached_but_not_named_errors():
    """A store the operator didn't opt into is unexpected IO. Fail loud so
    the operator sees the mismatch instead of surprise persistence."""
    with pytest.raises(RuntimeError, match="not in persist_streams"):
        fasten.init(
            service_id="svc", node_id="n",
            audit_store=_audit(),
            syslog_store=_stream("s_unlisted"),
            audit_store_failure_strategy="raise",
            persist_streams=[],
        )


def test_persist_streams_both_mismatches_reported_together():
    """One direction shouldn't mask the other — a caller with both errors
    should see both in one message rather than fix, re-run, see the
    second."""
    with pytest.raises(RuntimeError) as exc:
        fasten.init(
            service_id="svc", node_id="n",
            audit_store=_audit(),
            api_store=_stream("api_x"),   # attached, not named
            audit_store_failure_strategy="raise",
            persist_streams=["sys"],       # named, no store
        )
    msg = str(exc.value)
    assert "no store attached" in msg and "not in persist_streams" in msg


# ── validation ───────────────────────────────────────────────────────────

def test_persist_streams_rejects_unknown_stream_names():
    """audit is not a valid entry (driven by audit_store); typos ("syslog")
    must not silently pass through as if they matched a real stream."""
    for bad in (["audit"], ["syslog"], ["api", "audit"]):
        with pytest.raises(RuntimeError, match="unknown stream"):
            fasten.init(
                service_id="svc", node_id="n",
                audit_store=_audit(),
                audit_store_failure_strategy="raise",
                persist_streams=bad,
            )


def test_persist_streams_reads_from_env(monkeypatch):
    monkeypatch.setenv("FASTEN_PERSIST_STREAMS", "sys")
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=_audit(),
        syslog_store=_stream("s_env"),
        audit_store_failure_strategy="raise",
    )
    assert fasten.persisted_streams() == frozenset({"audit", "sys"})

    # Env-driven mismatch also fails.
    monkeypatch.setenv("FASTEN_PERSIST_STREAMS", "api")
    with pytest.raises(RuntimeError, match="no store attached"):
        fasten.init(
            service_id="svc", node_id="n",
            audit_store=_audit(),
            audit_store_failure_strategy="raise",
        )
