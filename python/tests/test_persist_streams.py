"""persist_streams must match the stream stores actually attached.

A stream named without a store, or a store attached but not named, is an
error. When persist_streams is unset, persistence follows the attached stores.
"""
from __future__ import annotations

import pytest

import fasten
from fasten.store.sqlite import SQLiteStore
from fasten.store.stream import StreamStore


def _audit():
    return SQLiteStore(":memory:")


def _stream(table: str = "s"):
    return StreamStore(":memory:", table=table)


# Matching configurations

def test_persist_streams_none_falls_back_to_derivation():
    """Unset: persistence follows the attached stores."""
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
    """persist_streams=[] with no stream stores is a valid match."""
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=_audit(),
        audit_store_failure_strategy="raise",
        persist_streams=[],
    )
    assert fasten.persisted_streams() == frozenset({"audit"})


# Mismatches

def test_persist_streams_named_but_no_store_errors():
    """Otherwise completeness would report "store" for rows never stored."""
    with pytest.raises(RuntimeError, match="no store attached"):
        fasten.init(
            service_id="svc", node_id="n",
            audit_store=_audit(),
            audit_store_failure_strategy="raise",
            persist_streams=["sys"],
        )


def test_persist_streams_store_attached_but_not_named_errors():
    """A store the operator didn't opt into would be unexpected IO."""
    with pytest.raises(RuntimeError, match="not in persist_streams"):
        fasten.init(
            service_id="svc", node_id="n",
            audit_store=_audit(),
            syslog_store=_stream("s_unlisted"),
            audit_store_failure_strategy="raise",
            persist_streams=[],
        )


def test_persist_streams_both_mismatches_reported_together():
    """Both errors are reported in one message."""
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


# Validation

def test_persist_streams_rejects_unknown_stream_names():
    """audit is controlled by audit_store, and typos like "syslog" are rejected."""
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
