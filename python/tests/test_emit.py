"""Emit roundtrip, anchor validation, request_id propagation."""
import re
import pytest
import fasten
from fasten.context import with_request_id


def test_emit_requires_init():
    with pytest.raises(RuntimeError, match="init()"):
        fasten.emit(code="USER_CREATED", target="u-1")


def test_emit_unknown_code(initialized):
    with pytest.raises(ValueError, match="unknown audit code"):
        fasten.emit(code="DOES_NOT_EXIST", target="u-1")


def test_emit_roundtrip(initialized, mem_store):
    row = fasten.emit(code="USER_CREATED", target="u-42", actor="alice")

    assert row.code == "USER_CREATED"
    assert row.action == "create"
    assert row.severity == "info"
    assert row.target == "u-42"
    assert row.actor == "alice"
    assert row.service_id == "test-svc"
    assert row.source_node_id == "test-node"
    assert re.match(r"^evt-[0-9a-f]{20}$", row.id)
    assert re.match(r"^[0-9a-f]{12}$", row.request_id)
    assert row.monotonic_seq >= 1


def test_emit_persisted_to_store(initialized, mem_store):
    row = fasten.emit(code="USER_CREATED", target="u-42")
    rows = mem_store.query(request_id=row.request_id)
    assert len(rows) == 1
    assert rows[0].id == row.id


def test_emit_request_id_from_context(initialized):
    with with_request_id("aabbccddeeff"):
        row = fasten.emit(code="USER_CREATED", target="u-42")
    assert row.request_id == "aabbccddeeff"


def test_emit_pii_redacted(initialized):
    row = fasten.emit(
        code="USER_CREATED", target="u-42",
        detail={
            "email": "alice@example.com",
            "api_key": "sk-secret",
            "nested": {"token": "xyz", "safe": "ok"},
        },
    )
    assert row.detail["email"] == "alice@example.com"
    assert row.detail["api_key"] == "***"
    assert row.detail["nested"]["token"] == "***"
    assert row.detail["nested"]["safe"] == "ok"


def test_emit_severity_override(initialized):
    row = fasten.emit(code="USER_CREATED", target="u-42", severity="warn")
    assert row.severity == "warn"


def test_emit_method_default(initialized):
    row = fasten.emit(code="USER_CREATED", target="u-42")
    assert row.method == "sdk"


def test_emit_monotonic_seq_increases(initialized):
    r1 = fasten.emit(code="USER_CREATED", target="u-1")
    r2 = fasten.emit(code="USER_DELETED", target="u-1")
    assert r2.monotonic_seq > r1.monotonic_seq
