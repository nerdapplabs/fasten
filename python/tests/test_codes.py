"""Code registry: register, lookup, dump, duplicate detection."""
import pytest
from fasten.codes import register, registry, dump, Meta, Severity, RetentionClass, AuditCatalogError


def test_registry_contains_session_codes():
    reg = registry()
    assert "USER_CREATED" in reg
    assert "USER_DELETED" in reg


def test_meta_fields():
    meta = registry()["USER_CREATED"]
    assert meta.action == "create"
    assert meta.domain == "user"
    assert meta.category == "account"
    assert meta.severity == Severity.INFO
    assert meta.retention_class == RetentionClass.SHORT


def test_duplicate_code_raises():
    with pytest.raises(AuditCatalogError, match="duplicate"):
        register("user", [
            ("USER_CREATED", Meta(
                id="USER_CREATED", domain="user", category="account",
                action="create", severity=Severity.INFO,
                description="dup", emitter="test",
                retention_class=RetentionClass.SHORT,
            )),
        ])


def test_dump_format():
    output = dump()
    lines = output.strip().splitlines()
    assert any(l.startswith("USER_CREATED,") for l in lines)
    for line in lines:
        parts = line.split(",")
        assert len(parts) == 3, f"expected id,domain,severity got: {line!r}"
