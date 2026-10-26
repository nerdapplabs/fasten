"""Shared fixtures for fasten unit tests."""
import pytest
from fasten.store.sqlite import SQLiteStore
from fasten.codes import register, Meta, Severity, RetentionClass


@pytest.fixture(autouse=True)
def fresh_state():
    """Reset the default Engine to pre-init state before and after each test."""
    from fasten.emitter import _default
    _default.reset_for_tests()
    yield
    _default.reset_for_tests()


@pytest.fixture
def mem_store():
    return SQLiteStore(":memory:")


@pytest.fixture
def initialized(mem_store, monkeypatch):
    """Initialised SDK with an in-memory store.

    Uses the ``raise`` failure strategy so emit writes synchronously and a
    test can read the store straight after. Tests of the ``queue`` drainer
    set the strategy themselves."""
    monkeypatch.setenv("FASTEN_SERVICE_ID", "test-svc")
    monkeypatch.setenv("FASTEN_NODE_ID", "test-node")
    import fasten
    fasten.init(
        service_id="test-svc",
        node_id="test-node",
        audit_store=mem_store,
        audit_store_failure_strategy="raise",
    )
    yield fasten


@pytest.fixture(scope="session", autouse=True)
def register_test_codes():
    """Register codes once for the whole test session."""
    register("user", {
        "USER_CREATED": Meta(
            id="USER_CREATED", domain="user", category="account",
            action="create", severity=Severity.INFO,
            description="Test code", emitter="test",
            retention_class=RetentionClass.SHORT,
        ),
        "USER_DELETED": Meta(
            id="USER_DELETED", domain="user", category="account",
            action="delete", severity=Severity.WARN,
            description="Test delete code", emitter="test",
            retention_class=RetentionClass.LONG,
        ),
    })
