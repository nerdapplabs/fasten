"""Shared fixtures for fasten unit tests."""
import importlib

import pytest
from fasten.store.sqlite import SQLiteStore
from fasten.codes import register, Meta, Severity, RetentionClass

# `import fasten.emit as _emit_mod` rebinds to the function `emit` because
# fasten/__init__.py does `from .emit import emit` (which shadows the
# submodule attribute). importlib bypasses the attribute path and gives
# the actual submodule reliably.
_emit_mod = importlib.import_module("fasten.emit")


@pytest.fixture(autouse=True)
def fresh_state():
    """Reset all module-level SDK state before each test."""
    _emit_mod._service_id = ""
    _emit_mod._node_id = ""
    _emit_mod._tenant_id = None
    _emit_mod._audit_store = None
    _emit_mod._api_store = None
    _emit_mod._stdout = None
    _emit_mod._seq = 0
    _emit_mod._redactor = _emit_mod.Redactor()
    yield


@pytest.fixture
def mem_store():
    return SQLiteStore(":memory:")


@pytest.fixture
def initialized(mem_store):
    """Initialised SDK with an in-memory store."""
    import os
    os.environ["FASTEN_SERVICE_ID"] = "test-svc"
    os.environ["FASTEN_NODE_ID"] = "test-node"
    import fasten
    fasten.init(service_id="test-svc", node_id="test-node", audit_store=mem_store)
    yield fasten
    del os.environ["FASTEN_SERVICE_ID"]
    del os.environ["FASTEN_NODE_ID"]


@pytest.fixture(scope="session", autouse=True)
def register_test_codes():
    """Register codes once for the whole test session."""
    register("user", [
        ("USER_CREATED", Meta(
            id="USER_CREATED", domain="user", category="account",
            action="create", severity=Severity.INFO,
            description="Test code", emitter="test",
            retention_class=RetentionClass.SHORT,
        )),
        ("USER_DELETED", Meta(
            id="USER_DELETED", domain="user", category="account",
            action="delete", severity=Severity.WARN,
            description="Test delete code", emitter="test",
            retention_class=RetentionClass.LONG,
        )),
    ])
