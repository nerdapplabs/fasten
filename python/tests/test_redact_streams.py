"""Sensitive-data leakage: every sys/api push path must redact.

Before this pass, only the audit `emit` path and the shim shims redacted.
Adopter direct-push via `transport.push_syslog({"password": "x"})` landed
the secret in stdout, the ring, and (if configured) the persistent store.
Same for `write_api` / `write_syslog` / `write_drainer_syslog`.

Also pins the stderr persist-failure message to type-only (Postgres
INSERT errors quote row values in their message text — stderr is not
redacted, so `str(exc)` used to leak PII on any persist failure)."""
from __future__ import annotations

import io

import pytest

import fasten
from fasten.store.sqlite import SQLiteStore
from fasten.store.stream import StreamStore


def _init(with_stream_store: bool = False):
    kwargs = {
        "service_id": "svc", "node_id": "n",
        "audit_store": SQLiteStore(":memory:"),
        "audit_store_failure_strategy": "raise",
    }
    if with_stream_store:
        kwargs["syslog_store"] = StreamStore(":memory:", table="sys_redact")
        kwargs["api_store"] = StreamStore(":memory:", table="api_redact")
        kwargs["persist_streams"] = ["sys", "api"]
    fasten.init(**kwargs)


# ── sys stream: every push path redacts ──────────────────────────────────

@pytest.mark.parametrize("method", ["push_syslog", "write_syslog"])
def test_sys_push_redacts_pii_keys(method, capsys):
    _init()
    t = fasten.transport()
    getattr(t, method)({
        "event": "auth_failed",
        "level": "error",
        "password": "hunter2",
        "api_key": "sk-real-key",
        "user": "alice@example.com",  # not a PII key, stays through
    })
    stdout, _ = capsys.readouterr()
    if method == "write_syslog":
        # stdout NDJSON must not carry the secret
        assert "hunter2" not in stdout
        assert "sk-real-key" not in stdout
    # ring content also redacted
    rows = t.query_syslog(limit=10)
    row = rows[0]
    assert row["password"] == "***"
    assert row["api_key"] == "***"
    assert row["user"] == "alice@example.com"


def test_sys_push_redacts_before_store_insert():
    _init(with_stream_store=True)
    t = fasten.transport()
    t.push_syslog({"event": "auth_failed", "level": "error", "token": "leaked-secret"})
    # Store must contain redacted, not raw
    rows = t.search_syslog(q="leaked-secret", since="2026-01-01T00:00:00Z")
    assert rows == [] or len(rows) == 0, (
        "the raw secret must not appear in the persistent store payload"
    )


def test_write_drainer_syslog_redacts(capsys):
    _init()
    t = fasten.transport()
    t.write_drainer_syslog({
        "event": "custom_diagnostic", "level": "warn",
        "authorization": "Bearer real-jwt-token",
    })
    _, stderr = capsys.readouterr()
    assert "real-jwt-token" not in stderr
    assert "***" in stderr


# ── api stream: every push path redacts ──────────────────────────────────

@pytest.mark.parametrize("method", ["push_api", "write_api"])
def test_api_push_redacts_pii_keys(method, capsys):
    _init()
    t = fasten.transport()
    getattr(t, method)({
        "method": "POST", "path": "/login", "status": 401,
        "password": "hunter2",
        "authorization": "Bearer secret-token",
        "request_id": "r-1",
    })
    stdout, _ = capsys.readouterr()
    if method == "write_api":
        assert "hunter2" not in stdout
        assert "secret-token" not in stdout
    rows = t.query_api(limit=10)
    row = rows[0]
    assert row["password"] == "***"
    assert row["authorization"] == "***"
    assert row["path"] == "/login"  # non-PII passes through


# ── persist-failure stderr: type-only, no exception message ──────────────

def test_persist_failure_stderr_is_type_only_not_exception_message(monkeypatch):
    """A Postgres INSERT error text can contain the offending row value
    (NotNullViolation quotes the column). stderr is not redacted, so the
    persist-failure line prints only the exception TYPE, never str(exc)."""
    _init(with_stream_store=True)
    t = fasten.transport()
    store = t._syslog_store

    def _boom(_row):
        raise RuntimeError("password=hunter2 violates constraint xyz")
    monkeypatch.setattr(store, "insert", _boom)

    captured_err = io.StringIO()
    monkeypatch.setattr("sys.stderr", captured_err)
    # Push through the transport — the persist-failure branch fires.
    t.push_syslog({"event": "e", "level": "info", "request_id": "r"})
    msg = captured_err.getvalue()

    assert "hunter2" not in msg, f"exception message must not leak: {msg!r}"
    assert "RuntimeError" in msg, f"stderr line must name the type: {msg!r}"
