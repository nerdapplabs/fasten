"""Tests for P1-9 — Python logging ergonomics.

Covers:
  #1 — fasten.shim.structlog.configure(...) end-to-end
  #2 — fasten.shim.stdlib.LoggingHandler standalone + recursion guard
  #3 — fasten.log.bound(name, **fields)
"""
import logging

import pytest

import fasten


# ── #3 fasten.log.bound() ────────────────────────────────────────────────

def test_log_bound_stamps_logger_field(initialized):
    """bound() returns a new logger that stamps `logger` on every emission."""
    transport = fasten.transport()

    fasten.log.info("plain_event")
    fasten.log.bound("buffer-manager").info("named_event")
    fasten.log.bound("pipeline-engine").info("from_pipeline", step="parse")

    rows = transport.query_syslog(limit=10)
    by_event = {r["event"]: r for r in rows}

    assert "logger" not in by_event["plain_event"]
    assert by_event["named_event"]["logger"] == "buffer-manager"
    assert by_event["from_pipeline"]["logger"] == "pipeline-engine"
    assert by_event["from_pipeline"]["step"] == "parse"


def test_log_bound_chains(initialized):
    """Chained bound() calls merge fields; later calls override."""
    transport = fasten.transport()

    base = fasten.log.bound("svc-a", region="us-east")
    base.info("first", extra=1)

    nested = base.bound(extra=99)  # override 'extra', keep region + name
    nested.info("second")

    rows = {r["event"]: r for r in transport.query_syslog(limit=10)}
    assert rows["first"]["region"] == "us-east"
    assert rows["first"]["extra"] == 1
    assert rows["first"]["logger"] == "svc-a"

    assert rows["second"]["region"] == "us-east"
    assert rows["second"]["extra"] == 99
    assert rows["second"]["logger"] == "svc-a"  # name preserved


def test_log_bound_explicit_field_overrides_bound(initialized):
    """Fields passed to .info() override bound fields for that call."""
    transport = fasten.transport()

    log = fasten.log.bound("worker", phase="setup")
    log.info("event_a")                     # uses bound phase=setup
    log.info("event_b", phase="run")        # caller overrides

    rows = {r["event"]: r for r in transport.query_syslog(limit=10)}
    assert rows["event_a"]["phase"] == "setup"
    assert rows["event_b"]["phase"] == "run"


# ── #2 fasten.shim.stdlib.LoggingHandler ─────────────────────────────────

def test_stdlib_logging_handler_pushes_to_ring(initialized):
    """LoggingHandler bridges stdlib logging into fasten's syslog ring."""
    from fasten.shim.stdlib import LoggingHandler

    h = LoggingHandler()
    root = logging.getLogger()
    # Reset and add only our handler so other test handlers don't interfere
    saved = list(root.handlers)
    saved_level = root.level
    try:
        root.handlers = [h]
        root.setLevel(logging.INFO)

        logging.getLogger("legacy.module").info("from_stdlib", extra={"user": "alice"})

        rows = fasten.transport().query_syslog(limit=10)
        match = [r for r in rows if r.get("event") == "from_stdlib"]
        assert match, "stdlib log record did not reach fasten ring"
        row = match[0]
        assert row["logger"] == "legacy.module"
        assert row["level"] == "info"
        assert row["user"] == "alice"
    finally:
        root.handlers = saved
        root.setLevel(saved_level)


def test_stdlib_logging_handler_redacts_secrets(initialized):
    """Adopter-supplied extras with secret keys are redacted."""
    from fasten.shim.stdlib import LoggingHandler

    h = LoggingHandler()
    root = logging.getLogger()
    saved = list(root.handlers)
    try:
        root.handlers = [h]
        logging.getLogger("svc").warning(
            "auth_called",
            extra={"api_key": "sk-secret", "ok": "keep"},
        )
        rows = fasten.transport().query_syslog(limit=10)
        match = [r for r in rows if r.get("event") == "auth_called"]
        assert match
        row = match[0]
        assert row["api_key"] == "***"
        assert row["ok"] == "keep"
    finally:
        root.handlers = saved


def test_stdlib_logging_handler_skips_fasten_internal_records(initialized):
    """Records tagged _fasten_internal must not loop back into the ring."""
    from fasten.shim.stdlib import LoggingHandler

    h = LoggingHandler()
    root = logging.getLogger()
    saved = list(root.handlers)
    try:
        root.handlers = [h]
        before = len(fasten.transport().query_syslog(limit=200))

        # Simulate fasten's pre-init fallback path
        logging.getLogger("fasten").info(
            "internal", extra={"_fasten_internal": True}
        )

        after = len(fasten.transport().query_syslog(limit=200))
        assert after == before, "internal record looped into the ring"
    finally:
        root.handlers = saved


# ── #1 fasten.shim.structlog.configure() ─────────────────────────────────

def test_structlog_configure_end_to_end(initialized):
    """configure() installs both bridges; structlog + stdlib reach the ring."""
    pytest.importorskip("structlog")
    import structlog
    from fasten.shim.structlog import configure

    # Snapshot stdlib root state, run configure, run logs, restore.
    saved_handlers = list(logging.getLogger().handlers)
    saved_level = logging.getLogger().level
    try:
        configure(json=True, debug=False, quiet=())

        # structlog logger — fasten processor pushes to the ring
        log = structlog.get_logger().bind(logger="buffer-manager")
        log.info("structlog_event", batch=42, api_key="sk-secret")

        # stdlib logger — LoggingHandler pushes to the same ring
        logging.getLogger("legacy.lib").info("stdlib_event")

        rows = fasten.transport().query_syslog(limit=20)
        events = {r.get("event") for r in rows}
        assert "structlog_event" in events
        assert "stdlib_event" in events

        # Redaction wired up: api_key scrubbed
        s_row = next(r for r in rows if r.get("event") == "structlog_event")
        assert s_row["api_key"] == "***"
        assert s_row["batch"] == 42
        assert s_row["logger"] == "buffer-manager"  # bound() carries it

        # stdlib row carries the stdlib logger name
        l_row = next(r for r in rows if r.get("event") == "stdlib_event")
        assert l_row["logger"] == "legacy.lib"
    finally:
        logging.getLogger().handlers = saved_handlers
        logging.getLogger().setLevel(saved_level)


# ── P1-10 — Meta.id optional + dict-form register ────────────────────────

def test_register_dict_form_fills_id_from_key():
    from fasten.codes import register, Meta, Severity, RetentionClass, registry, _registry

    # Use a domain unlikely to clash with session-registered codes
    code = "P1_10_FILLED"
    if code in _registry:
        del _registry[code]

    register("p1_10", {
        code: Meta(
            domain="p1_10", category="x", action="x",
            severity=Severity.INFO, description="x", emitter="t",
            retention_class=RetentionClass.SHORT,
        ),
    })
    m = registry()[code]
    assert m.id == code   # filled by register()


def test_register_dict_form_explicit_id_must_match():
    from fasten.codes import register, Meta, Severity, AuditCatalogError, _registry

    # Use a unique key to avoid duplicate-collision with prior runs
    code = "P1_10_MISMATCH"
    if code in _registry:
        del _registry[code]

    with pytest.raises(AuditCatalogError, match="disagrees with Meta.id"):
        register("p1_10b", {
            code: Meta(
                id="WRONG_ID", domain="p1_10b", category="x", action="x",
                severity=Severity.INFO, description="x", emitter="t",
            ),
        })


def test_register_invalid_key_shape():
    from fasten.codes import register, Meta, Severity, AuditCatalogError

    with pytest.raises(AuditCatalogError, match="UPPER_SNAKE_CASE"):
        register("p1_10c", {
            "lowercase_bad": Meta(
                domain="p1_10c", category="x", action="x",
                severity=Severity.INFO, description="x", emitter="t",
            ),
        })


