"""P1-5: pii_in_detail enforcement tests.

Two runtime behaviours, all verified here:

1. Force ``RetentionClass.SHORT`` at registration; WARN if adopter set otherwise
2. Force-redact ``detail`` on emit unless adopter declared
   ``detail_passthrough_keys``; PII rows carry ``_pii_in_detail: True`` marker
   in detail payload
"""
import logging


import fasten
from fasten.codes import Meta, RetentionClass, Severity, _registry, register


def _meta(**overrides):
    """Build a Meta with sensible defaults; overridable per test."""
    base = dict(
        domain="pii",
        category="profile",
        action="view",
        severity=Severity.INFO,
        description="x",
        emitter="test",
    )
    base.update(overrides)
    return Meta(**base)


def _clear(*codes):
    for c in codes:
        _registry.pop(c, None)


# ── #1 force SHORT at registration ────────────────────────────────────────

def test_pii_forces_retention_short_with_warning(caplog):
    _clear("PII_LONG_OVERRIDE")
    with caplog.at_level(logging.WARNING, logger="fasten"):
        register("pii", {
            "PII_LONG_OVERRIDE": _meta(
                domain="pii",
                pii_in_detail=True,
                retention_class=RetentionClass.LONG,
            ),
        })
    m = _registry["PII_LONG_OVERRIDE"]
    assert m.retention_class is RetentionClass.SHORT
    assert any(
        "PII_LONG_OVERRIDE" in r.message and "forced to SHORT" in r.message
        for r in caplog.records
    ), "expected WARNING about forced retention override"


def test_pii_already_short_no_warning(caplog):
    _clear("PII_ALREADY_SHORT")
    with caplog.at_level(logging.WARNING, logger="fasten"):
        register("pii", {
            "PII_ALREADY_SHORT": _meta(
                domain="pii",
                pii_in_detail=True,
                retention_class=RetentionClass.SHORT,
            ),
        })
    # No warning when adopter already declared SHORT
    pii_warnings = [
        r for r in caplog.records
        if "PII_ALREADY_SHORT" in r.message and "forced" in r.message
    ]
    assert pii_warnings == []


def test_non_pii_code_unaffected():
    _clear("NON_PII_LONG")
    register("pii", {
        "NON_PII_LONG": _meta(
            domain="pii",
            pii_in_detail=False,
            retention_class=RetentionClass.LONG,
        ),
    })
    assert _registry["NON_PII_LONG"].retention_class is RetentionClass.LONG


# ── #2 force-redact detail on emit ────────────────────────────────────────

def test_emit_force_redacts_pii_detail(initialized):
    _clear("PII_VIEWED")
    register("pii", {
        "PII_VIEWED": _meta(
            domain="pii",
            pii_in_detail=True,
        ),
    })
    row = fasten.emit(
        code="PII_VIEWED",
        target="u-42",
        actor="admin",
        detail={"city": "Mumbai", "ip": "203.0.113.1"},
    )
    # Whole detail map is replaced; no original keys leak through
    assert "city" not in row.detail
    assert "ip" not in row.detail
    assert row.detail["_redacted"] == "***"
    assert row.detail["_pii_in_detail"] is True


def test_emit_pii_passthrough_keys(initialized):
    _clear("PII_PARTIAL")
    register("pii", {
        "PII_PARTIAL": _meta(
            domain="pii",
            pii_in_detail=True,
            detail_passthrough_keys=("region",),  # only this key survives
        ),
    })
    row = fasten.emit(
        code="PII_PARTIAL",
        target="u-42",
        actor="admin",
        detail={"city": "Mumbai", "region": "MH", "api_key": "sk-secret"},
    )
    assert row.detail["region"] == "MH"            # passthrough survives
    assert row.detail["_redacted"] == "***"        # marker present
    assert row.detail["_pii_in_detail"] is True
    assert "city" not in row.detail                # not in passthrough → gone
    # api_key redacted via the normal redactor even when in passthrough — but
    # it's NOT in passthrough here, so it's gone entirely
    assert "api_key" not in row.detail


def test_emit_pii_passthrough_redacts_secret_keys(initialized):
    """A passthrough key value is still scrubbed by the secret-key redactor."""
    _clear("PII_PASSTHROUGH_SECRET")
    register("pii", {
        "PII_PASSTHROUGH_SECRET": _meta(
            domain="pii",
            pii_in_detail=True,
            detail_passthrough_keys=("api_key",),  # adopter explicitly opts in
        ),
    })
    row = fasten.emit(
        code="PII_PASSTHROUGH_SECRET",
        target="u-42",
        actor="admin",
        detail={"api_key": "sk-secret"},
    )
    # Even though api_key is a passthrough, the secret-key redactor still runs
    assert row.detail["api_key"] == "***"


def test_emit_non_pii_redacts_only_secret_keys(initialized):
    """Non-PII code: detail is preserved except for secret-key matches."""
    _clear("NON_PII_BASIC")
    register("nonpii", {
        "NON_PII_BASIC": _meta(domain="nonpii"),
    })
    row = fasten.emit(
        code="NON_PII_BASIC",
        target="u-42",
        actor="admin",
        detail={"city": "Mumbai", "api_key": "sk-secret"},
    )
    assert row.detail["city"] == "Mumbai"   # non-secret preserved
    assert row.detail["api_key"] == "***"   # secret key redacted
    assert "_redacted" not in row.detail
    assert "_pii_in_detail" not in row.detail


# ── #3 detail payload markers (no wire column) ───────────────────────────

def test_pii_detail_marker_present_in_detail(initialized):
    """PII rows carry _pii_in_detail: True in the detail payload."""
    _clear("PII_FLAG_ROW")
    register("pii", {
        "PII_FLAG_ROW": _meta(
            domain="pii",
            pii_in_detail=True,
        ),
    })
    row = fasten.emit(code="PII_FLAG_ROW", target="t", actor="a")
    assert row.detail.get("_pii_in_detail") is True
    assert row.detail.get("_redacted") == "***"


def test_non_pii_row_has_no_pii_marker_in_detail(initialized):
    """Non-PII rows do NOT have _pii_in_detail in their detail payload."""
    _clear("NORMAL_ROW")
    register("nonpii", {
        "NORMAL_ROW": _meta(domain="nonpii"),
    })
    row = fasten.emit(code="NORMAL_ROW", target="t", actor="a")
    assert "_pii_in_detail" not in row.detail


def test_sqlite_round_trip_preserves_pii_detail_marker(mem_store):
    """End-to-end: emit → SQLite insert → query → _pii_in_detail marker in detail survives."""
    from fasten.attrs import AuditRow
    from datetime import datetime, timezone
    from fasten.codes import Severity as S

    pii_row = AuditRow(
        id="evt-pii",
        origin_id="evt-pii",
        monotonic_seq=1,
        timestamp=datetime.now(timezone.utc),
        code="X_PII", action="x",
        severity=str(S.INFO),
        service_id="s", source_node_id="n",
        tenant_id=None, actor="a", actor_kind="user",
        target="t", category="c", domain="d",
        method="sdk", request_id="abc123",
        detail={"_redacted": "***", "_pii_in_detail": True},
    )
    mem_store.insert(pii_row)
    fetched = mem_store.query(request_id="abc123")
    assert len(fetched) == 1
    assert fetched[0].detail.get("_pii_in_detail") is True


def test_sqlite_legacy_table_rows_still_queryable(tmp_path):
    """Adopter opens a pre-existing SQLite table without pii_in_detail column.
    Existing rows are still queryable by the store."""
    import sqlite3
    from fasten.store.sqlite import SQLiteStore

    db = tmp_path / "legacy.db"
    legacy = sqlite3.connect(db)
    legacy.executescript("""
        CREATE TABLE audit_log (
            id               TEXT PRIMARY KEY,
            origin_id        TEXT NOT NULL,
            monotonic_seq    INTEGER NOT NULL,
            timestamp        TEXT NOT NULL,
            code             TEXT NOT NULL,
            action           TEXT NOT NULL,
            severity         TEXT NOT NULL,
            service_id       TEXT NOT NULL,
            source_node_id   TEXT NOT NULL,
            tenant_id        TEXT,
            actor            TEXT NOT NULL,
            actor_kind       TEXT NOT NULL,
            target           TEXT NOT NULL,
            category         TEXT NOT NULL,
            domain           TEXT NOT NULL,
            method           TEXT NOT NULL,
            request_id       TEXT NOT NULL,
            detail           TEXT NOT NULL,
            shipped_at       TEXT
        );
        INSERT INTO audit_log VALUES (
            'evt-legacy', 'evt-legacy', 1, '2026-01-01T00:00:00+00:00',
            'OLD_CODE', 'do', 'info',
            's', 'n', NULL, 'a', 'user',
            't', 'c', 'd', 'sdk', 'req-1', '{}', NULL
        );
    """)
    legacy.commit()
    legacy.close()

    # Open via SQLiteStore — existing rows should be queryable.
    store = SQLiteStore(str(db))
    rows = store.query(code="OLD_CODE")
    assert len(rows) == 1
