"""ARCH #3 — spec/audit_log.*.sql is the source of truth for the audit_log
shape across every SDK's SQLite-backed store.

Contract pinned here:
  1) A fresh SQLite store from Python creates every column declared in
     spec/audit_log.sqlite.sql — no drift.
  2) The additive migrations catch legacy tables missing later columns.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from fasten.store.sqlite import SQLiteStore


SPEC = (
    Path(__file__).parent.parent.parent / "spec" / "audit_log.sqlite.sql"
)


def _expected_columns() -> set[str]:
    """Parse the spec file for the CREATE TABLE column names."""
    text = SPEC.read_text()
    # Slice out the CREATE TABLE block, then pull the leading identifier of
    # every non-blank, non-comment, non-closing-paren line.
    start = text.index("CREATE TABLE IF NOT EXISTS")
    body_end = text.index(");", start)
    inside = text[text.index("(", start) + 1: body_end]
    cols: set[str] = set()
    for line in inside.splitlines():
        line = line.strip().rstrip(",")
        if not line or line.startswith("--"):
            continue
        cols.add(line.split()[0])
    return cols


def test_python_sqlite_store_creates_full_canonical_column_set(tmp_path: Path):
    db = tmp_path / "arch3.db"
    SQLiteStore(str(db), table="audit_log")
    with sqlite3.connect(str(db)) as conn:
        rows = conn.execute("PRAGMA table_info(audit_log)").fetchall()
    actual = {r[1] for r in rows}
    expected = _expected_columns()
    missing = expected - actual
    extra = actual - expected
    assert not missing and not extra, (
        f"schema drift from spec: missing={sorted(missing)} extra={sorted(extra)}"
    )


def test_python_sqlite_migrates_legacy_table_missing_new_columns(tmp_path: Path):
    """Pre-ARCH#3 Python schema was missing pii_in_detail + wire_version;
    open the store on such a legacy table and confirm the migration
    catches them via PRAGMA table_info without erroring."""
    db = tmp_path / "legacy.db"
    legacy_ddl = """
    CREATE TABLE audit_log (
        id TEXT PRIMARY KEY,
        origin_id TEXT NOT NULL,
        monotonic_seq INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        code TEXT NOT NULL,
        action TEXT NOT NULL,
        severity TEXT NOT NULL,
        service_id TEXT NOT NULL,
        source_node_id TEXT NOT NULL,
        tenant_id TEXT,
        actor TEXT NOT NULL,
        actor_kind TEXT NOT NULL,
        target TEXT NOT NULL,
        category TEXT NOT NULL,
        domain TEXT NOT NULL,
        method TEXT NOT NULL,
        request_id TEXT NOT NULL,
        detail TEXT NOT NULL,
        shipped_at TEXT
    )
    """
    with sqlite3.connect(str(db)) as conn:
        conn.executescript(legacy_ddl)
    # Opening the store must run the additive migration.
    SQLiteStore(str(db), table="audit_log")
    with sqlite3.connect(str(db)) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
    for expected in ("pii_in_detail", "wire_version", "hash", "prev_hash", "canonical_form_id"):
        assert expected in cols, f"migration failed to add {expected}"
