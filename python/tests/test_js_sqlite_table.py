"""
The Python store and reader on a table the JS SqliteStore created.

spec/js-sqlite-ddl.sql is the DDL the JS store runs on a new file (the JS
suite keeps it current). The rows of spec/js-sealed-form2.json go in by
plain SQL, with each detail column holding the text the JS store wrote,
then the Python store appends a row to the same chain.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

import fasten
from fasten.chain import verify_chain
from fasten.store.sqlite import SQLiteStore

SPEC = Path(__file__).resolve().parents[2] / "spec"
JS_DDL = SPEC / "js-sqlite-ddl.sql"
JS_ROWS = SPEC / "js-sealed-form2.json"

_COLUMNS = (
    "id", "wire_version", "origin_id", "monotonic_seq", "timestamp", "code",
    "action", "severity", "service_id", "source_node_id", "tenant_id",
    "actor", "actor_kind", "target", "category", "domain", "method",
    "request_id", "pii_in_detail", "shipped_at", "canonical_form_id",
    "prev_hash", "hash", "detail_salt", "detail_commitment",
)


def _js_rows() -> list[tuple[dict, str]]:
    """Each vector row and its detail text as the JS store wrote it: the
    text after "detail": on its line, which is the line's last field."""
    out = []
    for line in JS_ROWS.read_text(encoding="utf-8").splitlines():
        line = line.rstrip(",")
        if not line.startswith("{"):
            continue
        cut = line.index(',"detail":')
        text = line[cut + len(',"detail":'):-1]
        row = json.loads(line)
        assert json.loads(text) == row["detail"]
        out.append((row, text))
    return out


def _js_table(path: Path) -> None:
    with sqlite3.connect(path) as conn:
        conn.executescript(JS_DDL.read_text(encoding="utf-8"))
        cols = ", ".join(_COLUMNS + ("detail",))
        marks = ", ".join("?" * (len(_COLUMNS) + 1))
        for row, text in _js_rows():
            values = [row.get(c) for c in _COLUMNS]
            values[_COLUMNS.index("pii_in_detail")] = 1 if row["pii_in_detail"] else 0
            for c in ("detail_salt", "detail_commitment"):
                values[_COLUMNS.index(c)] = row.get(c) or ""
            conn.execute(f"INSERT INTO audit_log ({cols}) VALUES ({marks})",
                         (*values, text))


@pytest.fixture
def js_db(tmp_path):
    if not JS_DDL.exists():
        pytest.skip("spec/js-sqlite-ddl.sql not written yet: run the JS suite")
    path = tmp_path / "js.db"
    _js_table(path)
    return path


def _append(store: SQLiteStore) -> dict:
    fasten.init(service_id="gateway", node_id="node-js", audit_store=store,
                audit_store_failure_strategy="raise")
    return fasten.emit(code="USER_CREATED", target="u-1", actor="py",
                       actor_kind="service", detail={"n": 1.5, "who": "python"})


def test_python_appends_to_a_js_chain_and_verifies(js_db):
    store = SQLiteStore(str(js_db))
    js_main = [r for r, _ in _js_rows() if r["source_node_id"] == "node-js"]
    sealed = _append(store)
    assert sealed.monotonic_seq == len(js_main) + 1
    assert sealed.prev_hash == js_main[-1]["hash"]

    rows = store.chain_tail("node-js", 100)
    assert [r.id for r in rows] == [r["id"] for r in js_main] + [sealed.id]
    result = verify_chain(rows)
    assert result.ok, result.reason
    u16 = store.chain_tail("node-js-u16", 100)
    assert len(u16) == 1
    assert verify_chain(u16).ok


def test_python_reader_doctor_verifies_a_js_table(js_db):
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from fasten.reader.router import router as build_router

    _append(SQLiteStore(str(js_db)))
    app = FastAPI()
    app.include_router(build_router(dependencies=[]), prefix="/api/v1/logs")
    resp = TestClient(app).get("/api/v1/logs/audit/doctor")
    assert resp.status_code == 200
    chain = resp.json()["chain"]
    assert chain["verified"] is True, chain
    assert chain["breaks"] == 0
