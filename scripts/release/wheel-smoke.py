"""Check an installed fasten-sdk wheel: emit rows to SQLite and verify the chain.

Run it with `python -I` from outside the repo, so the installed package is
imported and not python/fasten.
"""
import sys
import tempfile
from pathlib import Path

import fasten
from fasten import core_ffi, verify_chain
from fasten.codes import Meta, RetentionClass, Severity, register
from fasten.store.sqlite import SQLiteStore

pkg = Path(fasten.__file__).parent
lib = Path(core_ffi._find_lib())
if lib.parent != pkg:
    sys.exit(f"libfasten_core loaded from {lib}, not from the wheel ({pkg})")

register("smoke", {
    "WHEEL_CHECKED": Meta(
        domain="smoke", category="release", action="check",
        severity=Severity.INFO, description="Wheel install check",
        emitter="wheel-smoke", retention_class=RetentionClass.SHORT,
    ),
})

store = SQLiteStore(str(Path(tempfile.mkdtemp()) / "audit.db"))
fasten.init(service_id="wheel-smoke", node_id="ci", audit_store=store)
for i in range(3):
    fasten.emit(code="WHEEL_CHECKED", target=f"t-{i}", actor="ci")
if not fasten.flush():
    sys.exit("flush timed out")

rows = store.query(limit=10)
if len(rows) != 3 or not all(r.hash for r in rows):
    sys.exit(f"expected 3 sealed rows, got {[(r.monotonic_seq, r.hash) for r in rows]}")
result = verify_chain(rows)
if not result.ok:
    sys.exit(f"verify_chain: {result.first_break_at} {result.reason}")
print(f"ok: {lib.name}, {len(rows)} rows, chain verified")
