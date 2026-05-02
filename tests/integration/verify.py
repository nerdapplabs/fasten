#!/usr/bin/env python3
"""
Verify a language SDK's stdout against the fasten wire contract.

Reads NDJSON lines from stdin (whatever a smoke program emitted) and
asserts:

  1. At least one {shape: "audit"}, {shape: "sys"}, and {shape: "api"} row appear.
  2. Audit row carries the required wire fields.
  3. Audit detail redaction worked: api_key and nested.token are "***",
     email is preserved.
  4. request_id is a 12-char hex string (or empty for sys before any emit).
  5. Sys row has the canonical level/event/timestamp shape.
  6. Api row carries method, path, status, request_id, timestamp.

Exit 0 if all assertions pass, non-zero with a readable diff otherwise.

Usage:

    docker run --rm fasten-itest-python | python tests/integration/verify.py

Each SDK must emit (in any order):

    log.info("startup_ok", {extra_field: 1})
    emit(code="USER_CREATED", target="u-42", actor="admin",
         detail={email, api_key, nested.token})
    write_api({method, path, status, ms, request_id, timestamp})
"""
from __future__ import annotations

import json
import re
import sys
from typing import Any

REQUIRED_AUDIT_FIELDS = {
    "shape", "id", "monotonic_seq", "timestamp",
    "code", "action", "severity",
    "service_id", "source_node_id",
    "actor", "actor_kind", "target", "category", "domain",
    "method", "request_id", "detail",
}
REQUIRED_SYS_FIELDS = {"shape", "level", "event", "request_id", "timestamp"}
REQUIRED_API_FIELDS = {"shape", "method", "path", "status", "request_id", "timestamp"}

ID_RE = re.compile(r"^evt-[0-9a-f]{16,32}$")
REQ_ID_RE = re.compile(r"^[0-9a-f]{12}$")


def fail(msg: str, ctx: Any = None) -> None:
    print(f"\nFAIL: {msg}", file=sys.stderr)
    if ctx is not None:
        print(f"  context: {json.dumps(ctx, indent=2, default=str)}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    audit_rows: list[dict] = []
    sys_rows: list[dict] = []
    api_rows: list[dict] = []

    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            # Tolerate noise (some Dockerfile bases write banner lines).
            continue
        if not isinstance(obj, dict):
            continue
        shape = obj.get("shape")
        if shape == "audit":
            audit_rows.append(obj)
        elif shape == "sys":
            sys_rows.append(obj)
        elif shape == "api":
            api_rows.append(obj)

    if not audit_rows:
        fail("no {shape: 'audit'} row produced")
    if not sys_rows:
        fail("no {shape: 'sys'} row produced")

    # --- Audit checks ---
    audit = audit_rows[0]
    missing = REQUIRED_AUDIT_FIELDS - set(audit.keys())
    if missing:
        fail(f"audit row missing fields: {sorted(missing)}", audit)

    if not ID_RE.match(audit["id"]):
        fail(f"audit.id does not match evt-<hex>: {audit['id']}")
    if not REQ_ID_RE.match(audit["request_id"]):
        fail(f"audit.request_id is not 12 hex chars: {audit['request_id']}")
    if audit["code"] != "USER_CREATED":
        fail(f"audit.code expected USER_CREATED, got {audit['code']}")
    if audit["action"] != "create":
        fail(f"audit.action expected 'create', got {audit['action']}")
    if audit["severity"] not in ("info", "Info", "INFO"):
        fail(f"audit.severity expected info, got {audit['severity']}")

    detail = audit.get("detail") or {}
    if detail.get("email") != "alice@acme.com":
        fail("audit.detail.email lost or mutated", detail)
    if detail.get("api_key") != "***":
        fail("audit.detail.api_key was NOT redacted", detail)
    # Nested redaction is checked only where the SDK supports nested detail
    # values (Python / JS / Rust / Go). C++ uses flat Fields and does not
    # carry a 'nested' key — skip silently if absent.
    nested = detail.get("nested")
    if isinstance(nested, dict):
        if nested.get("token") != "***":
            fail("audit.detail.nested.token was NOT redacted", detail)

    # --- Sys checks ---
    sys_row = sys_rows[0]
    missing = REQUIRED_SYS_FIELDS - set(sys_row.keys())
    if missing:
        fail(f"sys row missing fields: {sorted(missing)}", sys_row)
    if sys_row["level"] not in ("info", "Info", "INFO"):
        fail(f"sys.level expected info, got {sys_row['level']}")
    if sys_row["event"] != "startup_ok":
        fail(f"sys.event expected startup_ok, got {sys_row['event']}")

    # --- Api checks ---
    if not api_rows:
        fail("no {shape: 'api'} row produced")
    api = api_rows[0]
    missing = REQUIRED_API_FIELDS - set(api.keys())
    if missing:
        fail(f"api row missing fields: {sorted(missing)}", api)
    if not REQ_ID_RE.match(api["request_id"]):
        fail(f"api.request_id is not 12 hex chars: {api['request_id']}")
    if api["method"].upper() != "POST":
        fail(f"api.method expected POST, got {api['method']}")
    if api["status"] != 201:
        fail(f"api.status expected 201, got {api['status']}")

    print(f"OK — {len(audit_rows)} audit row(s), {len(sys_rows)} sys row(s), "
          f"{len(api_rows)} api row(s) — contract holds")


if __name__ == "__main__":
    main()
