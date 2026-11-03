#!/usr/bin/env python3
"""
Verify a language SDK's stdout against the fasten wire contract.

Reads NDJSON lines from stdin (whatever a smoke program emitted) and
asserts:

  1. At least one {shape: "audit"} and one {shape: "sys"} row appear, plus
     an {shape: "api"} row when FASTEN_VERIFY_REQUIRE_API=1.
  2. The audit row carries the required wire fields.
  3. Redaction worked: api_key, customer_token and nested.token (if present)
     are "***"; email is unchanged.
  4. Audit and api request_id values are 12 hex chars.
  5. The sys row has level, event, request_id and timestamp.
  6. An api row, if any, has method, path, status, request_id, timestamp.

Exits 0 if every check passes, else 1 with the failed check on stderr.

Usage:

    docker run --rm fasten-itest-python | python tests/integration/verify.py

Each smoke emits, in any order:

    log.info("startup_ok", {lang: ...})
    emit(code="USER_CREATED", target="u-42", actor="admin",
         detail={email, api_key, customer_token, nested.token})
    write_api({method, path, status, ms, request_id, timestamp})  # Python only
"""
from __future__ import annotations

import json
import re
import sys
from typing import Any

REQUIRED_AUDIT_FIELDS = {
    "wire_version",
    "shape", "id", "origin_id", "monotonic_seq", "timestamp",
    "code", "action", "severity",
    "service_id", "source_node_id",
    "actor", "actor_kind", "target", "category", "domain",
    "method", "request_id", "detail",
}
REQUIRED_SYS_FIELDS = {"shape", "level", "event", "request_id", "timestamp"}
REQUIRED_API_FIELDS = {"shape", "method", "path", "status", "request_id", "timestamp"}

# ID_RE: audit.id, "evt-" plus 20 hex chars, as in spec/row-schema.json
# properties.id.pattern. It is the dedup key when rows replicate, so any other
# length is a failure.
# REQ_ID_RE: request_id, 12 hex chars with no prefix. The same value appears
# on audit, sys and api rows for one request, so it can be grepped across logs.
ID_RE = re.compile(r"^evt-[0-9a-f]{20}$")
REQ_ID_RE = re.compile(r"^[0-9a-f]{12}$")


def fail(msg: str, ctx: Any = None) -> None:
    print(f"\nFAIL: {msg}", file=sys.stderr)
    if ctx is not None:
        print(f"  context: {json.dumps(ctx, indent=2, default=str)}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    # Set for the Python smoke only; the other SDKs don't write api rows
    # (see tests/integration/README.md).
    require_api = os.environ.get("FASTEN_VERIFY_REQUIRE_API", "0") == "1"

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

    audit = audit_rows[0]
    missing = REQUIRED_AUDIT_FIELDS - set(audit.keys())
    if missing:
        fail(f"audit row missing fields: {sorted(missing)}", audit)

    if audit.get("wire_version") != "1":
        fail(f"audit.wire_version must be '1', got {audit.get('wire_version')!r}", audit)
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
    # Key patterns match anywhere in the key, so customer_token is redacted
    # because it contains "token". An anchored regex would miss it.
    if detail.get("customer_token") != "***":
        fail("audit.detail.customer_token was NOT redacted (substring on 'token')", detail)
    # C++ detail is flat and has no "nested" key; the other smokes send one.
    nested = detail.get("nested")
    if isinstance(nested, dict):
        if nested.get("token") != "***":
            fail("audit.detail.nested.token was NOT redacted", detail)

    sys_row = sys_rows[0]
    missing = REQUIRED_SYS_FIELDS - set(sys_row.keys())
    if missing:
        fail(f"sys row missing fields: {sorted(missing)}", sys_row)
    if sys_row["level"] not in ("info", "Info", "INFO"):
        fail(f"sys.level expected info, got {sys_row['level']}")
    if sys_row["event"] != "startup_ok":
        fail(f"sys.event expected startup_ok, got {sys_row['event']}")

    if require_api and not api_rows:
        fail("no {shape: 'api'} row produced")
    if api_rows:
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

    api_note = (f"{len(api_rows)} api row(s)" if api_rows
                else "api rows: none (not required for this SDK)")
    print(f"OK — {len(audit_rows)} audit row(s), {len(sys_rows)} sys row(s), "
          f"{api_note} — contract holds")


if __name__ == "__main__":
    main()
