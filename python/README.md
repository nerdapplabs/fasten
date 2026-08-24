# fasten — Python

Audit + correlation SDK for Python services. v1.0.0-beta.

## Install

From source today (registry publish lands with the v1.0 GA tag):

```bash
pip install ./python                # core
pip install ./python[fastapi]       # + ASGI router for /logs/* reader
pip install ./python[postgres]      # + Postgres store
```

## Quickstart

Verified to run as-is on Python 3.10+:

```python
import os
os.environ["FASTEN_AUDIT_DSN"] = "sqlite:///./fasten-audit.db"

import fasten
from fasten.codes import register, Meta, Severity, RetentionClass
from fasten.context import with_request_id

register("user", {
    "USER_CREATED": Meta(
        domain="user", category="account", action="create",
        severity=Severity.INFO, description="New user account",
        emitter="auth-service", retention_class=RetentionClass.LONG,
    ),
})

fasten.init(service_id="auth-service", node_id="host-01")

with with_request_id():
    fasten.emit(code="USER_CREATED", target="u-42",
                actor="admin", detail={"email": "alice@example.com"})
    fasten.log.info("signup_complete", user_id="u-42")

fasten.flush()  # block until the audit row reaches the store
```

Both lines stream NDJSON to stdout under the same `request_id`. The audit
row is also persisted to `./fasten-audit.db`.

## Worked example — FastAPI service

A minimal HTTP service with `X-Request-ID` propagation, an audit row per
request, and the mountable `/logs/*` reader: see
[`examples/fastapi_app.py`](examples/fastapi_app.py).

```bash
pip install ./python[fastapi] uvicorn
FASTEN_SERVICE_ID=demo FASTEN_NODE_ID=host-01 \
  FASTEN_AUDIT_DSN=sqlite:///./demo-audit.db \
  uvicorn examples.fastapi_app:app --port 8000

curl -X POST http://localhost:8000/users -H 'content-type: application/json' \
     -d '{"email":"alice@example.com"}'
curl http://localhost:8000/logs/audit
```

## Bundled CLI + TUI

Console scripts installed by `pip install`:

| Tool        | Invoke                             | What it does                                  |
|-------------|------------------------------------|-----------------------------------------------|
| CLI         | `fasten dump`                      | Print registered codes (CI consistency gate)  |
| CLI         | `fasten doctor`                    | Verify init config + correlation wiring       |
| CLI         | `fasten tail --stream sys`         | Stream rows from a mounted reader             |
| TUI         | `fasten-tui --request-id <id>`     | Live multi-pane audit + sys + API feed (Rich) |

## Reading logs back: whole record, or a recent window?

Every reader response carries a per-stream `completeness` flag that answers
exactly this:

- **`store`** — the stream is backed by a durable store. The response is a
  query over the whole recorded history (paged by `limit`), not a window.
- **`ring`** — the stream lives in a bounded in-memory ring (default 2000
  rows, cleared on restart). The response only reaches as far back as the
  ring: older rows have been evicted, and there is no signal for *whether*
  eviction dropped matching rows. Treat it as "recent window", never "the
  record".
- **`store-degraded`** — store-backed, but at least one row failed to persist
  (full disk, closed handle, …). Reads still serve from the store, but durable
  history has known holes. The flag is sticky: it marks the history, not the
  current sink state.

The flag is the stream's durability *class* — it never says whether one
specific response lost rows. For `/correlate`, which caps each stream at
`limit`, compare `counts` (returned) against `totals` (matching rows available
in the backing source): `counts < totals` means the response is truncated —
raise `limit` or page the per-stream endpoints.

`audit` reports `store` when an audit store is attached (the default in
production `fasten.init(...)`) and `ring` when the SDK is running stdout-only
without one — a stdout-only audit is honestly not a durable record, and
`completeness` must reflect that. `api`/`sys` are ring-only unless you attach
a `StreamStore` via `fasten.init(api_store=…, syslog_store=…)`; persistence is
write-through (one synchronous INSERT + commit per pushed row — WAL +
`synchronous=NORMAL`, so no per-commit fsync, but still a per-row disk write).

## P1-15: audit-store failure handling

`fasten.emit()` defaults to **queue mode** — rows go onto a bounded
in-memory queue, drained by a background thread with exponential
backoff (100 ms → 60 s, ±20 % jitter). Store failures stay off the
request path. See `audit_store_failure_strategy="raise"` to opt into
synchronous-with-`AuditStoreError` semantics. `fasten.queue_stats()`
and `fasten.flush()` complete the public surface.

## Tests

```bash
docker run --rm -v $PWD/python:/work -w /work python:3.11 \
  sh -c "pip install -e .[fastapi] && pip install pytest httpx pyyaml structlog && python -m pytest -q"
```

Current: 112 passed.

## Docs + design

Full reference: [https://fasten.sh/docs/](https://fasten.sh/docs/) ·
Design + cross-language design: [README.md](../README.md).
