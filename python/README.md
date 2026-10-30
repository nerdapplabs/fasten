# fasten for Python

Audit and correlation SDK for Python services. v1.0.0-beta.

## Install

Install from source for now; the PyPI package will be published with the
v1.0 GA tag.

```bash
pip install ./python                # core
pip install ./python[fastapi]       # + ASGI router for the /logs/* reader
pip install ./python[postgres]      # + Postgres store
```

Redaction, the code catalog and the audit queue run in `libfasten_core`
(the Rust library in [`fasten-core/`](../fasten-core)), loaded through
ctypes. Build it first:

```bash
cd fasten-core && cargo build --release --features all
```

fasten looks for the library in this order: `FASTEN_CORE_LIB`, next to the
package (wheel), the system library path, then
`fasten-core/target/release/` in a source checkout. For a non-editable
install, set `FASTEN_CORE_LIB=/path/to/libfasten_core.so` (`.dylib` on
macOS).

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

Both lines go to stdout as NDJSON with the same `request_id`. The audit row
is also stored in `./fasten-audit.db`. `FASTEN_AUDIT_DSN` is optional:
without it (and without `audit_store=`), audit rows go to stdout only.

## Worked example: FastAPI service

A minimal HTTP service with `X-Request-ID` propagation, one audit row per
request, and the mountable `/logs/*` reader: see
[`examples/fastapi_app.py`](examples/fastapi_app.py).

```bash
pip install ./python[fastapi] uvicorn
cd python
FASTEN_SERVICE_ID=demo FASTEN_NODE_ID=host-01 \
  FASTEN_AUDIT_DSN=sqlite:///./demo-audit.db \
  uvicorn examples.fastapi_app:app --port 8000

curl -X POST http://localhost:8000/users -H 'content-type: application/json' \
     -d '{"email":"alice@example.com"}'
# The reader requires a Bearer token (DEMO_READER_TOKEN, default demo-token):
curl -H 'authorization: Bearer demo-token' http://localhost:8000/logs/audit
```

## Bundled CLI and TUI

Console scripts installed by `pip install`:

| Tool        | Invoke                             | What it does                                  |
|-------------|------------------------------------|-----------------------------------------------|
| CLI         | `fasten dump`                      | Print registered codes (CI consistency gate)  |
| CLI         | `fasten doctor`                    | Verify init config + correlation wiring       |
| CLI         | `fasten tail --stream sys`         | Stream rows from a mounted reader             |
| TUI         | `fasten-tui --request-id <id>`     | Live multi-pane audit + sys + API feed (Rich) |

## Reading logs back: whole record or recent window?

Every reader response carries a per-stream `completeness` flag that answers
this:

- **`store`**: the stream is backed by a durable store. The response is a
  query over the whole recorded history (paged by `limit`), not a window.
- **`ring`**: the stream lives in a bounded in-memory ring (default 2000
  rows, cleared on restart). The response only reaches as far back as the
  ring. Older rows have been evicted, and nothing tells you *whether*
  eviction dropped matching rows. Treat it as a recent window, never as the
  record.
- **`store-degraded`**: store-backed, but at least one row failed to persist
  (full disk, closed handle, and so on). Reads still come from the store, but
  the durable history has known gaps. The flag is sticky: it describes the
  history, not the current state of the sink.

The flag is the stream's durability *class*. It never says whether one
specific response lost rows. `/correlate` caps each stream at `limit`, so
compare `counts` (rows returned) with `totals` (matching rows in the backing
source): if `counts` is less than `totals`, the response is truncated. Raise
`limit` or page through the per-stream endpoints.

`audit` reports `store` when an audit store is attached (the usual production
`fasten.init(...)`) and `ring` when the SDK runs stdout-only. Stdout alone is
not a durable record, and `completeness` says so. `api` and `sys` are
ring-only unless you attach a `StreamStore` via
`fasten.init(api_store=..., syslog_store=...)`. Persistence is write-through:
one synchronous INSERT and commit per pushed row. With WAL and
`synchronous=NORMAL` there is no fsync per commit, but it is still a disk
write per row.

## Audit-store failure handling

`fasten.emit()` defaults to **queue mode**: rows go onto a bounded in-memory
queue, drained by a background thread with exponential backoff (100 ms to
60 s, plus or minus 20 % jitter). Store failures stay off the request path.
Pass `audit_store_failure_strategy="raise"` for synchronous writes that raise
`AuditStoreError`. `fasten.queue_stats()` and `fasten.flush()` complete the
public surface.

## Tests

The same steps CI runs (see
[`fasten-py.yml`](../.github/workflows/fasten-py.yml)), from the repo root:

```bash
(cd fasten-core && cargo build --release --locked --features all)
cd python
pip install -e ".[dev,postgres,fastapi,sqlite]" pyyaml structlog
LD_LIBRARY_PATH=$PWD/../fasten-core/target/release python -m pytest tests/ -q
```

Set `FASTEN_TEST_POSTGRES_DSN` to include the Postgres tests.

## Docs and design

Full reference: [https://fasten.sh/docs/](https://fasten.sh/docs/).
Design and cross-language design: [README.md](../README.md).
