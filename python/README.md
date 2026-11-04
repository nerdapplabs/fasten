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
60 s, plus or minus 20 % jitter) and dead-lettered after
`queue_drain_max_attempts`. A failed insert doesn't fail the request, but
when the queue is full `emit()` blocks until a slot frees, so in a long
outage it waits on the drainer's retries; size `queue_capacity` and the
retry settings for that. A row the store rejects outright (a DB-API
`DataError` or `IntegrityError`) is dead-lettered at once rather than
retried. `emit()` returns the row before it is stored, so its
`monotonic_seq` and `hash` are not set yet; the store seals it. Pass
`audit_store_failure_strategy="raise"` for synchronous writes that raise
`AuditStoreError` and return the sealed row. `fasten.queue_stats()` and
`fasten.flush()` complete the public surface.
`fasten.close(timeout=5.0)` stops the drainer on shutdown (the exit hook
calls it): it flushes for half of `timeout`, then stores the rows still
held. It returns within about `timeout`, reports rows not stored by then
as `audit_drain_lost_at_stop`, and returns False if any row was lost.
A row reported lost may still be stored by a call left running; that is
reported as `audit_drain_recovered_at_stop` unless the process has exited
by then. A
store call still running at that point is left behind on its thread
(`fasten-store`), not interrupted, and does not hold up or affect
interpreter exit: the exit status and other atexit hooks are unchanged.
Re-running `fasten.init()` waits at most 10 s for the drainer it replaces
in the same way, and emits `audit_drain_install_incomplete` if that
drainer's flush timed out or a row it held was not stored. Until it is
retired, `fasten.flush()` and `fasten.close()` wait for its rows too.

## Chain checkpoints

`verify_chain` cannot tell on its own that rows were cut off the end of a
chain, or that the whole chain was re-sealed. Publish checkpoints (each
node's latest seq and hash) somewhere the store's operator cannot rewrite,
and verify against them later
([spec §9](../spec/chain-replication.md#9-checkpoints)):

```python
from fasten import verify_chain
from fasten.checkpoints import FileCheckpointSink, load_checkpoints, publish_checkpoints

publish_checkpoints(store, FileCheckpointSink("/mnt/worm/checkpoints.jsonl"))
# HttpCheckpointSink(url) POSTs them instead.

result = verify_chain(all_rows, checkpoints=load_checkpoints("/mnt/worm/checkpoints.jsonl"))
```

By default the rows are taken as the whole chain: every checkpointed node
must have rows, and its newest checkpoint must fall within them. To check
a page or one node, pass `partial=True`; checkpoints below its rows, or for
nodes not in them, are then skipped. If the file's last line was cut short
by a crash, `load_checkpoints` skips it and logs a warning, and the next
publish drops it. Use one publisher per file.

With retention, a node whose rows have all been purged still has
checkpoints, and they fail a whole-chain verify. Pass only the checkpoints
taken since the latest purge finished, and publish again after each purge:

```python
from fasten.checkpoints import checkpoints_since

cps = checkpoints_since(load_checkpoints("/mnt/worm/checkpoints.jsonl"), purged_at)
result = verify_chain(all_rows, checkpoints=cps)
```

A whole-chain verify does not show rows deleted from the start of a chain
as long as the newest checkpointed row and the rows after it remain; that
looks the same as a purge.

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
