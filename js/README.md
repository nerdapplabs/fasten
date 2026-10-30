# fasten — Node / TypeScript

Audit + correlation SDK for Node services. v1.0.0-beta.

## Install

From source today (npm publish lands with the v1.0 GA tag):

```bash
npm install ./js
# or, when published:
npm install @nerdapplabs/fasten
```

Requires Node ≥ 24 (uses `AsyncLocalStorage`, `node:test`, ESM).

## Quickstart

Verified to run as-is on Node 24+:

```js
import fasten, { register, withRequestID, Severity, RetentionClass } from '@nerdapplabs/fasten';

register('user', {
    USER_CREATED: {
        domain: 'user', category: 'account', action: 'create',
        severity: Severity.INFO,
        description: 'New user account',
        emitter: 'auth-service',
        retentionClass: RetentionClass.LONG,
    },
});

// Optional: a sync audit-store sink. Without one, rows print to stdout only.
const auditStore = {
    insert(row) { /* persist row to your DB / queue / file */ },
};

fasten.init({
    serviceId: 'auth-service',
    nodeId:    'host-01',
    auditStore,
});

await withRequestID('req-a1b2c3', async () => {
    fasten.emit({ code: 'USER_CREATED', target: 'u-42',
                  actor: 'admin',
                  detail: { email: 'alice@example.com' } });
    fasten.log.info('signup_complete', { user_id: 'u-42' });
});

await fasten.flush();   // drain pending audit rows
```

Both lines stream NDJSON to stdout under the same `request_id`.

## Worked example — node:http service

A minimal HTTP service with `X-Request-ID` propagation, an audit row
per request: see [`examples/server.mjs`](examples/server.mjs). Zero
external deps — uses Node's built-in `http`.

```bash
cd js/examples
FASTEN_SERVICE_ID=demo FASTEN_NODE_ID=host-01 node server.mjs
# in another shell
curl -X POST http://localhost:8080/users -d '{"email":"alice@example.com"}'
curl http://localhost:8080/users/u-42
```

## P1-15: audit-store failure handling

`fasten.emit()` defaults to **queue mode** — rows are pushed onto an
in-memory queue and a `setImmediate`-driven drainer writes to the
sink with exponential backoff (100 ms → 60 s, ±20 % jitter). Sink
failures stay off the request path. Set
`auditStoreFailureStrategy: 'raise'` to opt into synchronous semantics
with `AuditStoreError`. With an async store such as `PostgresStore`,
raise-mode `emit()` returns a promise for the row; `await` it to see the
`AuditStoreError`. `queueStats()` and `flush(timeoutMs)` complete
the public surface. Re-`init()` stops the old drainer: rows still queued
get one more attempt each and are dead-lettered if it fails.

**Chain.** The JS SDK does not seal rows. `emit()` returns the row with
`monotonic_seq: 0`, and `PostgresStore` gives it the node's next seq in the
insert transaction, under the same per-node lock as the Python and Go
stores; `hash` and `prev_hash` stay empty. `PostgresStore` writes into a
table the Python or Go store created, and adds the columns it lacks.

**PII retention.** `redactExpired({ before })` clears `detail` (to `null`)
on rows of the PII codes older than `before`: codes with `piiInDetail` or
`retentionClass: SHORT` (`piiCodes()`). Each redacted row gets an
`AUDIT_ROW_REDACTED` row naming it, written before the row is cleared. Rows
are never deleted. Set `retentionPii: '30d'` (or `FASTEN_RETENTION_PII`) in
`init()` to run it on init and then hourly; the store must implement
`listRedactionCandidates` and `redactRows`, as `PostgresStore` does.

**Cross-language deviation.** Node is single-threaded — `emit()`
cannot synchronously block on a counting semaphore the way Python /
Go / Rust / C++ do. `queueCapacity` is the high-water-warn threshold
(`audit_queue_high_water` / `audit_queue_near_full` sys events), not
a hard cap.

## Tests

```bash
docker run --rm -v $PWD/js:/work -w /work node:20 \
  sh -c "npm install --silent && node --test test/*.test.mjs"
```

Current: 52 passed.

## Docs + design

Full reference: [https://fasten.sh/docs/](https://fasten.sh/docs/) ·
Design + cross-language design: [README.md](../README.md).
