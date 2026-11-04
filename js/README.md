# fasten for Node / TypeScript

Audit and correlation SDK for Node services. v1.0.0-beta.

## Install

Install from source for now; the npm package will be published with the
v1.0 GA tag.

```bash
npm install ./js
# or, once published:
npm install @nerdapplabs/fasten
```

Requires Node 24 or later (uses `AsyncLocalStorage`, `node:test`, ESM).

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

await fasten.close();   // on shutdown: store pending audit rows, stop the drainer
```

Both lines go to stdout as NDJSON with the same `request_id`.

## Worked example: node:http service

A minimal HTTP service with `X-Request-ID` propagation and one audit row per
request: see [`examples/server.mjs`](examples/server.mjs). It has no external
dependencies and uses Node's built-in `http`.

```bash
cd js/examples
FASTEN_SERVICE_ID=demo FASTEN_NODE_ID=host-01 node server.mjs
# in another shell
curl -X POST http://localhost:8080/users -d '{"email":"alice@example.com"}'
curl http://localhost:8080/users/u-42
```

## Audit-store failure handling

`fasten.emit()` defaults to **queue mode**: rows go onto an in-memory queue,
and a drainer writes them to the sink with exponential
backoff (100 ms to 60 s, plus or minus 20 % jitter). Sink failures stay off
the request path. Set `auditStoreFailureStrategy: 'raise'` for synchronous
writes that throw `AuditStoreError`. With an async store such as
`PostgresStore`, raise-mode `emit()` returns a promise for the row; `await`
it to see the `AuditStoreError`. `queueStats()`, `flush(timeoutMs)` and
`close(timeoutMs)` complete the public surface. Call `close()` on shutdown:
it flushes, then stops the drainer, giving rows still queued one more
attempt each. A row that fails it, or is still unstored at the timeout, is
reported as `audit_drain_lost_at_stop`, and `close()` resolves false.
Re-`init()` flushes the old drainer for up to 5 s, then stops it the same
way; `flush()` and `close()` also wait for it, and rows it could not store
are reported with `audit_drain_install_incomplete`. An idle drainer does not
keep the process alive.

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

**Differs from the other SDKs:** Node is single-threaded, so `emit()` cannot
block on a counting semaphore the way Python, Go, Rust and C++ do.
`queueCapacity` is a warning threshold (it drives the
`audit_queue_high_water` / `audit_queue_near_full` sys events), not a hard
cap.

## Tests

```bash
docker run --rm -v $PWD/js:/work -w /work node:24 \
  sh -c "npm install --silent && npm test"
```

## Docs and design

Full reference: [https://fasten.sh/docs/](https://fasten.sh/docs/).
Design and cross-language design: [README.md](../README.md).
