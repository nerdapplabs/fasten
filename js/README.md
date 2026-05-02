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
with `AuditStoreError`. `queueStats()` and `flush(timeoutMs)` complete
the public surface.

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
