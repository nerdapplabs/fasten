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

await fasten.flush();   // drain pending audit rows
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
and a `setImmediate`-driven drainer writes them to the sink with exponential
backoff (100 ms to 60 s, plus or minus 20 % jitter). Sink failures stay off
the request path. Set `auditStoreFailureStrategy: 'raise'` for synchronous
writes that throw `AuditStoreError`. `queueStats()` and `flush(timeoutMs)`
complete the public surface.

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
