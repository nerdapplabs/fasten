# fasten for Node / TypeScript

Audit and correlation SDK for Node services. v1.0.0-beta.

## Install

Install from source for now; the npm package will be published with the
v1.0 GA tag.

```bash
npm install ./js
# or, once published:
npm install fasten-sdk
```

Requires Node 24 or later (uses `AsyncLocalStorage`, `node:test`, ESM).

## Quickstart

Verified to run as-is on Node 24+:

```js
import fasten, { register, withRequestID, Severity, RetentionClass } from 'fasten-sdk';

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
// A store of your own writes rows unsealed unless it seals them (see
// "A store of your own" below); SqliteStore and PostgresStore seal them.
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
way, also when the new config is raise mode or has no store. `flush()` and
`close()` wait for it, rows it could not store are reported with
`audit_drain_install_incomplete`, and the next `close()` resolves false if
it lost rows. An idle drainer does not
keep the process alive. `queueStats().last_error` and the drainer's sys
events (`audit_drain_failed`, `audit_drain_degraded`,
`audit_drain_dead_letter`, `audit_sync_fallback_failed`'s `error_type`)
record the error type, such as `DatabaseError`, as the other SDKs do.

**Dropped connections.** `PostgresStore` and `PostgresStreamStore` recover
when the database drops their connections (a restart, a failover,
`pg_terminate_backend`): a call that meets a dead connection runs again on
a new one, as the Python stores reconnect and retry, and the pool drops
dead idle connections without ending the process. A write that still fails
is retried by the drainer in queue mode; in raise mode that `emit()`
rejects with `AuditStoreError` and the next one works. A COMMIT whose
answer was lost is not run again: the row is read back, as before. The
chain stays whole either way, since a retried row takes no new seq.

**Chain.** `emit()` returns the row with `monotonic_seq: 0`.
`PostgresStore` and `SqliteStore` seal it into its node's hash chain in
the insert transaction, under the same per-node lock as the Python, Go and
Rust stores (SQLite: `BEGIN IMMEDIATE`): the node's next seq, `prev_hash` from the node's latest sealed row,
a detail salt and commitment, and the hash (canonical form "2",
[spec §1.4](../spec/chain-replication.md)). Python, Go, Rust and JS writers
can share a node in one table: `PostgresStore` and `SqliteStore` write into a
table the Python or Go store created, and add the columns it lacks.

What `insert()` returns decides the rest. When it returns (or resolves to)
a row with the same `id` as the row given, raise-mode `emit()` returns that
row, and if it has a non-empty `hash` the engine writes it to stdout a
second time (spec §8). Otherwise `emit()` returns the row as built and
there is no second line. Queue-mode `emit()` always returns the unsealed
row at once. A retry of a row whose id is already stored returns the
stored row.

`emit()` throws `ChainError` at once, in both modes, for a `target` that is
not a string or a row field that is not a string or holds an unpaired
surrogate: no store could seal such a row. A store that refuses a row
throws `AuditRowRejectedError`, and the drainer dead-letters it without
retrying.

**One allocator per node.** A row with a `monotonic_seq` of its own is
stored as given, unsealed unless it carries a hash, and its seq must be
free on its node. An unsealed row at or above a node's first sealed seq
breaks `verifyChain` for that node, so do not write rows with their own
seqs on a node id that a sealing store writes for. Use `insertSealed` for a
row sealed elsewhere.

**A store of your own.** A store seals only if it does so itself and has a
`seals()` method that returns true; otherwise `init()` logs
`audit_chain_unavailable` and rows are stored unsealed. To seal, do what
`PostgresStore.insert` does, in one transaction per row:

1. Take a lock per `source_node_id` that every writer on the node shares.
2. If the row's `id` is stored, return the stored row.
3. Set `monotonic_seq` to the node's highest seq plus one, counting
   unsealed rows.
4. `seal(prev, row)`, with `prev` the hash of the node's latest sealed
   row, or `GENESIS`.
5. Store `detail` as the text `canonicalJSON(detail)`, and read it back
   with `parseJson`, so the numbers stay the ones that were hashed.
6. Return the sealed row from `insert()`.

A store whose `seals()` returns true but whose `insert()` returns no row
with a hash gets one `audit_chain_row_unsealed` error on stderr.

**Numbers in `detail`.** The hash covers numbers as CPython writes them
([spec §1.3](../spec/chain-replication.md)). A JS number is taken as the
text `String(n)` gives (what `JSON.stringify` writes) and hashed as CPython
renders the value that text reads back as: `75` as `75`, `75.5` as `75.5`,
`1e-7` as `1e-07`. JS has no float `75.0`; send it as `75`, an int. A
`BigInt` is an exact integer, so pass one for an integer above 2^53.
The stores write `detail` as the same canonical text, so what is stored is
what was hashed. A string `detail` given to a store's `insert` is read as
JSON text and must be an object.

**Reading rows.** A store's `query()` and `listUnshipped()` return rows
with the wire's snake_case keys, the shape of `Row` and of what `insert()`
returns. Their `detail` is parsed with `JSON.parse`, and an integer a
number cannot hold exactly is a `BigInt`. `JSON.stringify` throws on a
`BigInt`; pass a replacer such as
`(k, v) => typeof v === 'bigint' ? JSON.rawJSON(String(v)) : v`.

**PII retention.** `redactExpired({ before })` clears `detail` (to `null`)
on rows of the PII codes older than `before`: codes with `piiInDetail` or
`retentionClass: SHORT` (`piiCodes()`). Each redacted row gets an
`AUDIT_ROW_REDACTED` row naming it, written before the row is cleared. Rows
are never deleted. Set `retentionPii: '30d'` (or `FASTEN_RETENTION_PII`) in
`init()` to run it on init and then hourly; the store must implement
`listRedactionCandidates` and `redactRows`, as both bundled stores do.

**Age purge.** The engine never deletes audit rows, as in Python and Go:
`retentionApi` and `retentionSyslog` purge only the api and sys stores. To
drop old audit rows, call the store's `purge({ before, respectUnshipped })`
yourself. Per node it deletes only a seq prefix
([spec §2.3](../spec/chain-replication.md)), and by default keeps unshipped
rows and every row above them, so the rows left still verify: the chain
starts at a purged head. Publish checkpoints again after each purge and
verify with `checkpointsSince` (see "Chain checkpoints").

**Differs from the other SDKs:** Node is single-threaded, so `emit()` cannot
block on a counting semaphore the way Python, Go, Rust and C++ do.
`queueCapacity` is a warning threshold (it drives the
`audit_queue_high_water` / `audit_queue_near_full` sys events), not a hard
cap.

## SQLite store

`SqliteStore` keeps the audit rows in a SQLite file, on Node's built-in
`node:sqlite`, with no dependency to install:

```js
import fasten from 'fasten-sdk';
import { SqliteStore } from 'fasten-sdk/store/sqlite';

const auditStore = new SqliteStore('./audit.db');   // or { table, wal, busyTimeoutMs }
fasten.init({ serviceId: 'auth-service', nodeId: 'host-01', auditStore });
```

It does what `PostgresStore` does, with the same methods and row shapes:
it seals rows into the chain, returns the stored row on a retry, rejects a
different row under a stored id or at a taken seq, and has `insertSealed`,
`chainRows`, `allChainRows`, `chainTips`, `query` (with `afterSeq`),
`count`, `search`, `sources`, `chainTail`, `listUnshipped`, `markShipped`,
`purge`, the redaction methods and replication (below), so the reader
serves it as it serves `PostgresStore`. `search` lowercases `q` and
matches it against SQLite's `lower(detail)`, which folds only ASCII
letters, as the Python and Go SQLite stores do; Postgres's `ILIKE` folds
all letters. A
seq is taken in a `BEGIN IMMEDIATE` transaction, so several processes and
threads can write one file and still get one chain per node. A new file is
created owner-only (0600), in WAL mode, and a writer waits up to 5 s for
another's write lock.

The table works with the Python, Go and Rust SQLite stores, so they can
share one file. `SqliteStore` adds the columns a table another SDK created
lacks. On a table it creates, the `(source_node_id, monotonic_seq)` index is
unique, as in the Go and Rust stores; on an existing table without such an
index it adds a plain one, since older rows may repeat a seq.

`node:sqlite` is synchronous. Each call runs to the end before it returns
and blocks the event loop meanwhile, including while it waits for another
connection's write lock. The methods return promises only so the store has
`PostgresStore`'s interface. Where a wait on the lock would hold up
requests, use `PostgresStore`. In Node 24's documentation `node:sqlite`
is at stability 1.2, release candidate (since v24.15.0); it was
experimental before that.

## Stores from the environment

Without `auditStore`, `apiStore` or `syslogStore`, `init()` opens one from
`FASTEN_AUDIT_DSN`, `FASTEN_API_DSN` or `FASTEN_SYSLOG_DSN`, with the DSN
forms of the Python SDK:

| DSN | Store |
|---|---|
| `postgres://...` or `postgresql://...` | `PostgresStore`, or `PostgresStreamStore` for the streams |
| `sqlite:///./rel.db`, `sqlite:////abs/path.db`, `/abs/path.db` | `SqliteStore`, or `SqliteStreamStore` |

`?table=` names the table (default `audit_log`, `api_log`, `syslog`) and is
taken off a Postgres DSN before connecting; `?wal=false` turns WAL off on
SQLite. A store passed to `init()` wins over the environment. A stream DSN
with another scheme (`mysql://`, `postgresql+psycopg://`) is an error, not
a file. A re-init with the same DSN keeps the store it opened. The engine
does not close these stores; they live as long as the process.

Go reads only `FASTEN_API_DSN` and `FASTEN_SYSLOG_DSN`, and only for SQLite;
Python and JS read all three, for SQLite and Postgres.

## Replication

A node ships the rows it originated to an aggregator, which verifies them
and stores them without sealing them again
([spec §4](../spec/chain-replication.md)). On the node:

```js
const rows = await fasten.listUnshipped(500);   // this node's own rows, oldest first
await send(rows.map((r) => JSON.stringify(r)).join('\n'));
await fasten.markShipped(rows.map((r) => r.id));
```

`fasten.listUnshipped` asks the store for the rows this service and node
originated (`origin_id = id`), so rows ingested from other nodes are not
shipped again, and reads them with `exact: true`: their detail numbers are
the tokens that were hashed, and `JSON.stringify` writes them as they are.
A store's own `listUnshipped(limit, { serviceId, sourceNodeId, exact })`
takes the same options.

On the aggregator, pass each received line as it is, or parsed with
`parseJson` (`JSON.parse` turns `75.0` into `75`, and the row then fails to
verify):

```js
const result = await store.ingestReplicated(lines, { localNodeId: 'aggregator-01' });
// { inserted: 500, rejectedFromSeq: null, reason: null }
```

`ingestReplicated` verifies the batch's chain per node and checks it against
the rows the store already holds, in one transaction: a different row under
a stored id or at a stored (node, seq), a `prev_hash` that does not link to
the stored row before it, or a stored row after it that does not link to it,
is a break. It stores the rows before the first break, with each row's hash
and detail text as they were sealed, and does not throw on a break: the
result says where the batch broke, so the sender resends from there.
Unsealed rows are not stored. A re-delivered batch is a no-op.

| `IngestResult` (JS) | Python | Go | |
|---|---|---|---|
| `inserted` | `inserted` | `Inserted` | rows of the verified prefix passed to the insert, re-deliveries included |
| `rejectedFromSeq` | `rejected_from_seq` | `RejectedFromSeq` | seq of the first broken row; `null` (Go: 0) when none |
| `reason` | `reason` | `Reason` | why it broke there; `null` (Go: "") when it did not |

With `localNodeId`, the batch stops at the first row from that node, which
is reported as the break: a node's own rows come only from its emit path,
and such a row usually means two nodes share a node id. `fasten.ingestReplicated(rows)`
does the same with the default engine's store and node id.
`ingestReplicated` throws `ChainError` for a row it cannot read at all.
`insertReplicated(row)` stores one sealed row from elsewhere without
verifying a batch; it is `insertSealed`.

The transport must authenticate the sender: ingest verifies the chain, not
who sent it.

## Verifying the chain

`verifyChain` checks the hash chain over a set of rows and reports the
first break: an edited, inserted, deleted or reordered row
([spec §3](../spec/chain-replication.md)). Chains sealed by the Python, Go
and JS SDKs verify in each of them. Read stored rows with `chainRows(node)`
or `allChainRows()`: they keep each detail number as the text that was
hashed, which `query()` does not (`JSON.parse` turns `75.0` into `75`).
Captured stdout lines can be passed as they are, one string per line.

```js
import { verifyChain } from 'fasten-sdk';

const result = verifyChain(await store.chainRows('host-01'));
if (!result.ok) {
    console.log(result.firstBreakAt, result.firstBreakNode, result.reason);
}
```

`ok` covers only what was checked: `sealedRows` rows, and with checkpoints
`checkpointsChecked` of them that had a row at their seq. It is also true
when nothing was checked. `verifyChain` throws `ChainError` for a row it
cannot read. On its own it cannot tell that rows were deleted from the end
of a chain, that the start of a chain was deleted (that looks like a
purge), or that a whole chain was sealed again; checkpoints catch the
first and the last.

## Chain checkpoints

`verifyChain` cannot tell on its own that rows were cut off the end of a
chain, or that the whole chain was re-sealed. Publish checkpoints (each
node's latest seq and hash) somewhere the store's operator cannot rewrite,
and verify against them later ([spec §9](../spec/chain-replication.md)):

```js
import {
    FileCheckpointSink, loadCheckpoints, publishCheckpoints, verifyChain,
} from 'fasten-sdk';

await publishCheckpoints(store, new FileCheckpointSink('/var/lib/fasten/checkpoints.jsonl'));
// new HttpCheckpointSink(url) POSTs them instead.

const checkpoints = await loadCheckpoints('/var/lib/fasten/checkpoints.jsonl');
const result = verifyChain(await store.allChainRows(), { checkpoints });
```

By default the rows are taken as the whole chain: every checkpointed node
must have rows, and no checkpoint may be below its oldest row or above its
newest. To check a page or one node, pass `partial: true`; checkpoints
below or above its rows, or for nodes not in them, are then skipped, so only
a whole-chain verify detects a cut-off tail: a deleted tail needs
checkpoints. If the file's last line was
cut short by a crash, `loadCheckpoints` throws `PartialLastLineError`,
whose `checkpoints` are the whole lines before it, and the next publish
drops that line with a `checkpoint_unfinished_line_dropped` warning. An
unfinished last line longer than 4 KiB is not a cut-short checkpoint, and
the publish throws instead of dropping it. A store with no sealed rows
publishes nothing and logs `checkpoint_no_sealed_rows`. The
file sink reads and may truncate the file, so it does not work on a path
that only accepts appends. Use one publisher per file. The file lines are
the bytes the Python sink writes, and each SDK reads the others' files.

With retention, checkpoints taken before a purge are below the rows it
left, or belong to a node with no rows left, and they fail a whole-chain
verify. Pass only the checkpoints taken since the latest purge finished,
and publish again after each purge:

```js
import { checkpointsSince } from 'fasten-sdk';

const since = checkpointsSince(await loadCheckpoints(path), purgedAt);
const result = verifyChain(await store.allChainRows(), { checkpoints: since });
```

A whole-chain verify shows rows deleted from the start of a chain when one
of the given checkpoints falls among them. Rows deleted below every given
checkpoint look the same as a purge.

## Stored sys and api logs

`log.info(...)` lines (and fasten's own events) are the `sys` stream; one
row per HTTP request is the `api` stream. Both are kept in an in-memory
ring of 2000 rows, cleared on restart. Attach a stream store to keep them
([spec](../spec/persistent-streams.md)):

```js
import fasten, { apiLogger } from 'fasten-sdk';
import { PostgresStreamStore } from 'fasten-sdk/store/stream_postgres';

fasten.init({
    serviceId: 'auth-service', nodeId: 'host-01',
    apiStore:    new PostgresStreamStore(process.env.DATABASE_URL, { table: 'api_log' }),
    syslogStore: new PostgresStreamStore(process.env.DATABASE_URL, { table: 'syslog' }),
    persistStreams: ['api', 'sys'],   // or FASTEN_PERSIST_STREAMS=api,sys
    retentionApi: '7d', retentionSyslog: '30d',
});

app.use(apiLogger({ skip: ['/healthz'] }));   // Express; see below for node:http
```

- The tables are the Python and Go stream tables (`seq`, the lifted
  `request_id`, `timestamp`, `level`, `service_id`, `event`, `method`,
  `path`, `status` columns, and the whole row as JSON in `payload`), so any
  SDK reads what another wrote. `table` is required, so api rows cannot land
  in the syslog table. `SqliteStreamStore` from `fasten-sdk/store/stream_sqlite`
  is the same on `node:sqlite` (synchronous, WAL, file created 0600).
- `persistStreams` (or `FASTEN_PERSIST_STREAMS`) is optional. When set,
  `init()` throws unless it names exactly the streams with a store: a named
  stream without one, or a store not named, is an error.
- Rows are redacted before they are kept, stored or written. A row without
  a `request_id` gets a `boot-<service>-<id>` id until the first row with a
  real one, then an `orphan-` id. Rows reach the store in the order they
  were logged; `flush()` and `close()` wait for writes still running.
- A failed store write does not lose the stdout line. The store is marked
  degraded (`store-degraded` in every read from then on) and stderr gets
  `fasten: syslog persist failed: <ErrorType>`, without the row's values.
- `apiLogger()` records `method`, `path`, `status`, `duration_ms`,
  `request_id` and `timestamp`, writes the row to stdout with shape `api`,
  sets `X-Request-ID` (a usable incoming one, else a new id) and makes that
  id current for the request. With `node:http`:
  `apiLogger()(req, res, () => handler(req, res))`.
- `pushSyslog(row)` records a row from your own logger, and `pushApi(row)`
  an api row, without a stdout line. `writeApi(row)` writes one too.

With no stream store, reads come from the ring and say `ring`; search needs
a store.

## Serving the reader

`fasten-sdk/reader` serves the audit, api and sys rows over HTTP, with the
routes, parameters and responses of Python's `fasten.reader.router()` and
Go's `NewReader`. It returns raw audit data, so it has no default auth:

```js
import http from 'node:http';
import { reader, requireBearer } from 'fasten-sdk/reader';

const logs = reader({ auth: requireBearer() });   // FASTEN_READER_TOKEN
http.createServer((req, res) => logs(req, res)).listen(9000);

// Express: app.use('/api/v1/logs', logs);
// Fastify: fastify.get('/api/v1/logs/*', (req, reply) => logs(req.raw, reply.raw));
// Or strip a prefix yourself: reader({ auth, prefix: '/api/v1/logs' }).
```

`auth` is `{ bearer: token }`, `{ verify: (req) => boolean | Promise<boolean> }`,
or `"none"` when something in front of the reader authenticates every
request. Anything else throws when the reader is built. A missing or wrong
token gets `401 {"detail":"unauthenticated"}`; tokens are compared in
constant time.

| Route | Parameters |
|---|---|
| `GET /audit` | `request_id code domain source_node_id tenant_id actor target since until limit offset after` |
| `GET /audit/doctor` | none: store, queue, rings, init, and a chain check of this node's latest 50 rows |
| `GET /correlate` | `request_id` (required) `limit`: audit, api and sys rows with `counts`, `totals`, `truncated` |
| `GET /search` | `q since` (both required) `until limit streams` (`audit,api,sys`, default `sys`) |
| `GET /sys` | `level request_id service_id event since until limit`, or `q` with `since` |
| `GET /api` | `method path request_id status since until limit` |
| `GET /topology` | `since until`: rows per node, service and tenant |

- `limit` is 1 to 1000 (default 100; `/search` 1 to 200, default 50). A bad
  value is a 422 with `{"detail": "..."}`.
- `/audit` returns `total`, `limit`, `offset` and `next_after`, the lowest
  `monotonic_seq` on the page: pass it back as `after=` for the next page.
- `since` and `until` take RFC 3339 in any offset and are compared in the
  canonical form.
- Search is off unless `init({ searchEnabled: true })` or
  `FASTEN_SEARCH_ENABLED=true`. It needs `since`, matches case-insensitive
  substrings of the stored JSON (on SQLite, ASCII letters only), and a
  stream without a store gets an entry in `errors`. `q=` on `/sys` cannot be combined with filters (400), and
  `/api` refuses `q=` (400).
- Each response has `completeness` per stream: `store`, `store-degraded`
  or `ring`, as in the Python and Go readers.
- Rows are the snake_case rows the store's `query()` returns. A `BigInt`
  is written as its digits, a JSON number (no precision lost).
- The doctor verifies the chain from `chainTail()`, which reads the detail
  text as stored, so rows sealed by any SDK verify. It reports `verified`,
  `breaks`, `first_break_at`, `reason` and `chain_unavailable`.
- A store error is a 500 `{"detail":"internal error"}`; the service log
  gets `reader_query_failed` with the error type only.

`store` and `streams` read other stores than the engine's, for example a
reader process over tables other services write:

```js
reader({
    auth: { bearer: process.env.FASTEN_READER_TOKEN },
    store: new PostgresStore(dsn),
    streams: { api: new PostgresStreamStore(dsn, { table: 'api_log' }),
               sys: new PostgresStreamStore(dsn, { table: 'syslog' }) },
    nodeId: 'host-01',   // the node the doctor checks
});
```

On a shared multi-tenant store, pass `tenantScope: (req) => tenant` and
`enforceTenantIsolation: true`. Every route is then limited to the caller's
tenant and ignores `?tenant_id=`; a caller without a tenant gets a 401. sys
and api rows are matched on their `tenant_id` field, and rows without one
are left out. The doctor counts only the caller's rows, leaves out the host
`tenant_id`, and reports a chain break without the row it is on.

## Tests

```bash
docker run --rm -v $PWD/js:/work -w /work node:24 \
  sh -c "npm install --silent && npm test"
```

## Docs and design

Full reference: [https://fasten.sh/docs/](https://fasten.sh/docs/).
Design and cross-language design: [README.md](../README.md).
