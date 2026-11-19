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
// "A store of your own" below); PostgresStore seals them.
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
keep the process alive.

**Chain.** `emit()` returns the row with `monotonic_seq: 0`.
`PostgresStore` seals it into its node's hash chain in the insert
transaction, under the same per-node lock as the Python, Go and Rust
stores: the node's next seq, `prev_hash` from the node's latest sealed row,
a detail salt and commitment, and the hash (canonical form "2",
[spec §1.4](../spec/chain-replication.md)). Python, Go, Rust and JS writers
can share a node in one table: `PostgresStore` writes into a table the Python
or Go store created, and adds the columns it lacks.

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
`PostgresStore` writes `detail` as the same canonical text, so what is
stored is what was hashed. A string `detail` given to
`PostgresStore.insert` is read as JSON text and must be an object.

**Reading rows.** `PostgresStore.query()` and `listUnshipped()` return rows
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
`listRedactionCandidates` and `redactRows`, as `PostgresStore` does.

**Differs from the other SDKs:** Node is single-threaded, so `emit()` cannot
block on a counting semaphore the way Python, Go, Rust and C++ do.
`queueCapacity` is a warning threshold (it drives the
`audit_queue_high_water` / `audit_queue_near_full` sys events), not a hard
cap.

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

## Tests

```bash
docker run --rm -v $PWD/js:/work -w /work node:24 \
  sh -c "npm install --silent && npm test"
```

## Docs and design

Full reference: [https://fasten.sh/docs/](https://fasten.sh/docs/).
Design and cross-language design: [README.md](../README.md).
