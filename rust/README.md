# fasten for Rust

Audit and correlation SDK for Rust services. v1.0.0-beta.

## Install

Install from source for now; the crate will be published to crates.io with
the v1.0 GA tag.

```toml
[dependencies]
fasten-sdk = { path = "../fasten/rust" }     # local clone
# or, once published:
fasten-sdk = "1.0.0-beta"
```

The crate depends on [`fasten-core`](../fasten-core) by path, so build from
a full clone of the repo. `fasten-core` sets `rust-version = "1.90"`, which
is the minimum toolchain (see [`rust-toolchain.toml`](../rust-toolchain.toml)).

The crate is named `fasten-sdk`; code imports it as `fasten`
(`use fasten::...`).

Optional features: `async`, `store-postgres`, `store-sqlite`, `codes-yaml`.
`store-postgres` connects through native-tls, which on Linux needs
`pkg-config` and the OpenSSL headers (`libssl-dev` or `openssl-devel`).
`store-sqlite` compiles SQLite in, which needs a C compiler.

## Quickstart

Verified to compile and run on Rust 1.90+:

```rust
use fasten::{init, register, Config, EmitBuilder, Meta, Severity, RetentionClass};
use std::sync::Arc;

fn main() -> Result<(), fasten::Error> {
    register("user".into(), [(
        "USER_CREATED".to_string(),
        Meta {
            id: "USER_CREATED".into(),
            domain: "user".into(),
            category: "account".into(),
            action: "create".into(),
            severity: Severity::Info,
            description: "New user account".into(),
            emitter: "auth-service".into(),
            retention_class: RetentionClass::Long,
            high_volume: false,
            pii_in_detail: false,
            declared_unused: false,
            detail_passthrough_keys: vec![],
        },
    )])?;

    init(Config {
        service_id: "auth-service".into(),
        node_id:    "host-01".into(),
        // audit_store: Some(Arc::new(MyStore { ... })),  // any AuditStore impl
        ..Default::default()
    })?;

    EmitBuilder::new("USER_CREATED", "u-42")
        .actor("admin", "user")
        .submit()?;

    fasten::flush(std::time::Duration::from_secs(5));
    Ok(())
}
```

## Worked example: tiny_http service

A minimal HTTP service with `X-Request-ID` propagation and one audit row per
request: see [`examples/server.rs`](examples/server.rs). It is sync-only (no
tokio) and uses the single `tiny_http` dev-dependency.

```bash
cd rust
FASTEN_SERVICE_ID=demo FASTEN_NODE_ID=host-01 cargo run --example server
# in another shell
curl -X POST http://localhost:8080/users -d '{"email":"alice@example.com"}'
curl http://localhost:8080/users/u-42
```

## request_id in async code

`with_request_id(rid, || ...)` sets the id for one closure on the current
thread. In tokio code, where a task can move between threads at an
`.await`, enable the `async` feature and use:

- `fasten::scope_request_id(rid, fut)` to run a future with that id across
  every `.await`;
- `fasten::spawn(fut)` in place of `tokio::spawn`, to carry the current id
  into the new task (or mint one if there is none).

```rust
fasten::spawn(async move {
    process_refund().await;
    EmitBuilder::new("REFUND_ISSUED", "order-1042").submit()?;
    send_receipt().await;
    EmitBuilder::new("RECEIPT_SENT", "order-1042").submit()?;
    Ok::<_, fasten::AuditStoreError>(())
});
```

A plain `tokio::spawn`, `spawn_blocking` or `std::thread::spawn` does not
reliably copy the id; read it with `current_request_id()` and set it again
there.

## Audit-store failure handling

`EmitBuilder::submit()` defaults to **queue mode**: rows go onto a bounded
queue, drained by a `std::thread` with exponential backoff (100 ms to 60 s,
plus or minus 20 % jitter). Store failures stay off the request path. Set
`Config::audit_store_failure_strategy = Some("raise".into())` for
synchronous writes that return `AuditStoreError`. `fasten::queue_stats()`
and `fasten::flush(timeout)` complete the public surface.

## Chain and retention

The bundled stores, `PostgresStore` (feature `store-postgres`) and
`SqliteStore` (feature `store-sqlite`), seal each audit row into the node's
hash chain. `submit()` builds the row with `monotonic_seq: 0` and no hash; in
the insert transaction the store gives it the node's next seq, reads the hash
of the node's last sealed row and stores the row sealed (`prev_hash`, `hash`,
`canonical_form_id: "2"`, `detail_salt`, `detail_commitment`).
`PostgresStore` takes the same per-node lock as the Python, Go and JS stores,
and it can write into a table the Python or Go store created, so Rust, Python
and Go services on one node share one chain.

A row that reaches a store with a `monotonic_seq` of its own is stored as
given: unsealed, unless it already carries a hash. An unsealed row at or
above a node's sealed rows makes `verify_chain` fail for that node, so do
not write rows with their own seqs on a node id the store seals for. To copy
in rows another node sealed, use the stores' `insert_sealed(&chain_row,
pii_in_detail)`, which writes the detail text exactly as it was hashed.

```rust
let store = fasten::SqliteStore::open("audit.db", "audit_logs")?;
// or fasten::PostgresStore::new("host=localhost user=myapp dbname=audit", "audit_logs")?
```

A sealed row is written to stdout twice with the same `id`:

- The first line is written when `submit()` is called, before the row goes
  to the store. It is unsealed: `monotonic_seq` 0 and an empty `hash`.
- The second line is written once the store has stored the row, and is the
  row as stored: its seq, `prev_hash` and `hash`. In `raise` mode that is
  before `submit()` returns, and `submit()` returns the sealed row. In
  `queue` mode it is when the drainer stores the row, after `submit()` has
  returned the row as built; `fasten::flush(timeout)` waits for it.

There is no second line for a row the store never took (in `raise` mode
`submit()` returned the error; in `queue` mode the row was dead-lettered and
`audit_drain_dead_letter` names it), for a row with a seq of its own, or
with a store that does not seal. A retry of a row whose first insert did
land writes the sealed line again, the same line. If stdout cannot be
written the row is still stored and `audit_stdout_failed` on stderr names
it.

So a capture of stdout holds up to two lines per `id`, and one of them
never verifies on its own. Build a `ChainRow` from every line with
`ChainRow::from_json` and pass them all to `verify_chain`: it takes the
sealed copy of each row and skips the unsealed one.

To check a node's chain, read its rows and verify them:

```rust
let rows = store.chain_rows("node-1")?;
let result = fasten::verify_chain(&rows);
assert!(result.ok, "node {:?} broken at seq {:?}: {:?}",
        result.first_break_node, result.first_break_at, result.reason);
// `ok` alone is also true for no rows, and for rows that were never sealed.
println!("{} of {} rows are sealed and verify", result.sealed_rows, result.total_rows);
```

`chain_rows` and `all_chain_rows` read every matching row into memory in one
query, ordered by node id and then seq, with no paging, and hold the store's
connection until they return, so inserts through that store wait meanwhile.
For a large table verify one node at a time, from a second store handle.

Verification shows a row that was edited, removed or reordered inside the
chain. It runs only when you call it, and on its own it does not show rows
cut from the start or end of a chain, or a chain that was sealed again from
its first row: that takes checkpoints (next section).

A custom `AuditStore` seals rows only if it implements
`allocate_and_insert_originated` and returns `true` from `seals()`; override
both or neither. Inside its insert transaction it takes a per-node lock,
reads the node's highest seq and the hash of its last sealed row
(`fasten::GENESIS` when there is none) and stores what
`fasten::seal_row(prev_hash, &row, seq)` returns. Its own failures go back
as `fasten::Error::custom(e)`. Without a sealing store, or with no store at
all, rows are unsealed and `init` logs `audit_chain_unavailable`. Rows
written before sealing stay unsealed below the node's first sealed row and
are not covered by the chain.

Set `Config::retention_pii` (or `FASTEN_RETENTION_PII`) to a duration such as
`"30d"` to redact personal data: every hour, rows older than that whose code
has `pii_in_detail` or retention class Short get `detail` set to `null`, after
an `AUDIT_ROW_REDACTED` row records it. A redacted row keeps its hash, so the
chain still verifies. The engine never deletes audit rows; an operator can
(see [Purging audit rows](#purging-audit-rows)).

## Chain checkpoints

`verify_chain` cannot tell on its own that rows were cut off the end of a
chain, or that the whole chain was re-sealed. Publish checkpoints (each
node's latest seq and hash) somewhere the store's operator cannot rewrite,
and verify against them later
([spec §9](../spec/chain-replication.md#9-checkpoints)):

```rust
use fasten::{load_checkpoints, publish_checkpoints, verify_chain_with_checkpoints};
use fasten::{CheckpointOptions, FileCheckpointSink};

publish_checkpoints(&store, &FileCheckpointSink::new("/var/lib/fasten/checkpoints.jsonl"))?;

let checkpoints = load_checkpoints("/var/lib/fasten/checkpoints.jsonl")?;
let all_rows = store.all_chain_rows()?;
let result = verify_chain_with_checkpoints(&all_rows, &checkpoints, CheckpointOptions::whole());
```

`FileCheckpointSink` reads the file's last line and truncates it when it is
cut short, so it needs read and write access to the file. It cannot write to
a path that only accepts appends or forbids rewrites, such as a WORM mount:
for one of those implement `CheckpointSink` over the API it offers. A local
file is only as safe as the access to it, so keep it on a host the store's
operator cannot write to, or copy it there after each publish.

`store` is a `PostgresStore` or a `SqliteStore`. A store of your own
implements `CheckpointStore`: `chain_tips` returns, for each node with a
sealed row, the node id, seq and hash of its sealed row with the highest seq
(a `ChainTip`), read in one query or snapshot. The file has the format the
Python and Go SDKs write and read. There is no HTTP sink in the Rust SDK: to
publish elsewhere, implement `CheckpointSink`. `Checkpoint` works with
serde, which reads and writes the same four keys but not the bytes of a file
line; `Checkpoint::to_json` and `Checkpoint::from_json` are the file format.

By default the rows are taken as the whole chain: every checkpointed node
must have rows, and no checkpoint may be below its oldest row or above its
newest. To check a page or one node, pass `CheckpointOptions::partial()`;
checkpoints below or above its rows, or for nodes not in them, are then
skipped, so only a whole-chain verify detects a cut-off tail. If the file's
last line was cut short by a crash, `load_checkpoints` returns
`CheckpointFileError::PartialLastLine`, which carries the checkpoints read
before that line for a caller that accepts the file without it, and the next
publish drops the line with a `checkpoint_unfinished_line_dropped` warning
on stderr. Use one publisher per file.

With retention, checkpoints taken before a purge are below the rows it
left, or belong to a node with no rows left, and they fail a whole-chain
verify. The engine never deletes rows, so this applies after a manual
`purge` or a purge by another SDK. Pass only the checkpoints taken since the
latest purge finished, and publish again after each purge:

```rust
let kept = fasten::checkpoints_since(&checkpoints, purged_at)?;
let result = verify_chain_with_checkpoints(&all_rows, &kept, CheckpointOptions::whole());
```

A whole-chain verify shows rows deleted from the start of a chain when one
of the given checkpoints falls among them. Rows deleted below every given
checkpoint look the same as a purge.

## Replication

A node ships its sealed rows to another store, an aggregator, which
verifies them and stores them as they were sealed
([spec §4, §5](../spec/chain-replication.md#4-replication-ingest--ingestresult)). The rows go as
JSON lines in the wire format, which the Python, Go and JS SDKs read and
write too.

On the node, list the rows this engine originated (its service and node id;
rows it ingested from elsewhere are not shipped again), send them, then mark
them shipped:

```rust
let rows = fasten::list_unshipped(500)?;        // 0 for all
let body: String = rows.iter().map(|r| r.to_json() + "\n").collect();
send_to_aggregator(&body)?;                      // your transport
let ids: Vec<String> = rows.iter().map(|r| r.row.id.clone()).collect();
fasten::mark_shipped(&ids)?;
```

On the aggregator, read the lines and ingest them:

```rust
let rows: Vec<fasten::ReplicatedRow> = body
    .lines()
    .map(fasten::ReplicatedRow::from_json)
    .collect::<Result<_, _>>()?;
let result = fasten::ingest_replicated(&rows)?;  // or store.ingest_replicated(&rows, None)
if let Some(seq) = result.rejected_from_seq {
    // Resend from `seq`; `result.reason` says why the batch stopped there.
}
```

`ingest_replicated` verifies the batch per node and checks it against the
rows the store holds. It stores the verified prefix in one transaction, each
row with its detail text exactly as it was hashed, and stops at the first
break, which it reports in `IngestResult { inserted, rejected_from_seq,
reason }` rather than as an error:

- a row whose hash, commitment or link to the row before it does not verify;
- a different row under a stored id, or at a stored node and seq;
- a row that does not link to the stored row before it, or that the stored
  row after it does not link to;
- an id that appears twice in the batch;
- through the engine, a row from the engine's own node, whose rows come from
  its emit path only.

A row delivered again is skipped and counted in `inserted`, so a batch can
be resent safely. A batch with a timestamp the Python and Go stores could
not read back (not RFC 3339, year 0, a UTC year outside 1 to 9999) is
refused whole with `Error::AuditStoreRejected`. Any error means nothing of
the batch was stored. On Postgres the batch's node locks are taken in sorted
order, the lock every SDK's insert takes, so ingest and local writes on one
table do not interleave on a node.

`ReplicatedRow` carries the row as a `ChainRow`, whose detail keeps each
number as it was written, and its `pii_in_detail` flag. To store one row
already verified, without the checks, use the store's
`insert_replicated(&row)`. The stores'
`list_unshipped(limit, Some((service_id, node_id)))` returns the same rows
as `Row`s, whose detail `serde_json` holds, so ship `list_unshipped_sealed`.

## Purging audit rows

The engine never deletes audit rows (spec §7). An operator purges them with
the store ([spec §2.3](../spec/chain-replication.md#23-purge-normative)):

```rust
use fasten::AuditStore;
let deleted = store.purge(cutoff, true)?;   // cutoff: DateTime<Utc>
```

It deletes rows older than `cutoff`, per node only a run from the start of
the chain, so the rows left still verify. With `respect_unshipped` set,
unshipped rows and the rows after them are kept. Publish checkpoints again
after a purge, and verify with `checkpoints_since` (see above).

## Lost Postgres connections

`PostgresStore` keeps one connection. When it is lost (a server restart, a
failover, `pg_terminate_backend`), the next call connects again. A call cut
short by the loss runs once more on the new connection if running it again
is safe: a read, a statement that sets or removes the same rows again, or a
whole transaction, which the lost connection rolled back. A COMMIT cut short
is never run again: an insert reads its row back once and returns it as
stored, or returns a retryable error, and the drainer retries; the insert
looks up the row's id first, so it is never stored twice. A statement
timeout (SQLSTATE 57014) is not a lost connection and is returned as it is.
While the server stays down calls fail, and the queue holds the rows.

## Stores from the environment

With no `Config::audit_store`, `init` opens the audit store from
`FASTEN_AUDIT_DSN`, in the Python SDK's forms:

| DSN | Store |
|---|---|
| `postgres://...` or `postgresql://...` (any case) | `PostgresStore` (feature `store-postgres`) |
| `sqlite:///relative.db` | `SqliteStore` on `relative.db` (feature `store-sqlite`) |
| `sqlite:////absolute/path.db` | `SqliteStore` on `/absolute/path.db` |
| `/path/audit.db` or `audit.db` | `SqliteStore` on that path |

`?table=name` names the table (default `audit_log`) and `?wal=false` turns
off SQLite's WAL journal. Another scheme, libpq's keyword form
(`host=db dbname=app`), or a scheme whose store feature is not built is an
error from `init` that names the scheme and never the DSN; no file is
created. A store in the config wins. `init` again with the same DSN keeps
the store it opened; with another DSN it opens that one, and the old store
closes once the drainer has finished with it. A set `FASTEN_*` variable that
looks like a DSN but is not one `init` reads (say `FASTEN_AUDIT_DNS`) is
reported once on stderr as `env_dsn_not_read`, without its value.
`fasten::parse_dsn` and `fasten::audit_store_from_dsn` parse and open a DSN
directly.

`FASTEN_API_DSN` and `FASTEN_SYSLOG_DSN` open the stream stores (see below)
in the same forms and by the same rules, with the default tables `api_log`
and `syslog`.

## Stored sys and api logs

Every `fasten::log` line (shape `sys`) and every `fasten::log::api` row
(shape `api`) is written to stdout and kept in a 2,000-row ring per stream.
Attach a stream store and each row is also written to a table that the
Python, Go and JS stream stores share (spec/persistent-streams.md), so any
SDK can read what another wrote:

```rust
use std::sync::Arc;
use fasten::{Config, PostgresStreamStore, SqliteStreamStore};

let dsn = "host=localhost user=app dbname=logs sslmode=verify-full";
fasten::init(Config {
    service_id: "orders".into(),
    node_id: "host-01".into(),
    api_store: Some(Arc::new(PostgresStreamStore::new(dsn, "api_log")?)),
    syslog_store: Some(Arc::new(SqliteStreamStore::open("streams.db", "syslog")?)),
    persist_streams: Some(vec!["api".into(), "sys".into()]),
    retention_api: Some("7d".into()),
    retention_syslog: Some("30d".into()),
    ..Default::default()
})?;
fasten::log::api(serde_json::json!({ "method": "GET", "path": "/orders", "status": 200 }));
```

- Without a store in `Config`, `FASTEN_API_DSN` and `FASTEN_SYSLOG_DSN` are
  used, in the forms of `FASTEN_AUDIT_DSN` (see above), with the default
  tables `api_log` and `syslog`.
- `persist_streams` (or `FASTEN_PERSIST_STREAMS=api,sys`) makes `init` fail
  unless it names exactly the streams that have a store, with Python's
  error texts.
- `retention_api` / `retention_syslog` (or `FASTEN_RETENTION_API` /
  `FASTEN_RETENTION_SYSLOG`) delete older stream rows hourly. Audit rows are
  never deleted for age.
- Rows are redacted before they are kept, stored or printed, and a row
  without a `request_id` gets a sentinel one (`boot-...` until the first
  real request id, then `orphan-...`).
- Writes run on one thread per stream, in order; at most 10,000 rows wait.
  A failed or dropped write keeps the stdout line, marks the stream
  `store-degraded` for good, and is reported on stderr by error type only,
  once at the start of an outage and then at most once a minute. A stream
  INSERT is never run again after a lost connection.
- `fasten::flush(timeout)` waits for queued audit rows and stream writes;
  `fasten::close(timeout)` flushes and then stops the drainer, purgers and
  stream writers.

## HTTP reader

`fasten::reader` serves `/audit`, `/audit/doctor`, `/correlate`, `/search`,
`/sys`, `/api` and `/topology` with the parameters, response shapes and
error texts of Python's reader. It takes a plain request and returns a
status, headers and a JSON body, so it fits any server; it adds no
dependency. It must be built with an auth choice:

```rust
use fasten::reader::{require_bearer, Reader, Request};

let reader = Reader::builder()
    .auth(require_bearer("FASTEN_READER_TOKEN")?) // or Auth::verify(fn), or Auth::None
    .tenant_scope(|req| req.header("x-tenant").map(str::to_string)) // optional
    .prefix("/api/v1/logs")
    .build()?;

let res = reader.handle(&Request::new("GET", "/api/v1/logs/audit?limit=10")
    .with_header("Authorization", "Bearer s3cret"));
// res.status, res.headers, res.body (JSON text)
```

- Routes are matched on the path as sent; a path with an empty, `.` or `..`
  segment, a backslash, or `%2e`, `%2f` or `%5c` is not served.
  `try_handle` returns `None` for a path the reader does not serve.
- Order: 405 for anything but GET, then 401 for auth, 401 for an unresolved
  tenant, then 422 for bad parameters.
- With a tenant scope every row returned is the caller's, audit rows
  included, and a scoped doctor reports only the caller's row count and
  chain verdict.
- `/audit/doctor` verifies the newest 50 rows of the node's chain, read
  exactly as stored; `verified` is `null` when no sealed row was checked.
- Audit reads go through `AuditStore::query`, `count`, `search`, `sources`
  and `chain_tail`, which `SqliteStore` and `PostgresStore` implement. A
  custom store without them gets `Unsupported`, which the reader reports.
- Free-text search (`/search`, `/sys?q=`) needs `search_enabled` (or
  `FASTEN_SEARCH_ENABLED=true`) and a `since`.

`examples/reader.rs` runs the reader behind tiny_http.

## Tests

From the repo root (the crate needs `../fasten-core`):

```bash
docker run --rm -v $PWD:/work -w /work/rust rust:1.90 \
  cargo test -- --test-threads=1
```

`--test-threads=1` because the integration tests share the global config
and drainer. Add `--features store-sqlite` to run the SQLite store's tests
and the reader and stream tests, and `--features store-postgres` with
`FASTEN_TEST_POSTGRES_DSN` set to run them on Postgres too, including the
replication and lost-connection tests (`FASTEN_REQUIRE_POSTGRES=1` makes a
missing DSN a failure). The lost-connection tests end the store's
connections with `pg_terminate_backend`, so the test role must be allowed
to (a superuser, or a member of the role that owns them).

## Docs and design

Full reference: [https://fasten.sh/docs/](https://fasten.sh/docs/).
Design and cross-language design: [README.md](../README.md).
