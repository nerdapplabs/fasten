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
chain still verifies. Audit rows are never deleted.

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
verify. The Rust SDK redacts and never deletes rows, so this applies when
another SDK or an operator purges the table. Pass only the checkpoints taken
since the latest purge finished, and publish again after each purge:

```rust
let kept = fasten::checkpoints_since(&checkpoints, purged_at)?;
let result = verify_chain_with_checkpoints(&all_rows, &kept, CheckpointOptions::whole());
```

A whole-chain verify shows rows deleted from the start of a chain when one
of the given checkpoints falls among them. Rows deleted below every given
checkpoint look the same as a purge.

## Tests

From the repo root (the crate needs `../fasten-core`):

```bash
docker run --rm -v $PWD:/work -w /work/rust rust:1.90 \
  cargo test -- --test-threads=1
```

`--test-threads=1` because the integration tests share the global config
and drainer. Add `--features store-sqlite` to run the SQLite store's tests,
and `--features store-postgres` with `FASTEN_TEST_POSTGRES_DSN` set for the
Postgres store's.

## Docs and design

Full reference: [https://fasten.sh/docs/](https://fasten.sh/docs/).
Design and cross-language design: [README.md](../README.md).
