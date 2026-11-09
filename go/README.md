# fasten for Go

Audit and correlation SDK for Go services. v1.0.0-beta.

## Install

The SDK calls `libfasten_core` (the Rust library in
[`fasten-core/`](../fasten-core)) through cgo. Its cgo flags point at
`../fasten-core` next to the `go/` directory, so a plain `go get` does not
build: the module download has no `fasten-core`. Use a clone of the repo
instead.

You need Go 1.26+, a C compiler, and rustup (it picks up Rust 1.90 from
[`rust-toolchain.toml`](../rust-toolchain.toml)). On Linux, also
`pkg-config` and the OpenSSL headers (`libssl-dev`).

Clone the repo and build the library:

```bash
git clone https://github.com/nerdapplabs/fasten.git
cd fasten/fasten-core
cargo build --release --locked --features all
```

In your own module, next to the clone, point the SDK at it with a
`replace` directive:

```bash
go mod edit -require=github.com/nerdapplabs/fasten/go@v0.0.0 \
            -replace=github.com/nerdapplabs/fasten/go=../fasten/go
go mod tidy
CGO_ENABLED=1 go build -o myapp .
```

The binary loads `libfasten_core` at run time, so tell the loader where it
is:

```bash
LD_LIBRARY_PATH=../fasten/fasten-core/target/release ./myapp
```

On macOS use `DYLD_LIBRARY_PATH` instead.

## Quickstart

Verified to run as-is on Go 1.26+:

```go
package main

import (
    "context"
    "database/sql"
    "time"

    fasten "github.com/nerdapplabs/fasten/go"
    _ "modernc.org/sqlite" // pure-Go SQLite driver
)

func main() {
    fasten.MustRegister("user", map[fasten.Code]fasten.Meta{
        "USER_CREATED": {
            Domain: "user", Category: "account", Action: "create",
            Severity: fasten.SevInfo, Description: "New user account",
            Emitter: "auth-service", RetentionClass: fasten.RetLong,
        },
    })
    db, _ := sql.Open("sqlite", "./fasten-audit.db")
    store, _ := fasten.NewSQLiteStore(db, "fasten_audit")

    if err := fasten.Init(fasten.Config{
        ServiceID:  "auth-service",
        NodeID:     "host-01",
        AuditStore: store,
    }); err != nil {
        panic(err)
    }
    defer fasten.Close(5 * time.Second) // drain pending audit rows on exit

    ctx := fasten.WithRequestID(context.Background(), fasten.MintID())
    fasten.Emit(ctx, "USER_CREATED",
        fasten.Target("u-42"),
        fasten.Actor("admin", "user"),
        fasten.WithDetail(map[string]any{"email": "alice@example.com"}),
    )
    fasten.LogInfo(ctx, "signup_complete", "user_id", "u-42")
}
```

The audit row and the sys log line go to stdout with the same `request_id`.
The audit row is also stored in `./fasten-audit.db`.

## Worked example: net/http service

A minimal HTTP service with `X-Request-ID` propagation and one audit row per
request: see [`examples/server.go`](examples/server.go).

```bash
cd go/examples
FASTEN_SERVICE_ID=demo FASTEN_NODE_ID=host-01 go run server.go
# in another shell
curl -X POST http://localhost:8080/users -d '{"email":"alice@example.com"}'
```

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
`fasten.Init(...)`) and `ring` when the SDK runs stdout-only. Stdout alone is
not a durable record, and `completeness` says so. `api` and `sys` are
ring-only unless you attach a `StreamStore` via `Config.APIStore` /
`Config.SyslogStore`. Persistence is write-through: one synchronous INSERT
per pushed row. With WAL and `synchronous=NORMAL` there is no fsync per
commit, but it is still a disk write per row. `OpenStreamStore` adds both
pragmas to the DSN; if you build the store with `NewStreamStore` on your own
`*sql.DB`, set them in your DSN so every pooled connection gets them.

## Audit-store failure handling

`fasten.Emit()` defaults to **queue mode**: rows go onto the bounded
fasten-core queue, drained by a background thread with exponential backoff
(100 ms to 60 s, plus or minus 20 % jitter) and dead-lettered after
`QueueDrainMaxAttempts`. A failed insert doesn't fail the request, but
when the queue is full `Emit()` blocks until a slot frees, so in a long
outage it waits on the drainer's retries; size `QueueCapacity` and the
retry settings for that. A row the store rejects outright (a Postgres
class 22/23 error, a SQLite constraint) is dead-lettered at once rather
than retried. `Emit()` returns the row before it is stored, so its
`MonotonicSeq` and `Hash` are zero; the store seals it. Set
`Config.AuditStoreFailureStrategy = "raise"` for synchronous writes that
return `*fasten.AuditStoreError` and the sealed row.
`fasten.GetQueueStats()`, `fasten.Flush(timeout)` and
`fasten.Close(timeout)` complete the public surface; call `Close` on
shutdown so a row still being retried is stored or reported. `Close`
returns within about `timeout`, reports rows not stored by then as
`audit_drain_lost_at_stop`, and returns false if any row was lost. A store
call still running then, such as a lib/pq query to a server that stopped
answering, is left to finish in the background.

## Verifying the chain

`fasten.VerifyChain` checks the hash chain over a set of rows and reports
the first break: an edited, inserted, deleted or reordered row
([spec §3](../spec/chain-replication.md#3-verification)). Chains sealed by
the Go and Python SDKs verify in either.

```go
rows, err := store.Query(ctx, fasten.Filter{Limit: 10000})
if err != nil {
	return err
}
if res := fasten.VerifyChain(rows); !res.OK {
	log.Printf("chain breaks at seq %d: %s", res.FirstBreakAt, res.Reason)
}
```

## Chain checkpoints

`VerifyChain` cannot tell on its own that rows were cut off the end of a
chain, or that the whole chain was re-sealed. Publish checkpoints (each
node's latest seq and hash) somewhere the store's operator cannot rewrite,
and verify against them later
([spec §9](../spec/chain-replication.md#9-checkpoints)):

```go
sink := fasten.FileCheckpointSink{Path: "/mnt/worm/checkpoints.jsonl"}
// fasten.HTTPCheckpointSink{URL: url} POSTs them instead.
if _, err := fasten.PublishCheckpoints(ctx, store, sink); err != nil {
    return err
}

cps, err := fasten.LoadCheckpoints("/mnt/worm/checkpoints.jsonl")
res := fasten.VerifyChainWithCheckpoints(allRows, cps, fasten.CheckpointOptions{})
```

By default the rows are taken as the whole chain: every checkpointed node
must have rows, and no checkpoint may be below its oldest row or above its
newest. To check a page or one node, set `CheckpointOptions{Partial: true}`;
checkpoints below or above its rows, or for nodes not in them, are then
skipped, so only a whole-chain verify detects a cut-off tail. If the file's
last line was cut short by a crash, `LoadCheckpoints` returns the earlier
checkpoints with `ErrPartialLastLine`, and the next publish drops it. Use
one publisher per file.

With retention, checkpoints taken before a purge are below the rows it
left, or belong to a node with no rows left, and they fail a whole-chain
verify. Pass only the checkpoints taken since the latest purge finished,
and publish again after each purge:

```go
kept, err := fasten.CheckpointsSince(cps, purgedAt)
res := fasten.VerifyChainWithCheckpoints(allRows, kept, fasten.CheckpointOptions{})
```

A whole-chain verify shows rows deleted from the start of a chain when one
of the given checkpoints falls among them. Rows deleted below every given
checkpoint look the same as a purge.

## Tests

The same steps CI runs (see
[`fasten-go.yml`](../.github/workflows/fasten-go.yml)), from the repo root:

```bash
(cd fasten-core && cargo build --release --locked --features all)
cd go
CGO_ENABLED=1 \
CGO_LDFLAGS=-L$PWD/../fasten-core/target/release \
LD_LIBRARY_PATH=$PWD/../fasten-core/target/release \
  go test -count=1 ./...
```

CI also sets `FASTEN_TEST_POSTGRES_DSN` and runs with `-tags=integration
-race` to include the Postgres tests. On macOS use `DYLD_LIBRARY_PATH`
instead of `LD_LIBRARY_PATH`.

## Docs and design

Full reference: [https://fasten.sh/docs/](https://fasten.sh/docs/).
Design and cross-language design: [README.md](../README.md).
