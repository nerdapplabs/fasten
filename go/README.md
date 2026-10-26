# fasten for Go

Audit and correlation SDK for Go services. v1.0.0-beta.

## Install

```bash
go get github.com/nerdapplabs/fasten/go
```

The SDK calls `libfasten_core` (the Rust library in
[`fasten-core/`](../fasten-core)) through cgo, so it needs `CGO_ENABLED=1`
and the library built first:

Clone the repo, then:

```bash
cd fasten-core && cargo build --release --features all
export CGO_CFLAGS=-I$PWD/include
export CGO_LDFLAGS=-L$PWD/target/release
export LD_LIBRARY_PATH=$PWD/target/release   # Linux, at run time
```

## Quickstart

Verified to run as-is on Go 1.22+:

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
    defer fasten.Flush(5 * time.Second) // drain pending audit rows on exit

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

`fasten.Emit()` defaults to **queue mode**: rows go onto a bounded channel,
drained by a goroutine with exponential backoff (100 ms to 60 s, plus or
minus 20 % jitter). Store failures stay off the request path. Set
`Config.AuditStoreFailureStrategy = "raise"` for synchronous writes that
return `*fasten.AuditStoreError`. `fasten.GetQueueStats()` and
`fasten.Flush(timeout)` complete the public surface.

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
-race` to include the Postgres tests.

## Docs and design

Full reference: [https://fasten.sh/docs/](https://fasten.sh/docs/).
Design and cross-language design: [README.md](../README.md).
