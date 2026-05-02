# fasten — Go

Audit + correlation SDK for Go services. v1.0.0-beta.

## Install

```bash
go get github.com/nerdapplabs/fasten-go
```

## Quickstart

Verified to run as-is on Go 1.22+:

```go
package main

import (
    "context"
    "database/sql"
    "time"

    fasten "github.com/nerdapplabs/fasten-go"
    _ "modernc.org/sqlite" // pure-Go SQLite driver; CGO_ENABLED=0 friendly
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

The audit row + sys log share the same `request_id` on stdout. The
audit row is also persisted to `./fasten-audit.db`.

## Worked example — net/http service

A minimal HTTP service with `X-Request-ID` propagation, an audit row
per request: see [`examples/server.go`](examples/server.go).

```bash
cd go/examples
FASTEN_SERVICE_ID=demo FASTEN_NODE_ID=host-01 go run server.go
# in another shell
curl -X POST http://localhost:8080/users -d '{"email":"alice@example.com"}'
```

## P1-15: audit-store failure handling

`fasten.Emit()` defaults to **queue mode** — rows go onto a bounded
channel, drained by a goroutine with exponential backoff (100 ms →
60 s, ±20 % jitter). Store failures stay off the request path. Set
`Config.AuditStoreFailureStrategy = "raise"` to opt into synchronous
semantics with `*fasten.AuditStoreError`. `fasten.GetQueueStats()` and
`fasten.Flush(timeout)` complete the public surface.

## Tests

```bash
docker run --rm -v $PWD/go:/work -w /work -e CGO_ENABLED=0 \
  golang:1.22-alpine go test -count=1 ./...
```

## Docs + design

Full reference: [https://fasten.sh/docs/](https://fasten.sh/docs/) ·
Design + cross-language design: [README.md](../README.md).
