# fasten — Rust

Audit + correlation SDK for Rust services. v1.0.0-beta.

## Install

From source today (crates.io publish lands with the v1.0 GA tag):

```toml
[dependencies]
fasten = { path = "../fasten/rust" }     # local clone
# or, when published:
fasten = "1.0.0-beta"
```

Optional features: `async`, `store-sqlite`, `store-postgres`,
`shim-tracing`, `codes-yaml`.

## Quickstart

Verified to compile + run on Rust 1.85+:

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

## Worked example — tiny_http service

A minimal HTTP service with `X-Request-ID` propagation, an audit row
per request: see [`examples/server.rs`](examples/server.rs). Sync-only
(no tokio); uses the single `tiny_http` dev-dependency.

```bash
cd rust
FASTEN_SERVICE_ID=demo FASTEN_NODE_ID=host-01 cargo run --example server
# in another shell
curl -X POST http://localhost:8080/users -d '{"email":"alice@example.com"}'
curl http://localhost:8080/users/u-42
```

## P1-15: audit-store failure handling

`EmitBuilder::submit()` defaults to **queue mode** — rows are pushed
onto a bounded queue, drained by an `std::thread` with exponential
backoff (100 ms → 60 s, ±20 % jitter). Store failures stay off the
request path. Set `Config::audit_store_failure_strategy =
Some("raise".into())` to opt into synchronous semantics with
`AuditStoreError`. `fasten::queue_stats()` and `fasten::flush(timeout)`
complete the public surface.

The legacy `EmitBuilder::emit(store)` (taking the store per-call)
remains for back-compat.

## Tests

```bash
docker run --rm -v $PWD/rust:/work -w /work rust:1.85-alpine \
  cargo test -- --test-threads=1
```

Current: 18 passed. `--test-threads=1` because integration tests
share global config + drainer.

## Docs + design

Full reference: [https://fasten.sh/docs/](https://fasten.sh/docs/) ·
Design + cross-language design: [README.md](../README.md).
