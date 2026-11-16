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

Optional features: `async`, `store-postgres`, `codes-yaml`.

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

## Audit-store failure handling

`EmitBuilder::submit()` defaults to **queue mode**: rows go onto a bounded
queue, drained by a `std::thread` with exponential backoff (100 ms to 60 s,
plus or minus 20 % jitter). Store failures stay off the request path. Set
`Config::audit_store_failure_strategy = Some("raise".into())` for
synchronous writes that return `AuditStoreError`. `fasten::queue_stats()`
and `fasten::flush(timeout)` complete the public surface.

## Chain and retention

The Rust SDK does not seal rows. `submit()` returns the row with
`monotonic_seq: 0`, and `PostgresStore` gives it the node's next seq in the
insert transaction, under the same per-node lock as the Python, Go and JS
stores; `hash` and `prev_hash` stay empty. `PostgresStore` can write into a
table the Python or Go store created.

Set `Config::retention_pii` (or `FASTEN_RETENTION_PII`) to a duration such as
`"30d"` to redact personal data: every hour, rows older than that whose code
has `pii_in_detail` or retention class Short get `detail` set to `null`, after
an `AUDIT_ROW_REDACTED` row records it. Audit rows are never deleted.

## Tests

From the repo root (the crate needs `../fasten-core`):

```bash
docker run --rm -v $PWD:/work -w /work/rust rust:1.90 \
  cargo test -- --test-threads=1
```

`--test-threads=1` because the integration tests share the global config
and drainer.

## Docs and design

Full reference: [https://fasten.sh/docs/](https://fasten.sh/docs/).
Design and cross-language design: [README.md](../README.md).
