# fasten-core

The shared library behind the [fasten](https://github.com/nerdapplabs/fasten)
SDKs: the audit store (SQLite and PostgreSQL 15+), the background drainer,
redaction and the audit code catalog, behind a stable C ABI.

You normally don't use it directly. The fasten SDKs load it through the C ABI
(`libfasten_core.so` / `.dylib` / `.dll`, or the static `.a`), and the Rust
SDK, `fasten-sdk`, depends on it as a crate. Install an SDK instead; see
[fasten.sh/docs](https://fasten.sh/docs/).

## Features

| Feature        | Default | Adds                                   |
|----------------|---------|----------------------------------------|
| `sqlite`       | yes     | SQLite store, with SQLite bundled      |
| `postgres`     | yes     | PostgreSQL store (pure Rust, no libpq) |
| `postgres-tls` | yes     | TLS for the PostgreSQL store           |
| `all`          | no      | All of the above                       |

## Building the C library

```sh
cargo build --release --locked --features all
```

This writes `libfasten_core` to `target/release/`. The C header is
[`include/fasten_core.h`](include/fasten_core.h).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
