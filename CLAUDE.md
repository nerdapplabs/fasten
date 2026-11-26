# CLAUDE.md

## Repository shape

fasten is an audit + correlation SDK distributed across 6 production SDKs in one monorepo. Each language lives at the top level (`python/`, `go/`, `js/`, `rust/`, `cpp/`, `swift/`, `java/` placeholder). They all share a single Rust core (`fasten-core/`) compiled to a C-ABI dynamic library that every SDK loads via FFI for redaction, catalog registration, and store backends.

**`fasten-core` must be built before running tests for Python/JS/Go/C++/Swift** — the rust/ SDK is the only one that doesn't FFI into it.

```bash
cd fasten-core && cargo build --release --features all
# produces target/release/libfasten_core.so (Linux), .dylib (macOS), .dll (Windows)
```

Per-SDK env vars for the .so:
- Python: `FASTEN_CORE_LIB=$PWD/fasten-core/target/release/libfasten_core.so` + `LD_LIBRARY_PATH=$PWD/fasten-core/target/release`
- Go: `CGO_LDFLAGS=-L$PWD/fasten-core/target/release` + `LD_LIBRARY_PATH=...`
- JS / C++ / Swift: `LD_LIBRARY_PATH=$PWD/fasten-core/target/release` (plus `-Xlinker -L$FASTEN_LIB` for swift)

## Single source of truth: `spec/`

- `spec/row-schema.json` — canonical wire schema. Every SDK's row shape, severity enum, retention class enum, redact patterns derive from this.
- `spec/codegen.py --check` — CI gate. Fails if any SDK's generated constants drift from the spec. Use `--write` to regenerate.
- `spec/drainer-conformance.md` — normative spec for the bounded-queue / exponential-backoff drainer. **All five queue-mode drainers (Python/Go/JS/Rust/C++) MUST conform.** When changing drainer behavior, update the spec first and then sync every SDK.

When you touch any of: wire fields, enum values, redact patterns, drainer state machine, or catalog validation rules — the change is cross-SDK by construction. Single-SDK fixes here are bugs.

## Commands

### Python (min 3.10)

```bash
cd python
uv venv && uv pip install -e ".[dev,fastapi,postgres,mqtt,tui,structlog]"
ruff check fasten/
mypy fasten/
LD_LIBRARY_PATH=$PWD/../fasten-core/target/release pytest tests/ -v
```

### Go (min 1.22; CGO required)

```bash
cd go
CGO_ENABLED=1 CGO_LDFLAGS="-L$PWD/../fasten-core/target/release" \
LD_LIBRARY_PATH=$PWD/../fasten-core/target/release \
  go test -count=1 ./...
```

### JS / Node (min 24; loads .so via koffi)

```bash
cd js
npm install
npx biome check src/
LD_LIBRARY_PATH=$PWD/../fasten-core/target/release npm test
```

### Rust (min 1.85; depends on fasten-core as a crate, no FFI)

```bash
cd rust
cargo clippy -- -D warnings
cargo test -- --test-threads=1   # tests share global drainer state
```

### C++ (C++14; single-header `cpp/include/fasten.hpp`)

```bash
cd cpp
cmake -S . -B build -DFASTEN_BUILD_TESTS=ON \
  -DFASTEN_CORE_LIB_DIR=$PWD/../fasten-core/target/release
cmake --build build --parallel
LD_LIBRARY_PATH=$PWD/../fasten-core/target/release ctest --test-dir build --output-on-failure
```

### Swift (5.10)

```bash
cd swift
FASTEN_LIB=$PWD/../fasten-core/target/release
swift build -Xlinker -L$FASTEN_LIB
LD_LIBRARY_PATH=$FASTEN_LIB swift test -Xlinker -L$FASTEN_LIB
```

### Cross-language integration smokes (Docker)

```bash
cd tests/integration
make test          # all five SDKs
make test-python   # one language
```

Each smoke runs the SDK in its pinned base image, emits to stdout, and pipes through `verify.py` which asserts against `spec/row-schema.json`.

### Postgres fleet-scale scenarios

```bash
cd tests/postgres
docker compose up -d --wait
python run_all.py
# compares against baseline.json; non-zero exit if p99 regressed >2x
```

## Architecture invariants

### Queue mode is the default

`emit()` is async by default. Rows go onto a bounded in-memory queue, drained by one background thread per process with exponential backoff (100 ms → 60 s, ±20% jitter). A locked/down store will **not** cascade into 5xx on the request path. The drainer emits sys-stream events (`audit_drain_failed`, `audit_drain_degraded`, `audit_drain_recovered`, `audit_queue_high_water`, `audit_queue_near_full`).

Opt into synchronous behavior via `audit_store_failure_strategy="raise"` (Python/Go/JS/Rust/C++) or `strategy: .raise` (Swift). In raise mode, `emit()` throws a fasten-namespaced `AuditStoreError` on insert failure.

When changing drainer behavior, sync `spec/drainer-conformance.md` and every SDK's test vectors before merging.

### fasten-core (Rust, C-ABI)

- `fasten-core/src/redact.rs` — key-pattern + value-shape redaction (JWT, AWS key, PEM, GH/Stripe/OpenAI tokens, Luhn-valid CC).
- `fasten-core/src/catalog.rs` — code registration + validation.
- `fasten-core/src/store/{sqlite,postgres}.rs` — sync `AuditStore` trait implementations. Postgres uses pure-Rust `postgres` 0.19 (sync, no libpq) so it can be called from non-async hosts without `block_on` panics.
- `fasten-core/include/fasten_core.h` — C ABI header all SDKs include.
- `fasten-core/bindings/{python,go,node,swift,java}/` — thin language-side wrappers with co-located tests.

Built with `crate-type = ["cdylib", "staticlib", "rlib"]`. Canonical build: `cargo build --release --features all`.

### Wire-version forward-compatibility

Every audit row carries `"wire_version": "1"`. **Readers must accept any value higher than what they know about and process the row on best-effort basis.** A reader that hard-rejects unknown versions is a bug.

### Reader surface

Every SDK exposes `/api/v1/logs/{audit,sys,api}` and `/logs/audit/doctor` (Python + Go today). If you change query semantics, sync all SDKs.

## Workflow conventions

- **CHANGELOG.md is the authoritative log of adopter-visible changes.** Update it in the same PR for any adopter-observable change.
- **PR template (`.github/PULL_REQUEST_TEMPLATE.md`)** asks you to tick the affected SDK list and note cross-language impact.
- **CI fans out per-SDK.** Editing `fasten-core/` triggers every SDK's CI.
- **Java is a placeholder.** `emit()` throws today; do not invest in it unless explicitly asked.
- **No mocked databases in store tests.** Use the bundled sqlite + dockerized postgres (`tests/postgres/docker-compose.yml`).
