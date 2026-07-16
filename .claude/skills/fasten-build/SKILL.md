---
name: fasten-build
description: Build fasten-core and run any SDK's test suite with the correct env vars. Use when building the Rust core, running Python/Go/JS/Rust/C++/Swift tests, or wiring the FFI library paths.
---

# Build fasten-core and run SDK tests

The single Rust core (`fasten-core/`) must be built before running tests for Python/JS/Go/C++/Swift (the rust/ SDK is the only one that does not FFI into it):

```bash
cd fasten-core && cargo build --release --features all
# produces target/release/libfasten_core.so (Linux), .dylib (macOS), .dll (Windows)
```

Per-SDK env vars for the .so, and the exact test commands per language (Python/Go/JS/Rust/C++/Swift), live in the repo root `CLAUDE.md` under "Commands" - follow those verbatim. Cross-language integration smokes: `cd tests/integration && make test` (Docker, pinned base images, asserts against `spec/row-schema.json`).

Invariants to respect while testing: queue mode is the default (`emit()` async); wire changes are cross-SDK by construction (`spec/codegen.py --check` is the CI gate); no mocked databases in store tests.
