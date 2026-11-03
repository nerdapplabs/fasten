# Rust integration smoke. Build context = fasten repo root.
#
# The SDK depends on fasten-core by path, which needs Rust 1.90 (its
# rust-version, the rust-toolchain.toml pin). The repo layout is kept so
# both path dependencies resolve.
FROM rust:1.90-slim-bookworm AS build

WORKDIR /workspace
COPY fasten-core/Cargo.toml fasten-core/Cargo.lock fasten-core/
COPY fasten-core/src/ fasten-core/src/
COPY fasten-core/include/ fasten-core/include/
COPY fasten-core/tests/ fasten-core/tests/
COPY rust/ rust/
COPY tests/integration/rust/ tests/integration/rust/

RUN cd tests/integration/rust && cargo build --release --bin fasten-itest

FROM debian:bookworm-slim
COPY --from=build /workspace/tests/integration/rust/target/release/fasten-itest /smoke
CMD ["/smoke"]
