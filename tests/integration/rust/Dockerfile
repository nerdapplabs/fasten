# Rust integration smoke. Build context = fasten repo root.
# Bumped to 1.85 to match rust/Cargo.toml's `rust-version = "1.85"`;
# 1.82 (the prior pin) refused to compile the SDK after the Cargo.toml
# bump, leaving the Rust integration smoke dead in CI.
FROM rust:1.85-slim AS build

WORKDIR /workspace

# SDK and smoke side-by-side; rewrite path dep accordingly.
COPY rust/ /workspace/sdk-rust/
COPY tests/integration/rust/ /workspace/test/

RUN cd /workspace/test \
    && sed -i 's|path = "../../../rust"|path = "../sdk-rust"|' Cargo.toml \
    && cargo build --release --bin fasten-itest

FROM debian:bookworm-slim
COPY --from=build /workspace/test/target/release/fasten-itest /smoke
CMD ["/smoke"]
