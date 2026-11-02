# Go integration smoke. Build context = fasten repo root.
#
# The Go SDK calls fasten-core through cgo: it links libfasten_core from
# ../fasten-core/target/release. So fasten-core is built first, and the
# repo layout is kept so those relative paths resolve.
FROM rust:1.90-slim-bookworm AS core

# postgres-tls links OpenSSL.
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/fasten-core
COPY fasten-core/Cargo.toml fasten-core/Cargo.lock ./
COPY fasten-core/src/ src/
COPY fasten-core/include/ include/
COPY fasten-core/tests/ tests/
RUN cargo build --release --locked --features all

FROM golang:1.26-bookworm AS build

WORKDIR /workspace
COPY --from=core /workspace/fasten-core/include/ fasten-core/include/
COPY --from=core /workspace/fasten-core/target/release/libfasten_core.so fasten-core/target/release/
COPY go/ go/
COPY tests/integration/go/ tests/integration/go/

RUN cd tests/integration/go \
    && go mod tidy \
    && CGO_ENABLED=1 go build -o /smoke smoke.go

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=core /workspace/fasten-core/target/release/libfasten_core.so /usr/local/lib/
RUN ldconfig
COPY --from=build /smoke /smoke
CMD ["/smoke"]
