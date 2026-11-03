# C++14 integration smoke. Build context = fasten repo root.
#
# The C++ SDK calls fasten-core, so the smoke links libfasten_core.
# libstdc++ is linked statically: gcc:13 ships a newer one than the
# bookworm runtime image has.
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

FROM gcc:13-bookworm AS build

WORKDIR /workspace

COPY cpp/include/ /workspace/include/
COPY --from=core /workspace/fasten-core/include/ /workspace/fasten-core/include/
COPY --from=core /workspace/fasten-core/target/release/libfasten_core.so /workspace/lib/
COPY tests/integration/cpp/smoke.cpp /workspace/smoke.cpp

RUN g++ -std=c++14 -O2 -I/workspace/include -I/workspace/fasten-core/include \
    /workspace/smoke.cpp -L/workspace/lib -lfasten_core -pthread \
    -static-libstdc++ -static-libgcc -o /smoke

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=core /workspace/fasten-core/target/release/libfasten_core.so /usr/local/lib/
RUN ldconfig
COPY --from=build /smoke /smoke
CMD ["/smoke"]
