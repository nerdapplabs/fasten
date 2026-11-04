# Python integration smoke. Build context = fasten repo root.
#
# The SDK loads fasten-core through ctypes, so it is built first and
# FASTEN_CORE_LIB points at it.
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

FROM python:3.10-slim

WORKDIR /app

COPY --from=core /workspace/fasten-core/target/release/libfasten_core.so /usr/local/lib/
ENV FASTEN_CORE_LIB=/usr/local/lib/libfasten_core.so

# fasten from local source, plus structlog for the shim test.
COPY python/ /app/sdk/
RUN pip install --no-cache-dir /app/sdk "structlog>=21.5"

# Copy smoke
COPY tests/integration/python/smoke.py /app/smoke.py

ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/smoke.py"]
