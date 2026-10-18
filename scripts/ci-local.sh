#!/bin/sh
# Run what CI runs, locally, in one shot.
#
# Written after "rustc 1.85.1 is not supported" survived several pushes: four
# workflows pinned the Rust toolchain independently and each fix touched one of
# them. Every failure in that round was discoverable locally; none of them were
# discovered locally.
#
# Usage:  ./scripts/ci-local.sh
# Exit 0 only when every job a push would run is green.
set -u
cd "$(dirname "$0")/.." || exit 1

TC=$(grep -oE 'channel = "[0-9.]+"' rust-toolchain.toml | grep -oE '[0-9.]+')
fail=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fail=1; }

echo "toolchain (rust-toolchain.toml): $TC"
echo

echo "== toolchain declarations agree =="
MV=$(grep -oE 'rust-version = "[0-9.]+"' fasten-core/Cargo.toml | grep -oE '[0-9.]+')
if [ "$TC" = "$MV" ]; then
  pass "rust-toolchain.toml == fasten-core rust-version ($TC)"
else
  bad "rust-toolchain.toml=$TC != fasten-core rust-version=$MV"
fi

# Any workflow pinning its own version is how the 1.85 failure persisted.
STRAY=$(grep -rhoE "dtolnay/rust-toolchain@[0-9][0-9.]*|image: rust:[0-9][0-9.]*" \
          .github/workflows/ 2>/dev/null | grep -v "rust:$TC" | sort -u)
if [ -z "$STRAY" ]; then
  pass "no workflow pins a divergent toolchain"
else
  bad "divergent toolchain pins: $(echo $STRAY)"
fi

# Lockfiles must be tracked or --locked cannot work.
if git ls-files --error-unmatch rust/Cargo.lock fasten-core/Cargo.lock >/dev/null 2>&1; then
  pass "both Cargo.lock files are tracked"
else
  bad "a Cargo.lock is untracked — --locked will error 'needs to be updated'"
fi

echo
echo "== rust/ =="
if docker run --rm -v "$PWD":/w -w /w/rust "rust:$TC" \
     sh -c "cargo test --locked --quiet" >/dev/null 2>&1; then
  pass "rust/ tests"
else
  bad "rust/ tests"
fi

echo
echo "== fasten-core (all features — how go/py/cpp build it) =="
if docker run --rm -v "$PWD":/w -w /w/fasten-core "rust:$TC" sh -c \
     "apt-get update -qq && apt-get install -y -qq pkg-config libssl-dev && \
      cargo build --release --locked --features all && \
      cargo test --all-features --locked --quiet" >/dev/null 2>&1; then
  pass "fasten-core build + tests"
else
  bad "fasten-core build + tests"
fi

echo
echo "== python =="
if docker run --rm -v "$PWD":/w -w /w/python \
     -e FASTEN_CORE_LIB=/w/fasten-core/target/release/libfasten_core.so \
     python:3.12-slim sh -c \
     "pip install -q -e '.[sqlite,postgres,fastapi,dev]' && \
      ruff check fasten/ && mypy fasten/ && python -m pytest tests/ -q" >/dev/null 2>&1; then
  pass "ruff + mypy + pytest"
else
  bad "ruff + mypy + pytest"
fi

echo
echo "== go =="
# 6GB: the Docker default OOM-kills the compile of modernc.org/sqlite, and the
# failure reads as "build failed" rather than out-of-memory.
if docker run --rm --memory=6g -v "$PWD":/w -w /w/go \
     -e LD_LIBRARY_PATH=/w/fasten-core/target/release golang:1-bookworm \
     sh -c "go test -vet=off ./..." >/dev/null 2>&1; then
  pass "go tests"
else
  bad "go tests"
fi

echo
if [ $fail -eq 0 ]; then
  echo "ALL GREEN"
else
  echo "SOMETHING FAILED — do not push"
fi
exit $fail
