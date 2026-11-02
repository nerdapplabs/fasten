#!/bin/sh
# Run the CI checks locally (most in Docker) before pushing.
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

# Workflows must take the toolchain from rust-toolchain.toml, not pin their own.
STRAY=$(grep -rhoE "dtolnay/rust-toolchain@[0-9][0-9.]*|image: rust:[0-9][0-9.]*" \
          .github/workflows/ 2>/dev/null | grep -v "rust:$TC" | sort -u)
if [ -z "$STRAY" ]; then
  pass "no workflow pins a divergent toolchain"
else
  bad "divergent toolchain pins: $(echo $STRAY)"
fi

# dtolnay/rust-toolchain@master needs a toolchain input and does not read
# rust-toolchain.toml, so each use must be passed the channel read from it.
MASTER=$(grep -rlE "dtolnay/rust-toolchain@master" .github/workflows/ 2>/dev/null)
missing=""
for f in $MASTER; do
  grep -q "outputs.channel }}" "$f" || missing="$missing $(basename "$f")"
done
if [ -z "$MASTER" ]; then
  pass "no @master toolchain actions to check"
elif [ -z "$missing" ]; then
  pass "every @master toolchain action receives a toolchain input"
else
  bad "@master without a toolchain input:$missing"
fi

# The reader step greps rust-toolchain.toml, so checkout must precede it.
ORDER_OK=1
for f in $MASTER; do
  ck=$(grep -n "actions/checkout" "$f" | head -1 | cut -d: -f1)
  rd=$(grep -n "Read toolchain from rust-toolchain.toml" "$f" | head -1 | cut -d: -f1)
  [ -n "$ck" ] && [ -n "$rd" ] && [ "$ck" -lt "$rd" ] || ORDER_OK=0
done
[ "$ORDER_OK" -eq 1 ] && pass "checkout precedes the toolchain reader" \
                      || bad "a toolchain reader runs before checkout"

# A step that reads a repo-root file must not inherit a subdirectory
# working-directory. This script runs from the root and can't catch that by
# running the commands, so the workflow files are checked instead. In Docker
# because the host python3 may not have pyyaml.
WDCHECK=scripts/check-workflow-paths.py
if [ ! -f "$WDCHECK" ]; then
  bad "missing $WDCHECK"
else
  out=$(docker run --rm -v "$PWD":/w -w /w python:3.12-slim sh -c \
          "pip install -q pyyaml >/dev/null 2>&1 && python3 $WDCHECK" 2>&1)
  rc=$?
  if [ $rc -eq 0 ]; then
    pass "no step reads a repo-root path from a subdirectory default"
  else
    bad "repo-root path read under a subdirectory working-directory:"
    printf '%s\n' "$out" | sed 's/^/        /'
  fi
fi

# Go's tests verify the committed spec/python-sealed-forms.json, so it must
# match what Python seals today. Exit 1 means stale; any other non-zero exit
# means the check itself could not run.
vout=$(docker run --rm -v "$PWD":/w -w /w python:3.12-slim sh -c \
        "cd python && pip install -q -e '.[sqlite,dev]' && cd /w && \
         python3 scripts/gen_cross_sdk_vectors.py --check" 2>&1)
vrc=$?
if [ $vrc -eq 0 ]; then
  pass "spec/python-sealed-forms.json matches current sealing"
elif [ $vrc -eq 1 ]; then
  bad "spec/python-sealed-forms.json is stale: run scripts/gen_cross_sdk_vectors.py"
else
  bad "vector check could not run (exit $vrc): setup failed, the file was NOT compared:"
  printf '%s\n' "$vout" | tail -4 | sed 's/^/        /'
fi

# Lockfiles must be tracked or --locked cannot work.
if git ls-files --error-unmatch rust/Cargo.lock fasten-core/Cargo.lock >/dev/null 2>&1; then
  pass "both Cargo.lock files are tracked"
else
  bad "a Cargo.lock is untracked: --locked will error 'needs to be updated'"
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
# Compiling modernc.org/sqlite needs more memory than Docker's default; when
# it runs out the error reads "build failed", not out-of-memory.
if docker run --rm --memory=6g -v "$PWD":/w -w /w/go \
     -e LD_LIBRARY_PATH=/w/fasten-core/target/release golang:1-bookworm \
     sh -c "go test -vet=off ./..." >/dev/null 2>&1; then
  pass "go tests"
else
  bad "go tests"
fi

echo
echo "== postgres (local only; CI is SQLite-only by decision) =="
PGC=fasten-ci-local-pg
docker rm -f "$PGC" >/dev/null 2>&1
if docker run -d --name "$PGC" -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=fasten \
     -p 55433:5432 postgres:16-alpine >/dev/null 2>&1; then
  i=0; until docker exec "$PGC" pg_isready -U postgres >/dev/null 2>&1 || [ $i -ge 40 ]; do
    i=$((i+1)); sleep 1; done
  DSN="postgresql://postgres:pw@127.0.0.1:55433/fasten"
  if docker run --rm --network host -v "$PWD":/w -w /w/python \
       -e FASTEN_CORE_LIB=/w/fasten-core/target/release/libfasten_core.so \
       -e FASTEN_TEST_POSTGRES_DSN="$DSN" python:3.12-slim sh -c \
       "pip install -q -e '.[sqlite,postgres,fastapi,dev]' && \
        python -m pytest tests/test_postgres_allocation.py -q" >/dev/null 2>&1; then
    pass "python postgres allocation"
  else
    bad "python postgres allocation"
  fi
  # The Go Postgres tests need -tags integration. Without this step nothing
  # else in this script runs the Go allocator, its advisory lock or the
  # UNIQUE index against Postgres.
  if docker run --rm --network host --memory=6g -v "$PWD":/w -w /w/go \
       -e LD_LIBRARY_PATH=/w/fasten-core/target/release \
       -e FASTEN_TEST_POSTGRES_DSN="postgres://postgres:pw@127.0.0.1:55433/fasten?sslmode=disable" \
       golang:1-bookworm sh -c "go test -vet=off -tags integration -run 'TestPGAlloc' ./..." \
       >/dev/null 2>&1; then
    pass "go postgres allocation"
  else
    bad "go postgres allocation"
  fi
  docker rm -f "$PGC" >/dev/null 2>&1
else
  bad "could not start postgres:16"
fi

echo
if [ $fail -eq 0 ]; then
  echo "ALL GREEN"
else
  echo "SOMETHING FAILED — do not push"
fi
exit $fail
