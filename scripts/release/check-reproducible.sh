#!/usr/bin/env bash
# Build the release files twice from two separate clones and fail unless
# both builds are byte-identical and hold the expected files.
#
# Usage: scripts/release/check-reproducible.sh
#
# The second clone gets a different umask and file mtimes, so the check
# fails if the archives pick up either from the checkout.
set -euo pipefail
export LC_ALL=C

repo=$(git rev-parse --show-toplevel)
head=$(git -C "$repo" rev-parse HEAD)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

clone() {
  git clone -q --no-checkout --no-hardlinks "$repo" "$work/$1"
  git -C "$work/$1" checkout -q --detach "$head"
}
clone a
(umask 002 && clone b)
find "$work/b" -path "$work/b/.git" -prune -o -type f -exec touch -d '2001-02-03 04:05:06' {} +

# Stand-in library files, so the fasten-core packaging runs without a
# Rust toolchain.
mkdir -p "$work/lib"
printf 'so\n' > "$work/lib/libfasten_core.so"
printf 'a\n' > "$work/lib/libfasten_core.a"

tag=v0.0.0-check
gotag=go/v0.0.0-check
arch=$(uname -m)
fail=0
for side in a b; do
  (cd "$work/$side" && scripts/release/build-artifacts.sh "$tag" "$work/out-$side/main" "$work/lib" >/dev/null)
  (cd "$work/$side" && scripts/release/build-artifacts.sh "$gotag" "$work/out-$side/go" >/dev/null)
done

for set in main go; do
  if ! diff -u "$work/out-a/$set/SHA256SUMS" "$work/out-b/$set/SHA256SUMS"; then
    echo "FAIL: $set builds differ"
    fail=1
  fi
  (cd "$work/out-a/$set" && sha256sum --quiet -c SHA256SUMS) || fail=1
done

expect() { # expect <dir> <file>...: exactly these files, plus SHA256SUMS
  local dir=$1; shift
  local want got
  want=$(printf '%s\n' "$@" SHA256SUMS | sort)
  got=$(find "$dir" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
  if [ "$want" != "$got" ]; then
    echo "FAIL: $dir holds:"; echo "$got"; echo "expected:"; echo "$want"
    fail=1
  fi
}
expect "$work/out-a/main" "fasten-swift-$tag.tar.gz" "fasten-cpp-$tag.tar.gz" \
  "fasten-rust-$tag.tar.gz" "fasten-core-$tag-linux-$arch.tar.gz"
expect "$work/out-a/go" "fasten-go-v0.0.0-check.zip"

has() { # has <listing> <entry>...
  local listing=$1; shift
  for e in "$@"; do
    grep -qxF -- "$e" <<<"$listing" || { echo "FAIL: missing $e"; fail=1; }
  done
}
m=$work/out-a/main
has "$(tar -tzf "$m/fasten-swift-$tag.tar.gz")" \
  "fasten-swift-$tag/swift/Package.swift" "fasten-swift-$tag/LICENSE"
has "$(tar -tzf "$m/fasten-cpp-$tag.tar.gz")" \
  "fasten-cpp-$tag/cpp/include/fasten.hpp" "fasten-cpp-$tag/LICENSE"
has "$(tar -tzf "$m/fasten-rust-$tag.tar.gz")" \
  "fasten-rust-$tag/rust/Cargo.toml" "fasten-rust-$tag/fasten-core/Cargo.lock" \
  "fasten-rust-$tag/fasten-core/include/fasten_core.h" "fasten-rust-$tag/rust-toolchain.toml"
core=fasten-core-$tag-linux-$arch
has "$(tar -tzf "$m/$core.tar.gz")" \
  "$core/lib/libfasten_core.so" "$core/lib/libfasten_core.a" \
  "$core/include/fasten_core.h" "$core/LICENSE"
gozip=$work/out-a/go/fasten-go-v0.0.0-check.zip
has "$(python3 -c 'import sys, zipfile; print("\n".join(zipfile.ZipFile(sys.argv[1]).namelist()))' "$gozip")" \
  "github.com/nerdapplabs/fasten/go@v0.0.0-check/go.mod" \
  "github.com/nerdapplabs/fasten/go@v0.0.0-check/LICENSE"

# Every tracked file of each SDK is in its archive.
count() { git -C "$work/a" ls-files -- "$@" | wc -l; }
entries() { tar -tzf "$1" | grep -vc '/LICENSE$' || true; }
[ "$(entries "$m/fasten-swift-$tag.tar.gz")" -eq "$(count swift)" ] || { echo "FAIL: swift file count"; fail=1; }
[ "$(entries "$m/fasten-cpp-$tag.tar.gz")" -eq "$(count cpp/include)" ] || { echo "FAIL: cpp file count"; fail=1; }

# A tracked file that differs from HEAD stops the build, staged or not.
dirty() { # dirty <name> <command>: build in a clone after the command
  local name=$1 log; shift
  clone "$name"
  (cd "$work/$name" && "$@")
  log=$work/$name.log
  if (cd "$work/$name" && scripts/release/build-artifacts.sh "$tag" "$work/out-$name" "$work/lib") >"$log" 2>&1; then
    echo "FAIL: build ran with $name changes"; fail=1
  elif ! grep -q 'tracked files differ from HEAD' "$log"; then
    echo "FAIL: $name build failed for another reason:"; cat "$log"; fail=1
  elif [ -e "$work/out-$name" ]; then
    echo "FAIL: $name build wrote files"; fail=1
  fi
}
dirty modified sh -c 'echo x >> swift/Package.swift'
dirty staged sh -c 'echo x >> cpp/include/fasten.hpp && git add cpp/include/fasten.hpp'
# Untracked files are not packed, so they don't stop the build.
clone untracked
touch "$work/untracked/swift/extra.swift"
(cd "$work/untracked" && scripts/release/build-artifacts.sh "$tag" "$work/out-untracked" "$work/lib" >/dev/null) \
  || { echo "FAIL: untracked file stopped the build"; fail=1; }
cmp -s "$work/out-a/main/SHA256SUMS" "$work/out-untracked/SHA256SUMS" \
  || { echo "FAIL: untracked file changed the archives"; fail=1; }

if [ "$fail" -ne 0 ]; then
  echo "release artifacts check failed"
  exit 1
fi
echo "release artifacts are reproducible:"
cat "$work/out-a/main/SHA256SUMS" "$work/out-a/go/SHA256SUMS"
