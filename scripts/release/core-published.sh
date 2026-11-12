#!/usr/bin/env bash
# Decide whether a crate needs publishing. Prints publish when its version
# is not on crates.io, skip when it is and the published .crate holds the
# same files as `cargo package` of the tree. Exits 3 when they differ (the
# SDK would then build against the old published code) or the version is
# yanked; RELEASE_CHECK_LEVEL=warning reports that as a warning, for dry
# runs. Exits 1 when crates.io cannot be read or cargo package fails.
#
# Usage: scripts/release/core-published.sh <crate dir>
# CRATES_INDEX and CRATES_DL override the crates.io URLs (for the tests).
set -euo pipefail
export LC_ALL=C

[ $# -eq 1 ] || { echo "usage: $0 <crate dir>" >&2; exit 2; }
index=${CRATES_INDEX:-https://index.crates.io}
dl=${CRATES_DL:-https://static.crates.io/crates}
dir=$(cd "$1" && pwd)

field() { sed -n "s/^$1 = \"\(.*\)\"\$/\1/p" "$dir/Cargo.toml" | head -n 1; }
name=$(field name)
version=$(field version)
[ ${#name} -ge 4 ] && [ -n "$version" ] || { echo "::error::no name or version in $dir/Cargo.toml" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Without -f, curl exits 0 on any HTTP status, so a non-zero exit is a
# transfer failure (no answer, timeout, connection cut mid-body).
code=$(curl -sS --max-time 60 -o "$tmp/index" -w '%{http_code}' "$index/${name:0:2}/${name:2:2}/$name") \
  || { echo "::error::could not read the crates.io index for $name" >&2; exit 1; }
case $code in
  404) echo publish; exit 0 ;;
  200) ;;
  *) echo "::error::crates.io index returned $code for $name" >&2; exit 1 ;;
esac
grep_rc=0
line=$(grep "\"vers\":\"$version\"" "$tmp/index") || grep_rc=$?
[ "$grep_rc" -le 1 ] || { echo "::error::could not read the downloaded index for $name" >&2; exit 1; }
if [ -z "$line" ]; then
  echo publish
  exit 0
fi
level=${RELEASE_CHECK_LEVEL:-error}
case $line in
  *'"yanked":true'*) echo "::$level::$name $version is yanked on crates.io; bump its version" >&2; exit 3 ;;
esac

curl -fsS --max-time 60 -o "$tmp/published.crate" "$dl/$name/$name-$version.crate" \
  || { echo "::error::could not download $name $version from crates.io" >&2; exit 1; }
(cd "$dir" && CARGO_TARGET_DIR="$tmp/target" cargo package -q --no-verify --allow-dirty)

mkdir "$tmp/published" "$tmp/tree"
tar -xzf "$tmp/published.crate" -C "$tmp/published"
tar -xzf "$tmp/target/package/$name-$version.crate" -C "$tmp/tree"
# Cargo.toml is rewritten by cargo (Cargo.toml.orig is the source manifest
# and is compared); the VCS info and lock file are not source.
for d in "$tmp/published" "$tmp/tree"; do
  rm -f "$d/$name-$version/Cargo.toml" "$d/$name-$version/.cargo_vcs_info.json" "$d/$name-$version/Cargo.lock"
done

diff_rc=0
diff -rq "$tmp/published" "$tmp/tree" >&2 || diff_rc=$?
case $diff_rc in
  0) ;;
  1) echo "::$level::$name changed since $version was published; bump its version" >&2; exit 3 ;;
  *) echo "::error::could not compare $name with the published $version" >&2; exit 1 ;;
esac
echo skip
