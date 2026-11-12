#!/usr/bin/env bash
# Decide whether the npm package in <package dir> needs publishing. Prints
# publish when its version is not on npm, skip when it is and the published
# tarball has the same integrity as `npm pack` of the tree. Fails when the
# integrity differs or the registry lookup fails.
#
# Usage: scripts/release/npm-check.sh <package dir>
# NPM overrides the npm command (for the tests).
set -euo pipefail

[ $# -eq 1 ] || { echo "usage: $0 <package dir>" >&2; exit 2; }
npm=${NPM:-npm}
cd "$1"
name=$(node -p 'require("./package.json").name')
version=$(node -p 'require("./package.json").version')

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# A missing version of a published package prints nothing and exits 0; a
# package that was never published fails with E404.
if ! "$npm" view "$name@$version" dist.integrity > "$tmp/out" 2> "$tmp/err"; then
  if grep -q E404 "$tmp/out" "$tmp/err"; then
    echo publish
    exit 0
  fi
  cat "$tmp/out" "$tmp/err" >&2
  echo "::error::npm view $name@$version failed" >&2
  exit 1
fi
published=$(cat "$tmp/out")
if [ -z "$published" ]; then
  echo publish
  exit 0
fi

built=$("$npm" pack --dry-run --json | node -e 'let s = ""; process.stdin.on("data", (d) => { s += d; }).on("end", () => console.log(JSON.parse(s)[0].integrity))')
if [ "$published" != "$built" ]; then
  echo "::error::$name $version on npm has integrity $published, this build has $built" >&2
  exit 1
fi
echo "$name $version is already on npm with the same tarball" >&2
echo skip
