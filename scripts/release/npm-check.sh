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

# npm 11 fails with "404 No match found for version" for a missing version
# of a published package, and "404 Not Found - GET" for a package that was
# never published (npm says the same when the token has no access; npm
# publish then refuses a version that exists). Older npm printed nothing
# and exited 0 for a missing version.
if ! "$npm" view "$name@$version" dist.integrity > "$tmp/out" 2> "$tmp/err"; then
  if grep -Eq '404 (No match found for version|Not Found - GET)' "$tmp/out" "$tmp/err"; then
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
