#!/usr/bin/env bash
# Decide whether the npm package in <package dir> needs publishing. Prints
# publish when its version is not on npm, skip when it is and the published
# tarball has the same integrity as `npm pack` of the tree. Exits 3 when the
# integrity differs (RELEASE_CHECK_LEVEL=warning reports that as a warning,
# for dry runs), and 1 when the registry lookup or npm pack fails.
#
# Skip also needs one of NPM_OWNERS (comma-separated npm users) among the
# package's owners. Other owners exit 1; an unset NPM_OWNERS exits 3.
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

# Fails unless npm pack reports a sha512 integrity, so a change in its
# output is an error rather than a mismatch.
built=$("$npm" pack --dry-run --json | node -e '
let s = "";
process.stdin.on("data", (d) => { s += d; }).on("end", () => {
  const i = JSON.parse(s)[0]?.integrity;
  if (typeof i !== "string" || !i.startsWith("sha512-")) {
    console.error(`npm pack --json reported no sha512 integrity: ${s.slice(0, 200)}`);
    process.exit(1);
  }
  console.log(i);
});')
if [ "$published" != "$built" ]; then
  echo "::${RELEASE_CHECK_LEVEL:-error}::$name $version on npm has integrity $published, this build has $built" >&2
  exit 3
fi

if [ -z "${NPM_OWNERS:-}" ]; then
  echo "::${RELEASE_CHECK_LEVEL:-error}::$name $version is on npm with the same tarball, but NPM_OWNERS is not set, so its owner can't be checked" >&2
  exit 3
fi
if ! "$npm" owner ls "$name" > "$tmp/owners" 2> "$tmp/err"; then
  cat "$tmp/err" >&2
  echo "::error::npm owner ls $name failed" >&2
  exit 1
fi
owners=$(awk '{ print $1 }' "$tmp/owners")
for want in $(printf '%s' "$NPM_OWNERS" | tr ',' ' '); do
  if printf '%s\n' "$owners" | grep -qxF -- "$want"; then
    echo "$name $version is already on npm with the same tarball" >&2
    echo skip
    exit 0
  fi
done
echo "::error::$name on npm is owned by '$(printf '%s' "$owners" | tr '\n' ' ')', none of NPM_OWNERS ($NPM_OWNERS)" >&2
exit 1
