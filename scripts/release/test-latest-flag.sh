#!/usr/bin/env bash
# Cases for latest-flag.sh.
set -euo pipefail

dir=$(cd "$(dirname "$0")" && pwd)
fail=0

check() { # check <want> <tag> [existing tags...]
  local want=$1 tag=$2 got
  shift 2
  got=$(printf '%s\n' "$@" | "$dir/latest-flag.sh" "$tag")
  if [ "$got" != "$want" ]; then
    echo "FAIL: $tag with [$*]: got $got, want $want"
    fail=1
  fi
}

check true v1.0.0
check true v1.0.0 v1.0.0
check true v1.0.0 v0.9.0 v1.0.0
check true v1.10.0 v1.9.0 v1.2.0
check true v2.0.0 v1.0.0 v2.0.0-rc.1 v3.0.0-beta
check false v0.9.1 v0.9.0 v1.0.0
check false v1.9.0 v1.10.0
check false go/v1.0.0 v1.0.0
check false go/v2.0.0
check false v1.1.0-rc.1 v1.0.0
check false v1.0.0-dryrun
check false v0.0.0-dryrun v0.9.0

[ "$fail" -eq 0 ] || exit 1
echo "latest-flag: ok"
