#!/bin/sh
# Print the --latest value for the GitHub release of a tag: true for a
# vX.Y.Z tag that is the highest vX.Y.Z tag, false for anything else
# (go/ tags, prereleases, backports).
#
# Usage: git tag -l 'v*' | scripts/release/latest-flag.sh <tag>
set -eu
export LC_ALL=C

[ $# -eq 1 ] || { echo "usage: $0 <tag>" >&2; exit 2; }
tag=$1
release='^v[0-9]+\.[0-9]+\.[0-9]+$'
# Read all of stdin before deciding: exiting early would kill the writer
# (git tag -l) with SIGPIPE and fail a pipefail caller.
tags=$(cat)

if ! printf '%s\n' "$tag" | grep -Eq "$release"; then
  echo false
  exit 0
fi
highest=$(printf '%s\n%s\n' "$tags" "$tag" | grep -E "$release" | sort -t. -k1.2,1n -k2,2n -k3,3n | tail -n 1)
if [ "$highest" = "$tag" ]; then echo true; else echo false; fi
