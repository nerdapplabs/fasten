#!/bin/sh
# Print the npm dist-tag for a package version: the first prerelease
# identifier for a prerelease (1.0.0-beta.0 -> beta), latest otherwise.
#
# Usage: scripts/release/npm-dist-tag.sh <version>
set -eu

[ $# -eq 1 ] || { echo "usage: $0 <version>" >&2; exit 2; }
version=${1%%+*}
case $version in
  *-*)
    pre=${version#*-}
    echo "${pre%%.*}"
    ;;
  *) echo latest ;;
esac
