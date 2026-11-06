#!/bin/sh
# Print the npm dist-tag for a package version: the first prerelease
# identifier for a prerelease (1.0.0-beta.0 -> beta), next when that
# identifier is a number (1.0.0-0). A plain version gets latest when it is
# the highest plain version, and release-X.Y otherwise (a 1.0.1 backport
# after 1.1.0 -> release-1.0), so it does not move latest back.
#
# Usage: printf 'v%s\n' <published versions> | scripts/release/npm-dist-tag.sh <version>
set -eu

[ $# -eq 1 ] || { echo "usage: $0 <version>" >&2; exit 2; }
version=${1%%+*}
case $version in
  *-*)
    pre=${version#*-}
    pre=${pre%%.*}
    case $pre in
      *[!0-9]*) echo "$pre" ;;
      *) echo next ;;
    esac
    ;;
  *)
    if [ "$("$(dirname "$0")/latest-flag.sh" "v$version")" = true ]; then
      echo latest
    else
      minor=${version%.*}
      echo "release-$minor"
    fi
    ;;
esac
