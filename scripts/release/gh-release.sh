#!/usr/bin/env bash
# Create or finish the GitHub release for <tag> with the files in <dist dir>.
#
# A new release is created as a draft, so it is not public until every file
# is on it. Files already on the release are kept when their sha256 matches,
# so a re-run uploads only what is missing; a file left unfinished by an
# interrupted upload is replaced. A finished file with other bytes, one
# GitHub has no digest for, or a file that is not in <dist dir> fails the
# job. Once every file is on the release with the digest of this build, a
# draft is published, as the repo's latest release when <latest> is true.
#
# Usage: scripts/release/gh-release.sh <tag> <latest: true|false> <dist dir>
# Needs GITHUB_REPOSITORY. GH overrides the gh command and
# RELEASE_POLL_SECONDS the wait between release lookups (for the tests).
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 <tag> <true|false> <dist dir>" >&2; exit 2; }
tag=$1 latest=$2 dist=$3
repo=${GITHUB_REPOSITORY:?}
gh=${GH:-gh}
[ -n "$(ls -A "$dist")" ] || { echo "::error::no files in $dist" >&2; exit 1; }

# releases/tags/<tag> does not return drafts, so look through the list.
find_release() {
  "$gh" api --paginate "repos/$repo/releases" --jq ".[] | select(.tag_name == \"$tag\") | \"\(.id) \(.draft)\""
}
assets() {
  "$gh" api --paginate "repos/$repo/releases/$id/assets" --jq '.[] | "\(.name) \(.state) \(.id) \(.digest // "none")"'
}
asset() { # asset <name>: "<state> <id> <digest>" of that file on the release, or nothing
  printf '%s\n' "$existing" | awk -v n="$1" '$1 == n { print $2, $3, $4 }'
}
sha() { echo "sha256:$(sha256sum "$1" | cut -d' ' -f1)"; }

release=$(find_release)
if [ -z "$release" ]; then
  prerelease=false
  case $tag in *-*) prerelease=true ;; esac
  "$gh" release create "$tag" --repo "$repo" --draft --verify-tag --title "$tag" \
    --prerelease="$prerelease" \
    --notes "Verify these files with the steps in SECURITY.md (Verifying a release)."
  # The release list can lag a few seconds behind the create.
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    release=$(find_release)
    [ -z "$release" ] || break
    sleep "${RELEASE_POLL_SECONDS:-3}"
  done
fi
case $release in
  '') echo "::error::release $tag not found after creating it" >&2; exit 1 ;;
  *$'\n'*) echo "::error::more than one release for $tag" >&2; exit 1 ;;
esac
read -r id draft <<< "$release"

existing=$(assets)
upload=()
for f in "$dist"/*; do
  name=$(basename "$f")
  a=$(asset "$name")
  if [ -z "$a" ]; then
    upload+=("$f")
    continue
  fi
  read -r state aid digest <<< "$a"
  if [ "$state" != uploaded ]; then
    echo "$name on release $tag is $state from an interrupted upload; replacing it"
    "$gh" api -X DELETE "repos/$repo/releases/assets/$aid"
    upload+=("$f")
  elif [ "$digest" = none ]; then
    echo "::error::$name on release $tag has no digest on GitHub, so it cannot be compared with this build; delete it from the release and re-run" >&2
    exit 1
  elif [ "$digest" != "$(sha "$f")" ]; then
    echo "::error::$name on release $tag has digest $digest, which does not match this build; delete it from the release if this build should replace it" >&2
    exit 1
  else
    echo "$name is already on release $tag"
  fi
done
if [ ${#upload[@]} -gt 0 ]; then
  "$gh" release upload "$tag" "${upload[@]}" --repo "$repo"
fi

# The release must now hold exactly the files of this build.
existing=$(assets)
bad=0
for f in "$dist"/*; do
  name=$(basename "$f")
  read -r state _ digest <<< "$(asset "$name")"
  if [ "$state" = uploaded ] && [ "$digest" = "$(sha "$f")" ]; then
    continue
  fi
  echo "::error::$name is not on release $tag with the digest of this build" >&2
  bad=1
done
for name in $(printf '%s\n' "$existing" | cut -d' ' -f1); do
  if [ ! -e "$dist/$name" ]; then
    echo "::error::$name is on release $tag but not in this build" >&2
    bad=1
  fi
done
[ "$bad" -eq 0 ] || exit 1

if [ "$draft" = true ]; then
  "$gh" release edit "$tag" --repo "$repo" --draft=false --latest="$latest"
  echo "Published release $tag"
else
  echo "Release $tag was already published; its files match this build"
fi
