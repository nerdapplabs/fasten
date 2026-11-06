#!/bin/sh
# Check that a vX.Y.Z[-pre] release tag matches the version of an SDK
# package before it is published. Python versions are compared after
# PEP 440 normalisation, so v1.0.0-beta.0 matches 1.0.0b0.
#
# Usage: scripts/release/check-version.sh <python|js|rust> <tag> [repo root]
set -eu
export LC_ALL=C

case $# in 2|3) ;; *) echo "usage: $0 <python|js|rust> <tag> [repo root]" >&2; exit 2 ;; esac
sdk=$1
tag=$2
root=${3:-$(cd "$(dirname "$0")/../.." && pwd)}

case $tag in
  v[0-9]*) want=${tag#v} ;;
  *) echo "tag $tag is not a vX.Y.Z tag" >&2; exit 1 ;;
esac

# First `version = "..."` in the [package] or [project] table of a TOML file.
toml_version() { # toml_version <file> <table>
  awk -v table="[$2]" '
    /^\[/ { in_table = ($0 == table) }
    in_table && /^version[ \t]*=/ {
      sub(/^version[ \t]*=[ \t]*"/, ""); sub(/".*/, ""); print; exit
    }' "$1"
}

# PEP 440 pre-release spelling: 1.0.0-beta.0 and 1.0.0b0 both become 1.0.0b0.
pep440() {
  printf '%s\n' "$1" | tr '[:upper:]' '[:lower:]' | sed -E '
    s/([0-9])[-_.]?(alpha|a)[-_.]?([0-9]*)$/\1a\3/
    s/([0-9])[-_.]?(beta|b)[-_.]?([0-9]*)$/\1b\3/
    s/([0-9])[-_.]?(rc|c|preview|pre)[-_.]?([0-9]*)$/\1rc\3/
    s/([0-9])(a|b|rc)$/\1\20/'
}

fail=0
mismatch() { # mismatch <what> <version>
  echo "tag $tag does not match $1 version $2" >&2
  fail=1
}

case $sdk in
  python)
    got=$(toml_version "$root/python/pyproject.toml" project)
    [ "$(pep440 "$got")" = "$(pep440 "$want")" ] || mismatch python/pyproject.toml "$got"
    init=$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' "$root/python/fasten/__init__.py")
    [ "$init" = "$got" ] || {
      echo "python/fasten/__init__.py __version__ $init does not match python/pyproject.toml $got" >&2
      fail=1
    }
    ;;
  js)
    got=$(sed -n 's/^  "version": "\(.*\)",*$/\1/p' "$root/js/package.json" | head -n 1)
    [ "$got" = "$want" ] || mismatch js/package.json "$got"
    ;;
  rust)
    got=$(toml_version "$root/rust/Cargo.toml" package)
    [ "$got" = "$want" ] || mismatch rust/Cargo.toml "$got"
    # The SDK's fasten-core requirement must be the version in fasten-core/.
    core=$(toml_version "$root/fasten-core/Cargo.toml" package)
    req=$(sed -n 's/^fasten-core *=.*version *= *"\([^"]*\)".*/\1/p' "$root/rust/Cargo.toml")
    [ "$req" = "$core" ] || {
      echo "rust/Cargo.toml requires fasten-core ${req:-(no version)}, fasten-core/Cargo.toml is $core" >&2
      fail=1
    }
    ;;
  *) echo "unknown SDK $sdk" >&2; exit 2 ;;
esac

[ "$fail" -eq 0 ] || exit 1
echo "$sdk: tag $tag matches"
