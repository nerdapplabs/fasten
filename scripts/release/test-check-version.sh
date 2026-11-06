#!/bin/sh
# Cases for check-version.sh and npm-dist-tag.sh.
set -eu

dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0

# repo <py version> <__version__> <js version> <rust version> <core req> <core version>
repo() {
  rm -rf "$tmp/r"
  mkdir -p "$tmp/r/python/fasten" "$tmp/r/js" "$tmp/r/rust" "$tmp/r/fasten-core"
  printf '[build-system]\nversion = "9"\n\n[project]\nname = "fasten"\nversion = "%s"\n' "$1" \
    > "$tmp/r/python/pyproject.toml"
  printf '"""fasten."""\n\n__version__ = "%s"\n' "$2" > "$tmp/r/python/fasten/__init__.py"
  printf '{\n  "name": "@nerdapplabs/fasten",\n  "version": "%s",\n  "dependencies": {\n    "x": {\n      "version": "0.0.1"\n    }\n  }\n}\n' "$3" \
    > "$tmp/r/js/package.json"
  printf '[package]\nname = "fasten"\nversion = "%s"\n\n[dependencies]\nfasten-core = { path = "../fasten-core", version = "%s", default-features = false }\nserde = { version = "1" }\n' "$4" "$5" \
    > "$tmp/r/rust/Cargo.toml"
  printf '[package]\nname = "fasten-core"\nversion = "%s"\n' "$6" > "$tmp/r/fasten-core/Cargo.toml"
}

check() { # check <ok|fail> <sdk> <tag>
  if "$dir/check-version.sh" "$2" "$3" "$tmp/r" >/dev/null 2>&1; then got=ok; else got=fail; fi
  if [ "$got" != "$1" ]; then
    echo "FAIL: $2 $3: got $got, want $1"
    fail=1
  fi
}

repo 1.0.0b0 1.0.0b0 1.0.0-beta.0 1.0.0-beta.0 0.1.0 0.1.0
check ok python v1.0.0-beta.0
check ok python v1.0.0b0
check fail python v1.0.0-beta.1
check fail python v1.0.0
check fail python v1.0.0-alpha.0
check fail python go/v1.0.0-beta.0
check ok js v1.0.0-beta.0
check fail js v1.0.0-beta
check fail js v1.0.0
check fail js 1.0.0-beta.0
check ok rust v1.0.0-beta.0
check fail rust v1.0.1-beta.0
check fail other v1.0.0-beta.0

repo 1.2.0rc1 1.2.0rc1 1.2.0-rc.1 1.2.0-rc.1 0.1.0 0.1.0
check ok python v1.2.0-rc.1
check fail python v1.2.0-beta.1

repo 2.0.0a3 2.0.0a3 2.0.0 2.0.0 0.1.0 0.1.0
check ok python v2.0.0-alpha.3
check ok python v2.0.0-a.3
check fail python v2.0.0

repo 2.0.0 2.0.0 2.0.0 2.0.0 0.1.0 0.1.0
check ok python v2.0.0
check ok js v2.0.0
check ok rust v2.0.0

# __version__ out of step with pyproject.
repo 1.0.0b0 1.0.0b1 1.0.0-beta.0 1.0.0-beta.0 0.1.0 0.1.0
check fail python v1.0.0-beta.0

# fasten-core requirement out of step with fasten-core.
repo 1.0.0b0 1.0.0b0 1.0.0-beta.0 1.0.0-beta.0 0.1.0 0.2.0
check fail rust v1.0.0-beta.0

tag() { # tag <want> <version>
  got=$("$dir/npm-dist-tag.sh" "$2")
  if [ "$got" != "$1" ]; then
    echo "FAIL: npm-dist-tag $2: got $got, want $1"
    fail=1
  fi
}

tag beta 1.0.0-beta.0
tag beta 1.0.0-beta
tag rc 2.1.0-rc.3
tag alpha 1.0.0-alpha.1+build.5
tag latest 1.0.0
tag latest 1.0.0+build.5

[ "$fail" -eq 0 ] || exit 1
echo "check-version: ok"
