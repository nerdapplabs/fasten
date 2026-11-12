#!/usr/bin/env bash
# Build the files attached to a GitHub release.
#
# Usage: scripts/release/build-artifacts.sh <tag> <out-dir> [core-lib-dir]
#
#   vX.Y.Z     Swift, C++ and Rust source archives, plus the fasten-core
#              library when core-lib-dir holds a release build of it.
#   go/vX.Y.Z  The Go module zip, laid out as the module proxy serves it.
#
# Archives hold only tracked files at HEAD, and the script stops if any
# tracked file differs from HEAD. Entries are sorted, owned by
# 0:0, stamped with the commit time and use normalized modes, so the same
# commit always gives the same bytes. Needs git, GNU tar, gzip, sha256sum
# and python3.
set -euo pipefail
export LC_ALL=C

usage() { echo "usage: $0 <tag> <out-dir> [core-lib-dir]" >&2; exit 2; }
if [ $# -lt 2 ] || [ $# -gt 3 ]; then usage; fi
tag=$1
out=$2
core_lib=${3:-}

[[ $tag =~ ^(go/)?v[0-9][0-9A-Za-z.+-]*$ ]] || { echo "bad tag: $tag" >&2; exit 2; }
tar --version 2>/dev/null | grep -q 'GNU tar' || { echo "GNU tar is required" >&2; exit 1; }
[ -z "$core_lib" ] || core_lib=$(cd "$core_lib" && pwd)

cd "$(git rev-parse --show-toplevel)"
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "tracked files differ from HEAD; build from a clean checkout:" >&2
  git status --short --untracked-files=no >&2
  exit 1
fi
epoch=$(git log -1 --format=%ct HEAD)
mkdir -p "$out"
out=$(cd "$out" && pwd)
[ -z "$(ls -A "$out")" ] || { echo "$out is not empty" >&2; exit 1; }

tar_flags=(--create --no-recursion --null --files-from=-
  --mtime="@$epoch" --owner=0 --group=0 --numeric-owner
  --mode='u=rwX,go=rX' --format=gnu)

# pack <name> <path>...: tracked files under the paths, plus LICENSE and
# NOTICE, under a top-level <name>/ directory.
pack() {
  local name=$1; shift
  git ls-files -z -- "$@" LICENSE NOTICE | sort -z \
    | tar "${tar_flags[@]}" --transform="s,^,$name/," \
    | gzip -9n > "$out/$name.tar.gz"
}

# The Go module zip: tracked files in go/ except nested modules, with the
# repo LICENSE and NOTICE when go/ has none, under <module>@<version>/.
pack_go() {
  local version=$1 module
  module=$(awk '$1 == "module" { print $2; exit }' go/go.mod)
  git ls-files -z -- go LICENSE NOTICE | python3 -c '
import sys, time, zipfile, posixpath
out, prefix, epoch = sys.argv[1], sys.argv[2], int(sys.argv[3])
files = [p for p in sys.stdin.read().split("\0") if p]
nested = {posixpath.dirname(p) + "/" for p in files
          if p.startswith("go/") and posixpath.basename(p) == "go.mod" and p != "go/go.mod"}
entries = {}
for p in files:
    if p.startswith("go/") and not any(p.startswith(d) for d in nested):
        entries[p[len("go/"):]] = p
for top in ("LICENSE", "NOTICE"):
    if top not in entries and top in files:
        entries[top] = top
stamp = max(time.gmtime(epoch)[:6], (1980, 1, 1, 0, 0, 0))
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for name in sorted(entries):
        info = zipfile.ZipInfo(prefix + "/" + name, stamp)
        info.external_attr = 0o644 << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        with open(entries[name], "rb") as f:
            z.writestr(info, f.read())
' "$out/fasten-go-$version.zip" "$module@$version" "$epoch"
}

# The fasten-core library and its C header.
pack_core_lib() {
  local name=$1 stage
  stage=$(mktemp -d)
  mkdir -p "$stage/$name/lib" "$stage/$name/include"
  cp "$core_lib/libfasten_core.so" "$core_lib/libfasten_core.a" "$stage/$name/lib/"
  cp fasten-core/include/fasten_core.h "$stage/$name/include/"
  cp LICENSE NOTICE "$stage/$name/"
  (cd "$stage" && find "$name" -type f -print0 | sort -z \
    | tar "${tar_flags[@]}") | gzip -9n > "$out/$name.tar.gz"
  rm -rf "$stage"
}

case $tag in
  go/*)
    pack_go "${tag#go/}"
    ;;
  *)
    pack "fasten-swift-$tag" swift
    pack "fasten-cpp-$tag" cpp/include
    pack "fasten-rust-$tag" rust fasten-core rust-toolchain.toml
    if [ -n "$core_lib" ]; then
      pack_core_lib "fasten-core-$tag-linux-$(uname -m)"
    fi
    ;;
esac

cd "$out"
sums=$(find . -maxdepth 1 -type f -printf '%f\0' | sort -z | xargs -0 sha256sum --)
printf '%s\n' "$sums" > SHA256SUMS
cat SHA256SUMS
