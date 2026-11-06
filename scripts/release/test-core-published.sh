#!/usr/bin/env bash
# Cases for core-published.sh, against a local stand-in for crates.io.
set -euo pipefail

dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
pid=
trap '[ -z "$pid" ] || kill "$pid"; rm -rf "$tmp"' EXIT
fail=0

mkdir -p "$tmp/www/index/fa/st" "$tmp/www/dl/fasten-core" "$tmp/crate/src"
python3 -c '
import functools, http.server, sys
class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
s = http.server.HTTPServer(("127.0.0.1", 0), functools.partial(H, directory=sys.argv[1]))
open(sys.argv[2], "w").write(str(s.server_port))
s.serve_forever()
' "$tmp/www" "$tmp/port" &
pid=$!
for _ in $(seq 50); do [ -s "$tmp/port" ] && break; sleep 0.1; done
url="http://127.0.0.1:$(cat "$tmp/port")"
export CRATES_INDEX="$url/index" CRATES_DL="$url/dl"

printf '[package]\nname = "fasten-core"\nversion = "0.1.0"\nedition = "2021"\nlicense = "Apache-2.0"\ndescription = "test"\n' \
  > "$tmp/crate/Cargo.toml"
echo 'pub fn f() -> u8 { 1 }' > "$tmp/crate/src/lib.rs"

# Publish the tree as it is now: the .crate and an index line.
publish() {
  (cd "$tmp/crate" && CARGO_TARGET_DIR="$tmp/target" cargo package -q --no-verify --allow-dirty)
  cp "$tmp/target/package/fasten-core-0.1.0.crate" "$tmp/www/dl/fasten-core/"
  printf '{"name":"fasten-core","vers":"0.1.0"}\n' >> "$tmp/www/index/fa/st/fasten-core"
}

check() { # check <publish|skip|fail> <case>
  local got
  got=$("$dir/core-published.sh" "$tmp/crate" 2>/dev/null) || got=fail
  if [ "$got" != "$1" ]; then
    echo "FAIL: $2: got $got, want $1"
    fail=1
  fi
}

check publish "not on crates.io"
printf '{"name":"fasten-core","vers":"0.0.9"}\n' > "$tmp/www/index/fa/st/fasten-core"
check publish "another version on crates.io"
publish
check skip "same files on crates.io"
touch "$tmp/crate/src/lib.rs"
check skip "same files, newer mtime"
echo 'pub fn g() -> u8 { 2 }' >> "$tmp/crate/src/lib.rs"
check fail "source changed"
echo 'pub fn f() -> u8 { 1 }' > "$tmp/crate/src/lib.rs"
echo 'pub fn h() {}' > "$tmp/crate/src/extra.rs"
check fail "file added"
rm "$tmp/crate/src/extra.rs"
printf 'readme = false\n' >> "$tmp/crate/Cargo.toml"
check fail "manifest changed"

[ "$fail" -eq 0 ] || exit 1
echo "core-published: ok"
