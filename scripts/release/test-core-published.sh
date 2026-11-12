#!/usr/bin/env bash
# Cases for core-published.sh, against a local stand-in for crates.io.
set -euo pipefail

dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
pid=
trap '[ -z "$pid" ] || kill "$pid"; rm -rf "$tmp"' EXIT
fail=0

mkdir -p "$tmp/www/index/fa/st" "$tmp/www/dl/fasten-core" "$tmp/crate/src"
# Paths under /fail/ answer 500; under /short/, a 200 whose body is cut off.
python3 -c '
import functools, http.server, sys
class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path.startswith("/fail/"):
            self.send_error(500)
        elif self.path.startswith("/short/"):
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            self.wfile.write(b"{")
            self.wfile.flush()
            self.close_connection = True
        else:
            super().do_GET()
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

check() { # check <publish|skip|differs|fail> <case> [<stderr pattern>]
  local got rc=0
  got=$("$dir/core-published.sh" "$tmp/crate" 2>"$tmp/err") || rc=$?
  case $rc in 0) ;; 3) got=differs ;; *) got=fail ;; esac
  if [ "$got" != "$1" ]; then
    echo "FAIL: $2: got $got, want $1"
    cat "$tmp/err"
    fail=1
  elif [ $# -ge 3 ] && ! grep -q "$3" "$tmp/err"; then
    echo "FAIL: $2: stderr has no '$3'"
    cat "$tmp/err"
    fail=1
  fi
}

changed="::error::fasten-core changed since 0.1.0 was published"

check publish "not on crates.io"
CRATES_INDEX="$url/fail/index" check fail "index answers 500" "::error::crates.io index returned 500"
CRATES_INDEX="http://127.0.0.1:1" check fail "index unreachable" "::error::could not read the crates.io index"
CRATES_INDEX="$url/short/index" check fail "index cut off mid-body" "::error::could not read the crates.io index"
printf '{"name":"fasten-core","vers":"0.0.9"}\n' > "$tmp/www/index/fa/st/fasten-core"
check publish "another version on crates.io"
publish
check skip "same files on crates.io"
CRATES_DL="$url/fail/dl" check fail "published .crate download fails" "::error::could not download fasten-core 0.1.0"
cp "$tmp/www/index/fa/st/fasten-core" "$tmp/index.bak"
printf '{"name":"fasten-core","vers":"0.0.9"}\n{"name":"fasten-core","vers":"0.1.0","yanked":true}\n' \
  > "$tmp/www/index/fa/st/fasten-core"
check differs "same files, version yanked" "::error::fasten-core 0.1.0 is yanked on crates.io"
cp "$tmp/index.bak" "$tmp/www/index/fa/st/fasten-core"
touch "$tmp/crate/src/lib.rs"
check skip "same files, newer mtime"
echo 'pub fn g() -> u8 { 2 }' >> "$tmp/crate/src/lib.rs"
check differs "source changed" "$changed"
RELEASE_CHECK_LEVEL=warning check differs "source changed, as a warning" "::warning::fasten-core changed since 0.1.0"
echo 'pub fn f() -> u8 { 1 }' > "$tmp/crate/src/lib.rs"
echo 'pub fn h() {}' > "$tmp/crate/src/extra.rs"
check differs "file added" "$changed"
rm "$tmp/crate/src/extra.rs"
printf 'readme = false\n' >> "$tmp/crate/Cargo.toml"
check differs "manifest changed" "$changed"

[ "$fail" -eq 0 ] || exit 1
echo "core-published: ok"
