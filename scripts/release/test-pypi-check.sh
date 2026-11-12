#!/usr/bin/env bash
# Cases for pypi-check.py, against a local stand-in for the PyPI JSON API.
set -euo pipefail

dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
pid=
trap '[ -z "$pid" ] || kill "$pid"; rm -rf "$tmp"' EXIT
fail=0

mkdir -p "$tmp/www" "$tmp/dist"
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
export PYPI_URL="http://127.0.0.1:$(cat "$tmp/port")"

whl=fasten_sdk-1.0.0-py3-none-any.whl
echo built > "$tmp/dist/$whl"
sha() { python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())' "$1"; }

# Serve a PyPI version page listing <filename> with the sha256 of <content>.
serve() { # serve <filename> <content>
  mkdir -p "$tmp/www/fasten-sdk/1.0.0"
  printf '{"urls":[{"filename":"%s","digests":{"sha256":"%s"}}]}' "$1" "$(sha "$2")" \
    > "$tmp/www/fasten-sdk/1.0.0/json"
}

check() { # check <0|1> <case>
  local got=0
  "$dir/pypi-check.py" "$tmp/dist" >/dev/null 2>&1 || got=$?
  if [ "$got" != "$1" ]; then
    echo "FAIL: $2: exit $got, want $1"
    fail=1
  else
    echo "ok: $2"
  fi
}

check 0 "version not on PyPI"
serve "$whl" $'built\n'
check 0 "same file already on PyPI"
serve "$whl" $'other\n'
check 1 "same file name, different bytes"
serve fasten_sdk-1.0.0-cp310-abi3-manylinux_2_34_x86_64.whl $'other\n'
check 0 "only other files on PyPI"

exit "$fail"
