#!/usr/bin/env bash
# Cases for pypi-check.py, against a local stand-in for the PyPI JSON API.
set -euo pipefail

dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
pid=
trap '[ -z "$pid" ] || kill "$pid"; rm -rf "$tmp"' EXIT
fail=0

mkdir -p "$tmp/www" "$tmp/dist"
# Paths under /fail/ answer 500.
python3 -c '
import functools, http.server, sys
class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path.startswith("/fail/"):
            self.send_error(500)
        else:
            super().do_GET()
s = http.server.HTTPServer(("127.0.0.1", 0), functools.partial(H, directory=sys.argv[1]))
open(sys.argv[2], "w").write(str(s.server_port))
s.serve_forever()
' "$tmp/www" "$tmp/port" &
pid=$!
for _ in $(seq 50); do [ -s "$tmp/port" ] && break; sleep 0.1; done
url="http://127.0.0.1:$(cat "$tmp/port")"

whl=fasten_sdk-1.0.0-py3-none-any.whl
abi3=fasten_sdk-1.0.0-cp310-abi3-manylinux_2_34_x86_64.whl
sha() { python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())' "$1"; }

build() { # build <filename>... : dist holds these files, each containing "built"
  rm -f "$tmp/dist"/*
  for f in "$@"; do echo built > "$tmp/dist/$f"; done
}

# Serve a PyPI version page listing each <filename> with the sha256 of
# <content>; with no arguments, the version is not on PyPI.
serve() { # serve [<filename> <content>]...
  rm -rf "$tmp/www/fasten-sdk"
  [ $# -gt 0 ] || return 0
  local urls=
  while [ $# -gt 0 ]; do
    urls="$urls${urls:+,}{\"filename\":\"$1\",\"digests\":{\"sha256\":\"$(sha "$2")\"}}"
    shift 2
  done
  mkdir -p "$tmp/www/fasten-sdk/1.0.0"
  printf '{"urls":[%s]}' "$urls" > "$tmp/www/fasten-sdk/1.0.0/json"
}

check() { # check <exit> <case> [<stderr pattern>]
  local got=0
  PYPI_URL=${base:-$url} "$dir/pypi-check.py" "$tmp/dist" >/dev/null 2>"$tmp/err" || got=$?
  if [ "$got" != "$1" ]; then
    echo "FAIL: $2: exit $got, want $1"
    fail=1
  elif [ $# -ge 3 ] && ! grep -q "$3" "$tmp/err"; then
    echo "FAIL: $2: stderr has no '$3'"
    cat "$tmp/err"
    fail=1
  else
    echo "ok: $2"
  fi
}

built=$'built\n'
build "$whl"
serve
check 0 "version not on PyPI"
serve "$whl" "$built"
check 0 "same file already on PyPI"
serve "$whl" $'other\n'
check 1 "same file name, different bytes" "::error::$whl on PyPI has sha256"
serve "$abi3" $'other\n'
check 1 "only other files on PyPI" "::error::$abi3 is on PyPI for 1.0.0 but not in this build"
serve "$whl" "$built" "$abi3" $'other\n'
check 1 "same file on PyPI, plus one not in this build" "::error::$abi3 is on PyPI for 1.0.0 but not in this build"

build "$whl" "$abi3"
serve "$whl" "$built"
check 0 "one file on PyPI and the same, one not there yet"
serve "$whl" "$built" "$abi3" $'other\n'
check 1 "one file the same, one different" "::error::$abi3 on PyPI has sha256"
serve "$abi3" $'other\n'
check 1 "first file not there yet, second different" "::error::$abi3 on PyPI has sha256"

build "$whl"
mkdir -p "$tmp/www/fasten-sdk/1.0.0"
echo '{}' > "$tmp/www/fasten-sdk/1.0.0/json"
check 1 "version page without urls" "unexpected response"
echo 'not json' > "$tmp/www/fasten-sdk/1.0.0/json"
check 1 "version page not JSON" "unexpected response"
base="$url/fail" check 1 "PyPI answers 500" "HTTP Error 500"
base="http://127.0.0.1:1" check 1 "PyPI unreachable" "::error::http://127.0.0.1:1/"
build "$whl" fasten_sdk-1.0.0.tar.gz
check 1 "sdist in dist" "only wheels are checked"
build
check 1 "no wheels" "no wheels"

exit "$fail"
