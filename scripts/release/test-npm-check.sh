#!/usr/bin/env bash
# Cases for npm-check.sh, against a stand-in for the npm command.
set -euo pipefail

dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0

mkdir -p "$tmp/pkg"
printf '{"name":"@nerdapplabs/fasten","version":"1.0.0"}\n' > "$tmp/pkg/package.json"

# The stand-in answers `npm view <name>@<version> dist.integrity` from
# VIEW_OUT, VIEW_ERR and VIEW_RC, and `npm pack --dry-run --json` with
# PACK_OUT (default: a pack result with the integrity in PACK) and PACK_RC.
# Any other command line exits 99.
cat > "$tmp/npm" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  'view @nerdapplabs/fasten@1.0.0 dist.integrity')
    printf '%s' "${VIEW_OUT:-}"; printf '%s' "${VIEW_ERR:-}" >&2; exit "${VIEW_RC:-0}" ;;
  'pack --dry-run --json')
    if [ -n "${PACK_OUT:-}" ]; then
      printf '%s\n' "$PACK_OUT"
    else
      printf '[{"integrity":"%s"}]\n' "$PACK"
    fi
    exit "${PACK_RC:-0}" ;;
  *) echo "unexpected: npm $*" >&2; exit 99 ;;
esac
EOF
chmod +x "$tmp/npm"
export NPM="$tmp/npm" PACK=sha512-built

check() { # check <publish|skip|fail> <case> [<stderr pattern>]
  local got
  got=$("$dir/npm-check.sh" "$tmp/pkg" 2>"$tmp/err") || got=fail
  if [ "$got" != "$1" ]; then
    echo "FAIL: $2: got $got, want $1"
    cat "$tmp/err"
    fail=1
  elif grep -q '^unexpected: npm' "$tmp/err"; then
    echo "FAIL: $2: npm-check.sh ran an unexpected npm command"
    cat "$tmp/err"
    fail=1
  elif [ $# -ge 3 ] && ! grep -q "$3" "$tmp/err"; then
    echo "FAIL: $2: stderr has no '$3'"
    cat "$tmp/err"
    fail=1
  fi
}

# What npm 11 prints for a missing version and a never-published package.
missing=$'npm error code E404\nnpm error 404 No match found for version 1.0.0\n'
never=$'npm error code E404\nnpm error 404 Not Found - GET https://registry.npmjs.org/@nerdapplabs%2ffasten - Not found\n'

VIEW_OUT= VIEW_ERR="$missing" VIEW_RC=1 check publish "version not on npm"
VIEW_OUT= VIEW_ERR= VIEW_RC=0 check publish "version not on npm (older npm)"
VIEW_OUT= VIEW_ERR="$never" VIEW_RC=1 check publish "package never published"
VIEW_OUT=sha512-built VIEW_ERR= VIEW_RC=0 check skip "same tarball on npm"
VIEW_OUT=sha512-other VIEW_ERR= VIEW_RC=0 check fail "different tarball on npm" "has integrity sha512-other, this build has sha512-built"
VIEW_OUT= VIEW_ERR='npm error code ETIMEDOUT' VIEW_RC=1 check fail "registry unreachable" "npm view .* failed"
VIEW_OUT= VIEW_ERR='npm error code E500' VIEW_RC=1 check fail "registry error" "npm view .* failed"
VIEW_OUT= VIEW_ERR='npm error code E404' VIEW_RC=1 check fail "other 404" "npm view .* failed"
VIEW_OUT=sha512-built VIEW_ERR= VIEW_RC=0 PACK_RC=1 check fail "npm pack fails"
VIEW_OUT=sha512-built VIEW_ERR= VIEW_RC=0 PACK_OUT='not json' check fail "npm pack prints no JSON" "SyntaxError"

[ "$fail" -eq 0 ] || exit 1
echo "npm-check: ok"
