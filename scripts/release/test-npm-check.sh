#!/usr/bin/env bash
# Cases for npm-check.sh, against a stand-in for the npm command.
set -euo pipefail

dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0

mkdir -p "$tmp/pkg"
printf '{"name":"@nerdapplabs/fasten","version":"1.0.0"}\n' > "$tmp/pkg/package.json"

# The stand-in answers `npm view` from VIEW_OUT, VIEW_ERR and VIEW_RC, and
# `npm pack --dry-run --json` with the integrity in PACK.
cat > "$tmp/npm" <<'EOF'
#!/usr/bin/env bash
case $1 in
  view) printf '%s' "${VIEW_OUT:-}"; printf '%s' "${VIEW_ERR:-}" >&2; exit "${VIEW_RC:-0}" ;;
  pack) printf '[{"integrity":"%s"}]\n' "$PACK" ;;
esac
EOF
chmod +x "$tmp/npm"
export NPM="$tmp/npm" PACK=sha512-built

check() { # check <publish|skip|fail> <case>
  local got
  got=$("$dir/npm-check.sh" "$tmp/pkg" 2>/dev/null) || got=fail
  if [ "$got" != "$1" ]; then
    echo "FAIL: $2: got $got, want $1"
    fail=1
  fi
}

VIEW_OUT= VIEW_ERR= VIEW_RC=0 check publish "version not on npm"
VIEW_OUT= VIEW_ERR='npm error code E404' VIEW_RC=1 check publish "package never published"
VIEW_OUT=sha512-built VIEW_ERR= VIEW_RC=0 check skip "same tarball on npm"
VIEW_OUT=sha512-other VIEW_ERR= VIEW_RC=0 check fail "different tarball on npm"
VIEW_OUT= VIEW_ERR='npm error code ETIMEDOUT' VIEW_RC=1 check fail "registry unreachable"
VIEW_OUT= VIEW_ERR='npm error code E500' VIEW_RC=1 check fail "registry error"

[ "$fail" -eq 0 ] || exit 1
echo "npm-check: ok"
