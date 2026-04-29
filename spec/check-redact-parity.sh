#!/usr/bin/env bash
# check-redact-parity.sh — verify every language adapter contains each key
# from spec/redact-keys.txt.
#
# Run from repo root:
#   bash spec/check-redact-parity.sh
#
# Exit code: 0 = all keys present in all adapters, 1 = missing keys found.

set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SPEC="$REPO/spec/redact-keys.txt"

# Read canonical keys (skip blank lines and comments). bash 3.2-compatible.
KEYS=()
while IFS= read -r line; do
    KEYS+=("$line")
done < <(grep -v '^\s*#' "$SPEC" | grep -v '^\s*$')

failures=0

check_adapter() {
    local lang="$1"
    local file="$2"
    local missing=()

    if [ ! -f "$file" ]; then
        printf "  ? %-10s %s  (file not found)\n" "$lang" "$file"
        return
    fi

    for key in "${KEYS[@]}"; do
        if ! grep -qF "$key" "$file"; then
            missing+=("$key")
        fi
    done

    if [ ${#missing[@]} -eq 0 ]; then
        printf "  ✓ %-10s %s\n" "$lang" "$file"
    else
        printf "  ✗ %-10s %s\n" "$lang" "$file"
        for k in "${missing[@]}"; do
            echo "      missing: $k"
        done
        failures=$((failures + ${#missing[@]}))
    fi
}

todo_adapter() {
    local lang="$1"
    local file="$2"
    printf "  - %-10s %s  (redact not yet implemented)\n" "$lang" "$file"
}

echo "fasten redact-key parity check"
echo "spec: $SPEC  (${#KEYS[@]} keys)"
echo ""

check_adapter "python"  "$REPO/python/fasten/redact.py"
check_adapter "c++"     "$REPO/cpp/include/fasten.hpp"

# Unimplemented — flagged as informational, not failures.
todo_if_unimplemented() {
    local lang="$1"; local file="$2"; local label="${3:-$file}"
    if [ -f "$file" ] && grep -q 'TODO.*redact' "$file"; then
        todo_adapter "$lang" "$label"
    fi
}
todo_if_unimplemented "go"   "$REPO/go/fasten.go"
todo_if_unimplemented "js"   "$REPO/js/src/index.js"
todo_if_unimplemented "rust" "$REPO/rust/src/lib.rs"
todo_if_unimplemented "java" "$REPO/java/src/main/java/sh/fasten/Fasten.java" "java/.../Fasten.java"

echo ""
if [ "$failures" -eq 0 ]; then
    echo "All implemented adapters contain every key from spec/redact-keys.txt"
    exit 0
else
    echo "$failures key(s) missing — add them to the adapter(s) shown above"
    exit 1
fi
