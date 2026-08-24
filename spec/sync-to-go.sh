#!/usr/bin/env bash
# ARCH #3 — refresh the go/internal/spec/ mirror from the canonical
# spec/ directory. Run after every edit to spec/audit_log.*.sql; commit
# both trees together. A CI check compares hashes and fails on drift.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
mirror="$here/../go/internal/spec"
mkdir -p "$mirror"
for f in audit_log.sqlite.sql audit_log.postgres.sql; do
  cp "$here/$f" "$mirror/$f"
done
echo "synced spec/{sqlite,postgres}.sql -> go/internal/spec/"
