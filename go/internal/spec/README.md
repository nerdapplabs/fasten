# go/internal/spec — mirrored DDL fragments

These files are **byte-for-byte mirrors** of the canonical spec at
[../../../spec/](../../../spec/). The mirror exists purely because Go's
`//go:embed` cannot reach files outside the module tree.

Every schema change lands in `spec/` first. Run `spec/sync-to-go.sh` (or
the equivalent one-liner in `Makefile`) to refresh this mirror, then
commit both directories together. A CI check compares hashes and fails
if they diverge — never edit these files directly.
