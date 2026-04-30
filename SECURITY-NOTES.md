# Security Scan Notes

Findings from `pip-audit`, `govulncheck`, and `npm audit` run in CI against the minimum
supported language versions (Python 3.10-slim, Go 1.22-alpine, Node 20-alpine).

## Python (`pip-audit`)

**Status: CLEAN**

fasten's Python SDK has zero runtime dependencies (`dependencies = []` in pyproject.toml).
Dev dependencies (pytest, ruff, mypy, pip-audit) are not shipped. No findings expected.

## Go (`govulncheck`)

**Status: CLEAN**

fasten's Go SDK has zero external dependencies (`go.mod` declares no `require` block).
stdlib-only: `crypto/rand`, `database/sql`, `encoding/json`, `sync`, `context`.

## JS (`npm audit`)

**Status: CLEAN**

fasten's JS SDK has zero production dependencies. `package.json` declares no `dependencies`
block. `node:async_hooks` and `node:crypto` are Node.js builtins.

---

*Last updated: 2026-04-30. Re-run `pip-audit` / `govulncheck ./...` / `npm audit` after
adding any dependency.*
