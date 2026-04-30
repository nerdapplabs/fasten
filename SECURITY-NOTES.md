# Security Scan Notes

Findings from `pip-audit`, `govulncheck`, and `npm audit` run in CI against the minimum
supported language versions (Python 3.10-slim, Go 1.22-alpine, Node 20-alpine).

## Python (`pip-audit`)

**Status: CLEAN (after toolchain upgrade)**

fasten's Python SDK has zero runtime dependencies (`dependencies = []` in pyproject.toml).
Dev dependencies (pytest, ruff, mypy, pip-audit) are not shipped. No findings expected
in fasten itself.

`pip-audit` scans the entire interpreter environment, so on the `python:3.10-slim` base
image it would otherwise flag the bundled `pip` (23.0.1) and `wheel` (0.45.1). The CI
workflow runs `python -m pip install --upgrade pip wheel setuptools` before any other
step, which clears PYSEC-2023-228, CVE-2025-8869, CVE-2026-1703, and CVE-2026-24049.

**Currently ignored:** `CVE-2026-3219` (pip) — no fix version published upstream yet.
Tracked via `--ignore-vuln CVE-2026-3219` in `.github/workflows/fasten-py.yml`. Remove
the flag once a fixed pip release lands.

## Go (`govulncheck`)

**Status: CLEAN**

fasten's Go SDK has zero external dependencies (`go.mod` declares no `require` block).
stdlib-only: `crypto/rand`, `database/sql`, `encoding/json`, `sync`, `context`.

## JS (`npm audit`)

**Status: CLEAN**

fasten's JS SDK has zero production dependencies. `package.json` declares no `dependencies`
block. `node:async_hooks` and `node:crypto` are Node.js builtins.

---

*Last updated: 2026-05-01. Re-run `pip-audit` / `govulncheck ./...` / `npm audit` after
adding any dependency.*
