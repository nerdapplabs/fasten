# [P0-1] Wire CI: per-language tests + lint + vulnerability scanners

**Priority:** P0 · **Effort:** L · **Labels:** `priority/P0` `area/ci` `area/security`

## What

Three GitHub Actions workflows on every PR + main push, plus the test fixtures they execute, plus the dependency-management infra:

**Workflows** under `rivet/.github/workflows/`:

- `rivet-py.yml` — pytest, ruff, mypy, **`pip-audit`**
- `rivet-go.yml` — `go test -race`, `staticcheck`, **`govulncheck`**
- `rivet-js.yml` — `node --test`, `eslint`, **`npm audit --audit-level=high`**

**Test fixtures:**

- `rivet/python/tests/` — emit roundtrip, register/dump, redact deep-objects, store insert+query, ring-buffer eviction, request_id propagation through `with_request_id` (~6–8 tests)
- `rivet/go/*_test.go` — `Init` validation, slog handler attribute mapping, `SQLiteStore.Insert/Query`, ring-buffer cap (~4–6 tests)
- `rivet/js/test/` — `init()` env reading, `emit()` payload shape, `currentRequestID()` AsyncLocalStorage (~3 tests)

**Dep-management infra:**

- Lockfiles committed: `requirements.lock` (or `uv.lock`), `go.sum` verified, `package-lock.json`
- `rivet/.github/dependabot.yml` covering pip / gomod / npm
- One-shot run of `pip-audit`, `govulncheck`, `npm audit`; fix or document each finding in `rivet/SECURITY-NOTES.md`

Rust / Java / C++ are flagged "experimental" for v0.1.0-alpha (see [README.md](README.md) language readiness) and don't need CI yet — defer their workflows to when each goes stable.

## Why

Today nothing gates a PR. A vuln in a transitive dep ships unnoticed; a regression in `emit()` lands silently. Adopters won't trust an audit library that can't verify its own contract. CI is the cheapest single lever that turns rivet from artisanal into engineered. Unblocks **goal 3** (audit posture) and **goal 2** (releasable) simultaneously.

## Acceptance

- [ ] Three workflows merged and green on the working branch
- [ ] Each workflow fails the build on high-severity vuln-scanner findings
- [ ] Per-language test count meets the targets above; all green
- [ ] Lockfiles committed for Python, Go, JS
- [ ] `dependabot.yml` opens its first auto-PR within a week of landing
- [ ] `SECURITY-NOTES.md` either empty (clean) or documents every known finding with planned fix-by date

## Related

- **Blocks:** [P0-2] (CHANGELOG references CI ground truth), [P0-3] (smoke tests build on this scaffolding)
- **Sister:** [P1-2] adds SBOM + signing on top of the CI baseline this issue lays
