# Security Policy

## Supported versions

| Version          | Supported |
|------------------|-----------|
| 1.0.0-beta.x     | Yes       |
| 0.1.0-alpha      | No (superseded) |

Only the latest release receives security fixes. There is no LTS branch before v1.0.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via [GitHub Security Advisories](https://github.com/nerdapplabs/fasten/security/advisories/new)
or email **praveen.garg@nerdapplabs.com**.

Include:
- Description of the vulnerability and affected component
- Steps to reproduce or proof-of-concept (if available)
- Your assessment of severity / impact

## Response SLA

| Stage             | Target                              |
|-------------------|-------------------------------------|
| Acknowledgement   | 2 business days                     |
| Triage + severity | 5 business days                     |
| Fix or mitigation | 30 days for Critical/High; 90 for Medium/Low |
| Public disclosure | After fix ships, or 90 days from report (whichever is first) |

We follow coordinated disclosure. If you need more time before we disclose, say so in your report.

## CVE assignment

We file CVEs via [GitHub Security Advisories](https://docs.github.com/en/code-security/security-advisories).
GitHub acts as a CNA; advisories are published to the NVD automatically on release.

## Supply-chain attestation

**v1.0.0-beta — planned, not yet shipped.** The following land with the
v1.0 GA tag (tracked in
[issue P1-2](https://github.com/nerdapplabs/fasten/issues)):

- Release artifacts signed with [Sigstore](https://www.sigstore.dev/) cosign;
  verification instructions on each [release](https://github.com/nerdapplabs/fasten/releases).
- PyPI packages via [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC, no long-lived tokens).
- npm packages with `--provenance` (linked back to source commit).
- SBOM published per-language alongside each release.

For now, build from source and pin the commit SHA.

## Current scan posture

CI runs three vulnerability scanners on every push against the
minimum supported language version (Python 3.10-slim, Go 1.22-alpine,
Node 20-alpine). All three are CLEAN as of the latest commit:

| Language | Scanner          | Status | Notes |
|----------|------------------|--------|-------|
| Python   | `pip-audit`      | CLEAN  | Zero runtime deps (`dependencies = []` in `pyproject.toml`). CI uses `uv venv` + `uv pip install`; the resulting venv contains only project + dev deps — no `pip` / `wheel` to flag. |
| Go       | `govulncheck`    | CLEAN  | Zero external deps (`go.mod` declares no `require` block). Stdlib-only: `crypto/rand`, `database/sql`, `encoding/json`, `sync`, `context`. |
| JS       | `npm audit`      | CLEAN  | Zero production deps (`package.json` has no `dependencies` block). Uses `node:async_hooks` + `node:crypto` builtins. |

Re-run after adding any dependency: `pip-audit` · `govulncheck ./...` · `npm audit`.

## Scope

In scope:
- Secret redaction bypass (a key matching `REDACT_PATTERNS` not being redacted)
- `request_id` correlation leakage across tenant boundaries
- SQLite / Postgres injection in store implementations
- Authentication bypass in the reader endpoint
- Supply chain: dependency confusion, typosquatting, compromised build artifacts

Out of scope:
- Denial of service against a service that embeds fasten (fasten is a library, not a network service)
- Vulnerabilities in libraries fasten does not depend on
- Issues in forks or third-party integrations not maintained in this repo
