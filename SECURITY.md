# Security Policy

See [docs/security.md](docs/security.md) for the full threat model: trust boundaries, attack surfaces, mitigations in place, and what is explicitly out of scope.

## Supported versions

| Version          | Supported |
|------------------|-----------|
| 1.0.0-beta.x     | Yes       |
| 0.1.0-alpha      | No (superseded) |

Only the latest release receives security fixes. There is no LTS branch before v1.0.0.

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

**No releases have been published to PyPI, npm or crates.io yet.**
v1.0.0-beta is source-only: clone the repo and build from a pinned
commit SHA. The first published release will be the v1.0.0 GA tag.

**Configured, and active from the first published release:**

- PyPI Trusted Publishing (OIDC, no long-lived tokens) with PEP 740
  attestations, in [`release-python.yml`](.github/workflows/release-python.yml).
- npm `--provenance` (linked back to the source commit), in
  [`release-js.yml`](.github/workflows/release-js.yml).
- GitHub artifact attestations (signed with [Sigstore](https://www.sigstore.dev/))
  for every file on a [GitHub release](https://github.com/nerdapplabs/fasten/releases),
  in [`release-provenance.yml`](.github/workflows/release-provenance.yml).
  A `vX.Y.Z` release carries Swift, C++ and Rust source archives and the
  fasten-core library for linux x86_64. A `go/vX.Y.Z` release carries the Go
  module zip. Each release also has a `SHA256SUMS` file. The source archives
  and the Go module zip are reproducible: `scripts/release/build-artifacts.sh
  <tag> <dir>` run on the tagged commit gives the same bytes when built with
  GNU tar, GNU gzip and the stock Python zlib, as CI does on Ubuntu. Other
  compressor builds (zlib-ng, for one) can give different bytes for the same
  content.

**Planned for the v1.0.0 GA tag:**

- A per-language SBOM published with each release.

### Verifying a release

Replace `1.0.0` / `v1.0.0` with the release you install.

Python (PyPI), with [`pypi-attestations`](https://github.com/pypi/pypi-attestations):

```bash
uvx pypi-attestations verify pypi --repository https://github.com/nerdapplabs/fasten \
  pypi:fasten_sdk-1.0.0-py3-none-any.whl
```

JavaScript (npm), in the project that installed `@nerdapplabs/fasten`:

```bash
npm audit signatures
```

GitHub release files (Swift, C++, Rust, fasten-core library), with the
[GitHub CLI](https://cli.github.com/):

```bash
gh release download v1.0.0 --repo nerdapplabs/fasten --dir fasten-v1.0.0
cd fasten-v1.0.0
sha256sum -c SHA256SUMS
for f in *; do
  gh attestation verify "$f" --repo nerdapplabs/fasten --source-ref refs/tags/v1.0.0 \
    --signer-workflow nerdapplabs/fasten/.github/workflows/release-provenance.yml
done
```

Go: the same commands with the `go/v1.0.0` tag and
`--source-ref refs/tags/go/v1.0.0`. The `go` command does not download this
zip; the module proxy builds its own from the tag. To tie the two, compute
the zip's `h1:` hash and compare it with the one `go` records:

```bash
python3 -c 'import sys, zipfile, hashlib, base64
z = zipfile.ZipFile(sys.argv[1])
s = "".join(hashlib.sha256(z.read(n)).hexdigest() + "  " + n + "\n" for n in sorted(z.namelist()))
print("h1:" + base64.b64encode(hashlib.sha256(s.encode()).digest()).decode())' fasten-go-v1.0.0.zip
go mod download -json github.com/nerdapplabs/fasten/go@v1.0.0 | grep '"Sum"'
```

The two `h1:` values must match. The second is also the hash in `go.sum` and
on sum.golang.org for `github.com/nerdapplabs/fasten/go v1.0.0`.

## Current scan posture

Each SDK's dependencies are scanned against the minimum supported
language version (Python 3.10-slim, Go 1.26-alpine, Node 24-alpine). All
three are clean as of the latest scan:

| Language | Scanner          | Status | Notes |
|----------|------------------|--------|-------|
| Python   | `pip-audit`      | Clean  | Zero runtime deps (`dependencies = []` in `pyproject.toml`). Runs in CI on every push and pull request that touches `python/` or `fasten-core/`. CI installs the project and dev deps into a `uv venv`, which has no `pip` / `wheel` to flag, then runs `uvx pip-audit@2.10.1 --path <venv site-packages>` from its own environment, so the audit covers the project venv and not pip-audit's own dependencies. The job fails if site-packages is not found. |
| Go       | `govulncheck`    | Clean  | Three direct deps: `gopkg.in/yaml.v3` (catalog parsing), `modernc.org/sqlite` (CGO-free SQLite driver, which pulls the 13 indirect deps in `go.mod`) and `github.com/lib/pq` (Postgres driver). `govulncheck` reports no advisories against the resolved set. Re-run after any `go.mod` change. |
| JS       | `npm audit`      | Clean  | Zero production deps (`package.json` has an empty `dependencies` block). Uses the `node:async_hooks` and `node:crypto` builtins. `pg` (Postgres store) and `js-yaml` (catalog parsing only) are optional and not installed by default. |

Re-run after adding any dependency: `pip-audit`, `govulncheck ./...`, `npm audit`.

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
