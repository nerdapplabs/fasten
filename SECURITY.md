# Security Policy

## Supported versions

| Version       | Supported |
|---------------|-----------|
| 0.x (current) | Yes       |
| < 0.1.0-alpha | No        |

Only the latest release receives security fixes. There is no LTS branch before v1.0.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via [GitHub Security Advisories](https://github.com/nerdapplabs/fasten/security/advisories/new)
or email **security@nerdapplabs.com**.

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

## Verification (supply chain)

Release artifacts are signed with [Sigstore](https://www.sigstore.dev/) cosign.
Verification instructions are published with each release on the
[Releases page](https://github.com/nerdapplabs/fasten/releases).
PyPI packages use [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC, no long-lived tokens).
npm packages use `--provenance` (linked back to the source commit).

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
