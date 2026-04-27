# [P0-2] Governance docs for public release: SECURITY.md + CHANGELOG.md

**Priority:** P0 · **Effort:** S · **Labels:** `priority/P0` `area/governance` `area/security`

## What

Two files at `rivet/` root.

**`rivet/SECURITY.md`:**

- Vulnerability disclosure policy
- Security contact email + GPG key fingerprint
- Supported-version matrix (initial: `0.x.x = current latest only`)
- Response SLA — target: triage within 5 business days, fix-or-mitigate within 30
- Embargo handling for coordinated disclosure
- CVE-assignment intent (we file via GitHub Security Advisories)
- Verification recipe for cosign signatures (forward-reference to [P1-2])

**`rivet/CHANGELOG.md`:**

- Keep-a-Changelog 1.1 format
- Single baseline entry: `## [0.1.0-alpha] — YYYY-MM-DD` with three bullets — initial public release · 6 language implementations (Python+Go+JS stable, others experimental) · open-core scope

## Why

Without `SECURITY.md`, the first researcher who finds a redaction bypass posts on Twitter instead of emailing us. Without `CHANGELOG.md`, `cargo publish` / `twine upload` / `npm publish` either fail or ship blank metadata. These are the two cheapest, most-blocking files to move "code in a folder" → "tagged public release."

## Acceptance

- [ ] `rivet/SECURITY.md` committed with fully-resolved fields (no TODOs)
- [ ] GPG key for the security contact published; fingerprint in the file
- [ ] `rivet/CHANGELOG.md` committed with the baseline entry dated
- [ ] Both linked from `rivet/README.md` (Security + Releases sections)

## Related

- **Sister:** [P0-1] (CI references the supported-version matrix declared here)
- **Sister:** [P1-1] (CONTRIBUTING points at SECURITY for vuln reporting)
