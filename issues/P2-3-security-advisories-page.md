# [P2-3] Public security advisories page

**Priority:** P2 · **Effort:** S · **Labels:** `priority/P2` `area/security` `area/docs`

## What

`rivet/website/docs/advisories.md` — auto-generated from GitHub Security Advisories (GHSA). Index of past CVEs with:

- CVE / GHSA identifier
- Affected versions
- Severity (CVSS)
- Mitigation / fixed-in version
- Discovery credit

Generation script: small GH API caller (Python or Go) that runs as a CI job whenever a GHSA is published, regenerates the markdown, commits via bot. Or use GitHub's built-in advisories page and just link from `rivet/website/docs/`.

## Why

Transparency on past issues builds trust faster than silence. Adopters who can read the history are more confident than those who must ask. Pulls double-duty as a forcing-function for actually using GitHub Security Advisories properly when issues arise — without a public advisories page, the temptation to "just patch quietly" is strong, and that erodes trust the moment it leaks.

## Acceptance

- [ ] `advisories.md` page exists; auto-publishes from GHSA on merge of any new advisory
- [ ] Linked from `rivet/SECURITY.md` and from the website's docs nav
- [ ] Either backfill says "No advisories yet" or lists every known issue (none expected at v0.1.0-alpha)

## Related

- **Depends on:** [P0-2] (SECURITY.md establishes the disclosure flow)
- **Sister:** [P1-3] (any bypass found during adversarial-test development should be filed as a GHSA → appears on this page)
