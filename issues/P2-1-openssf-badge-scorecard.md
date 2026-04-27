# [P2-1] OpenSSF Best Practices Silver + Scorecard CI

**Priority:** P2 · **Effort:** M · **Labels:** `priority/P2` `area/governance` `area/security`

## What

**OpenSSF Best Practices badge — Silver level:**

- Complete the Silver criteria at <https://www.bestpractices.dev/>
- Most criteria are already met after [P0-1] / [P0-2] / [P1-1] land — Silver requires CONTRIBUTING, SECURITY, CHANGELOG, CI tests, vuln scanning, etc.
- Display the earned badge on `rivet/README.md`

**OpenSSF Scorecard GitHub Action:**

- `rivet/.github/workflows/scorecard.yml` — weekly schedule + on push to main
- Uploads results as a GitHub Security tab finding
- Target: ≥ 7.0 score
- Findings either fixed or filed as follow-up issues

## Why

OpenSSF Best Practices Silver signals that rivet follows industry-baseline practices — free credibility for security-conscious adopters. Scorecard catches regressions in posture (signed commits, branch protection, pinned deps) continuously, not point-in-time. Both are essentially "free" once [P0-1] / [P1-1] land — the prerequisites are already done.

## Acceptance

- [ ] OpenSSF Best Practices Silver badge earned and displayed on `rivet/README.md`
- [ ] `scorecard.yml` workflow merged; first run completes
- [ ] Scorecard score ≥ 7.0
- [ ] Each Scorecard finding ≤ score 7 either fixed or filed as a follow-up issue

## Related

- **Depends on:** [P0-1], [P0-2], [P1-1] (most prerequisites)
- **Sister:** [P2-2] (SLSA L1 complements Scorecard's supply-chain criteria)
