# [P1-1] Community governance: CONTRIBUTING + DCO + Code of Conduct

**Priority:** P1 · **Effort:** S · **Labels:** `priority/P1` `area/governance` `area/community`

## What

Two files at `rivet/` root plus a CI gate.

**`rivet/CONTRIBUTING.md`:**

- PR flow (branch from `main`, semantic commits, small PRs preferred)
- Branch naming convention
- DCO sign-off requirement (`Signed-off-by:` line via `git commit -s`)
- Test-running instructions per language (mirrors [P0-1] workflows)
- Code-style links per language (ruff for Python, gofmt + staticcheck for Go, eslint for JS)

**`rivet/CODE_OF_CONDUCT.md`:** Contributor Covenant 2.1 verbatim. Enforcement contact = same address as `SECURITY.md`.

**CI:** add `dco-check` (or equivalent GitHub Action) on every PR to enforce sign-off.

## Why

Community contributions arrive as soon as the repo is publicly indexed. Without `CONTRIBUTING.md`, PRs are stylistically inconsistent and the maintainer burns review time on form rather than substance. DCO is the lightweight alternative to a CLA — Linux kernel and k8s precedent — and avoids the legal-review burden a full CLA imposes on small contributors. Code of Conduct pre-empts community issues and is a prerequisite for the OpenSSF Best Practices badge in [P2-1].

## Acceptance

- [ ] `rivet/CONTRIBUTING.md` committed; linked from `README.md` and from issue/PR templates
- [ ] `rivet/CODE_OF_CONDUCT.md` committed (Contributor Covenant 2.1 verbatim)
- [ ] DCO check enforced via GitHub Action on every PR
- [ ] Issue + PR templates include a checkbox: "I have signed off my commits"

## Related

- **Depends on:** [P0-2] (CONTRIBUTING references SECURITY.md for vuln-disclosure flow)
- **Unblocks:** [P2-1] (OpenSSF Silver requires CoC + CONTRIBUTING)
