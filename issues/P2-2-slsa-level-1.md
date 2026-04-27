# [P2-2] SLSA Level 1 attestation

**Priority:** P2 · **Effort:** M · **Labels:** `priority/P2` `area/supply-chain`

## What

Adopt the SLSA reusable workflow producing build provenance per release. Attach attestation to every GitHub Release alongside SBOM + cosign signature from [P1-2].

- `slsa-framework/slsa-github-generator/.github/workflows/generic_generator.yml` for non-language-specific artifacts
- Language-specific generators where available (`slsa-github-generator/python_generator`, `go_generator`)
- Attestation verifiable via `slsa-verifier verify-artifact` against the released package

## Why

Baseline supply-chain attestation. Many compliance frameworks (NIST SSDF, EU Cyber Resilience Act anticipated regulations) now reference SLSA. L1 is the cheapest level — it just requires automated provenance generation, no isolated build environment yet. Crosses one important credibility threshold for enterprise/regulated adopters without significant infra investment. Reproducible-build attestation (a separate harder problem) is **explicitly out of scope** here — defer to post-1.0.

## Acceptance

- [ ] SLSA L1 provenance attached to a release (alongside SBOM and signature)
- [ ] `slsa-verifier` confirms the attestation against the artifact
- [ ] `rivet/SECURITY.md` updated with verification recipe

## Related

- **Depends on:** [P1-2] (signed releases are a SLSA prereq)
- **Out of scope:** reproducible builds, SLSA L2/L3 (would require isolated builders + provenance verification at install time — defer)
