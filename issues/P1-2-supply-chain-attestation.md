# [P1-2] Supply-chain attestation: SBOM + cosign-signed releases

**Priority:** P1 · **Effort:** M · **Labels:** `priority/P1` `area/supply-chain` `area/security`

## What

Both attached to every GitHub Release as artifacts:

**SBOM (CycloneDX 1.4):**

- Python: `cyclonedx-py` against the wheel
- Go: `cyclonedx-gomod`
- JS: `cyclonedx-npm`

**Sigstore cosign signing:**

- Sign every release artifact (`.whl`, `.tar.gz`, `.jar`, npm tarball, `.crate`)
- Keyless via OIDC (preferred) — uses GitHub Actions identity, no key custody required
- Fallback: org GPG key if keyless unavailable
- Verification command published in `rivet/SECURITY.md`

Land both under a single `rivet-release.yml` reusable workflow triggered on tag push.

## Why

Enterprise / regulated buyers (HIPAA, FedRAMP, SOC 2) increasingly require an SBOM with the artifact — without it, rivet fails procurement at the buyer segment most likely to pay for the rivet Cloud upsell. Cosign-signed releases let adopters verify provenance against typosquatting and supply-chain attacks; also a SLSA Level 2 prereq when [P2-2] graduates from L1 → L2 later.

## Acceptance

- [ ] CI release workflow attaches CycloneDX SBOMs (one per language) to GitHub Releases
- [ ] CI release workflow signs every artifact with cosign keyless
- [ ] `rivet/SECURITY.md` documents the SBOM + signature verification recipe
- [ ] At least one tagged release (e.g., `v0.1.0-alpha`) ships with both attached
- [ ] One adopter-facing test: `cosign verify` succeeds against the published artifact

## Related

- **Depends on:** [P0-1] (CI scaffolding), [P0-2] (SECURITY.md verification recipe lives here), [P1-4] (publish workflows are the trigger)
- **Unblocks:** [P2-2] (SLSA L1 builds on signed releases)
