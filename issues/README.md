# rivet — issues index

16 issues covering release-readiness + audit posture for `v0.1.0-alpha`
public tag and beyond. Each file is the body of one GitHub issue, ready
for `gh issue create`.

| #     | Issue                                                                               | Effort |
|-------|-------------------------------------------------------------------------------------|--------|
| 🔴 **P0 — release-blocking**                                                                                          |
| P0-1  | [Wire CI: per-language tests + lint + vulnerability scanners](P0-1-ci-tests-lockfiles.md) | L      |
| P0-2  | [Governance docs: SECURITY.md + CHANGELOG.md](P0-2-governance-docs.md)              | S      |
| P0-3  | [End-to-end smoke tests in edge / edge-sync / edge-manager](P0-3-end-to-end-smoke.md) | M      |
| P0-4  | [Secured reader: `X-Rivet-Key` + CORS + bundled-tools auth](P0-4-secured-reader.md) | M      |
| P0-5  | [Honest CLI: implement doctor + tail; require RIVET_AUDIT_DSN](P0-5-honest-cli.md) | S      |
| 🟠 **P1 — before v1.0 / first paid customer**                                                                          |
| P1-1  | [Community governance: CONTRIBUTING + DCO + Code of Conduct](P1-1-community-governance.md) | S      |
| P1-2  | [Supply-chain attestation: SBOM + cosign-signed releases](P1-2-supply-chain-attestation.md) | M      |
| P1-3  | [Security depth: threat model + multi-tenant + PII adversarial tests](P1-3-security-depth.md) | M      |
| P1-4  | [Release process: API stability + per-language publish workflows](P1-4-release-workflows.md) | M      |
| P1-5  | [Enforce `pii_in_detail` (not just advisory)](P1-5-pii-flag-enforcement.md)         | S      |
| P1-6  | [Copy honesty pass: README + website match code reality](P1-6-copy-honesty-pass.md) | S      |
| 🟡 **P2 — OSS prestige**                                                                                              |
| P2-1  | [OpenSSF Best Practices Silver + Scorecard CI](P2-1-openssf-badge-scorecard.md)     | M      |
| P2-2  | [SLSA Level 1 attestation](P2-2-slsa-level-1.md)                                    | M      |
| P2-3  | [Public security advisories page](P2-3-security-advisories-page.md)                 | S      |
| P2-4  | [C++ ecosystem packaging (when C++ stabilises)](P2-4-cpp-ecosystem-packaging.md)    | L      |
| P2-5  | [Adoption case studies + blog content](P2-5-adoption-case-studies.md)               | M      |

**Effort key:** S = ≤1 day · M = 2–5 days · L = 1+ sprints.

## Sequencing

**P0 order:** P0-1 → P0-2 → P0-5 → P0-4 → P0-3.

- **P0-1** is the heaviest; it unblocks goals 2 (releasable) and 3
  (audit posture) simultaneously.
- **P0-2** is half a day of mostly-template work — crosses the line
  from "can't release" to "can tag v0.1.0-alpha".
- **P0-5** lands `rivet doctor` + `rivet tail` (currently advertised as
  bundled but stubbed), and removes the silent in-memory fallback
  (`init()` now requires `RIVET_AUDIT_DSN` — audit data must be
  durable). Pure first-impression hygiene before the public tag.
- **P0-4** ships the security wedge (`X-Rivet-Key` reader auth + CORS +
  bundled-tools support) — required before any default-Mode-2 production
  use, but the SDK ships safely without it (Mode-1 adopters use their
  own auth).
- **P0-3** validates goal 1 (clean adoption) is real, not just compiled.

**P1 order:** P1-6 (copy honesty — minutes) → P1-1, P1-3, P1-5 → P1-2,
P1-4. P1 work earns its place when a real customer asks; P1-6 lands
first because it protects the launch even if longer P1 issues slip.
P1-5 (`pii_in_detail` enforcement) is small enough to ship alongside
P1-3.

**P2 items** are discretionary OSS-credibility signals.

## Out of scope

Deliberately not included in any rivet issue:

- **`blocks/connectors/modbus-cpp/TOOD.md`** typo fix — that's an
  edgebits-repo concern, not rivet's. Track in main TODO_0.md.
- **Reproducible-build attestation** — gold-standard supply-chain trust,
  but cost is high relative to the marginal credibility above SLSA L1.
  Revisit post-1.0.
- **Internationalisation / i18n of website + docs** — defer until rivet
  has non-English-speaking adopters.

## Language readiness for v0.1.0-alpha

Public release scope:

- **Python** — reference implementation **and** production-stable (used in edge gateway). Fully tested, published to PyPI
- **Go** — production-used in edge-sync and edge-manager, tested, published to pkg.go.dev
- **Node + TypeScript** — beta, smoke-tested, published to npm

Experimental (header-only / skeleton, not in P0 scope):

- **Rust** — public API not stable
- **Java** — published to Maven Central but marked experimental in README
- **C++** — header-only `rivet.hpp`; CMakeLists ships in P2-4 when stable

This split keeps P0-1 scope realistic; non-experimental languages get full
CI + tests, experimental ones get a "this is alpha" disclaimer in their
language's README.
