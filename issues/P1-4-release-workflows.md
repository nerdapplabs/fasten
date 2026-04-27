# [P1-4] Release process: API stability + per-language publish workflows

**Priority:** P1 · **Effort:** M · **Labels:** `priority/P1` `area/release` `area/governance`

## What

**`rivet/website/docs/stability.md`** — public stability promise:

- Public API surface enumerated per language (what SemVer covers)
- Experimental APIs explicitly listed (e.g., `shim.agent_tool` — see open questions in `rivet/README.md` §18.4)
- Deprecation window: ≥ 1 minor release for stable APIs
- MSRV (minimum supported Rust version) / minimum-Python-version policy
- ABI promise for C++ when the language graduates from experimental (header-only stays header-only through 1.x)

**Per-language release workflows** (`.github/workflows/release-*.yml`) triggered on `v*` tag push:

- **Python** → PyPI via `twine upload` + PyPI Trusted Publishing (no API token in repo)
- **Go** → tag *is* the release; verify `pkg.go.dev` indexes within 24h post-tag
- **JS** → `npm publish --provenance`
- **Rust** → `cargo publish` to crates.io (when language graduates from experimental)
- **Java** → `mvn deploy` to Sonatype OSSRH (when language graduates)

For v0.1.0-alpha, only the first three (Python / Go / JS) are required. Rust + Java workflows ship later when each language stabilises.

## Why

Today there's no path from `git tag v0.1.0` to "user runs `pip install rivet`". Adopters can't plan upgrades without a SemVer policy. Without `--provenance` on npm and trusted-publishing on PyPI, the supply-chain claims in [P1-2] don't reach the package registries — a gap an attacker can exploit.

Out of scope for this issue: the deferred design questions in `rivet/README.md` §18.4 (Node pino-style logger, Java SLF4J builder, `shim.agent_tool` API, `rivet doctor` v1 output, path-sanitisation hook). Each is a separate small change; group them under a follow-up after v0.1.0-alpha.

## Acceptance

- [ ] `rivet/website/docs/stability.md` committed
- [ ] Three release workflows green on a dry-run tag push (e.g., `v0.1.0-alpha-rc1`)
- [ ] First public tag (`v0.1.0-alpha`) successfully publishes to PyPI / pkg.go.dev / npm + GitHub Release
- [ ] `pip install rivet`, `go get github.com/.../rivet-go`, `npm install @nerdapplabs/rivet` all work end-to-end against the published artifact

## Related

- **Depends on:** [P0-2] (CHANGELOG.md drives release notes), [P1-2] (SBOM + signing attached at publish time)
- **Splits-out:** §18.4 design-question follow-ups tracked separately
