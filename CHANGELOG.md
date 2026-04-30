# Changelog

All notable changes to fasten are documented here.
Format: [Keep a Changelog 1.1](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning 2.0](https://semver.org/).

## [Unreleased]

## [1.0.0-beta.0] — 2026-05-01

Promotion to 1.0.0-beta. Python, Go, and Node.js SDKs back the API
contract — emit + log + redaction + correlation, all driven by
`spec/row-schema.json`. C++14 single-header and Rust ship at beta
status alongside; Java remains a placeholder pending its own beta.

### Changed
- Version bumped from `0.1.0-alpha` to `1.0.0-beta.0` across Python,
  JS (`@nerdapplabs/fasten`), and Rust manifests
- Python `pyproject.toml` Development Status: Alpha → Beta
- JS `package.json` `exports` block — dropped non-existent
  `./shim/*`, `./store/*`, and `./reader` entries (deferred to
  follow-on releases). Core `.` export is unchanged.
- CI: `astral-sh/setup-uv` pinned to immutable `v8.0.0` tag

### Added (since 0.1.0-alpha)
- Go: built-in `LogInfo/Warn/Error/Debug` for the sys stream + deep
  `RedactDetail` (was missing) — Go consumers no longer need slog
  to get `shape:"sys"` lines
- Rust: `fasten::log::info/warn/error/debug` writing `shape:"sys"`
  NDJSON (was previously absent)
- Per-language Docker integration tests (`tests/integration/`)

### Notes
- Java SDK still pre-beta; `emit()` throws `UnsupportedOperationException`.
  Marketing + docs label it "coming soon."

## [0.1.0-alpha] — 2026-04-30

Initial public release of the fasten audit + correlation SDK.

### Added
- **Python** reference implementation — `emit()`, `log.*`, `init()`, SQLite store,
  HTTP / MQTT / scheduler shims, structlog shim, mountable reader, CLI (`doctor`, `tail`), TUI
- **Go** SDK — `Register`, `Init`, `Emit`, `LogInfo/Warn/Error/Debug`, `RedactDetail`,
  SQLiteStore, slog handler, HTTP shim, ring-buffer transport
- **Node.js / TypeScript** SDK — `init`, `emit`, `log.*`, deep redaction,
  AsyncLocalStorage correlation, HTTP / MQTT / scheduler shims
- **Rust** SDK (beta) — typed `Row`, `Severity`, `RetentionClass`, `with_request_id`,
  `AuditRepository` + `AuditOutboxRepository` traits, `EmitBuilder`
- **C++14** single-header SDK — `fasten::emit()`, `RedactConfig`, `RequestIDMiddleware`,
  `FastenReader`, transport shims
- **Java** placeholder (emit throws — coming in v0.1.1)
- `spec/row-schema.json` — JSON Schema as single source of truth for enums + redact rules
- `spec/codegen.py` — generates enum/constant blocks into all 6 adapters (`--write` / `--check`)
- Per-language Docker integration smokes + `tests/integration/verify.py` contract checker

[1.0.0-beta.0]: https://github.com/nerdapplabs/fasten/releases/tag/v1.0.0-beta.0
[0.1.0-alpha]: https://github.com/nerdapplabs/fasten/releases/tag/v0.1.0-alpha
[Unreleased]: https://github.com/nerdapplabs/fasten/compare/v1.0.0-beta.0...HEAD
