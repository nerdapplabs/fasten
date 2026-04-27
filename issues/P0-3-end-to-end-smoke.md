# [P0-3] End-to-end smoke tests in edge / edge-sync / edge-manager

**Priority:** P0 · **Effort:** M · **Labels:** `priority/P0` `area/integration` `area/tests`

## What

Three CI smoke tests that boot real services and verify rivet round-trips actually work end-to-end. Not unit tests — the goal is to catch *integration* drift between the SDK and the consuming services.

**Edge gateway (Python):**

- Boot the gateway in a test container (sqlite-only, no Timescale / MQTT required)
- Hit a route that emits an audit row (`POST /api/v1/pipelines` or similar mutating endpoint)
- Query `/api/v1/logs/audit?request_id=<id>` and assert the row landed with the right shape

**Edge-sync (Go):**

- Boot edge-sync against a stub Edge API
- Trigger a poll cycle that emits a `SYNC_*` audit code via rivet
- Read the SQLite store directly; assert row + correct anchors (actor, target, request_id from the cycle)

**Edge-manager (Go):**

- Boot edge-manager API
- Hit a fleet-mutating endpoint (`POST /api/v1/nodes/claim`) that emits `NODE_CLAIMED`
- Query the manager's audit endpoint; assert the row + slog handler captured the syslog line under the same request_id

Land all three under a single `rivet-integration.yml` workflow that builds the three service images, runs them in test containers, and tears down on completion.

## Why

Goal 1 is "rivet is clean and being used by edge / edge-sync / edge-manager." We have evidence that the *code compiles* and that imports are wired — but no test that the SDK actually emits, stores, and reads back correctly across the three Languages × three services × three streams matrix. Without this, a regression in the SDK (e.g., a redaction bug) ships silently and we discover it from a customer report.

This is also the test that proves rivet's design promise: same data shape, queryable across services, threaded by `request_id`. If the smoke tests fail, the design hasn't actually landed.

## Acceptance

- [ ] `rivet-integration.yml` workflow merged; runs on every PR + main push
- [ ] All three service smoke tests pass against a fresh build of `main`
- [ ] One smoke test deliberately fails when the SDK is broken (regression-canary check)
- [ ] Test runtime ≤ 5 minutes total (parallelisable across the three services)

## Related

- **Depends on:** [P0-1] (uses the same CI scaffolding)
- **Validates:** goal 1 (clean adoption across three services)
- **Sister:** [P1-3] (adversarial security tests build on this integration scaffold)
