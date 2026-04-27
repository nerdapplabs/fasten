# [P1-3] Security depth: threat model + multi-tenant + PII adversarial tests

**Priority:** P1 · **Effort:** M · **Labels:** `priority/P1` `area/security` `area/tests`

## What

**`rivet/website/docs/security.md`** — formal threat-model document:

- Trust boundaries (gateway ↔ block, gateway ↔ store, reader ↔ caller)
- Attack surfaces enumerated:
  - PII redaction bypass (nested objects, encoded values, wrapper keys like `user_password`)
  - SQL injection on filter params (paramerised queries verified)
  - Path traversal in reader endpoints
  - Deserialisation of `detail` payloads
  - Resource exhaustion (unbounded ring buffers, large emit payloads)
  - Cross-tenant leakage via missing `site_id` filter
  - Credential leakage in stack traces / logs / audit `detail`
- Mitigations in place per surface; mitigations planned with target version

**Multi-tenant isolation test** (integration, runs in CI):

- Create tenants `site_id=A`, `site_id=B`
- Emit rows for each
- Query via `/logs/audit?site_id=A` and assert zero B-rows
- Run against SQLite + Postgres stores

**PII-redaction adversarial tests** (unit-level):

*Key-name attacks (current redactor surface):*

- Token nested inside object two levels deep
- Token inside array
- Base64-encoded secret in string value
- `Authorization` header value
- JWT in URL query string
- Secret embedded in stack-trace string
- `password` field with wrapper key (e.g., `{"user_password": "..."}`)
- Mixed-case key matching (`"API_KEY"` vs `"api_key"` vs `"ApiKey"`)

*Value-shape attacks (new — current redactor is value-blind):*

- Stripe live key in any field: `{"user_id": "sk_live_a1b2c3..."}`
- JWT in any field: `{"context": "eyJhbGciOiJIUzI1NiIs..."}`
- AWS access key in any field: `{"audit_actor": "AKIAIOSFODNN7EXAMPLE"}`
- GitHub PAT shape: `{"label": "ghp_a1b2c3d4..."}`
- OpenAI key shape: `{"comment": "sk-a1b2c3d4..."}`
- Generic high-entropy string heuristic over a configurable threshold

The current redactor at [`redact.py:42-51`](../python/rivet/redact.py#L42-L51)
does dict-key regex matching only — none of the value-shape cases above are
caught today. Implement a `ValueShapeScanner` that runs after key matching;
must be opt-out via `RIVET_REDACT_VALUE_SHAPES=0` for adopters with strict
performance budgets.

**Cross-language redaction parity:**

- Go SDK already redacts via `redact.go`; verify behavioural parity with Python
- JS SDK currently has [`TODO: redact`](../js/src/index.js#L98) — implement the
  same redactor (key + value shapes); without this, the Node "beta" claim
  in [P1-4] doesn't ship. A node service emitting unredacted PII to the same
  audit table breaks the compliance promise.

## Why

The redactor is the single layer between adopter sloppy `emit()` calls and PII landing in audit rows. Adversarial tests are how we verify the regex set is robust, not just plausible. The threat model is the document security teams will demand before adoption — better to write it ourselves with our framing than answer questionnaire after questionnaire from scratch each customer. Site_id leakage is the most-likely high-severity bug; one integration test is cheap insurance.

## Acceptance

- [ ] `rivet/website/docs/security.md` committed; linked from `SECURITY.md`
- [ ] Multi-tenant isolation test exists for SQLite + Postgres; runs in CI
- [ ] PII-redaction adversarial tests cover all 8 key-name cases + 6 value-shape cases; all pass
- [ ] `ValueShapeScanner` implemented in Python + Go + JS; cross-language parity verified
- [ ] JS SDK [`TODO: redact`](../js/src/index.js#L98) resolved — `emit()` redacts on every call
- [ ] Any bypass found during writing is fixed before merge (or filed as a separate issue with severity)
- [ ] Threat model doc explicitly states what is *not* mitigated (e.g., compromised host = full audit-log access by design)

## Related

- **Depends on:** [P0-3] (uses the same integration scaffolding), [P0-1] (CI runs the adversarial tests)
- **Sister:** [P2-3] (advisories page reflects fixed bypasses with CVE entries)
