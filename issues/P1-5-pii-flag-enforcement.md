# [P1-5] Enforce `pii_in_detail` (not just advisory)

**Priority:** P1 · **Effort:** S · **Labels:** `priority/P1` `area/security` `area/compliance`

## What

The `pii_in_detail` field on [`Meta`](../python/rivet/codes.py#L52) is currently
documentation-only. The website implies enforcement
([retention section](../website/index.html#retention)):

> "Codes declared `pii_in_detail: true` force the `short` class regardless —
> GDPR-style 'shortest safe retention' by default."

The code does not enforce this. Wire it.

**Three runtime behaviours when `pii_in_detail=True`:**

1. **Force `RetentionClass.SHORT`** at registration time — override whatever
   the adopter declared on `Meta(retention_class=...)`. Log a `WARNING` if
   the adopter set anything other than SHORT, naming the code:
   `"rivet: code USER_PROFILE_VIEWED has pii_in_detail=True; retention_class forced to SHORT (was MEDIUM)."`

2. **Force-redact `detail` on emit** — apply the redactor to the entire
   `detail` payload regardless of key names. Today, `detail={"city": "Mumbai"}`
   on a PII-tagged code lands raw because no key matches the redact pattern.
   With this fix, the whole payload is replaced with
   `{"_redacted": "***", "_pii_in_detail": True}` unless the adopter explicitly
   opts in via `Meta(pii_in_detail=True, detail_passthrough_keys=[...])`.

3. **Mark the row** — set `audit_log.pii_in_detail = TRUE` column so the
   retention sweep + report queries can filter PII rows distinctly. Schema
   migration ships in this issue.

**Schema:**

```sql
ALTER TABLE audit_log ADD COLUMN pii_in_detail BOOLEAN NOT NULL DEFAULT 0;
CREATE INDEX idx_audit_pii ON audit_log(pii_in_detail) WHERE pii_in_detail = 1;
```

**Cross-language parity:** Go SDK + JS SDK get the same enforcement (Go is
production today, JS is beta — see [P1-3]).

## Why

The site pitches "GDPR-style minimisation by default" and a flag-driven PII
contract. The code ships a flag with no runtime effect. Either fix the gap
or stop claiming it on the site — auditors will catch this in the first
review. Fixing it is half a day of work; rewording the site is the wrong
direction (the contract is genuinely useful).

Forcing SHORT retention prevents the most common bug: an adopter writes a
code with `pii_in_detail=True, retention_class=LONG` because they want a
long audit trail and forget that those constraints conflict. The library
should refuse to keep PII for 3 years — that's the whole point of the flag.

## Acceptance

- [ ] `register()` overrides `retention_class` to SHORT when `pii_in_detail=True`; logs WARNING if the override happened
- [ ] `emit()` force-redacts `detail` for PII-tagged codes unless `detail_passthrough_keys` is set
- [ ] New schema column + index ships with idempotent migration in `SQLiteStore.init()` and `PostgresStore.init()`
- [ ] Tests cover: (a) declared LONG → forced SHORT + WARNING, (b) `detail={"city": "Mumbai"}` → redacted on PII-tagged code, (c) `detail_passthrough_keys=["region"]` lets `region` through but not other keys
- [ ] Go + JS SDKs implement the same three behaviours; cross-language consistency gate (`rivet dump` includes `pii_in_detail` column) verifies parity
- [ ] [`website/docs/index.html#retention`](../website/docs/index.html) doc updated with the explicit contract

## Related

- **Sister:** [P1-3] (PII adversarial tests verify the new force-redact behaviour)
- **Depends on:** [P0-1] (CI runs the new tests)
- **Touches:** [`codes.py`](../python/rivet/codes.py), [`emit.py`](../python/rivet/emit.py), [`store/sqlite.py`](../python/rivet/store/sqlite.py), `js/src/index.js`, `go/emit.go`
