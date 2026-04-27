# ask-praveen

Strategic review captured for reference — what's actually blocking, what's
debt, what's overengineered, and when rivet should split out as its own
repo. Snapshot from the 2026-04 review.

---

## 1 · Real blockers (must close before any public/external use)

| # | Blocker | Evidence | Status |
|---|---|---|---|
| 1 | **No CI / no tests** | The `meta.domain.value` AttributeError surfaced in the P0-5 e2e smoke test was sitting in [emit.py:142](python/rivet/emit.py) — a one-liner bug that any test would catch at import. There are zero tests; this class of latent bug is everywhere. | [P0-1](issues/P0-1-ci-tests-lockfiles.md) — **not started** |
| 2 | **No SECURITY.md / CVE disclosure path** | Required day-1 for responsible OSS, and any regulated buyer's first compliance question. | [P0-2](issues/P0-2-governance-docs.md) — **not started** |
| 3 | **Reader has zero auth (Mode 2)** | [reader/router.py](python/rivet/reader/router.py) accepts any caller. If anyone mounts the reader in production with rivet's DB, they leak the entire audit log via HTTP. | [P0-4](issues/P0-4-secured-reader.md) — **not started** |
| 4 | **Install commands lie** | [README.md](README.md) says `go get …` and `npm install …` work; neither package is published. First impression for an audit/compliance tool. | [P1-4](issues/P1-4-release-workflows.md) (publish) + [P1-6](issues/P1-6-copy-honesty-pass.md) (copy fix) — **not started** |

These four are non-negotiable. P0-5 (doctor + tail + durable storage
required) is now **off** this list — shipped 2026-04-26.

---

## 2 · Not good yet / overly complex (debt; can extract with caveats)

| Area | Concern | Recommendation |
|---|---|---|
| **`Domain` mental model** | [codes.py:22](python/rivet/codes.py#L22) explicitly says "intentionally NOT an enum" — but emit.py was calling `.value` on it. Mixed model = bug breeding ground. Other implicit-conversion sites (Severity, RetentionClass) likely have the same drift. | Pick one model and audit all sites. Tests would surface this immediately. |
| **PII redaction is key-only** | [redact.py:42-51](python/rivet/redact.py#L42-L51). Stripe key in `{"user_id": "sk_live_..."}` ships unredacted. The website pitches GDPR-grade minimisation; the code doesn't deliver it. | [P1-3](issues/P1-3-security-depth.md) value-shape scanner |
| **`pii_in_detail` is advisory** | Documentation says it forces SHORT retention; code does nothing. | [P1-5](issues/P1-5-pii-flag-enforcement.md) |
| **JS SDK has `TODO: redact`** | [js/src/index.js:98](js/src/index.js#L98) — Node "beta" status is misleading. | Block JS publishing in [P1-4](issues/P1-4-release-workflows.md) until fixed. |
| **Three-stream model** (audit DB + sys ring + api ring) | Pedagogically necessary, but every doc has to re-explain it. Adopters new to rivet take longer to grok than necessary. | Acceptable complexity — keep, but add one diagram in docs that locks the mental model. |
| **Redactor coupled to structlog** | [redact.py:53-68](python/rivet/redact.py#L53-L68) ships `as_structlog_processor()` even though structlog isn't a core dep. | Move structlog adapter to `rivet.shim.structlog`; keep core redactor framework-agnostic. |
| **`rivet/cloud/` scaffolding** | UI + CLI + TUI for the paid product, but no backend exists. ~3000 LoC of mock surface adding cognitive load to the monorepo. | Move to its own `rivet-cloud/` directory at extraction time, or its own repo. Don't ship it under `rivet/` once rivet goes public — different licence model, different release cadence. |
| **Reader's framework lock-in** | [reader/router.py](python/rivet/reader/router.py) hard-codes FastAPI. The "framework-agnostic core + adapter" design isn't realised yet. | Accept for v0.1; refactor when a Flask/Sanic adopter materialises. Premature otherwise. |

The bones are sound — these are debt items, not architecture mistakes.

---

## 3 · Why reader auth is needed even when the DSN has a password

A common pushback: *"the DSN has a password — isn't the database already
protected?"* Yes, but the password protects a different layer.

- **DSN password** = who can connect to the database directly (e.g., someone
  running `psql` from a bastion).
- **Reader auth** = who can hit `/api/v1/logs/audit` over HTTP. The reader
  runs *inside a service that already has the DSN* — anyone who can reach
  the HTTP endpoint bypasses the DB password entirely.

```
attacker ──> service.example.com/api/v1/logs/audit  ←─ no auth, returns rows
                          │
                          ▼  (rivet uses the DSN here)
                       Postgres   ←─ password protects this hop
                          │
                       audit_log
```

Concrete attack paths the DSN password does **not** stop:

- A misconfigured ingress / loadbalancer that exposes the service publicly
- An internal employee in another team who shouldn't see audit data
- A sidecar / debug route / dashboard mounted in the same FastAPI app
- The staging environment that someone pointed at prod by mistake
- An SSRF in another endpoint that fetches `localhost/api/v1/logs/audit`

Same pattern as: your Postgres has a password, but `GET /api/users` still
needs auth — because the user hitting it never needs the DB password;
the service already used it on their behalf.

That's why [P0-4](issues/P0-4-secured-reader.md) is needed in Mode 2.
In Mode 1 (adopter's DB), the adopter wires their own HTTP auth on the
route via FastAPI `Depends`, so the gap closes via their existing layer.

Full security model in [website/docs/index.html#security](website/docs/index.html).

---

## 4 · When to extract `rivet/` as its own repo

**Don't extract just because the work feels "ready."** Extraction has
real cost: separate CI to maintain, separate issue tracker to triage,
version-coupling pain when both edgebits and rivet need a change. Stay
in-monorepo as long as possible.

### Triggers — any one is enough

| Trigger | Today | Notes |
|---|---|---|
| Second team consumes it (outside edgebits monorepo) | **No** — only edge / edge-sync / edge-manager use it, same team | The strongest signal. Until this happens, extraction has more cost than benefit. |
| External adopter (anyone outside NerdAppLabs) | **No** | Implies a public release happened. |
| Independent release cadence needed | **No** | When you need to ship a security patch faster than edgebits cuts a release, the coupling becomes a drag. |
| Going public on PyPI / npm / pkg.go.dev | **No** | The reference repo for `pip install rivet` should be `nerdapplabs/rivet`, not a private monorepo. |

### Required-before-extraction checklist (regardless of trigger)

- [x] **P0-5** — durable storage required, doctor + tail real
- [ ] **P0-1** — CI green on day 1 (without it, extraction surfaces every latent bug)
- [ ] **P0-2** — SECURITY.md, CHANGELOG.md, LICENSE, NOTICE
- [ ] **P0-4** — reader auth landed OR docs explicitly say *"Mode 2 is preview, do not expose publicly"*
- [ ] **P0-3** — at least one consumer (edge gateway) tests against the *published package*, not the in-tree path. Proves the public API is what we think it is.
- [ ] Decide what comes with: just `python/` + `go/` + `js/` + `website/` + `issues/`? My recommendation: **leave `cloud/` in edgebits** until the paid product has a backend. Different license model, different release cycle.

### Recommended sequence

1. **Now → next 2 weeks:** stay in monorepo, close P0-1 → P0-2 → P0-4 → P0-3 (in that order). Keep iterating fast.
2. **Then:** tag `v0.1.0-alpha` in monorepo, publish to PyPI / pkg.go.dev / npm via [P1-4](issues/P1-4-release-workflows.md).
3. **Then:** when *any* extraction trigger fires (most likely: first external adopter or going-public moment), do the extraction with `git filter-repo` preserving history of `rivet/` only. Issue files migrate to GitHub Issues via `gh issue create -F issues/P*.md` (~2 hours of scripted work).
4. **Cloud:** stays in edgebits at extraction. Splits to its own `rivet-cloud/` repo when the paid product backend gets serious investment.

### Bottom line

Four P0 issues away from "could go public." All four are tractable —
none requires a rewrite. The complexity in §2 is debt, not architecture
mistakes — the bones are sound.

---

## Cross-references

- **Issue index:** [issues/README.md](issues/README.md)
- **Security model docs:** [website/docs/index.html#security](website/docs/index.html)
- **rivet Cloud spec:** [rivet-cloud.md](rivet-cloud.md)
- **Main README:** [README.md](README.md)
