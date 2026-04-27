# rivet Cloud — product spec

> Sibling to [README.md](README.md). README is the open-source SDK design;
> this is the **hosted (or self-hostable) commercial audit data plane**
> that the SDK feeds. Together they form the open-core: free SDK forever,
> paid Cloud.
>
> Status: v0 spec · Working name: **rivet Cloud** · See also [issues/](issues/).

---

## Open questions

Decisions deliberately deferred — read these first, because they constrain
how to interpret the spec below.

| Question | Direction |
|---|---|
| Pricing model: per-node vs per-event vs storage GB? | Defer to first paying customer feedback |
| Self-hosted licensing: AGPL, BSL, or commercial-only? | Defer to legal review (closer to v1.1) |
| Multi-tenant: hard tenant isolation (separate DBs) vs row-level? | Lean hard, but verify with first 3 design partners' security review |
| Data residency: per-tenant region pinning? | Required for EU adopters; defer implementation to v1.1 |
| Auditor SaaS upsell: separate "auditor portal" pricing or bundled? | v2 question |
| Federated query: can a tenant span multiple Cloud instances? | Defer; not v1 |

---

## Spec — points 1 to 12

## 1 · What it is

A multi-node audit warehouse with compliance-report generation, tiered
retention, tamper-evident archive, and a web UI for fleet-wide audit
search. Adopters install the rivet SDK in their services; rivet Cloud
ingests their audit rows, aggregates them across nodes, indexes them for
fast query, and produces the regulator-ready evidence packs that ship at
audit time.

**One-line pitch:**

> *Free SDK gets your audit shape right. rivet Cloud gets you through your
> next SOC 2 / HIPAA / GMP audit without writing a single export script.*

## 2 · Why it exists — the open-core economics

| Question | Answer |
|---|---|
| Why open-source the SDK? | Audit libraries running closed-source code don't pass security review at compliance-conscious shops. Free SDK = unblocked adoption. |
| Why is the SDK free forever? | Pure logger ergonomics is commoditised (structlog / slog / pino). The SDK alone has no pricing power. |
| What carries pricing power? | Multi-node fleet aggregation, compliance-report generation, tamper-evident archive, retention tiering, SLA support. |
| Who pays? | Regulated SaaS (HIPAA / SOC 2), industrial fleets (GMP / ISO 26262 / FSSC), AI-agent platforms (regulated AI), multi-tenant admin-audit shops. |
| Comparable open-core shapes | Sentry (free SDK · paid hosted error tracking), Grafana (free Grafana · paid Cloud), Elastic (free libs · paid X-Pack), BentoML (free SDK · paid orchestration). |

The SDK seeds the funnel; rivet Cloud monetises the audit-data plane.
**Edge Manager is our first-party deployment** of rivet Cloud — proof that
it works under our own load before we ship it as a separate product.

## 3 · How — architecture

```
                                 ┌──────────────────────────────┐
   adopter services              │    rivet Cloud                │
   (rivet SDK)                   │                              │
                                 │  ┌────────────────────────┐  │
   edge gateway ──audit rows──►  │  │ ingest API             │  │
   edge-sync    ──audit rows──►  │  │   /api/v1/audit/ingest │  │
   edge-manager ──audit rows──►  │  │   (batched, deduped)   │  │
   3rd-party    ──audit rows──►  │  └─────────┬──────────────┘  │
                                 │            │                  │
                                 │  ┌─────────▼──────────────┐  │
                                 │  │ hot tier (Postgres /    │  │
                                 │  │   ClickHouse) — 90d     │  │
                                 │  │ cold tier (S3+Parquet)  │  │
                                 │  │   — 7y, queryable       │  │
                                 │  │ archive (immutable WORM)│  │
                                 │  │   — 10y, sealed         │  │
                                 │  └─────────┬──────────────┘  │
                                 │            │                  │
                                 │  ┌─────────▼──────────────┐  │
                                 │  │ query layer · UI · API │  │
                                 │  │ compliance reports     │  │
                                 │  │ evidence packs         │  │
                                 │  └────────────────────────┘  │
                                 └──────────────────────────────┘
```

### 3.1 Ingest

- HTTP `POST /api/v1/audit/ingest` — batched JSON rows, the rivet SDK
  shape (see [README.md §3](README.md))
- m2m auth via short-lived tokens (default 24h) issued at node onboarding
- Idempotency key on `(source_node_id, edge_row_id)` — re-ships of a batch
  are no-ops
- Backpressure: 429 with `Retry-After` when storage tier is saturated;
  SDK has SQLite outbox locally so no row is lost

### 3.2 Storage tiers

| Tier | Backend | Retention | Query latency | Use case |
|---|---|---|---|---|
| Hot | Postgres or ClickHouse | 90 days (default; configurable) | < 100 ms | Operational queries — "what did this user do today" |
| Cold | S3 + Parquet (DuckDB query) | 7 years (compliance default) | seconds | Compliance reports, historical investigations |
| Archive | Object storage with WORM lock + chained hash | 10 years | minutes (rare) | Tamper-evident long-term retention; insurance against revisionism |

Tier transitions are background jobs. Adopters configure thresholds per
retention class declared on each `audit_code` (see SDK).

### 3.3 Tamper-evident chained hashing

- Each batch on ingest computes `seal = sha256(prev_seal || sorted_row_ids)`
- Daily seal published to a public log (planned: Sigstore Rekor or a
  similar transparency log)
- Adopters can prove "this row existed at time T and has not been altered"
  via a Merkle inclusion proof against the published seal
- Required for FDA Title 21 §11 / GMP-grade integrity claims

### 3.4 Compliance report generator

- Parameterised templates per regulation (see §6)
- Input: tenant + site_id + date-range + regulation
- Output: PDF + CSV evidence pack + signed manifest
- Reports run against the cold tier (Parquet) — no hot-tier load impact
- Cached per tenant + date range; immutable once generated

### 3.5 Multi-tenancy

- **Tenant** = the paying customer (one per contract / org)
- **site_id** = per-deployment scope *inside* a tenant (factory floor,
  region, business unit)
- Hard isolation between tenants: no shared tables, no shared queues,
  no shared S3 prefixes
- Soft isolation between sites: shared storage, mandatory `site_id`
  filter on every query (enforced at the query layer, not just the UI)
- See [issues/P1-3](issues/P1-3-security-depth.md) for the multi-tenant
  isolation test

## 4 · Audience — who pays

Sharper version of [README.md §1.2](README.md):

| Segment | Why they buy rivet Cloud |
|---|---|
| **Regulated SaaS** (HIPAA / SOC 2 / PCI-DSS) | Compliance reports replace months of internal evidence-gathering work; auditor accepts the signed pack as-is. |
| **Industrial fleet** (manufacturing, energy, automotive) | Per-site GMP / ISO 26262 / FSSC reports across hundreds of edge nodes; fleet view is impossible without aggregation. |
| **AI-agent platforms** (regulated AI, healthcare LLMs) | Every tool-call is audited; cost per-actor billing is a side effect; no other tool ships this. |
| **Multi-tenant admin audit** (any SaaS with "admin edited customer X's config") | Per-tenant audit surface for customers; sold as a tenant-isolated B2B feature. |
| **Chain-of-custody** (legal evidence, pharmacy, forensics) | Tamper-evident archive is the legal-admissibility property they need. |

## 5 · Feature matrix — SDK vs Cloud

| Capability | rivet SDK (OSS, Apache-2.0) | rivet Cloud (commercial) |
|---|---|---|
| `emit()` audit rows with 5 Ws + H + correlation | ✅ | (uses SDK) |
| Local SQL store (SQLite / Postgres) | ✅ | ✅ (relayed) |
| Three streams (syslog / API / audit) | ✅ | ✅ (audit only ingested) |
| Single-node `/logs/audit` reader | ✅ | ✅ (relayed) |
| Multi-node fleet aggregation | ❌ | ✅ |
| Cross-tenant isolation (`site_id`) | partial | ✅ enforced |
| Tiered retention (hot / cold / archive) | retention class only | ✅ implemented |
| Tamper-evident chained hashing | ❌ | ✅ |
| Compliance report generation | ❌ | ✅ |
| Evidence pack export (PDF + CSV + signed manifest) | ❌ | ✅ |
| **Bulk audit export — JSON + Parquet (portability commitment)** | (own DB → query directly) | ✅ **never paywalled** |
| Web UI for fleet audit search | partial | ✅ |
| SSO / SAML / OIDC | ❌ | ✅ |
| RBAC | ❌ | ✅ |
| SLA + 24/7 support | community best-effort | ✅ tiered |

The free / paid line is drawn so that **a single-node user can run rivet
SDK forever for free and never need Cloud.** Cloud earns its keep at
multi-node scale or at compliance-audit time.

### Portability commitment — no lock-in

Bulk export is **never paywalled**, never rate-limited beyond reasonable
fair-use, and always available:

- **Format:** newline-delimited JSON (always) + Apache Parquet (always).
  Both formats include the full audit row schema, retention metadata, and
  the chained-hash seal so the export is independently verifiable.
- **Path:** one-shot CLI (`rivet-cloud export --since … --until …`) and
  a programmatic streaming API (gRPC server-streaming) — both work on
  every plan including community.
- **Frequency:** no per-day caps; rate limits scale with paid plan but
  free-tier users can complete a full-history export in a finite time.
- **Versioning:** the export schema is itself versioned + documented;
  schema changes go through a 6-month deprecation window.

A regulated buyer's first evaluation question is *"how do I leave?"*
Answering that explicitly — in the spec, not in a future-tense roadmap —
is the difference between *"hosted audit data plane"* and *"hosted audit
data hostage."*

## 6 · Compliance report library

Each report is a parameterised template that runs against the cold tier
and produces a signed PDF + CSV + JSON manifest.

| Regulation | What the report shows | Status |
|---|---|---|
| **HIPAA** (45 CFR §164.312) | Every access to PHI: who, when, what record, how (UI / API / agent_tool) | v1 |
| **SOC 2 Type II** | System access events, configuration changes, security-relevant events with control-mapping | v1 |
| **GDPR** (Art. 30 + Art. 15) | Data subject access requests, right-to-erasure events, processing-activity register | v1 |
| **ISO 26262** (automotive functional safety) | Functional-safety event traceability per ASIL level | v1.1 |
| **GMP / FDA Title 21 §11** | Pharma manufacturing audit trail; tamper-evident; e-signature events | v1.1 |
| **FSSC 22000** | Food-safety management event log; CCP monitoring events | v1.2 |
| **SOX** | Financial-audit trail; access to financial-control systems | v1.2 |

Reports are versioned independently of the rivet Cloud release; new
regulations land as add-on packs.

## 7 · Pricing tiers (placeholder)

| Tier | Nodes | Retention | Compliance reports | Support | Price (placeholder) |
|---|---|---|---|---|---|
| **Community** | unlimited | local-only | none | community | **free forever** |
| **Starter** | 1 node | 30 days hot | none | best-effort | $X/month |
| **Pro** | ≤ 10 nodes | 90 days hot + 1y cold | basic pack (HIPAA / SOC 2 / GDPR) | business-hours | $XX/month |
| **Enterprise** | unlimited | full tiered (hot / cold / archive) | full library + custom | 24/7 SLA | contact sales |

Open question: usage-based vs flat per-node? Probably hybrid — flat per
node + overage on storage GB. Defer to first paying customer.

## 8 · Deployment models

| Model | Who runs it | When it makes sense |
|---|---|---|
| **Hosted SaaS** (rivet-cloud.com or similar) | nerdAppLabs | SaaS adopters, fastest time-to-value |
| **Self-hosted** (single binary or Helm chart) | adopter, on their infra | Air-gapped industrial customers, sovereignty constraints, regulatory data-residency |
| **Hybrid** | nerdAppLabs hosts ingest + reports; adopter hosts cold-tier S3 in their own AWS | Compromise: regulator-acceptable data residency without ops burden of hot-tier |
| **Air-gapped** | adopter, fully offline; reports generated locally and exported on USB | Defence, classified, certain pharma sites |

All four use the same code; differences are deployment topology + which
component runs where.

## 9 · Out of scope

| Adjacent thing | Why we don't do it |
|---|---|
| General log aggregation (Loki, ELK, Splunk) | Different data model, different volume profile. Adopters can ship rivet SDK's syslog stream to those if desired; we focus on audit. |
| Metrics (Prometheus) | Different shape entirely. Out of scope. |
| Distributed tracing (Jaeger, Tempo) | rivet's `request_id` ↔ OTel `trace_id` bridge means tracing tools coexist; we don't replace them. |
| APM (Datadog, New Relic) | Application performance ≠ audit; adjacent but distinct. |
| SIEM (Splunk Enterprise Security, IBM QRadar) | rivet Cloud feeds SIEM via export but doesn't try to be one. |

The discipline: rivet Cloud does **audit data plane**, deeply. Everything
else is a coexistence story, not a replacement bid.

## 10 · Roadmap to v1

| Milestone | Version | Date target | Deliverable |
|---|---|---|---|
| Open-core foundation | rivet SDK 0.1.0-α | Q3 2026 | SDK shipped + 12 issues from [issues/](issues/) closed |
| **Client scaffolds** | **rivet Cloud 0.1** | **Q3 2026** | **UI / CLI / TUI skeletons under [`cloud/`](cloud/) — see `cloud/README.md`** |
| First-party deployment | Edge Manager 1.0 | Q4 2026 | Edge Manager ships with embedded rivet Cloud audit data plane |
| Hosted public beta | rivet Cloud 0.9 | Q2 2027 | rivet-cloud.com private beta with 5 design partners |
| GA — hosted | rivet Cloud 1.0 | Q4 2027 | Public hosted launch + first 3 compliance report templates (HIPAA / SOC 2 / GDPR) |
| GA — self-hosted | rivet Cloud 1.1 | Q1 2028 | Helm chart + air-gapped install path |
| Compliance pack expansion | rivet Cloud 1.2 | Q2 2028 | ISO 26262 + GMP + FSSC + SOX templates |
| **Root-Cause Investigator (5 Whys)** | rivet Cloud 1.3 | Q3 2028 | Walk-the-trail UI for incident investigation — see §12 |
| Auditor portal | rivet Cloud 2.0 | 2028 | Read-only auditor logins, evidence-pack collaboration, "auditor view" of the dataset |

Dates are placeholders. Real dates land once design partners are signed.

## 11 · Relationship to rivet SDK

| Question | Answer |
|---|---|
| Can adopters use rivet SDK without rivet Cloud? | **Yes — forever, free, fully-functional for single-node.** |
| Can rivet Cloud function without rivet SDK? | No — Cloud is the data plane *for* the SDK's emit shape. Adopters must run the SDK in their services. |
| Does adopting rivet Cloud lock me in? | No — `audit_log` table shape is documented (see SDK README §4); export is `pg_dump` on the cold tier or Parquet pull from S3. |
| What happens if I outgrow Cloud or want to self-host? | Same code; Helm chart deploys the Cloud stack on your infra. Migration = standard Postgres dump/restore. |

The deliberate design constraint: **the SDK never depends on the Cloud,
only the reverse.** This keeps the OSS half credible — it's not a teaser
for the paid product, it's a complete tool that can talk to Cloud as one
of several backends.

---

## 12 · Root-Cause Investigator — 5 Whys for industrial / regulated ops

> Planned for **rivet Cloud 1.3** (see §10 roadmap). Direct fit for the
> Lean / Toyota Production System customer base — exactly rivet's
> industrial-edge beachhead.

### What it is

A walk-the-trail UI on top of the cold-tier audit data. Operator picks a
symptom event, rivet Cloud auto-pulls every causally-linked event (same
`request_id`, plus events on the same `target` in the preceding window),
and presents an iterative "Why?" drill-down — directly modelled on the
Toyota Production System 5 Whys technique.

### Why it earns a feature slot

| Reason | Detail |
|---|---|
| **Beachhead alignment** | Manufacturing / industrial customers already think in 5 Whys. They don't need to learn a new methodology — rivet Cloud just gives them better data than logs + tribal knowledge. |
| **Differentiation** | Loki / ELK / Splunk have logs but no typed audit shape — they can't auto-generate "WHO did WHAT to WHICH target" candidate questions. Jaeger has spans but only HTTP. LangSmith / Langfuse have agent traces but no industrial deployment context. **No incumbent fits this.** |
| **Reuses existing data** | Zero new data plane. RCI is a UI + query-engine layer on the audit rows already ingested; no schema change, no new ingest path. |
| **AI-assist optional, not required** | Anchors are typed (actor / target / method) — an LLM consuming them gets clean facts, not log soup. But the deterministic walk-the-trail flow works without any LLM, which matters for air-gapped / deterministic-output customers (defence, regulated pharma). |

### How it works — concrete walk-through

```
1.  Operator picks a symptom event (e.g., CONNECTOR_ERROR or POLICY_DENIED)

2.  rivet Cloud auto-pulls the trail:
      ├─ Every event with the same request_id (cross-service)
      ├─ Every event on the same target in [T-30min, T]
      └─ Every CONFIG_NODE_UPDATED on related paths in [T-24h, T]

3.  UI presents the first "Why?" with candidate branches:
      "Why did target=p-123 hit POLICY_DENIED?"
        ├─ ConfigNode services/p-123/connection.url changed at 14:02 by admin
        ├─ ConnectorRestarted at 14:03 picked up the new value
        └─ RuleTriggered at 14:05 — bytes_per_sec exceeded 80MB

4.  Operator clicks any branch — UI generates the next "Why?" against
    that branch's events. Repeat 3-5 levels until convergence.

5.  Surface "Likely root cause" candidates ranked by:
      ├─ Causal proximity (how few hops to the symptom)
      ├─ State-change recency (changes shortly before the symptom)
      └─ Anomaly score (events outside normal frequency for that code)

6.  Operator can:
      ├─ Save the trail as an Investigation record (auditable)
      ├─ Export as a 5-Whys report (PDF — feeds Lean / TPS workflows)
      └─ Optionally: LLM summary of the chain (toggle, off by default)
```

### What rivet primitives make this cheap to build

| 5 Whys move | rivet primitive |
|---|---|
| "Pull the trail for this incident" | `request_id` correlation across syslog / API / audit, already indexed |
| "What changed before the failure?" | UPDATE rows carry `path`, `old_value_hash`, `new_value`, `diff_preview` |
| "Who did this?" / "Was it a user, scheduler, or agent?" | `actor` + `actor_kind` anchors |
| "Across which transport?" | `method` anchor (`http` / `mqtt` / `scheduler` / `cli` / `ui` / `agent_tool`) |
| "Was a rule fired right before this?" | `RULE_TRIGGERED` audit code; correlated to the symptom by `request_id` or temporal proximity |
| "Were configs aligned at the time of failure?" | `config_hash` on `*_DEPLOYED` events lets us answer "was the right version running at T?" |
| "Order events that happened in the same millisecond" | `monotonic_seq` per node breaks same-ms ties |

The substrate is already in rivet's audit row shape — RCI is a UI + ranker, not a data-plane change.

### Out of scope for v1.3

| Item | Why deferred |
|---|---|
| Causal-graph machine learning ("learn that X always causes Y") | High R&D cost; manual operator drill-down is good enough for the first release |
| Cross-organisation investigation (compare incidents across tenants) | Multi-tenant boundary blocks this; would need careful anonymisation |
| Real-time symptom alerting | Out of scope for the data plane; integrate with adopter's SIEM / PagerDuty instead |
| Auto-fix / auto-rollback action triggering | Audit-only product; deliberately not a control plane |

### Open questions (to settle before v1.3 design)

| Question | Lean direction |
|---|---|
| LLM-assisted summary on by default or opt-in? | **Opt-in.** Air-gapped customers need it deterministic; LLM is value-add not requirement. |
| Save trails as Investigation records — how long retained? | Same as the underlying audit rows; honour the retention class of the symptom event |
| Export format: PDF only, or PDF + machine-readable JSON? | Both. PDF for the auditor; JSON for programmatic Lean / TPS systems integration. |
| Surface "anomaly score" how? | Z-score on per-code event frequency, scoped per `site_id`. Cheap, deterministic, no ML. |

### Pitch

> *"Your team already runs 5 Whys after every incident. With rivet Cloud,
> the trail is already there — typed actors, typed targets, threaded by
> request_id. You walk it, not reconstruct it. PDF report stamps out
> automatically. That's an hour of post-mortem time saved per incident,
> per shift."*

This positions rivet Cloud directly against the Toyota / Lean culture
that defines our industrial beachhead — and against zero competing
products that ship typed audit + cross-transport correlation + 5 Whys
tooling in one package.

---

**Cross-references:** [README.md](README.md) (SDK design) · [issues/README.md](issues/README.md) (open work for v0.1.0-α) · [website/docs/](website/docs/) (public docs)
