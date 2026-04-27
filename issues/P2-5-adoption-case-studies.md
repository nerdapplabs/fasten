# [P2-5] Adoption case studies + blog content

**Priority:** P2 · **Effort:** M · **Labels:** `priority/P2` `area/marketing` `area/docs`

## What

2–3 long-form write-ups, hosted under `rivet/website/blog/` (or edgebits.io blog with a rivet tag):

1. **"How edgebits uses rivet for industrial audit trails"** — first-party, real numbers (rows/day, retention class distribution, query volume, p99 emit latency)
2. **"Replacing Loki + Jaeger with rivet for a regulated SaaS"** — fictional or with-permission real adopter; before/after diagrams; what was kept (Prometheus, infra dashboards), what was retired
3. **"AI-agent audit with rivet — typed actor/target/correlation in 50 lines"** — angled at the LangChain/Langfuse market; demos `actor_kind=agent` + `method=agent_tool` shim

Each post should include:

- A concrete code snippet runnable as-is
- A "what didn't work" paragraph (real adoption pain, not just success)
- Links to the relevant `rivet/website/docs/` sections

## Why

OSS adoption follows narrative, not feature lists. Case studies are the most efficient marketing for technical buyers — they make the value concrete in the way docs cannot. The first-party post (edgebits's own usage) is the most credible and easiest to write because we have the data. The third post (AI agents) directly feeds the SDK-as-product → rivet Cloud paid-layer funnel by addressing an audience with no existing audit-library option.

## Acceptance

- [ ] At least 2 case studies published on `rivet/website/blog/`
- [ ] Each links the relevant `rivet/website/docs/security.md` / `rivet/website/docs/stability.md` / etc. sections
- [ ] HN / r/programming submission attempted for at least one post (no requirement to make front page — distribution is the experiment)
- [ ] Adopter quoted in (2) explicitly approves the post pre-publication

## Related

- **Depends on:** [P1-3] (security depth doc to link to), [P1-4] (stability doc to link to)
- **Feeds:** rivet Cloud paid-layer funnel
