# [P1-6] Copy honesty pass: README + website match code reality

**Priority:** P1 · **Effort:** S · **Labels:** `priority/P1` `area/docs` `area/website`

## What

Three places where copy promises ahead of code. One sweep across all of them.

**1. Languages table — `[README.md](../README.md#L60-L70)` + [`website/index.html#languages`](../website/index.html)**

Current copy lists Rust / Java / C++ as "skeleton". Reality:

| Lang | Today | Honest label |
|---|---|---|
| Python | reference + production | `stable` |
| Go | production-used (edge-sync, edge-manager) | `stable` |
| Node + TypeScript | beta — but missing redact ([P1-3]) | `beta` |
| Rust | 26 LoC; no `init() / emit()` | `experimental — coming soon` |
| Java | `pom.xml` only; no implementation | `experimental — coming soon` |
| C++ | header-only; untested | `experimental — single-header` |

"Skeleton" reads as "MVP-functional"; "experimental — coming soon" sets
honest expectations. Match the wording already used in
[`issues/README.md`](README.md) "Language readiness for v0.1.0-alpha"
section so the site, the package readme, and the issue index all agree.

**2. Install commands — `README.md` + website hero**

Current README lists:

```bash
pip install rivet                          # ✅ works
go get github.com/nerdapplabs/rivet-go    # ❌ not published
npm install @nerdapplabs/rivet            # ❌ not published
```

Either gate behind [P1-4] (publish the packages — preferred), or rewrite
the section as:

```bash
pip install rivet                          # available now
# Go, Node + TypeScript: publishing in v0.1.0-alpha — see issues/P1-4
# C++: copy cpp/include/rivet.hpp — header-only, zero deps
```

The C++ note is honest as-is; only Go + Node lines need the change until
[P1-4] ships.

**3. Bundled-tooling table — `README.md`**

[Bundled tooling section](../README.md) lists `rivet doctor` and `rivet
tail` as if they work. They don't yet ([P0-5]). Either:

- Wait for [P0-5] to land and remove this issue, **or**
- Add a `(coming in v0.1.0)` parenthetical against the two stub commands.

`rivet dump` and `rivet tui` are real today — they stay.

## Why

For an audit + compliance SDK, install commands that fail and feature
claims that don't deliver are a credibility cliff. A regulated buyer's
first-pass evaluation runs the install commands; one failure ends the
evaluation. We're not entitled to a "beta forgiveness" reflex from this
audience.

The issue exists separately from [P1-4] (publishing) and [P0-5]
(implementing) because the copy fix lands in *minutes* and protects
the launch even if those longer issues slip. It's pure honesty hygiene.

## Acceptance

- [ ] Languages tables in [`README.md`](../README.md), [`website/index.html`](../website/index.html), and [`website/docs/index.html`](../website/docs/index.html) all use the same six-row labelling above
- [ ] Install commands in `README.md` and website hero either (a) work end-to-end against published packages, or (b) carry an explicit "publishing in v0.1.0-alpha" note
- [ ] Bundled-tooling table in `README.md` accurately reflects which subcommands work today vs are landing in [P0-5]
- [ ] Single PR reviewed for *consistency* — anyone can grep "Rust" or "Java" across the three docs and see the same wording

## Related

- **Closes when [P1-4] + [P0-5] ship:** the copy will then describe shipping reality without the parentheticals
- **Sister:** [P0-2] (CHANGELOG entry covers the wording change for tracking)
