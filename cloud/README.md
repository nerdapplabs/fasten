# rivet/cloud — clients for the rivet Cloud audit data plane

> Scaffolding for **rivet Cloud v0.1** — three thin clients against the
> rivet Cloud ingest / query API. The data plane itself (storage, ingest,
> compliance reports) is specified in [../rivet-cloud.md](../rivet-cloud.md);
> this folder is the operator-facing surface.

## What lands in v0.1

| Client | Folder | Stack | v0.1 scope |
|---|---|---|---|
| **UI** (web) | [`ui/`](ui/) | React + Vite + TypeScript | Search, single-row view, audit-activity chart. Minimal auth (placeholder SSO). |
| **CLI** | [`cli/`](cli/) | Go + cobra | `login`, `query`, `export`, `report`. Single binary, distributable via apt / brew / scoop. |
| **TUI** | [`tui/`](tui/) | Go + Bubble Tea | Live audit feed, filter, drill-down. Operator-friendly for SSH / air-gapped sessions. |

All three speak the same rivet Cloud HTTP API. No backend lives in this
folder — the audit data plane is a separate service (see roadmap in
`../rivet-cloud.md` §10).

## Why three clients

| Audience | Clients they reach for |
|---|---|
| Compliance / audit reviewer | UI (browse, export evidence packs) |
| SRE / on-call (incident response) | TUI (SSH-friendly, no browser needed in air-gapped sites) |
| Automation / CI / scripts | CLI (composable, scriptable, single binary) |

Industrial / regulated customers often disallow GUI access to production
hosts entirely — TUI + CLI are the only options on those systems. Web UI
serves the office side. All three from the same backend = consistent
view + zero duplication of business logic.

## Repo conventions

- **CLI + TUI in Go** — matches `edge/cli/` + `edge/tui/` + `edge-manager/cli/` + `edge-manager/tui/` layout in the edgebits monorepo. Go for static binaries, easy cross-compilation, native arm64 support for industrial deployments.
- **UI in React + Vite** — matches `edge/ui/` + `edge-manager/ui/`. CSS custom properties (no Tailwind), Plus Jakarta Sans + Roboto Mono per house style.
- **Auth model** — short-lived JWTs from rivet Cloud's auth endpoint; refresh-token flow. Same scheme as the SDK ingest m2m tokens.

## v0.1 acceptance

- [ ] All three clients call rivet Cloud's `/api/v1/audit/query` and render rows
- [ ] CLI `--help` describes every subcommand
- [ ] TUI launches into a live-feed view that updates in real-time
- [ ] UI loads, lets the operator search by `request_id`, and shows row detail
- [ ] All three handle expired tokens gracefully (re-auth or graceful error)

## Out of scope for v0.1

- Compliance report generation UI (deferred to v1 — see rivet-cloud.md §6)
- Tamper-evident archive verification (rivet-cloud.md §3.3 — v1)
- 5 Whys Root-Cause Investigator UI (rivet-cloud.md §13 — v1.3)
- Multi-tenant org-admin views (v1)
- Real-time alerting (out-of-scope per rivet-cloud.md §9)

## Layout

```
cloud/
├── README.md           ← this file
├── ui/                 React + Vite web client
├── cli/                Go CLI (cobra)
└── tui/                Go TUI (Bubble Tea)
```
