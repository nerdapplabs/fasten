# rivet-cloud UI — web client

> v0.1 scaffold. React 18 + Vite + TypeScript. Matches edgebits house
> style: CSS custom properties (no Tailwind), Plus Jakarta Sans + Roboto Mono.

## v0.1 screens

- **Login** — placeholder OIDC redirect (real flow in v0.2)
- **Tenant + site picker** — first-time landing
- **Audit search** — filter by `request_id`, `code`, `domain`, `actor`, `target`, `since`/`until`
- **Row detail** — single audit row with anchors expanded + linked syslog/API rows under same `request_id`
- **Activity chart** — rows-per-minute over the past hour (sparkline)

Out of scope for v0.1 (deferred to v1):

- Compliance report generator UI
- Tamper-evident archive verification
- 5 Whys Root-Cause Investigator (rivet-cloud.md §13 — v1.3)
- Multi-tenant org-admin views

## Run

```bash
cd rivet/cloud/ui
npm install
npm run dev      # → http://localhost:5173
```

Set `VITE_RIVET_CLOUD_API` in `.env.local` to point at a rivet Cloud
backend (or a local mock).

## Layout

```
ui/
├── README.md
├── package.json
├── vite.config.ts
├── tsconfig.json
├── index.html
└── src/
    ├── main.tsx           Vite entry
    ├── App.tsx            top-level router + layout
    └── styles.css         CSS custom properties (Jakarta Sans + Roboto Mono)
```

Pages, components, API client land in v0.2 — kept flat in v0.1 to keep
the scaffold inspectable.
