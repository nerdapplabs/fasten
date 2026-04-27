# rivet-cloud-tui — terminal UI for the audit feed

> v0.1 scaffold. Go + [Bubble Tea](https://github.com/charmbracelet/bubbletea).
> SSH-friendly: works over slow links, in air-gapped sites, on industrial
> Linux hosts where no GUI is permitted.

## Why a TUI

- Industrial / regulated customers often disallow GUI on production hosts
- SREs investigating incidents over SSH want a live audit feed without
  spawning a browser tunnel
- Lower bandwidth + lower CPU footprint than the web UI

## v0.1 screens

```
┌─ Live audit feed ─────────────────────────────────────────────┐
│ 14:23:17  USER_CREATED       admin   target=u-42       ✔     │
│ 14:23:18  ORDER_PLACED       u-42    target=ord-9001   ✔     │
│ 14:23:18  PAYMENT_FAILED     system  target=ord-9001   ✘     │
│ 14:23:19  USER_LOGOUT        admin                     ✔     │
│ ...                                                            │
├─ Filter: code=PAYMENT_*  site=site-A  ─────────────────────────┤
│  / search    j/k navigate   enter inspect   q quit             │
└────────────────────────────────────────────────────────────────┘
```

Single screen for v0.1 — live tailing feed with keyboard filter +
inspect. Search, drill-down detail view, and 5 Whys mode (link to
[`../../rivet-cloud.md` §13](../../rivet-cloud.md)) land in v0.2 / v1.3.

## Build

```bash
cd rivet/cloud/tui
go build -o rivet-cloud-tui ./cmd/rivet-cloud-tui
```

## Run

```bash
rivet-cloud-tui                                # uses ~/.rivet-cloud/token.json
rivet-cloud-tui --endpoint https://api...      # explicit
rivet-cloud-tui --site-id site-A               # pre-filter
```

## Layout

```
tui/
├── README.md
├── go.mod
└── cmd/
    └── rivet-cloud-tui/
        └── main.go        ← Bubble Tea root model
```
