# rivet-cloud CLI — `rivet-cloud`

> v0.1 scaffold. Single static Go binary. Distributable via apt / brew / scoop.

## Why a CLI

Scripts, CI pipelines, evidence-pack export jobs, ad-hoc queries from
SSH sessions. The web UI is for browsing; the CLI is for automation.

## v0.1 commands

```
rivet-cloud login                                    # OIDC device-flow auth
rivet-cloud query --request-id <id>                  # pull the trail
rivet-cloud query --code USER_CREATED --since 7d     # filtered query
rivet-cloud export --site-id site-A --format json    # bulk export
rivet-cloud report --regulation hipaa --month 2026-04 # compliance pack (v1)
rivet-cloud whoami                                   # show current token + tenant
```

## Build

```bash
cd rivet/cloud/cli
go build -o rivet-cloud ./cmd/rivet-cloud
```

## Layout

```
cli/
├── README.md
├── go.mod
└── cmd/
    └── rivet-cloud/
        └── main.go        ← cobra root command, subcommand wiring
```

Subcommand implementations land in `internal/` packages in v0.2 (kept
flat in v0.1 to keep the scaffold minimal).
