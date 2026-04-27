# rivet

> *Logs tell you what happened. Traces tell you where. rivet tells you
> who changed what — and why.*

Audit + correlation SDK. 5 Ws + H anchors enforced at the type level,
one `request_id` threaded across HTTP / MQTT / scheduler / deploy-pipeline /
agent-tool — three streams (syslog / API / audit), one mountable query
surface. Apache-2.0.

**[Full docs →](website/docs/)**

---

## Install

```bash
pip install rivet                                       # Python (reference)
pip install 'rivet[tui]'                                # + bundled live TUI
go get github.com/nerdapplabs/rivet-go                 # Go
npm install @nerdapplabs/rivet                         # Node / TypeScript
# C++14: copy cpp/include/rivet.hpp — zero dependencies
```

## Quickstart

```python
import rivet
from rivet.codes import register, Meta, Severity, RetentionClass

register("user", [
    ("USER_CREATED", Meta(id="USER_CREATED", domain="user", category="account",
                          action="create", severity=Severity.INFO,
                          description="New user account created", emitter="auth-service",
                          retention_class=RetentionClass.LONG)),
])

rivet.init(service_id="auth-service", node_id="host-01")

rivet.emit(code="USER_CREATED", target="u-42",
           actor="admin", detail={"email": "alice@example.com"})
rivet.log.info("signup_complete", user_id="u-42")
```

Both lines share the same `request_id` on stdout. That's the join key.

---

## What it solves

| Question                                          | Before rivet          | With rivet            |
|---------------------------------------------------|-----------------------|-----------------------|
| Who deployed this config at 14:32?                | grep + Slack + 20 min | `?since=&until=` → 30 s |
| Which HTTP request caused this MQTT disconnect?   | Unknown               | Same `request_id`     |
| Show every mutation to this resource in 30 days   | Log scraping          | `?target=resource-id` |
| Compliance audit trail for a regulated deployment | Custom table + glue   | `?code=&since=&until=` |

---

## Bundled tooling

The Python reference SDK ships a CLI and a live TUI — both run against
any rivet-mounted service (local SQLite, edge-manager, or rivet Cloud)
via the standard `/api/v1/logs/{audit,sys,api}` reader.

| Tool       | Invoke                          | What it does                                     |
|------------|---------------------------------|--------------------------------------------------|
| CLI        | `rivet dump`                    | Print registered codes (CI consistency gate)     |
| CLI        | `rivet tail --stream sys`       | Stream rows from a mounted reader                |
| CLI        | `rivet doctor`                  | Verify init config + correlation wiring          |
| **TUI**    | `rivet tui --request-id <id>`   | Live multi-pane audit + sys + API feed (Rich)    |

The TUI is SSH-friendly — works on industrial Linux hosts where no GUI
is permitted. Install with `pip install 'rivet[tui]'`. v0.1 polls; v0.2
moves to Textual for non-blocking keystrokes (stream toggle, drill-down,
filter prompt). For the paid hosted aggregator, see
[`rivet-cloud`](https://github.com/nerdapplabs/rivet-cloud).

---

## Languages

| Language   | Status         | Location                                          |
|------------|----------------|---------------------------------------------------|
| Python     | reference      | [`python/`](python/)                              |
| Go         | skeleton       | [`go/`](go/)                                      |
| Node.js    | skeleton       | [`js/`](js/)                                      |
| TypeScript | ships with JS  | [`js/src/index.d.ts`](js/src/index.d.ts)          |
| C++14      | single-header  | [`cpp/include/rivet.hpp`](cpp/include/rivet.hpp)  |
| Rust       | skeleton       | [`rust/`](rust/)                                  |
| Java       | skeleton       | [`java/`](java/)                                  |

---

## Docs

| Topic                    | Link                                              |
|--------------------------|---------------------------------------------------|
| Quickstart + output      | [docs/ → 5-min quickstart](website/docs/#quickstart) |
| Incident debugging       | [docs/ → Incident debugging](website/docs/#incident) |
| 7 anchors                | [docs/ → Anchors](website/docs/#anchors)          |
| Operational FAQ          | [docs/ → FAQ](website/docs/#faq)                  |
| Env-var reference        | [docs/ → Env-vars](website/docs/#envvars)         |
| Retention + PII          | [docs/ → Retention](website/docs/#retention)      |
| Code evolution + compat  | [docs/ → Evolution](website/docs/#evolution)      |
| Open-core roadmap        | [docs/ → Roadmap](website/docs/#opencore)         |

---

## Status

Pre-v1. This is the standalone rivet repo — Apache-2.0 SDK, open for contribution once P0-1 / P0-2 land.

## License

Apache-2.0. See [LICENSE](LICENSE).
