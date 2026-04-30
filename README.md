# fasten

> *Logs tell you what happened. Traces tell you where. fasten tells you
> who changed what — and why.*

Audit + correlation SDK. 5 Ws + H anchors enforced at the type level,
one `request_id` threaded across HTTP / MQTT / scheduler / deploy-pipeline /
agent-tool — three streams (syslog / API / audit), one mountable query
surface. Apache-2.0.

**[Full docs →](website/docs/)**

---

## Install

```bash
pip install fasten                                       # Python (reference)
pip install 'fasten[tui]'                                # + bundled live TUI
go get github.com/nerdapplabs/fasten-go                 # Go
npm install @nerdapplabs/fasten                         # Node / TypeScript
# C++14: copy cpp/include/fasten.hpp — zero dependencies
```

## Quickstart

```python
import fasten
from fasten.codes import register, Meta, Severity, RetentionClass

register("user", [
    ("USER_CREATED", Meta(id="USER_CREATED", domain="user", category="account",
                          action="create", severity=Severity.INFO,
                          description="New user account created", emitter="auth-service",
                          retention_class=RetentionClass.LONG)),
])

fasten.init(service_id="auth-service", node_id="host-01")

fasten.emit(code="USER_CREATED", target="u-42",
           actor="admin", detail={"email": "alice@example.com"})
fasten.log.info("signup_complete", user_id="u-42")
```

Both lines share the same `request_id` on stdout. That's the join key.

---

## What it solves

| Question                                          | Before fasten          | With fasten            |
|---------------------------------------------------|-----------------------|-----------------------|
| Who deployed this config at 14:32?                | grep + Slack + 20 min | `?since=&until=` → 30 s |
| Which HTTP request caused this MQTT disconnect?   | Unknown               | Same `request_id`     |
| Show every mutation to this resource in 30 days   | Log scraping          | `?target=resource-id` |
| Compliance audit trail for a regulated deployment | Custom table + glue   | `?code=&since=&until=` |

---

## Bundled tooling

The Python reference SDK ships a CLI and a live TUI — both run against
any fasten-mounted service (local SQLite, edge-manager, or fasten Cloud)
via the standard `/api/v1/logs/{audit,sys,api}` reader.

| Tool       | Invoke                          | What it does                                     |
|------------|---------------------------------|--------------------------------------------------|
| CLI        | `fasten dump`                    | Print registered codes (CI consistency gate)     |
| CLI        | `fasten tail --stream sys`       | Stream rows from a mounted reader                |
| CLI        | `fasten doctor`                  | Verify init config + correlation wiring          |
| **TUI**    | `fasten tui --request-id <id>`   | Live multi-pane audit + sys + API feed (Rich)    |

The TUI is SSH-friendly — works on industrial Linux hosts where no GUI
is permitted. Install with `pip install 'fasten[tui]'`. v0.1 polls; v0.2
moves to Textual for non-blocking keystrokes (stream toggle, drill-down,
filter prompt). For the paid hosted aggregator, see
[`fasten-cloud`](https://github.com/nerdapplabs/fasten-cloud).

---

## Languages

| Language   | Status                    | Location                                          |
|------------|---------------------------|---------------------------------------------------|
| Python     | reference                 | [`python/`](python/)                              |
| Go         | usable                    | [`go/`](go/)                                      |
| C++14      | single-header             | [`cpp/include/fasten.hpp`](cpp/include/fasten.hpp)  |
| Node.js    | beta                      | [`js/`](js/)                                      |
| TypeScript | ships with JS             | [`js/src/index.d.ts`](js/src/index.d.ts)          |
| Rust       | beta                      | [`rust/`](rust/)                                  |
| Java       | coming soon (placeholder) | [`java/`](java/)                                  |

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

---

## Status

Pre-v1. This is the standalone fasten repo — Apache-2.0 SDK, open for contribution once P0-1 / P0-2 land.

## License

Apache-2.0. See [LICENSE](LICENSE).
