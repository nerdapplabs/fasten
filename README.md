# fasten

> *Logs tell you what happened. Traces tell you where. fasten tells you
> who changed what — and why.*

Audit + correlation SDK. 5 Ws + H anchors enforced at the type level,
one `request_id` threaded across HTTP / MQTT / scheduler / deploy-pipeline /
agent-tool — three streams (syslog / API / audit), one mountable query
surface. Apache-2.0.

**[Full docs →](https://fasten.sh/docs/)**

---

## Install

PyPI and npm packages publish at **v1.0.0-beta.0**. Install from source today:

```bash
pip install ./python                        # Python (reference)
go get github.com/nerdapplabs/fasten-go    # Go — works today via module path
npm install ./js                            # Node / TypeScript
# C++14: copy cpp/include/fasten.hpp — zero dependencies
```

Coming with v1.0.0-beta.0:

```bash
pip install fasten==1.0.0b0
pip install 'fasten[tui]==1.0.0b0'         # + bundled live TUI
npm install @nerdapplabs/fasten@1.0.0-beta.0
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
| Quickstart + output      | [fasten.sh/docs/#quickstart](https://fasten.sh/docs/#quickstart) |
| Incident debugging       | [fasten.sh/docs/#incident](https://fasten.sh/docs/#incident) |
| 7 anchors                | [fasten.sh/docs/#anchors](https://fasten.sh/docs/#anchors) |
| Operational FAQ          | [fasten.sh/docs/#faq](https://fasten.sh/docs/#faq) |
| Env-var reference        | [fasten.sh/docs/#envvars](https://fasten.sh/docs/#envvars) |
| Retention + PII          | [fasten.sh/docs/#retention](https://fasten.sh/docs/#retention) |
| Code evolution + compat  | [fasten.sh/docs/#evolution](https://fasten.sh/docs/#evolution) |

---

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy and response SLA.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Status

Pre-v1. Apache-2.0, open for contribution once P0-1 / P0-2 land.

## License

Apache-2.0. See [LICENSE](LICENSE).
