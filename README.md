# fasten

> *Logs tell you what happened. Traces tell you where. fasten tells you
> who changed what — and why.*

Audit + correlation SDK.

Logs, HTTP access trail, and typed audit rows — one `request_id` threads
all three streams. 6 anchors (5 Ws + How) enforced at the type level;
bundled shims for HTTP, MQTT, and scheduler-fired jobs. One mountable
query surface. Apache-2.0.

**v1.0.0-beta.** Python is the reference SDK; Go / JS / Rust / C++ are
beta. Not yet on PyPI / npm / crates.io — install from source.

**[Website →](https://fasten.sh)**

---

## Install (source)

```bash
git clone https://github.com/nerdapplabs/fasten
cd fasten

pip install ./python                              # Python (reference)
go get github.com/nerdapplabs/fasten-go          # Go
npm install ./js                                  # Node / TypeScript
# C++14: copy cpp/include/fasten.hpp — zero dependencies
```

## Quickstart

Verified to run as-is on Python 3.10+:

```python
import os
os.environ["FASTEN_AUDIT_DSN"] = "sqlite:///./fasten-audit.db"

import fasten
from fasten.codes import register, Meta, Severity, RetentionClass
from fasten.context import with_request_id

register("user", {
    "USER_CREATED": Meta(
        domain="user", category="account", action="create",
        severity=Severity.INFO, description="New user account",
        emitter="auth-service", retention_class=RetentionClass.LONG,
    ),
})

fasten.init(service_id="auth-service", node_id="host-01")

with with_request_id():
    fasten.emit(code="USER_CREATED", target="u-42",
                actor="admin", detail={"email": "alice@example.com"})
    fasten.log.info("signup_complete", user_id="u-42")

fasten.flush()  # block until the audit row reaches fasten-audit.db
```

Both lines emit on stdout under the same `request_id` — that's the join
key. The audit row is also persisted to `./fasten-audit.db`.

In a real service the HTTP / MQTT / scheduler shim opens the
`with_request_id()` context for you; the kernel pattern above is what
the shims wrap.

---

## What it solves

| Question                                          | Before fasten          | With fasten            |
|---------------------------------------------------|-----------------------|-----------------------|
| Who deployed this config at 14:32?                | grep + Slack + 20 min | `?since=&until=` → 30 s |
| Which HTTP request caused this MQTT disconnect?   | Unknown               | Same `request_id`     |
| Show every mutation to this resource in 30 days   | Log scraping          | `?target=resource-id` |
| Compliance audit trail for a regulated deployment | Custom table + glue   | `?code=&since=&until=` |

---

## Bundled CLI + TUI (Python)

Installed as console scripts when you `pip install ./python`. Run against
any fasten-mounted service via the standard `/api/v1/logs/{audit,sys,api}`
reader.

| Tool       | Invoke                            | What it does                                  |
|------------|-----------------------------------|-----------------------------------------------|
| CLI        | `fasten dump`                     | Print registered codes (CI consistency gate)  |
| CLI        | `fasten tail --stream sys`        | Stream rows from a mounted reader             |
| CLI        | `fasten doctor`                   | Verify init config + correlation wiring       |
| TUI        | `fasten-tui --request-id <id>`    | Live multi-pane audit + sys + API feed (Rich) |

The TUI is SSH-friendly — works on industrial Linux hosts where no GUI
is permitted.

---

## Languages

| Language   | Status                    | Location                                          |
|------------|---------------------------|---------------------------------------------------|
| Python     | reference                 | [`python/`](python/)                              |
| Go         | usable                    | [`go/`](go/)                                      |
| Node.js / TypeScript | beta            | [`js/`](js/)                                      |
| Rust       | beta                      | [`rust/`](rust/)                                  |
| C++14      | single-header             | [`cpp/include/fasten.hpp`](cpp/include/fasten.hpp)|
| Java       | placeholder               | [`java/`](java/)                                  |

Cross-language P1-15 (audit-store failure handling — the queue-mode
default that keeps emit() off the request path) is shipped in Python;
Go / JS / Rust / C++ ports are in progress. Until they land, those SDKs
will surface store errors synchronously on emit().

---

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Status

v1.0.0-beta. Apache-2.0, contributions welcome.

## License

Apache-2.0. See [LICENSE](LICENSE).
