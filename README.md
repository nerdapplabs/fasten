# fasten

[![Python SDK](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-py.yml/badge.svg)](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-py.yml)
[![Go SDK](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-go.yml/badge.svg)](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-go.yml)
[![JS SDK](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-js.yml/badge.svg)](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-js.yml)
[![Rust SDK](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-rust.yml/badge.svg)](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-rust.yml)
[![C++ SDK](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-cpp.yml/badge.svg)](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-cpp.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0--beta-teal.svg)](CHANGELOG.md)

> *Logs tell you what happened. Traces tell you where. fasten tells you
> who changed what — and why.*

Audit + correlation SDK.

Logs, HTTP access trail, and typed audit rows — one `request_id` threads all three streams. 6 anchors (5 Ws + How) enforced at the type level; bundled shims for HTTP, MQTT, and scheduler-fired jobs. 

One mountable query (API endpoints) surface.

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

| Language             | Status        | Min runtime | Location                                           |
|----------------------|---------------|-------------|----------------------------------------------------|
| Python               | reference     | 3.10        | [`python/`](python/)                               |
| Go                   | usable        | 1.21        | [`go/`](go/)                                       |
| Node.js / TypeScript | beta          | Node 18     | [`js/`](js/)                                       |
| Rust                 | beta          | 1.70        | [`rust/`](rust/)                                   |
| C++                  | single-header | C++14       | [`cpp/include/fasten.hpp`](cpp/include/fasten.hpp) |
| Java                 | placeholder   | —           | [`java/`](java/)                                   |

Audit-store failure handling — the queue-mode default that keeps
`emit()` off the request path — is shipped in all 5 SDKs (Python,
Go, JS, Rust, C++). A locked / down audit store no longer cascades
into 5xxs on the request path: rows queue with exponential backoff
and the drainer self-reports queue health on the sys stream.
Adopters who want loud failures during config debugging opt in via
`audit_store_failure_strategy="raise"`.

### Wire schema versioning

Every audit row carries `"wire_version": "1"`. This field exists so
that tools reading fasten output — log ingestors, compliance
dashboards, replication outboxes — can tell which schema they are
looking at, even years after the row was written.

The contract is forward-compatible: **readers must accept any
`wire_version` value higher than what they know about** and process
the row on a best-effort basis. A reader that hard-rejects unknown
versions will break silently when fasten releases a future schema
revision. If fasten ever changes the row shape in a way that could
break readers (renaming a required field, changing a type), it will
bump the version number so readers have an explicit signal to act on.

---

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Status

v1.0.0-beta. Apache-2.0, contributions welcome.

## License

Apache-2.0. See [LICENSE](LICENSE).
