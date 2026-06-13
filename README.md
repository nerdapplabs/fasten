# fasten

[![Python SDK](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-py.yml/badge.svg)](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-py.yml)
[![Go SDK](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-go.yml/badge.svg)](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-go.yml)
[![JS SDK](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-js.yml/badge.svg)](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-js.yml)
[![Rust SDK](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-rust.yml/badge.svg)](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-rust.yml)
[![C++ SDK](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-cpp.yml/badge.svg)](https://github.com/nerdapplabs/fasten/actions/workflows/fasten-cpp.yml)
[![Coverage](https://codecov.io/gh/nerdapplabs/fasten/branch/main/graph/badge.svg?flag=python)](https://codecov.io/gh/nerdapplabs/fasten)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0--beta-teal.svg)](CHANGELOG.md)

> *Logs tell you what happened. Traces tell you where. fasten tells you
> who changed what — and why.*

Audit + correlation SDK.

**For AI agents and software systems.**

Logs, HTTP access trail, and typed audit rows — one `request_id` threads all three streams. 7 anchors (5 Ws + H + CORRELATION) enforced at the type level. Bundled shims for HTTP, MQTT, and scheduler-fired jobs. A mountable HTTP reader API for querying it back.

**v1.0.0-beta.** Python is the reference SDK. Go, JS, Rust, C++, and Swift
are beta. Not yet on PyPI, npm, or crates.io — install from source.

**[Website →](https://fasten.sh)**

---

## Where it fits

fasten is the open-source substrate. Two commercial layers build on it:

- **[Membrane](https://fasten.sh/membrane)** governs what your agents
  believe and refuses bad writes at decision time.
- **[fasten fleet](https://fasten.sh/fleet)** aggregates records across
  many services, generates compliance evidence packs, and exposes
  `/investigate` for cited cross-stream answers.

You only need fasten to start.

---

## What it solves

| Question                                          | Before fasten          | With fasten            |
|---------------------------------------------------|-----------------------|-----------------------|
| Who deployed this config at 14:32?                | grep + Slack + 20 min | `?since=&until=` → 30 s |
| Which HTTP request caused this MQTT disconnect?   | Unknown               | Same `request_id`     |
| Show every mutation to this resource in 30 days   | Log scraping          | `?target=resource-id` |
| Compliance audit trail for a regulated deployment | Custom table + glue   | `?code=&since=&until=` |
| Which agent tool call wrote this record?          | Unknowable across multiple agents on one key | `?actor=&request_id=` |

---

## Install (source)

```bash
git clone https://github.com/nerdapplabs/fasten
cd fasten

pip install ./python                              # Python (reference)
go get github.com/nerdapplabs/fasten/go           # Go
npm install ./js                                  # Node / TypeScript
# Swift (SPM): add .package(url: "…/fasten", from: "1.0.0") to Package.swift
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

## Bundled CLI + TUI (Python)

Installed as console scripts when you `pip install ./python`. Run against
any fasten-mounted service via the standard `/api/v1/logs/{audit,sys,api}`
reader.

| Tool       | Invoke                            | What it does                                  |
|------------|-----------------------------------|-----------------------------------------------|
| CLI        | `fasten dump`                     | Print registered codes (CI consistency gate)  |
| CLI        | `fasten tail --stream sys`        | Stream rows from a mounted reader             |
| CLI        | `fasten doctor`                   | Verify init config + correlation wiring       |
| TUI        | `fasten-tui [--request-id <id>]`  | Live three-pane audit + sys + API feed (Rich) |

**TUI interactive controls** (no mouse; works over SSH):

| Key         | Action                                                     |
|-------------|------------------------------------------------------------|
| `L` / space | Toggle live polling on/off (default: **on** ●)            |
| `/`         | Open request_id picker — fuzzy search, ↑↓ cursor, Enter to select, Esc to clear |
| Tab         | Rotate primary pane: audit → sys → api → audit            |
| `q` / Ctrl-C | Quit                                                      |

If `--request-id <id>` is given, the TUI pre-selects it; `/` still lets you change it from inside the live view.

The TUI is SSH-friendly — works on industrial Linux hosts where no GUI
is permitted.

---

## Languages

| Language             | Status        | Min runtime | Location                                           |
|----------------------|---------------|-------------|----------------------------------------------------|
| Python               | reference     | 3.10        | [`python/`](python/)                               |
| Go                   | beta          | 1.21        | [`go/`](go/)                                       |
| Node.js / TypeScript | beta          | Node 18     | [`js/`](js/)                                       |
| Rust                 | beta          | 1.70        | [`rust/`](rust/)                                   |
| C++                  | single-header | C++14       | [`cpp/include/fasten.hpp`](cpp/include/fasten.hpp) |
| Swift                | beta          | macOS 13 / iOS 16 / Linux | [`swift/`](swift/)                   |
| Java                 | placeholder   | —           | [`java/`](java/)                                   |

Audit-store failure handling — the queue-mode default that keeps
`emit()` off the request path — is shipped in all 6 production SDKs
(Python, Go, JS, Rust, C++, Swift). A locked / down audit store no
longer cascades into 5xxs on the request path: rows queue with
exponential backoff and the drainer self-reports queue health on the sys
stream. Adopters who want loud failures during config debugging opt in via
`audit_store_failure_strategy="raise"` (Python/Go/JS/Rust/C++) or
`strategy: .raise` (Swift).

### C++ logger bridges

Three opt-in, header-only shims bridge popular C++ logging libraries into
fasten's `/logs/sys` ring — no call-site changes required:

| Library | Shim header | Usage |
|---------|------------|-------|
| **spdlog** | `fasten/shim/spdlog.hpp` | Push `fasten::shim::spdlog_sink_mt` onto your logger's sink list |
| **glog** | `fasten/shim/glog.hpp` | Call `fasten::shim::glog::install()` once after `fasten::init()` |
| **Boost.Log** | `fasten/shim/boost_log.hpp` | Add `fasten::shim::boost_log::sink_mt` to `boost::log::core` |

Each shim applies the same key-pattern and value-shape redaction as
`fasten::emit()`, so secrets in log messages are scrubbed before they
reach the ring. A per-thread recursion guard prevents infinite re-entry
if fasten's own internal log writes use the same logger.

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
