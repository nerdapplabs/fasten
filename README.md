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

A software system is more than AI agents. Logs, metrics, and traces tell
you *what is happening*. **fasten is the connective tissue across AI and
non-AI components** — the fourth pillar, joining all three with the
tamper-evident record of *what happened, who changed it, who can prove it*.

Logs, HTTP access trail, and typed audit rows — one `request_id` threads all three streams. 7 anchors (5 Ws + H + CORRELATION) enforced at the type level. Bundled shims for HTTP, MQTT, and scheduler-fired jobs. A mountable HTTP reader API for querying it back.

**v1.0.0-beta.** Python is the reference SDK. Go, JS, Rust, C++, and Swift
are beta. Not yet on PyPI, npm, or crates.io — install from source.

**[Website →](https://fasten.sh)**

---

## Where it fits

fasten is the open-source substrate. It treats AI agents as one kind of
actor, alongside users, services, schedulers, and integrations. Same
primitive for every actor.

Two commercial layers build on it:

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

## Reference

The full docs live at **[fasten.sh/docs](https://fasten.sh/docs/)** —
language matrix (Python, Go, Node, Rust, C++, Swift), bundled CLI + TUI,
C++ logger bridges (spdlog, glog, Boost.Log), audit-store failure
handling, PII redaction, and the wire schema versioning contract.

---

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Status

v1.0.0-beta. Apache-2.0, contributions welcome.

## License

Apache-2.0. See [LICENSE](LICENSE).
