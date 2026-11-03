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
> who changed what, and why.*

fasten is an audit and correlation SDK for AI agents and software systems.
It goes beyond observability to state over time, and from observation to
evidence: verify before, govern during, prove after.

A software system is more than its AI agents. Logs, metrics and traces tell
you what is happening. fasten is a fourth pillar next to them: it connects AI
and non-AI components with a tamper-evident record of what happened, who
changed it, and who can prove it.

It writes three streams: logs, an HTTP access trail, and typed audit rows.
One `request_id` ties them together. Every audit row carries 7 anchors (the
5 Ws, H, and CORRELATION), enforced at the type level. Shims for HTTP, MQTT
and scheduler-fired jobs are included, along with a mountable HTTP reader
API for querying the record back.

**Status: v1.0.0-beta.** Python is the reference SDK. Go, JS, Rust, C++ and
Swift are beta. Nothing is published to PyPI, npm or crates.io yet; install
from source.

[Website](https://fasten.sh)

---

## Where it fits

fasten is the open-source base layer. It treats AI agents as one kind of
actor alongside users, services, schedulers and integrations, and records
all of them the same way.

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
| Who deployed this config at 14:32?                | grep + Slack + 20 min | `?since=&until=`, 30 s |
| Which HTTP request caused this MQTT disconnect?   | Unknown               | Same `request_id`     |
| Show every mutation to this resource in 30 days   | Log scraping          | `?target=resource-id` |
| Compliance audit trail for a regulated deployment | Custom table + glue   | `?code=&since=&until=` |
| Which agent tool call wrote this record?          | Unknowable across multiple agents on one key | `?actor=&request_id=` |

---

## Install and quickstart

Start at **[fasten.sh/docs](https://fasten.sh/docs/)**. The install steps
for every language and a runnable Python quickstart are at the top of the
page. Each SDK directory also has its own README:
[Python](python/README.md), [Go](go/README.md), [Node](js/README.md),
[Rust](rust/README.md), [C++](cpp/README.md), [Java](java/README.md).

---

## Reference

The same docs cover the language matrix (Python, Go, Node, Rust, C++,
Swift), the bundled CLI and TUI, the C++ logger bridges (spdlog, glog,
Boost.Log), audit-store failure handling, PII redaction, and the wire
schema versioning contract.

---

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Status

v1.0.0-beta. Apache-2.0. Contributions are welcome.

## License

Apache-2.0. See [LICENSE](LICENSE).
