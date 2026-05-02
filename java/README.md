# fasten — Java (placeholder)

> **Not implemented.** This directory ships the typed shape (`Row`,
> `Meta`, `Severity`, `Anchor`, `AuditRepository`) so adopters can
> compile against the API surface, but `Fasten.emit(...).write()`
> throws `UnsupportedOperationException`. Use Python, Go, JS, Rust,
> or C++ SDKs for actual emit functionality — they share a common
> wire format defined in
> [`spec/row-schema.json`](../spec/row-schema.json), so audit rows
> emitted from any of them are readable from any other.

## Why ship the package at all?

So multi-language adopters can wire fasten's typed `Row` into
Java-side downstream consumers (e.g. Kafka deserializers, Spring
reader endpoints) before the implementation lands.

## Status

v1.0 GA: placeholder. Emit semantics tracked at
[https://github.com/nerdapplabs/fasten/issues](https://github.com/nerdapplabs/fasten/issues).
