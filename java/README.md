# fasten for Java (placeholder)

> **Not implemented.** This directory ships the typed shape (`Row`,
> `Meta`, `Severity`, `Anchor`, `AuditRepository`) so you can compile
> against the API, but `Fasten.emit(...).write()` throws
> `UnsupportedOperationException`. Use the Python, Go, JS, Rust or C++
> SDK to emit rows. They share the wire format defined in
> [`spec/row-schema.json`](../spec/row-schema.json), so audit rows
> emitted from any of them can be read from any other.

## Why ship the package at all?

So multi-language adopters can wire fasten's typed `Row` into Java-side
consumers (for example Kafka deserializers or Spring reader endpoints)
before the implementation lands.

## Status

v1.0 GA: placeholder. Emit support is tracked at
[https://github.com/nerdapplabs/fasten/issues](https://github.com/nerdapplabs/fasten/issues).
