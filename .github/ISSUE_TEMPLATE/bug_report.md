---
name: Bug report
about: Something doesn't work the way the docs / spec say it should.
labels: bug
---

<!--
Security vulnerability? Please follow SECURITY.md instead — do NOT
open a public issue.
-->

### Affected SDK

<!-- Mark all that apply. -->

- [ ] Python
- [ ] Go
- [ ] Node / TypeScript
- [ ] Rust
- [ ] C++14
- [ ] Spec / wire format (`spec/row-schema.json`)
- [ ] Reader endpoint / docs

### Versions

- fasten: <!-- e.g. v1.0.0-beta SHA abc1234 -->
- Language runtime: <!-- e.g. Python 3.11.7 / Go 1.22 / Node 24 / Rust 1.85 -->
- OS / arch: <!-- e.g. linux/amd64, macOS 14 / arm64 -->
- Store backend: <!-- sqlite / postgres / custom AuditRepository -->

### What happened

<!-- Concise description of the actual behaviour. Stack trace, error
message, or stdout NDJSON line as a code block. -->

### What you expected

<!-- One or two lines. Link the doc / spec line that says it should
behave the other way, if you can. -->

### Minimal reproducer

<!-- The smallest code/sample that triggers it. If it needs Docker, a
1-line `docker run ...` is ideal. -->

```
# code or shell here
```

### Evidence

<!-- Paste the actual artifacts. The more concrete, the faster the fix.
Anything that helps someone else reproduce or diagnose:

- Stack trace / exception message (full, with file:line)
- The {"shape":"audit"|"sys"|"api",...} stdout NDJSON line(s)
- `fasten.queue_stats()` output (Python) / `GetQueueStats()` (Go) /
  `queueStats()` (JS) / `fasten::queue_stats()` (Rust / C++)
- `GET /logs/audit/doctor` JSON if the reader is mounted
- `fasten doctor` CLI output (Python adopters)
- Container / OS logs around the failure (timestamp ± 5 s) -->

```
# paste output / logs / JSON here
```

### Anything else

<!-- Related issues, workarounds you tried, suspected root cause. -->

