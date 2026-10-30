# fasten threat model

**Version:** 1.0.0-beta  
**Last reviewed:** 2026-10-26  
**Scope:** Python (reference SDK), Go, JS/TS, Rust, C++, Swift

This document covers the security model of the fasten SDK: what it protects, what it explicitly does not protect, and the attack surfaces to consider when embedding fasten in a production service.

---

## 1. System overview

fasten is a library, not a standalone service. It runs inside the adopter's process and writes to:

- **stdout**: NDJSON audit, sys and api rows (the "ring transport")
- **an optional audit store**: a SQLite file or Postgres database, configured with `FASTEN_AUDIT_DSN` or an `audit_store` passed to `init()`. Without one, audit rows go to stdout only.

The runtime layout:

```
[ External caller / end-user ]
          │  HTTP request
          ▼
[ Adopter service process ]
   ├── fasten.emit() / log.*       ← SDK runs HERE, inside the adopter process
   ├── ring transport → stdout     ← captured by log aggregator (out of scope)
   └── audit store (SQLite/PG)     ← local file or network DB
          │
          ▼
[ fasten reader / query endpoints ]
   └── mounted at /api/v1/logs/*   ← served by the adopter's HTTP framework
```

**Trust boundary 1, process and store:** The audit store is trusted infrastructure. A compromised store (for example a shared Postgres server another tenant can write to) is outside fasten's threat model. fasten assumes the adopter controls the store.

**Trust boundary 2, caller and reader endpoints:** The reader routes (`/logs/audit`, `/logs/sys`, `/logs/api`, `/logs/audit/doctor`) return raw audit data. fasten has no built-in authentication; the adopter supplies it, for example with `dependencies=[Depends(require_auth)]`. An unauthenticated mount on a network interface is a misconfiguration.

**Trust boundary 3, emit and row content:** `fasten.emit()` accepts a `detail` dict from the adopter. The SDK redacts it before the row is written, but the adopter controls which keys and values go in. fasten does not check application-level correctness; it only removes recognisable secret shapes.

---

## 2. Attack surfaces

### 2.1 PII and secrets in emit() detail

**Description:** An adopter calls `fasten.emit(code=..., detail={"user_email": "alice@example.com", "token": "sk_live_..."})`. Without redaction, secrets land in the audit store.

**Mitigations in place:**

- *Key-pattern redaction (all SDKs):* Values whose keys match a case-insensitive regex covering `password`, `token`, `secret`, `key`, `authorization`, `api_key` and related patterns are replaced with `"***"` before the row is written to stdout or the store. The patterns come from `spec/row-schema.json` and are kept in sync across SDKs by `spec/codegen.py`.

- *Value-shape redaction (Python, Go, JS, Rust, C++, Swift; added in v1.0.0-beta):* String values not already redacted by the key-pattern pass are checked against known secret shapes: JWT (three-segment base64url), PEM private key block, AWS access key (`AKIA`/`ASIA`), GitHub tokens (`ghp_`/`ghs_`/etc.), Stripe live secret (`sk_live_`), OpenAI key (`sk-`/`sk-proj-`), and credit-card numbers that pass the Luhn checksum. Matches are replaced with type-hinting tokens (`***JWT***`, `***CC***`, etc.).

- *Structlog processor:* `fasten.redactor().as_structlog_processor()` applies the same two-pass redaction to structlog's event dict, so log lines that reach `fasten.log.*` get the same scrubbing.

**Not mitigated:**

- High-entropy strings that match no named shape (random UUIDs, custom token formats). Adopters with custom secret shapes should call `fasten.init(extra_redact_keys=[...], extra_value_redact_patterns=[...])`.
- Secrets inside longer natural-language strings (e.g. `"error: invalid token eyJ..."`). The value-shape scanner uses `search()`, not a full-string match, so embedded JWTs are caught, but unusual wrapping can defeat shape detection for formats without a named rule.
- Base64-encoded secrets (double-encoded PII is not detected).

---

### 2.2 SQL injection in filter parameters

**Description:** Reader endpoints (`GET /logs/audit?actor=...&code=...`) pass caller-supplied strings into SQL queries. With string interpolation, a malicious value could alter the query.

**Mitigations in place:**

- Every filter parameter in the SQLite store (`store/sqlite.py`) and the Postgres store (`store/postgres.py`) is passed as a positional bind parameter (`?` for SQLite, `%s` for Postgres). The `WHERE` clause is built from a list of static predicate strings; only values come from caller input, never column names or operators.
- `LIMIT` and `OFFSET` are bound parameters, not interpolated.

**Not mitigated:**

- The table name (with an optional `schema.` prefix on Postgres) is set at `init()` time from trusted configuration, such as the DSN's `?table=` parameter or the store constructor, never from request parameters. It is interpolated into the `CREATE TABLE` / `SELECT` statements as an f-string, because SQLite and Postgres do not support bind parameters for table names. The store constructors reject names that are not plain SQL identifiers, but table and schema names must still be treated as trusted configuration and never built from attacker-controlled data.

---

### 2.3 Reader endpoint authentication

**Description:** The reader returns raw audit rows, including actor, target and detail fields. An unauthenticated reader on a public interface exposes the audit trail.

**Mitigations in place:**

- `fasten.reader.router()` requires a `dependencies=` argument, such as `[Depends(require_admin)]` or the bundled `fasten.reader.require_bearer()`. FastAPI applies it to every route, including `/doctor`. Calling `router()` without it raises at startup; mounting without auth takes an explicit `dependencies=[]`.
- The router docstring leads with the authenticated example and states that the router has no auth of its own. The unauthenticated, trusted-network mount is the secondary example.

**Not mitigated:**

- fasten does not enforce authentication. A router mounted with `dependencies=[]` on a public interface has no access control. This is a deployment concern rather than a library concern, but treat the `/logs/*` routes like any internal admin endpoint.
- The `/doctor` endpoint returns queue depth, store row count and init parameters. This is less sensitive than audit rows but should still be gated.

---

### 2.4 Cross-tenant row access

**Description:** In a multi-tenant deployment where several tenants share one audit store, a query without a `tenant_id` filter returns rows for all tenants.

**Mitigations in place:**

- The `tenant_id` column is part of the row schema and is stored in the audit table. The `query()` / `count()` methods accept `tenant_id` as a filter.
- The reader accepts a `tenant_scope` hook (`router(tenant_scope=...)` in Python, `NewReader(WithTenantScope(...))` in Go) that resolves the caller's tenant from the authenticated request. When it is set, every reader endpoint ignores any caller-supplied `?tenant_id=` and scopes results to the resolved tenant. `enforce_tenant_isolation=True` (Go: `EnforceTenantIsolation()`) refuses to build the reader without the hook.
- Adopters can also enforce per-tenant filtering in their own auth dependency by extracting the tenant from the authenticated identity and passing it explicitly to `fasten.audit_store().query(tenant_id=...)`.
- Tenant isolation is covered by tests (`python/tests/test_multitenant.py`, `python/tests/test_tenant_scope.py`, `go/tenant_scope_test.go`).

**Not mitigated:**

- fasten does not enforce tenant isolation on its own. There is no row-level security in the SQLite or Postgres schema. Without a `tenant_scope` hook, the reader honours `?tenant_id=` from the query string as-is, so a tenant could query another tenant's rows by substituting a different `tenant_id`.

---

### 2.5 Credentials in stack traces and log messages

**Description:** Exception stack traces, debug log lines, or framework-generated request logs may contain secret values that reach the sys ring or the audit `detail` field.

**Mitigations in place:**

- The spdlog, glog and Boost.Log C++ shims apply the same two-pass redaction to log message strings before pushing to the sys ring.
- `fasten.shim.stdlib.LoggingHandler` redacts the whole row it builds from a stdlib `LogRecord`: the `extra` fields get key-pattern and value-shape redaction, and the formatted message is checked against the value-shape rules.
- `fasten.shim.structlog.configure()` installs the redactor processor into structlog's chain, which applies the key-pattern and value-shape passes to the event dict's payload fields.

**Not mitigated:**

- Exception messages the adopter puts in `detail` (e.g. `detail={"error": str(exc)}`) may contain secrets if the exception string does. fasten catches recognised shapes but cannot catch every pattern.
- Stack traces passed as strings to `fasten.log.error()` or `emit(detail={"traceback": ...})` are value-shape scanned but not parsed, so a secret inside a traceback frame string is caught only if it matches a known shape.

---

### 2.6 Deserialization of detail payloads

**Description:** The `detail` field is a free-form dict. If fasten serialised and deserialised it with an unsafe mechanism (pickle, or YAML with `Loader=yaml.Loader`), a crafted payload could execute code.

**Mitigations in place:**

- `detail` is serialised to JSON (stdlib `json.dumps`) for storage and stdout. JSON has no execution semantics.
- The catalog YAML loader (`fasten.codes.load()`) uses `yaml.safe_load()`, which does not construct arbitrary Python objects.
- The reader turns stored JSON back into Python dicts with `json.loads()`. No pickle, no `yaml.load` with an unsafe loader, no `eval`.

**Not mitigated:**

- A value in `detail` that is not JSON-serialisable (such as a class instance) is written as its `str()` form. It is never turned back into an object, so it cannot execute code. This is a fail-safe rather than a mitigation.

---

### 2.7 Path traversal in reader endpoints

**Description:** Reader endpoints take path or query parameters. If a parameter were used to build a file path or include name, a traversal attack could read arbitrary files.

**Mitigations in place:**

- Reader route parameters (`request_id`, `code`, `domain`, `actor`, `target`, `since`, `until`, `limit`, `offset`) are all SQL bind parameters. None is used to build a file system path.
- The SQLite DSN (`sqlite:///./fasten-audit.db`) is set at `init()` time from trusted configuration, not from request parameters.

**Not mitigated:**

- None identified. The reader serves no files, and no parameter reaches an `open()` call.

---

### 2.8 Ring buffer resource exhaustion

**Description:** The in-memory sys and api rings have a fixed capacity. Under high throughput the oldest rows are overwritten first. This is a data-loss concern rather than a security concern, but worth noting:

- The ring size is fixed when the transport is created (default 2000 rows per stream). An adversary who can generate high log volume can push older rows out of the ring before they are read.
- The audit queue (`queue_capacity`, default 100) blocks `emit()` callers when full, applying back-pressure rather than dropping rows silently. An adversary who can saturate the audit store can make `emit()` block on the request path, but that requires controlling the store, which is outside the threat model.

---

## 3. What is explicitly not mitigated

The following are outside fasten's security boundary by design:

| Scenario | Rationale |
|----------|-----------|
| Compromised host OS | If the host is compromised, the process memory, the SQLite file, stdout and the Postgres credentials are all readable. fasten adds no protection above the OS. |
| Compromised audit store | An attacker who can write to the audit store directly, without going through fasten, can insert or modify rows. The hash chain (`prev_hash`) detects tampering on read but does not prevent it. |
| Denial of service against the adopter service | fasten is a library. Traffic against the adopter's HTTP service can saturate fasten's rings, but that is an application-level concern, not a fasten security boundary. |
| Unauthenticated reader mount | Deploying the reader with `dependencies=[]` on a public interface is a misconfiguration. fasten documents this and provides the hook; enforcement is the deployer's responsibility. |
| Secrets in adopter-controlled `detail` values that match no known shape | fasten catches what it knows. Custom token formats, encoded secrets or new PII patterns need `extra_redact_keys` / `extra_value_redact_patterns` registered by the adopter. |
| Multi-tenant row isolation without a `tenant_scope` hook or adopter-enforced `tenant_id` filtering | fasten stores `tenant_id` but does not filter on it by itself. The query API and the reader's `tenant_scope` hook support filtering; enforcement is the adopter's responsibility. |

---

## 4. Reporting

See [SECURITY.md](../SECURITY.md) for the vulnerability disclosure policy and response SLA.

To report a secret the redaction layer missed, include the `detail` dict that was not redacted, the SDK version, and the language. A reproducible test case helps but is not required for triage.
