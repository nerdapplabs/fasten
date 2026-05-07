# fasten — Threat Model

**Version:** 1.0.0-beta  
**Last reviewed:** 2026-05-08  
**Scope:** Python (reference SDK), Go, JS/TS, Rust, C++, Swift

This document covers the security model of the fasten SDK: what it protects, what it explicitly does not protect, and the attack surfaces an adopter should reason about when embedding fasten in a production service.

---

## 1. System overview

fasten is a library, not a standalone service. It embeds into the adopter's process and writes to:

- **stdout** — NDJSON audit/sys/api rows (the "ring transport")
- **an audit store** — SQLite file or Postgres database, configured via `FASTEN_AUDIT_DSN`

Two trust boundaries exist at runtime:

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

**Trust boundary 1 — process ↔ store:** The audit store is trusted infrastructure. A compromised store (e.g. a shared Postgres server a different tenant can write to) is outside fasten's threat model. fasten assumes the store is controlled by the adopter.

**Trust boundary 2 — caller ↔ reader endpoints:** The reader routes (`/logs/audit`, `/logs/sys`, `/logs/api`, `/logs/audit/doctor`) surface raw audit data. fasten provides no built-in authentication; authentication is the adopter's responsibility via `dependencies=[Depends(require_auth)]`. An unauthenticated mount on a network interface is a misconfiguration.

**Trust boundary 3 — emit ↔ row content:** `fasten.emit()` accepts a `detail` dict from the adopter. The SDK applies redaction before the row is written; but the adopter controls what keys and values enter the dict. fasten does not sanitize for application-level correctness — it only removes recognisable secret shapes.

---

## 2. Attack surfaces

### 2.1 PII / secret leakage via emit() detail

**Description:** An adopter calls `fasten.emit(code=..., detail={"user_email": "alice@example.com", "token": "sk_live_..."})`. Without redaction, secrets land in the audit store.

**Mitigations in place:**

- *Key-pattern redaction (all SDKs):* Values whose keys match a case-insensitive regex covering `password`, `token`, `secret`, `key`, `authorization`, `api_key`, and related patterns are replaced with `"***"` before the row is written to stdout or the store. Patterns are generated from `spec/row-schema.json` and kept in sync across SDKs via `spec/codegen.py`.

- *Value-shape redaction (Python, Go, JS, Rust, C++, Swift — added in v1.0.0-beta):* String scalars not already redacted by key-pattern pass are checked against known secret shapes: JWT (three-segment base64url), PEM private key block, AWS access key (`AKIA`/`ASIA`), GitHub tokens (`ghp_`/`ghs_`/etc.), Stripe live secret (`sk_live_`), OpenAI key (`sk-`/`sk-proj-`), and credit-card numbers passing the Luhn checksum. Replaced with type-hinting tokens (`***JWT***`, `***CC***`, etc.).

- *Structlog processor:* `fasten.redactor().as_structlog_processor()` applies the same two-pass redaction to structlog's event dict, so log lines that reach `fasten.log.*` go through the same scrubbing.

**Not mitigated:**

- High-entropy strings that do not match any named shape (random UUIDs, custom token formats). Adopters with custom secret shapes should call `fasten.init(extra_redact_keys=[...], extra_value_redact_patterns=[...])`.
- Secrets embedded inside longer natural-language strings (e.g. `"error: invalid token eyJ..."`) — the value-shape scanner uses `search()` not full-string match, so embedded JWTs ARE caught, but obscured wrapping may defeat shape detection for unnamed formats.
- Base64-encoded secrets (double-encoded PII is not detected).

---

### 2.2 SQL injection in filter parameters

**Description:** Reader endpoints (`GET /logs/audit?actor=...&code=...`) pass caller-supplied strings into SQL queries. If string interpolation were used, a malicious value could alter the query.

**Mitigations in place:**

- All filter parameters in both the SQLite store (`store/sqlite.py`) and Postgres store (`store/postgres.py`) are passed as positional bind parameters (`?` for SQLite, `%s` for Postgres). The `WHERE` clause is built from a list of static predicate strings; only values, never column names or operators, come from caller input.
- The `LIMIT` and `OFFSET` values are bound parameters, not interpolated.

**Not mitigated:**

- The table name and schema name are set at `init()` time from trusted configuration (env var or explicit argument), not from request parameters. They are interpolated into the `CREATE TABLE` / `SELECT` statement as f-strings. This is intentional — table name bind parameters are not supported in SQLite or Postgres. An adopter who passes attacker-controlled data to `FASTEN_AUDIT_TABLE` or `FASTEN_PG_SCHEMA` would be vulnerable; these must be treated as trusted configuration.

---

### 2.3 Reader endpoint authentication bypass

**Description:** The reader exposes raw audit rows including actor, target, and detail fields. An unauthenticated reader on a public interface leaks the audit trail.

**Mitigations in place:**

- `fasten.reader.router()` takes a `dependencies=[Depends(...)]` argument. When supplied, FastAPI applies the dependency to every route including `/doctor`. This is the recommended path and is the primary example in the docstring.
- The router docstring includes an explicit `WARNING` that no built-in auth exists and the trusted-network mount is a secondary path.

**Not mitigated:**

- fasten does not enforce authentication. A router mounted without `dependencies=` on a public interface has no access control. This is a deployment concern, not a library concern, but adopters should treat `/logs/*` routes the same as any internal admin endpoint.
- The `/doctor` endpoint returns queue depth, store row count, and init parameters. This is lower-sensitivity than audit rows but should still be gated.

---

### 2.4 Cross-tenant row leakage

**Description:** In a multi-tenant deployment where multiple tenants share one audit store, a query without a `tenant_id` filter returns rows for all tenants.

**Mitigations in place:**

- The `tenant_id` column exists in the row schema and is stored in the audit table. The `query()` / `count()` methods accept `tenant_id` as a filter parameter.
- Adopters can enforce per-tenant filtering in their auth dependency by extracting the tenant from the authenticated identity and passing it explicitly to `fasten.audit_store().query(tenant_id=...)`.

**Not mitigated:**

- fasten does not auto-enforce tenant isolation. There is no row-level security built into the SQLite or Postgres schema. If the reader endpoint passes `tenant_id` from query params without validating it against the authenticated identity, a tenant could query another tenant's rows by substituting a different `tenant_id` in the request.
- A dedicated test verifying zero cross-tenant leakage across SQLite and Postgres is tracked as part of P1-3 and is not yet in CI.

---

### 2.5 Credential leakage in stack traces and log messages

**Description:** Exception stack traces, debug log lines, or framework-generated request logs may contain secret values that reach the sys ring or the audit `detail` field.

**Mitigations in place:**

- The spdlog, glog, and Boost.Log C++ shims apply the same two-pass redaction to log message strings before pushing to the sys ring.
- `fasten.shim.stdlib.LoggingHandler` applies redaction to the `extra` dict attached to a stdlib `LogRecord`. The `msg` string itself is not redacted — structured extras are (this mirrors the contract in Python logging where the message template is static but extras are structured data).
- `fasten.shim.structlog.configure()` installs the redactor processor into structlog's chain; all structlog event_dict fields (including `event`) go through the key-pattern + value-shape pass.

**Not mitigated:**

- Exception messages embedded in `detail` by the adopter (e.g. `detail={"error": str(exc)}`) may contain secrets if the exception string itself contains a secret. fasten will catch recognised shapes but cannot catch all possible leakage patterns.
- Stack traces passed as strings to `fasten.log.error()` or `emit(detail={"traceback": ...})` are value-shape scanned but not structurally parsed — a secret inside a traceback frame string is caught only if it matches a known shape.

---

### 2.6 Deserialization of detail payloads

**Description:** The `detail` field is a free-form dict. If fasten serialised and re-deserialised this using an unsafe mechanism (pickle, YAML with `Loader=yaml.Loader`), a crafted payload could achieve code execution.

**Mitigations in place:**

- `detail` is serialised to JSON (stdlib `json.dumps`) for storage and stdout output. JSON has no execution semantics.
- The catalog YAML loader (`fasten.codes.load()`) uses `yaml.safe_load()`, which does not execute arbitrary Python objects.
- The reader deserialises stored JSON back to Python dicts using `json.loads()`. No pickle, no `yaml.load` with an unsafe loader, no `eval`.

**Not mitigated:**

- If an adopter stores a reference to a class instance in `detail` (not JSON-serialisable), `json.dumps` will raise `TypeError` — it will not silently succeed and execute code. This is a fail-safe rather than a mitigation, but it means the failure mode is a visible error, not silent code execution.

---

### 2.7 Path traversal in reader endpoints

**Description:** Reader endpoints take path or query parameters. If any parameter were used to construct a file path or include name, a traversal attack could read arbitrary files.

**Mitigations in place:**

- Reader route parameters (`request_id`, `code`, `domain`, `actor`, `target`, `since`, `until`, `limit`, `offset`) are all passed as SQL bind parameters. No parameter is used to construct a file system path.
- The SQLite DSN (`sqlite:///./fasten-audit.db`) is set at `init()` time from trusted configuration, not from request parameters.

**Not mitigated:**

- None identified. The reader has no file-serving functionality and no parameter reaches a `open()` call.

---

### 2.8 Ring buffer resource exhaustion

**Description:** The in-memory syslog and API rings have a fixed capacity. Under high throughput, old rows are overwritten (oldest-first). This is a data-loss concern, not a security concern, but it is worth noting:

- The ring size is fixed at init time (`ring_capacity`, default 512 per stream). An adversary who can generate high log volume can push older rows out of the ring before they are read.
- The audit queue (`queue_capacity`, default 100) blocks `emit()` callers when full, applying back-pressure rather than dropping silently. An adversary who can saturate the audit store can force `emit()` to block on the request path — but this requires controlling the store, which is outside the threat model.

---

## 3. What is explicitly NOT mitigated

The following are outside fasten's security boundary by design:

| Scenario | Rationale |
|----------|-----------|
| Compromised host OS | If the host is compromised, the process memory, the SQLite file, stdout, and the Postgres credentials are all readable. fasten provides no additional protection layer above the OS. |
| Compromised audit store | If an attacker can write to the audit store directly (bypassing fasten), they can insert or modify rows. The hash-chain field (`prev_hash`) detects tampering on read but does not prevent it. |
| Denial of service against the adopter service | fasten is a library. An adversary generating traffic against the adopter's HTTP service can saturate fasten's rings, but this is an application-level concern — not a fasten security boundary. |
| Unauthenticated reader mount | Deploying the reader without `dependencies=[Depends(auth)]` on a public interface is a misconfiguration. fasten documents this prominently and provides the hook; enforcement is the deployer's responsibility. |
| Secrets in adopter-controlled `detail` values that don't match any known shape | fasten catches what it knows. Custom token formats, encoded secrets, or novel PII patterns require `extra_redact_keys` / `extra_value_redact_patterns` to be registered by the adopter. |
| Multi-tenant row isolation without adopter-enforced `tenant_id` filtering | fasten stores `tenant_id` but does not auto-filter. The query API is filtering-capable; enforcement is the adopter's responsibility. |

---

## 4. Reporting

See [SECURITY.md](../SECURITY.md) for the vulnerability disclosure policy and response SLA.

To report a bypass in the redaction layer, include the `detail` dict that was not redacted, the SDK version, and the language. A reproducible test case is appreciated but not required for triage.
