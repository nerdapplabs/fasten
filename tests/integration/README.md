# Integration tests — per-language Docker smokes

Each smoke runs the SDK in its language's most-used current base image,
exercises the audit + sys streams, and pipes stdout to `verify.py`,
which asserts the wire contract against the canonical
[spec/row-schema.json](../../spec/row-schema.json).

## Coverage

| Language | Base image           | Streams tested       | Path                  |
|----------|----------------------|----------------------|-----------------------|
| Python   | `python:3.10-slim`   | audit · sys · **api** | [`python/`](python/) |
| Go       | `golang:1.22-alpine` | audit · sys          | [`go/`](go/)         |
| Node.js  | `node:20-alpine`     | audit · sys          | [`node/`](node/)     |
| Rust     | `rust:1.85-slim`     | audit · sys          | [`rust/`](rust/)     |
| C++14    | `gcc:13-bookworm`    | audit · sys          | [`cpp/`](cpp/)       |
| Java     | _coming soon_        | —                    | _placeholder SDK; emit() throws today._ |

The **api stream** is tested in the Python smoke via a direct `write_api()` call
(no HTTP server needed). Go/Node/Rust/C++ api coverage follows once their HTTP
shims stabilise.

## What each smoke does

Core scenario (all five languages):

```
1. Register one code: USER_CREATED (domain=user, severity=info, action=create)
2. init() with FASTEN_SERVICE_ID=itest-<lang>, FASTEN_NODE_ID=host-itest
3. log.info("startup_ok", {lang})         → {"shape": "sys", ...} on stdout
4. emit(USER_CREATED, target=u-42,        → {"shape": "audit", ...} on stdout
        actor=admin, detail={
          email: "alice@acme.com",        ← preserved
          api_key: "sk-secret-abc",       ← redacted to "***"
          nested: {token: "xyz"}          ← nested.token redacted (where SDK supports nested detail)
        })
```

Python smoke additionally exercises:

```
5. write_api({method, path, status, ms, request_id, timestamp})
                                          → {"shape": "api", ...} on stdout
6. structlog shim: make_fasten_processor() buffers structlog events into
   fasten's syslog ring (in-process assertion; ring is not on stdout)
```

## Running

Requires Docker. From this directory:

```bash
make test                  # build + run + verify all five
make test-python           # one language only
make build                 # build images, no run
make clean                 # remove all images
```

`verify.py` is invoked by the Makefile via pipe; you can also feed it any
captured stdout by hand:

```bash
docker run --rm fasten-itest-rust | python3 verify.py
```

It exits 0 with `OK — N audit row(s), M sys row(s) — contract holds` on
success, non-zero with a readable `FAIL: …` message on contract violation.

## Wire contract checked

For every smoke, `verify.py` asserts:

- ≥ 1 line with `shape: "audit"` and ≥ 1 line with `shape: "sys"`
- **Audit row** — required fields (`id`, `monotonic_seq`, `timestamp`,
  `code`, `action`, `severity`, `service_id`, `source_node_id`, `actor`,
  `actor_kind`, `target`, `category`, `domain`, `method`, `request_id`,
  `detail`), `id` matches `evt-<hex>`, `request_id` is 12 hex chars,
  `code = USER_CREATED`, `action = create`, `severity ∈ {info,Info,INFO}`
- **Redaction** — `detail.email` preserved, `detail.api_key = "***"`,
  `detail.nested.token = "***"` (when nested support exists)
- **Sys row** — required fields (`level`, `event`, `request_id`,
  `timestamp`), `level ∈ {info,Info,INFO}`, `event = startup_ok`

## Why these base image versions

| Lang   | Pick    | Why |
|--------|---------|-----|
| Python | 3.10    | Lowest currently-maintained interpreter; `pyproject.toml` requires `>=3.10` |
| Go     | 1.22    | Module's `go 1.22` directive; alpine for image size |
| Node   | 20      | Active LTS; `package.json` engines `>=20` |
| Rust   | 1.85    | Matches `rust/Cargo.toml` `rust-version = "1.85"` |
| C++    | gcc 13  | C++14 support clean; bookworm-stable toolchain |

## Local CI integration

These tests are intended to land as the first concrete piece of P0-1 (CI
on day 1). A GitHub Actions workflow can run `make test` in a matrix —
each language as a parallel job.

## Adding a new language

1. Pick a base image (latest LTS / most-used current stable)
2. Add `<lang>/Dockerfile`, `<lang>/smoke.<ext>`, any build-config files
3. Add `<lang>` to the `LANGS` list in [`Makefile`](Makefile)
4. Run `make test-<lang>` until it passes
