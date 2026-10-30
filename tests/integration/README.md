# Integration tests: per-language Docker smokes

Each smoke runs the SDK in its language's most-used current base image,
writes audit and sys rows, and pipes stdout to `verify.py`, which checks the
wire contract against the canonical
[spec/row-schema.json](../../spec/row-schema.json).

## Coverage

| Language | Base image           | Streams tested       | Path                  |
|----------|----------------------|----------------------|-----------------------|
| Python   | `python:3.10-slim`   | audit, sys, **api**  | [`python/`](python/) |
| Go       | `golang:1.22-alpine` | audit, sys           | [`go/`](go/)         |
| Node.js  | `node:24-alpine`     | audit, sys           | [`node/`](node/)     |
| Rust     | `rust:1.85-slim`     | audit, sys           | [`rust/`](rust/)     |
| C++14    | `gcc:13-bookworm`    | audit, sys           | [`cpp/`](cpp/)       |
| Java     | _coming soon_        | none                 | _placeholder SDK; emit() throws today._ |

The **api stream** is tested only in the Python smoke, through a direct
`write_api()` call (no HTTP server needed). Go, Node, Rust and C++ api
coverage will follow once their HTTP shims are stable.

## What each smoke does

Core scenario (all five languages):

```
1. Register one code: USER_CREATED (domain=user, severity=info, action=create)
2. init() with FASTEN_SERVICE_ID=itest-<lang>, FASTEN_NODE_ID=host-itest
3. log.info("startup_ok", {lang})         → {"shape": "sys", ...} on stdout
4. emit(USER_CREATED, target=u-42,        → {"shape": "audit", ...} on stdout
        actor=admin, detail={
          email: "alice@acme.com",              ← preserved
          api_key: "sk-secret-abc",             ← redacted to "***"
          customer_token: "tok-substring-test", ← redacted (key contains "token")
          nested: {token: "xyz"}                ← nested.token redacted (not in C++, whose detail is flat)
        })
```

The Python smoke also covers:

```
5. write_api({method, path, status, ms, request_id, timestamp})
                                          → {"shape": "api", ...} on stdout
6. structlog shim: make_fasten_processor() copies structlog events into
   fasten's syslog ring (checked in-process; the ring is not on stdout)
```

## Running

Requires Docker. From this directory:

```bash
make test                  # build + run + verify all five
make test-python           # one language only
make build                 # build images, no run
make clean                 # remove all images
```

The Makefile pipes each container's stdout into `verify.py`. You can also
feed it any captured stdout by hand:

```bash
docker run --rm fasten-itest-rust | python3 verify.py
```

On success it exits 0 and prints
`OK — N audit row(s), M sys row(s), ... — contract holds`. On a contract
violation it exits non-zero with a readable `FAIL: ...` message.

Set `FASTEN_VERIFY_REQUIRE_API=1` to also require an api row. `make
test-python` sets it; the other targets do not.

## Wire contract checked

For every smoke, `verify.py` checks:

- At least one line with `shape: "audit"` and at least one with
  `shape: "sys"`.
- **Audit row**: required fields (`wire_version`, `shape`, `id`,
  `origin_id`, `monotonic_seq`, `timestamp`, `code`, `action`, `severity`,
  `service_id`, `source_node_id`, `actor`, `actor_kind`, `target`,
  `category`, `domain`, `method`, `request_id`, `detail`);
  `wire_version = "1"`; `id` matches `evt-` plus 20 hex chars;
  `request_id` is 12 hex chars; `code = USER_CREATED`; `action = create`;
  `severity` is one of `info`, `Info`, `INFO`.
- **Redaction**: `detail.email` preserved; `detail.api_key = "***"`;
  `detail.customer_token = "***"`; `detail.nested.token = "***"` when
  `nested` is present.
- **Sys row**: required fields (`level`, `event`, `request_id`,
  `timestamp`); `level` is one of `info`, `Info`, `INFO`;
  `event = startup_ok`.
- **Api row**, if any: required fields (`method`, `path`, `status`,
  `request_id`, `timestamp`); `request_id` is 12 hex chars;
  `method = POST`; `status = 201`.

## Why these base image versions

| Lang   | Pick    | Why |
|--------|---------|-----|
| Python | 3.10    | Lowest maintained interpreter; `pyproject.toml` requires `>=3.10` |
| Go     | 1.22    | Module's `go 1.22` directive; alpine for image size |
| Node   | 24      | Matches `js/package.json` engines `>=24` |
| Rust   | 1.85    | Older than fasten-core's `rust-version = "1.90"`, so this image can't build it yet |
| C++    | gcc 13  | Clean C++14 support; bookworm-stable toolchain |

## CI

No GitHub Actions workflow runs these smokes yet. They don't run as-is
either: the Go, Python and Rust images don't build `fasten-core`, and
`verify.py` is missing an `import os` (#141).

## Adding a new language

1. Pick a base image (latest LTS or most-used current stable).
2. Add `<lang>/Dockerfile`, `<lang>/smoke.<ext>`, and any build-config files.
3. Add `<lang>` to the `LANGS` list in [`Makefile`](Makefile).
4. Run `make test-<lang>` until it passes.
