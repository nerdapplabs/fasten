# [P0-4] Secured reader: `X-Rivet-Key` + CORS + bundled-tools auth

**Priority:** P0 · **Effort:** M · **Labels:** `priority/P0` `area/security` `area/api`

## What

Three pieces that ship together — designing reader auth without bundling
client-side support and CORS leaves bundled tools and adopters stuck.

**1. Bundled key system (Mode 2 — when rivet owns the DB)**

- New table `reader_keys (id, name, hash, scopes, created_at, last_used_at, revoked_at)`
  in the audit DSN; values stored as `sha256` hash, plaintext shown once at creation.
- New CLI subcommands (operate via direct DSN, no HTTP bootstrap problem):
  - `rivet key create --name <label> --scopes audit[,sys,api]`
  - `rivet key list`
  - `rivet key revoke <id>`
  - `rivet key rotate <id>` — creates new + revokes old
- New FastAPI dependency `rivet.reader.with_keys(store)` that:
  1. Reads `X-Rivet-Key: <token>` → 401 if missing
  2. `sha256(token)` → table lookup → 401 if no match or `revoked_at IS NOT NULL`
  3. Checks scope vs requested stream → 403 if not allowed
  4. Updates `last_used_at`, sets `request.state.key_name`
  5. Emits `READER_QUERY` audit row (`actor_kind=app`, `actor=key.name`, original `request_id`)
- Off by default. Activated by `RIVET_READER_AUTH=keys` or by explicitly mounting
  `rivet.reader.with_keys(...)` instead of `rivet.reader.router(...)`.

**2. CORS / origin allowlist**

- Default: `Access-Control-Allow-Origin` not set (cross-origin reads denied).
- `RIVET_READER_ALLOW_ORIGINS=https://dash.example.com,https://ops.example.com` opts in.
- `Access-Control-Allow-Headers` includes `X-Rivet-Key`, `X-Rivet-Request-Id`, `X-Rivet-Scope`.
- Documented in [`website/docs/index.html#security`](../website/docs/index.html) (already drafted).

**3. Bundled tools honour the key**

- `RIVET_READER_KEY` env var read by:
  - `rivet/python/rivet/tui/app.py` — add `Authorization: ` not, but `X-Rivet-Key:` header
  - `rivet/python/rivet/cli/__init__.py` — `tail` subcommand (when implemented in [P0-5])
- `--key <token>` CLI flag overrides the env var.
- HTTPS verification stays default-on; `--insecure` flag for dev only, prints a WARN.

**Mode 1 stays untouched.** Adopters who write to their own DB wire their own
auth via the standard FastAPI extension point:

```python
app.include_router(
    rivet.reader.router(),
    dependencies=[Depends(my_auth)],
)
```

rivet's reader does not add a second check in Mode 1 — two auth layers fight.

## Why

[`rivet/python/rivet/reader/router.py`](../python/rivet/reader/router.py) ships
three FastAPI endpoints (`/sys`, `/api`, `/audit`) with **zero** auth checks.
Any caller with network access reads the entire audit log. An "audit +
compliance SDK" that ships an unauthenticated audit-data dump fails the
first 5 minutes of any regulated buyer's review.

The bundled tools ([`tui/app.py:39`](../python/rivet/tui/app.py#L39),
[`cli/__init__.py`](../python/rivet/cli/__init__.py)) currently use bare
`urllib.request.urlopen()` with no auth headers — meaning the moment auth
lands, the tools we tell users to install can't talk to the reader they
just secured. Must land paired.

CORS is the next attack surface once auth is on: a browser-mounted reader
without origin checks is a cross-origin audit-data exfil vector. Cheap
to fix, must ship in the same milestone or someone will discover the gap
in week one.

`X-Rivet-Key` (not `Authorization: Bearer`) because the reader is server-
to-server, never user-bearing — separating credential namespaces avoids
collision with adopter user JWTs in shared environments. Rationale + flow
diagram already documented in [`website/docs/index.html#security`](../website/docs/index.html).

## Acceptance

- [ ] `reader_keys` table created idempotently when `RIVET_READER_AUTH=keys`
- [ ] `rivet key create / list / revoke / rotate` all work against SQLite + Postgres DSNs
- [ ] `with_keys()` dependency rejects missing / bad / revoked / out-of-scope keys with correct status codes (401 / 401 / 401 / 403)
- [ ] `READER_QUERY` and `READER_AUTH_BAD` audit rows emitted with full context (key name, request_id, path)
- [ ] CORS denies cross-origin by default; allow-list env var works; preflight passes for `X-Rivet-Key`
- [ ] `rivet tui` + `rivet tail` honour `RIVET_READER_KEY` env var and `--key` flag
- [ ] Mode 1 path documented + tested: mounting `rivet.reader.router()` without keys, behind adopter's `Depends(my_auth)`, returns rivet's data without rivet adding a second auth check
- [ ] [`website/docs/index.html#security`](../website/docs/index.html) updated to drop the `tag-planned` markers on `X-Rivet-Key` / `X-Rivet-Scope`

## Related

- **Pairs with:** [P0-5] (bundled tools must honour the key once `rivet tail` ships)
- **Depends on:** [P0-1] (CI verifies the integration tests pass)
- **Sister:** [P1-3] (adversarial tests for auth-bypass attempts)
- **Docs:** [`website/docs/index.html#security`](../website/docs/index.html) — already drafted; this issue makes it real
