-- ═══════════════════════════════════════════════════════════════════════════
-- fasten audit_log — SQLite dialect · CANONICAL SOURCE
-- ═══════════════════════════════════════════════════════════════════════════
--
-- This file is the single source of truth for the audit_log schema on every
-- SQLite-backed fasten store (Python, Go, Rust core, Rust legacy). Any
-- schema change lands here first; every store then loads this file at
-- migrate() time. Prior state was 7 hand-rolled CREATE TABLE definitions
-- that had already drifted (missing pii_in_detail on Python; missing
-- hash-chain trio on Rust) — see ARCH #3 in fasten-cloud/issues/.
--
-- Placeholder: the store substitutes `{table}` for the target table name
-- (bare identifier only — SQLite CREATE TABLE does not accept schema.table).
-- No other templating: every store must accept the shape verbatim.
--
-- Migration policy: additive only. New columns land here with a safe
-- DEFAULT; each backend's per-language migration path uses
-- `PRAGMA table_info` to add the column to older databases (SQLite has no
-- `ADD COLUMN IF NOT EXISTS` — the backends check first). NEVER drop a
-- column; NEVER change the type or NOT NULL of an existing column here.
-- The write/read paths in each SDK are free to ignore columns they don't
-- consume yet — the point of this file is that the shape is identical
-- across languages, not that every language wires every column today.
-- ═══════════════════════════════════════════════════════════════════════════

PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS {table} (
    id                 TEXT    PRIMARY KEY,
    origin_id          TEXT    NOT NULL,
    monotonic_seq      INTEGER NOT NULL,
    timestamp          TEXT    NOT NULL,
    code               TEXT    NOT NULL,
    action             TEXT    NOT NULL,
    severity           TEXT    NOT NULL,
    service_id         TEXT    NOT NULL,
    source_node_id     TEXT    NOT NULL,
    tenant_id          TEXT,
    actor              TEXT    NOT NULL,
    actor_kind         TEXT    NOT NULL,
    target             TEXT    NOT NULL,
    category           TEXT    NOT NULL,
    domain             TEXT    NOT NULL,
    method             TEXT    NOT NULL,
    request_id         TEXT    NOT NULL,
    detail             TEXT    NOT NULL,
    pii_in_detail      INTEGER NOT NULL DEFAULT 0,
    shipped_at         TEXT,
    wire_version       TEXT    NOT NULL DEFAULT '1',
    hash               TEXT    NOT NULL DEFAULT '',
    prev_hash          TEXT    NOT NULL DEFAULT 'genesis',
    canonical_form_id  TEXT    NOT NULL DEFAULT '1'
);

-- Indexes on columns that were present in every historical schema — safe
-- to create before the additive-column migrations below run.
CREATE INDEX IF NOT EXISTS idx_{table}_req       ON {table}(request_id);
CREATE INDEX IF NOT EXISTS idx_{table}_code      ON {table}(code);
CREATE INDEX IF NOT EXISTS idx_{table}_ts        ON {table}(timestamp);
CREATE INDEX IF NOT EXISTS idx_{table}_seq       ON {table}(monotonic_seq);
CREATE INDEX IF NOT EXISTS idx_{table}_svc       ON {table}(service_id);
CREATE INDEX IF NOT EXISTS idx_{table}_unshipped ON {table}(shipped_at) WHERE shipped_at IS NULL;

-- @DEFERRED_AFTER_MIGRATIONS
-- Loaders MUST split the file at this marker: run the pre-marker section,
-- then execute additive ADD COLUMN migrations for the columns listed in
-- the header, then run the post-marker section. Without the split, this
-- CREATE INDEX runs against a legacy table whose pii_in_detail column
-- hasn't been added yet and fails with "no such column".
CREATE INDEX IF NOT EXISTS idx_{table}_pii       ON {table}(pii_in_detail) WHERE pii_in_detail = 1;
