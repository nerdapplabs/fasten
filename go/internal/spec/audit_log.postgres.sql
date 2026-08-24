-- ═══════════════════════════════════════════════════════════════════════════
-- fasten audit_log — PostgreSQL dialect · CANONICAL SOURCE
-- ═══════════════════════════════════════════════════════════════════════════
--
-- Postgres-dialect companion to spec/audit_log.sqlite.sql. Same columns,
-- native Postgres types (TIMESTAMPTZ / BIGINT / SMALLINT), same additive-
-- migration policy — see the sqlite file's header for the full contract.
--
-- Placeholders:
--   {table}  — fully-qualified table name (schema.name or bare name)
--   {bare}   — bare table name, used in index names since Postgres does not
--              allow schema-qualified index identifiers
--
-- Postgres supports ALTER TABLE ADD COLUMN IF NOT EXISTS natively, so
-- additive column migrations live directly in this file (unlike sqlite).
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS {table} (
    id                 TEXT        PRIMARY KEY,
    origin_id          TEXT        NOT NULL,
    monotonic_seq      BIGINT      NOT NULL,
    timestamp          TIMESTAMPTZ NOT NULL,
    code               TEXT        NOT NULL,
    action             TEXT        NOT NULL,
    severity           TEXT        NOT NULL,
    service_id         TEXT        NOT NULL,
    source_node_id     TEXT        NOT NULL,
    tenant_id          TEXT,
    actor              TEXT        NOT NULL,
    actor_kind         TEXT        NOT NULL,
    target             TEXT        NOT NULL,
    category           TEXT        NOT NULL,
    domain             TEXT        NOT NULL,
    method             TEXT        NOT NULL,
    request_id         TEXT        NOT NULL,
    detail             TEXT        NOT NULL,
    pii_in_detail      SMALLINT    NOT NULL DEFAULT 0,
    shipped_at         TIMESTAMPTZ,
    wire_version       TEXT        NOT NULL DEFAULT '1',
    hash               TEXT        NOT NULL DEFAULT '',
    prev_hash          TEXT        NOT NULL DEFAULT 'genesis',
    canonical_form_id  TEXT        NOT NULL DEFAULT '1'
);

-- Additive migrations for tables that predate a column.
ALTER TABLE {table} ADD COLUMN IF NOT EXISTS pii_in_detail      SMALLINT    NOT NULL DEFAULT 0;
ALTER TABLE {table} ADD COLUMN IF NOT EXISTS wire_version       TEXT        NOT NULL DEFAULT '1';
ALTER TABLE {table} ADD COLUMN IF NOT EXISTS hash               TEXT        NOT NULL DEFAULT '';
ALTER TABLE {table} ADD COLUMN IF NOT EXISTS prev_hash          TEXT        NOT NULL DEFAULT 'genesis';
ALTER TABLE {table} ADD COLUMN IF NOT EXISTS canonical_form_id  TEXT        NOT NULL DEFAULT '1';

-- Indexes on columns that were present in every historical schema — safe
-- to create alongside the CREATE TABLE. The pii_in_detail index moves
-- below the marker so it runs after the ADD COLUMN IF NOT EXISTS above
-- takes effect on legacy tables.
CREATE INDEX IF NOT EXISTS idx_{bare}_req       ON {table}(request_id);
CREATE INDEX IF NOT EXISTS idx_{bare}_code      ON {table}(code);
CREATE INDEX IF NOT EXISTS idx_{bare}_ts        ON {table}(timestamp);
CREATE INDEX IF NOT EXISTS idx_{bare}_seq       ON {table}(monotonic_seq);
CREATE INDEX IF NOT EXISTS idx_{bare}_svc       ON {table}(service_id);
CREATE INDEX IF NOT EXISTS idx_{bare}_unshipped ON {table}(shipped_at) WHERE shipped_at IS NULL;

-- @DEFERRED_AFTER_MIGRATIONS
-- Loaders MUST split at this marker: pre-marker → ADD COLUMN migrations →
-- post-marker. Postgres handles `ADD COLUMN IF NOT EXISTS` inline just
-- above, so the split matters mostly for parity with the sqlite loader —
-- but keeping the marker in both dialects means one code path in each SDK.
CREATE INDEX IF NOT EXISTS idx_{bare}_pii       ON {table}(pii_in_detail) WHERE pii_in_detail = 1;
