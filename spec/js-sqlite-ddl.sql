CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    origin_id TEXT NOT NULL,
    monotonic_seq INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    code TEXT NOT NULL,
    action TEXT NOT NULL,
    severity TEXT NOT NULL,
    service_id TEXT NOT NULL,
    source_node_id TEXT NOT NULL,
    tenant_id TEXT,
    actor TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    target TEXT NOT NULL,
    category TEXT NOT NULL,
    domain TEXT NOT NULL,
    method TEXT NOT NULL,
    request_id TEXT NOT NULL,
    detail TEXT NOT NULL,
    shipped_at TEXT,
    canonical_form_id TEXT NOT NULL DEFAULT '1',
    detail_salt TEXT NOT NULL DEFAULT '',
    detail_commitment TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL DEFAULT 'genesis',
    hash TEXT NOT NULL DEFAULT '',
    pii_in_detail INTEGER NOT NULL DEFAULT 0,
    wire_version TEXT NOT NULL DEFAULT '1'
);
CREATE INDEX idx_audit_log_code ON audit_log(code);
CREATE INDEX idx_audit_log_pii ON audit_log(pii_in_detail) WHERE pii_in_detail = 1;
CREATE INDEX idx_audit_log_req ON audit_log(request_id);
CREATE INDEX idx_audit_log_ts ON audit_log(timestamp);
CREATE INDEX idx_audit_log_unshipped ON audit_log(shipped_at) WHERE shipped_at IS NULL;
CREATE UNIQUE INDEX uq_audit_log_node_seq ON audit_log(source_node_id, monotonic_seq);
