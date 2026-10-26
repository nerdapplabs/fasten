use serde::{Deserialize, Serialize};

/// Wire-format audit row. Fields map 1-to-1 with the fasten JSON wire spec.
///
/// Timestamps are plain ISO-8601 strings so they survive the C FFI boundary
/// without a DateTime parser in the store layer. The calling SDK is responsible
/// for producing well-formed timestamps; the store persists them as-is.
///
/// `detail` is a JSON value (object, array, or scalar) stored as TEXT in
/// both SQLite and PostgreSQL. The TEXT is valid JSON, so the Postgres column
/// can be altered to JSONB if it needs indexing.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Row {
    // Wire envelope
    pub wire_version: String,    // "1"; persisted for future readers

    // Identity
    pub id: String,              // "evt-<20 hex chars>"
    pub origin_id: String,       // dedup key; equals id on first write

    // When
    pub monotonic_seq: u64,
    pub timestamp: String,       // ISO-8601 UTC, e.g. "2026-05-07T12:00:00.000Z"

    // What
    pub code: String,
    pub action: String,
    pub severity: String,        // "debug" | "info" | "warn" | "error" | "critical"

    // Where
    pub service_id: String,
    pub source_node_id: String,
    #[serde(default)]
    pub tenant_id: Option<String>,

    // Who
    pub actor: String,
    pub actor_kind: String,      // "user" | "service" | "schedule" | "agent"

    // Whom
    pub target: String,
    pub category: String,
    pub domain: String,

    // How
    pub method: String,          // "http" | "mqtt" | "cli" | "sdk" | ...

    // Correlation
    pub request_id: String,

    // Payload
    pub detail: serde_json::Value,  // JSON object; stored as TEXT
    #[serde(default)]
    pub pii_in_detail: bool,

    // Shipping
    #[serde(default)]
    pub shipped_at: Option<String>,  // ISO-8601 UTC; None = not yet shipped

    // SDK passthrough
    // Unknown fields (e.g. hash, prev_hash from SDKs with hash-chain support)
    // are kept here and written back out unchanged, so they survive the
    // round trip through the C ABI drainer.
    #[serde(flatten, default)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}
