use serde::{Deserialize, Serialize};

/// Wire-format audit row. Fields map 1-to-1 with the fasten JSON wire spec.
///
/// Timestamps are plain ISO-8601 strings so they survive the C FFI boundary
/// without a DateTime parser in the store layer. The calling SDK is responsible
/// for producing well-formed timestamps; the store persists them as-is.
///
/// `detail` is a JSON value (object, array, or scalar) serialized to TEXT in
/// both SQLite and PostgreSQL. Adopters who need Postgres JSONB for indexing
/// can alter the column type after migration — the TEXT values are valid JSON.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Row {
    // ── Wire envelope ──────────────────────────────────────────────────────
    pub wire_version: String,    // "1" — persisted for future readers

    // ── Identity ───────────────────────────────────────────────────────────
    pub id: String,              // "evt-<20 hex chars>"
    pub origin_id: String,       // dedup key; equals id on first write

    // ── WHEN ───────────────────────────────────────────────────────────────
    pub monotonic_seq: u64,
    pub timestamp: String,       // ISO-8601 UTC, e.g. "2026-05-07T12:00:00.000Z"

    // ── WHAT ───────────────────────────────────────────────────────────────
    pub code: String,
    pub action: String,
    pub severity: String,        // "debug" | "info" | "warn" | "error" | "critical"

    // ── WHERE ──────────────────────────────────────────────────────────────
    pub service_id: String,
    pub source_node_id: String,
    #[serde(default)]
    pub tenant_id: Option<String>,

    // ── WHO ────────────────────────────────────────────────────────────────
    pub actor: String,
    pub actor_kind: String,      // "user" | "service" | "schedule" | "agent"

    // ── WHOM ───────────────────────────────────────────────────────────────
    pub target: String,
    pub category: String,
    pub domain: String,

    // ── HOW ────────────────────────────────────────────────────────────────
    pub method: String,          // "http" | "mqtt" | "cli" | "sdk" | …

    // ── Correlation ────────────────────────────────────────────────────────
    pub request_id: String,

    // ── Payload ────────────────────────────────────────────────────────────
    pub detail: serde_json::Value,  // JSON object; stored as TEXT
    #[serde(default)]
    pub pii_in_detail: bool,

    // ── Shipping ───────────────────────────────────────────────────────────
    #[serde(default)]
    pub shipped_at: Option<String>,  // ISO-8601 UTC; None = not yet shipped

    // ── SDK passthrough ────────────────────────────────────────────────────
    // Unknown fields (e.g. hash, prev_hash from SDKs with hash-chain support)
    // are captured here and re-emitted verbatim so the C-ABI drainer roundtrip
    // does not silently drop SDK-specific wire fields.
    #[serde(flatten, default)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}
