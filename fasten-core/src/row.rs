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

    // ── Chain (spec §1, §2) ────────────────────────────────────────────────
    // Set by an SDK that seals the row; the stores persist them as given. A
    // field that was absent stays absent on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_form_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail_salt: Option<String>,        // form "2" only
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail_commitment: Option<String>,  // form "2" only

    // ── SDK passthrough ────────────────────────────────────────────────────
    // Other unknown fields are captured here and re-emitted verbatim so the
    // C-ABI drainer roundtrip does not silently drop SDK-specific wire fields.
    #[serde(flatten, default)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::Row;

    #[test]
    fn chain_fields_are_typed_and_absent_ones_stay_absent() {
        let sealed = serde_json::json!({
            "wire_version": "1", "id": "e", "origin_id": "e", "monotonic_seq": 1,
            "timestamp": "t", "code": "C", "action": "a", "severity": "info",
            "service_id": "s", "source_node_id": "n", "actor": "x", "actor_kind": "user",
            "target": "t", "category": "c", "domain": "d", "method": "sdk",
            "request_id": "r", "detail": {}, "prev_hash": "genesis", "hash": "h",
            "canonical_form_id": "2", "detail_salt": "s", "detail_commitment": "m",
        });
        let row: Row = serde_json::from_value(sealed.clone()).unwrap();
        assert_eq!(row.hash.as_deref(), Some("h"));
        assert!(row.extra.is_empty());
        let back = serde_json::to_value(&row).unwrap();
        assert_eq!(back["hash"], "h");
        assert_eq!(back["detail_commitment"], "m");

        let mut plain = sealed;
        for k in ["prev_hash", "hash", "canonical_form_id", "detail_salt", "detail_commitment"] {
            plain.as_object_mut().unwrap().remove(k);
        }
        let back = serde_json::to_value(serde_json::from_value::<Row>(plain).unwrap()).unwrap();
        assert!(back.get("hash").is_none() && back.get("detail_salt").is_none());
    }
}
