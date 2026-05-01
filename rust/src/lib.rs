//! fasten — audit + correlation SDK for Rust services.
//!
//! Same shape as Python / Go / Node.js / C++ references: 6 audit anchors
//! (5 Ws + H) + correlation, opt-in shims per transport, pluggable store,
//! mountable reader. v0.1 / beta — sync core, optional async/store features.
//!
//! See `../README.md` for the full design.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::sync::{OnceLock, RwLock};

// ── FASTEN GENERATED ─ source: spec/row-schema.json ─ run: python spec/codegen.py ──
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Debug,  // Low-level diagnostic, filtered in production
    Info,  // Normal operational event
    Warn,  // Potentially problematic, not yet an error
    Error,  // Operation failed, requires attention
    Critical,  // Severe failure, may impact availability
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Debug => f.write_str("debug"),
            Severity::Info => f.write_str("info"),
            Severity::Warn => f.write_str("warn"),
            Severity::Error => f.write_str("error"),
            Severity::Critical => f.write_str("critical"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetentionClass {
    Short,  // Default 30 days
    Medium,  // Default 180 days
    Long,  // Default 1095 days (3 years)
}

impl fmt::Display for RetentionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RetentionClass::Short => f.write_str("short"),
            RetentionClass::Medium => f.write_str("medium"),
            RetentionClass::Long => f.write_str("long"),
        }
    }
}

// WHO anchor wire values.
pub const ACTOR_USER: &str = "user";  // Human user (browser, mobile, CLI on behalf of a user)
pub const ACTOR_SERVICE: &str = "service";  // Internal service or daemon
pub const ACTOR_SCHEDULE: &str = "schedule";  // Cron job or task scheduler
pub const ACTOR_AGENT: &str = "agent";  // AI agent

// HOW anchor wire values.
pub const METHOD_HTTP: &str = "http";  // HTTP/HTTPS request (REST, GraphQL, gRPC-web, webhook)
pub const METHOD_MQTT: &str = "mqtt";  // MQTT message (IoT telemetry, device command)
pub const METHOD_CLI: &str = "cli";  // CLI command typed by a human
pub const METHOD_SCHEDULER: &str = "scheduler";  // Automated cron or task scheduler
pub const METHOD_UI: &str = "ui";  // Web or desktop UI action, human-initiated
pub const METHOD_AGENT_TOOL: &str = "agent_tool";  // AI agent tool call
pub const METHOD_SDK: &str = "sdk";  // Direct SDK call, no transport shim active. Default.

pub const REDACT_REPLACEMENT: &str = "***";
pub const REDACT_PATTERNS: &[&str] = &[
    "api[_-]?key",
    "password",
    "passwd",
    "token",
    "secret",
    "authorization",
    "bearer",
    "m2m[_-]?key",
    "cert[_-]?private",
    "private[_-]?key",
    "access_key",
    "session_id",
    "cookie",
    "credential",
    "auth",
];
// ── END FASTEN GENERATED ──────────────────────────────────────────────────

// --- Defaults for codegen enums ------------------------------------------
//
// Codegen output has no Default derives; impl them here so Meta { ..Default::default() }
// works for adopters who only set a few fields. Sensible defaults: INFO + MEDIUM.

impl Default for Severity {
    fn default() -> Self { Severity::Info }
}

impl Default for RetentionClass {
    fn default() -> Self { RetentionClass::Medium }
}

// --- Domain --------------------------------------------------------------
//
// Plain string — adopters define their own vocabulary (e.g. "user",
// "billing", "node"). Matches Python / JS / C++ adapters; no built-in enum.
pub type Domain = String;

// --- 6 audit anchors as typed row ----------------------------------------

/// Classical audit dimensions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Anchor {
    Who,         // actor, actor_kind
    What,        // code, action
    When,        // timestamp, monotonic_seq
    Where,       // source_node_id, service_id, tenant_id
    Whom,        // target, category, domain
    How,         // method
    Correlation, // request_id
}

/// Canonical audit row — wire shape matches spec/row-schema.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    pub id: String,
    pub origin_id: String,
    pub monotonic_seq: u64,

    pub timestamp: DateTime<Utc>,

    pub code: String,
    pub action: String,
    pub severity: Severity,

    pub service_id: String,
    pub source_node_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    pub actor: String,
    pub actor_kind: String,

    pub target: String,
    pub category: String,
    pub domain: Domain,

    pub method: String,

    pub request_id: String,
    pub detail: HashMap<String, serde_json::Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub shipped_at: Option<DateTime<Utc>>,
}

// --- Code catalog --------------------------------------------------------

/// Per-code metadata.
///
/// `id` is optional in adopter code — `register()` fills it from the
/// tuple key. Setting `id` explicitly is allowed but must match the
/// key (mismatch is a typo, never a feature).
#[derive(Debug, Clone, Default)]
pub struct Meta {
    pub id: String,
    pub domain: Domain,
    pub category: String,
    pub action: String,
    pub severity: Severity,
    pub description: String,
    pub emitter: String,
    pub retention_class: RetentionClass,
    pub high_volume: bool,
    pub pii_in_detail: bool,
    pub declared_unused: bool,
}

/// Library error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("duplicate code: {0}")]
    DuplicateCode(String),
    #[error("unknown code: {0}")]
    UnknownCode(String),
    #[error("code {code} declares domain={got:?} but registered under {want:?}")]
    DomainMismatch { code: String, got: Domain, want: Domain },
    #[error("code key {key:?} disagrees with Meta.id={got:?}")]
    IdMismatch { key: String, got: String },
    #[error("code key {0:?} must be UPPER_SNAKE_CASE")]
    InvalidKey(String),
    #[error("yaml catalog: {0}")]
    YamlInvalid(String),
    #[error("missing required anchor: {0:?}")]
    MissingAnchor(Anchor),
    #[error("init not called")]
    NotInitialised,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub(crate) fn registry() -> &'static RwLock<HashMap<String, Meta>> {
    static REG: OnceLock<RwLock<HashMap<String, Meta>>> = OnceLock::new();
    REG.get_or_init(|| RwLock::new(HashMap::new()))
}

pub(crate) fn is_upper_snake(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_uppercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Register a batch of codes for a domain.
///
/// Validation runs in this order; first failure returns an error:
///   - key shape: UPPER_SNAKE_CASE identifier
///   - `Meta.id` empty → fill from key; set → must match key
///   - `Meta.domain` must match `domain`
///   - duplicate code across registrations
///
/// Drop `Meta.id` in new code; the tuple key is the single source of truth.
pub fn register<I>(domain: Domain, codes: I) -> Result<(), Error>
where
    I: IntoIterator<Item = (String, Meta)>,
{
    let mut guard = registry().write().expect("registry poisoned");
    for (id, mut meta) in codes {
        if !is_upper_snake(&id) {
            return Err(Error::InvalidKey(id));
        }
        if meta.id.is_empty() {
            meta.id = id.clone();
        } else if meta.id != id {
            return Err(Error::IdMismatch {
                key: id,
                got: meta.id,
            });
        }
        if meta.domain != domain {
            return Err(Error::DomainMismatch {
                code: id,
                got: meta.domain,
                want: domain,
            });
        }
        if guard.contains_key(&id) {
            return Err(Error::DuplicateCode(id));
        }
        guard.insert(id, meta);
    }
    Ok(())
}

/// Look up Meta by code.
pub fn meta_of(code: &str) -> Option<Meta> {
    registry().read().expect("registry poisoned").get(code).cloned()
}

/// Dump `id,domain,severity` sorted one-per-line — feeds cross-language gate.
pub fn dump() -> String {
    let guard = registry().read().expect("registry poisoned");
    // Sort by stringified severity so we don't need Ord on the codegen enum.
    let mut rows: Vec<(String, Domain, String)> = guard
        .values()
        .map(|m| (m.id.clone(), m.domain.clone(), m.severity.to_string()))
        .collect();
    rows.sort();
    rows.into_iter()
        .map(|(id, dom, sev)| format!("{},{},{}", id, dom, sev))
        .collect::<Vec<_>>()
        .join("\n")
}

// --- Correlation context -------------------------------------------------
//
// Thread-local for sync + same-task async use. Across-task async correlation
// (where context shouldn't leak between tasks) is a v0.2 concern — opt in
// via the "async" feature once we wire tokio task_local.

thread_local! {
    static REQUEST_ID: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Mint a 12-char request id.
pub fn mint_id() -> String {
    uuid::Uuid::new_v4().simple().to_string().chars().take(12).collect()
}

/// Read the ambient request_id (None if unset).
pub fn current_request_id() -> Option<String> {
    REQUEST_ID.with(|cell| cell.borrow().clone())
}

/// Run `f` with `rid` set as ambient correlation. Restores prior id on exit.
pub fn with_request_id<F, T>(rid: String, f: F) -> T
where
    F: FnOnce() -> T,
{
    let prev = REQUEST_ID.with(|cell| cell.replace(Some(rid)));
    let out = f();
    REQUEST_ID.with(|cell| {
        *cell.borrow_mut() = prev;
    });
    out
}

// --- Built-in structured log (sys stream) --------------------------------
//
// Adopters get NDJSON sys lines without bringing `tracing` or `log`.
// Auto-stamps request_id from current_request_id() and service_id from
// the active config. Falls back to bare line if init() not yet called.

pub mod log {
    use super::current_request_id;
    use serde::Serialize;
    use serde_json::json;

    fn write(level: &str, event: &str, fields: serde_json::Value) {
        let cfg = super::CONFIG
            .get()
            .and_then(|slot| slot.read().ok().and_then(|g| g.clone()));
        let service_id = cfg.as_ref().map(|c| c.service_id.clone()).unwrap_or_default();

        let mut payload = json!({
            "shape": "sys",
            "level": level,
            "event": event,
            "request_id": current_request_id().unwrap_or_default(),
            "service_id": service_id,
            "timestamp": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        });

        if let serde_json::Value::Object(merge_into) = &mut payload {
            if let serde_json::Value::Object(extra) = fields {
                for (k, v) in extra {
                    merge_into.insert(k, v);
                }
            }
        }

        println!("{}", payload);
    }

    /// Convenience: pass key-value fields as a `serde_json::Value::Object`.
    pub fn info(event: &str, fields: serde_json::Value) { write("info", event, fields); }
    pub fn warn(event: &str, fields: serde_json::Value) { write("warn", event, fields); }
    pub fn error(event: &str, fields: serde_json::Value) { write("error", event, fields); }
    pub fn debug(event: &str, fields: serde_json::Value) { write("debug", event, fields); }

    /// Variant for callers without serde_json::json! at hand.
    pub fn info_with<T: Serialize>(event: &str, fields: &T) {
        let v = serde_json::to_value(fields).unwrap_or(serde_json::Value::Null);
        write("info", event, v);
    }
}

// --- Redaction -----------------------------------------------------------
//
// Spec patterns are simple regex-like strings (e.g. `api[_-]?key`). For v0.1
// we avoid the regex crate dep: lower-case + strip `_` and `-` from both
// key and pattern, then substring-match. Behaviour matches Python's
// case-insensitive search for all patterns in the spec.

fn norm_key(s: &str) -> String {
    s.to_ascii_lowercase().replace(['_', '-'], "")
}

fn pattern_words() -> &'static [String] {
    static WORDS: OnceLock<Vec<String>> = OnceLock::new();
    WORDS.get_or_init(|| {
        REDACT_PATTERNS
            .iter()
            .map(|p| p.replace("[_-]?", "").replace(['_', '-'], "").to_ascii_lowercase())
            .collect()
    })
}

fn key_is_secret(key: &str, extra: Option<&[String]>) -> bool {
    let k = norm_key(key);
    if pattern_words().iter().any(|p| k.contains(p)) {
        return true;
    }
    if let Some(ex) = extra {
        if ex.iter().any(|p| k.contains(&norm_key(p))) {
            return true;
        }
    }
    false
}

fn redact_value(v: &serde_json::Value, extra: Option<&[String]>) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, vv) in map {
                if key_is_secret(k, extra) {
                    out.insert(k.clone(), Value::String(REDACT_REPLACEMENT.into()));
                } else {
                    out.insert(k.clone(), redact_value(vv, extra));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(|x| redact_value(x, extra)).collect()),
        _ => v.clone(),
    }
}

fn redact_detail(
    detail: HashMap<String, serde_json::Value>,
    extra: Option<&[String]>,
) -> HashMap<String, serde_json::Value> {
    detail
        .into_iter()
        .map(|(k, v)| {
            let nv = if key_is_secret(&k, extra) {
                serde_json::Value::String(REDACT_REPLACEMENT.into())
            } else {
                redact_value(&v, extra)
            };
            (k, nv)
        })
        .collect()
}

// --- Init + Emit ---------------------------------------------------------

/// Adopter-supplied store. Sync trait so the core compiles without tokio.
pub trait AuditStore: Send + Sync {
    fn insert(&self, row: &Row) -> Result<(), Error>;
}

#[derive(Clone, Default)]
pub struct Config {
    pub service_id: String,
    pub node_id: String,
    pub tenant_id: Option<String>,
    pub extra_redact_keys: Option<Vec<String>>,
}

/// Read env vars; return Config.
pub fn config_from_env() -> Result<Config, Error> {
    let service_id = std::env::var("FASTEN_SERVICE_ID").unwrap_or_default();
    let node_id = std::env::var("FASTEN_NODE_ID").unwrap_or_default();
    if service_id.is_empty() || node_id.is_empty() {
        return Err(Error::NotInitialised);
    }
    let extra = std::env::var("FASTEN_REDACT_KEYS").ok().map(|s| {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect::<Vec<_>>()
    });
    Ok(Config {
        service_id,
        node_id,
        tenant_id: std::env::var("FASTEN_TENANT_ID").ok(),
        extra_redact_keys: extra,
    })
}

static CONFIG: OnceLock<RwLock<Option<Config>>> = OnceLock::new();
static SEQ: OnceLock<std::sync::atomic::AtomicU64> = OnceLock::new();

fn seq_next() -> u64 {
    SEQ.get_or_init(|| std::sync::atomic::AtomicU64::new(0))
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        + 1
}

/// Initialise fasten with a Config. Required before `emit()`.
pub fn init(cfg: Config) -> Result<(), Error> {
    if cfg.service_id.is_empty() || cfg.node_id.is_empty() {
        return Err(Error::NotInitialised);
    }
    let slot = CONFIG.get_or_init(|| RwLock::new(None));
    *slot.write().expect("config poisoned") = Some(cfg);
    Ok(())
}

fn current_config() -> Result<Config, Error> {
    CONFIG
        .get()
        .and_then(|slot| slot.read().ok().and_then(|g| g.clone()))
        .ok_or(Error::NotInitialised)
}

/// Fluent-style Emit builder. Caller supplies `code`, `target`, optional
/// `actor` / `method` / `detail`. Anchors auto-fill from Meta + ctx + config.
pub struct EmitBuilder {
    code: String,
    target: String,
    actor: String,
    actor_kind: String,
    method: String,
    detail: HashMap<String, serde_json::Value>,
    severity: Option<Severity>,
}

impl EmitBuilder {
    pub fn new(code: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            target: target.into(),
            actor: "system".into(),
            actor_kind: "service".into(),
            method: "sdk".into(),
            detail: HashMap::new(),
            severity: None,
        }
    }

    pub fn actor(mut self, actor: impl Into<String>, kind: impl Into<String>) -> Self {
        self.actor = actor.into();
        self.actor_kind = kind.into();
        self
    }

    pub fn method(mut self, m: impl Into<String>) -> Self {
        self.method = m.into();
        self
    }

    pub fn detail(mut self, d: HashMap<String, serde_json::Value>) -> Self {
        self.detail = d;
        self
    }

    pub fn severity(mut self, s: Severity) -> Self {
        self.severity = Some(s);
        self
    }

    /// Emit synchronously. Mirrors the row to stdout (NDJSON, `shape: audit`)
    /// and optionally inserts into a store. Returns the canonical Row.
    pub fn emit(self, store: Option<&dyn AuditStore>) -> Result<Row, Error> {
        let cfg = current_config()?;
        let meta = meta_of(&self.code).ok_or_else(|| Error::UnknownCode(self.code.clone()))?;

        let hex = uuid::Uuid::new_v4().simple().to_string();
        let id = format!("evt-{}", &hex[..20]);
        let request_id = current_request_id().unwrap_or_else(mint_id);
        let detail = redact_detail(self.detail, cfg.extra_redact_keys.as_deref());

        let row = Row {
            id: id.clone(),
            origin_id: id,
            monotonic_seq: seq_next(),
            timestamp: Utc::now(),
            code: self.code,
            action: meta.action,
            severity: self.severity.unwrap_or(meta.severity),
            service_id: cfg.service_id,
            source_node_id: cfg.node_id,
            tenant_id: cfg.tenant_id,
            actor: self.actor,
            actor_kind: self.actor_kind,
            target: self.target,
            category: meta.category,
            domain: meta.domain,
            method: self.method,
            request_id,
            detail,
            shipped_at: None,
        };

        if let Some(s) = store {
            s.insert(&row)?;
        }

        let mut payload = serde_json::to_value(&row)?;
        if let serde_json::Value::Object(map) = &mut payload {
            map.insert("shape".into(), serde_json::Value::String("audit".into()));
        }
        println!("{}", payload);
        Ok(row)
    }
}

// --- Query filter --------------------------------------------------------

/// Query filter for reader implementations.
#[derive(Debug, Default, Clone)]
pub struct Filter {
    pub request_id: Option<String>,
    pub code: Option<String>,
    pub domain: Option<Domain>,
    pub source_node_id: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub limit: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(id: &str, domain: &str) -> Meta {
        Meta {
            id: id.into(),
            domain: domain.into(),
            category: "account".into(),
            action: "create".into(),
            severity: Severity::Info,
            description: "x".into(),
            emitter: "test".into(),
            retention_class: RetentionClass::Long,
            high_volume: false,
            pii_in_detail: false,
            declared_unused: false,
        }
    }

    #[test]
    fn redact_top_level_and_nested() {
        let mut d: HashMap<String, serde_json::Value> = HashMap::new();
        d.insert("email".into(), serde_json::json!("a@b.com"));
        d.insert("api_key".into(), serde_json::json!("sk-abc"));
        d.insert(
            "nested".into(),
            serde_json::json!({"token": "xyz", "ok": "keep"}),
        );
        let out = redact_detail(d, None);
        assert_eq!(out["email"], serde_json::json!("a@b.com"));
        assert_eq!(out["api_key"], serde_json::json!("***"));
        assert_eq!(out["nested"]["token"], serde_json::json!("***"));
        assert_eq!(out["nested"]["ok"], serde_json::json!("keep"));
    }

    #[test]
    fn registry_round_trip() {
        register("test_dom".into(), [("CODE_A".into(), meta("CODE_A", "test_dom"))])
            .unwrap();
        let m = meta_of("CODE_A").unwrap();
        assert_eq!(m.domain, "test_dom");
        let dump = dump();
        assert!(dump.contains("CODE_A,test_dom,info"));
    }

    // P1-10: id is filled from the key when omitted.
    #[test]
    fn register_fills_id_from_key() {
        register(
            "p1_10".into(),
            [(
                "P1_10_FILLED".into(),
                Meta {
                    domain: "p1_10".into(),
                    category: "x".into(),
                    action: "x".into(),
                    severity: Severity::Info,
                    description: "x".into(),
                    emitter: "t".into(),
                    ..Default::default()
                },
            )],
        )
        .unwrap();
        let m = meta_of("P1_10_FILLED").unwrap();
        assert_eq!(m.id, "P1_10_FILLED");
    }

    // P1-10: explicit id that disagrees with the key raises IdMismatch.
    #[test]
    fn register_id_mismatch_raises() {
        let result = register(
            "p1_10b".into(),
            [(
                "P1_10_MISMATCH".into(),
                Meta {
                    id: "WRONG_ID".into(),
                    domain: "p1_10b".into(),
                    severity: Severity::Info,
                    ..Default::default()
                },
            )],
        );
        match result {
            Err(Error::IdMismatch { key, got }) => {
                assert_eq!(key, "P1_10_MISMATCH");
                assert_eq!(got, "WRONG_ID");
            }
            other => panic!("expected IdMismatch, got {:?}", other),
        }
    }

    // P1-10: lowercase / invalid key shape raises InvalidKey.
    #[test]
    fn register_invalid_key_shape_raises() {
        let result = register(
            "p1_10c".into(),
            [(
                "lowercase_bad".into(),
                Meta {
                    domain: "p1_10c".into(),
                    severity: Severity::Info,
                    ..Default::default()
                },
            )],
        );
        match result {
            Err(Error::InvalidKey(k)) => assert_eq!(k, "lowercase_bad"),
            other => panic!("expected InvalidKey, got {:?}", other),
        }
    }
}

// ── Catalog yaml (P1-11) ─────────────────────────────────────────────────
//
// Optional feature, gated behind the `codes-yaml` cargo feature so adopters
// who stay on programmatic register() never pull in serde_yaml.
//
//   fasten = { version = "1", features = ["codes-yaml"] }
//   fasten::codes::load("fleet.codes.yaml")?;
//   fasten::codes::reload()?;

#[cfg(feature = "codes-yaml")]
pub mod codes_yaml;

#[cfg(feature = "codes-yaml")]
pub mod codes {
    pub use super::codes_yaml::{load, reload};
}
