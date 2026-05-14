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
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

pub mod engine;
pub use engine::{Engine, DEFAULT};

// ── P1-15 drainer public surface ─────────────────────────────────────────────

/// Snapshot of the active drainer state. Re-exported from fasten-core.
pub use fasten_core::drainer::QueueStats;

/// Raised by `EmitBuilder::submit()` in `raise` mode when the store insert fails.
#[derive(Debug, thiserror::Error)]
#[error("fasten audit store: {source}")]
pub struct AuditStoreError {
    #[source]
    pub source: Error,
}

/// Block until pending audit rows drain (or `timeout` elapses).
/// No-op + returns `true` in `raise` mode.
pub fn flush(timeout: std::time::Duration) -> bool { DEFAULT.flush(timeout) }

/// Snapshot of the active drainer, or `None` in `raise` mode.
pub fn queue_stats() -> Option<QueueStats> { DEFAULT.queue_stats() }

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

pub use fasten_core::redact::DEFAULT_REPLACEMENT as REDACT_REPLACEMENT;
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
];
// ── END FASTEN GENERATED ──────────────────────────────────────────────────

// --- Defaults for codegen enums ------------------------------------------
//
// Codegen output has no Default derives; impl them here so Meta { ..Default::default() }
// works for adopters who only set a few fields. Sensible defaults: INFO + MEDIUM.

#[allow(clippy::derivable_impls)]
impl Default for Severity {
    fn default() -> Self { Severity::Info }
}

#[allow(clippy::derivable_impls)]
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
    pub wire_version: String,

    pub id: String,
    pub origin_id: String,
    pub monotonic_seq: u64,

    pub timestamp: DateTime<Utc>,

    pub code: String,
    pub action: String,
    pub severity: Severity,

    pub service_id: String,
    pub source_node_id: String,
    // Always emit the key (null when absent) so readers see a consistent shape.
    pub tenant_id: Option<String>,

    pub actor: String,
    pub actor_kind: String,

    pub target: String,
    pub category: String,
    pub domain: Domain,

    pub method: String,

    pub request_id: String,
    pub detail: HashMap<String, serde_json::Value>,

    #[serde(default)]
    pub pii_in_detail: bool,

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
    /// Detail keys that survive force-redact when `pii_in_detail` is true.
    /// Each surviving value still passes through the secret-key redactor.
    pub detail_passthrough_keys: Vec<String>,
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
    #[error("audit_store_failure_strategy must be \"queue\" or \"raise\" (got {0:?})")]
    InvalidStrategy(String),
    #[error("audit store: {0}")]
    AuditStoreInsert(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub(crate) fn registry() -> &'static RwLock<HashMap<String, Meta>> {
    static REG: OnceLock<RwLock<HashMap<String, Meta>>> = OnceLock::new();
    REG.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Register a batch of codes for a domain.
///
/// Validation (key shape, id-match, domain-match, pii_in_detail forcing) is
/// delegated to a fresh `fasten_core::catalog::CodeRegistry` so the
/// rules stay in one place.  The validated codes are then committed to the
/// SDK's own typed registry.
///
/// Drop `Meta.id` in new code; the tuple key is the single source of truth.
pub fn register<I>(domain: Domain, codes: I) -> Result<(), Error>
where
    I: IntoIterator<Item = (String, Meta)>,
{
    use fasten_core::catalog::CodeRegistry as CoreReg;
    let codes: Vec<(String, Meta)> = codes.into_iter().collect();

    // Validate via a throw-away fasten-core registry — handles all rules
    // without touching the global singleton (safe to call from tests).
    let core_map: HashMap<String, fasten_core::catalog::Meta> =
        codes.iter().map(|(id, m)| (id.clone(), to_core_meta(m))).collect();
    CoreReg::new().register(&domain, core_map).map_err(map_core_catalog_err)?;

    // Cross-batch duplicate check against the already-registered SDK codes.
    let mut guard = registry().write().expect("registry poisoned");
    for (id, _) in &codes {
        if guard.contains_key(id.as_str()) {
            return Err(Error::DuplicateCode(id.clone()));
        }
    }

    // Commit with filled/normalised fields.
    for (id, mut meta) in codes {
        if meta.id.is_empty() { meta.id = id.clone(); }
        if meta.pii_in_detail && meta.retention_class != RetentionClass::Short {
            eprintln!(
                "fasten: code {} has pii_in_detail=true; retention_class forced to SHORT (was {}).",
                id, meta.retention_class
            );
            meta.retention_class = RetentionClass::Short;
        }
        guard.insert(id, meta);
    }
    Ok(())
}

fn to_core_meta(m: &Meta) -> fasten_core::catalog::Meta {
    fasten_core::catalog::Meta {
        id:                      m.id.clone(),
        domain:                  m.domain.clone(),
        category:                m.category.clone(),
        action:                  m.action.clone(),
        severity:                m.severity.to_string(),
        description:             m.description.clone(),
        emitter:                 m.emitter.clone(),
        retention_class:         m.retention_class.to_string(),
        high_volume:             m.high_volume,
        pii_in_detail:           m.pii_in_detail,
        declared_unused:         m.declared_unused,
        detail_passthrough_keys: m.detail_passthrough_keys.clone(),
    }
}

fn map_core_catalog_err(e: fasten_core::error::Error) -> Error {
    use fasten_core::error::Error as CE;
    match e {
        CE::InvalidKey(k) => Error::InvalidKey(k),
        CE::IdMismatch { key, id } => Error::IdMismatch { key, got: id },
        CE::DomainMismatch { key, declared, registered } =>
            Error::DomainMismatch { code: key, got: declared, want: registered },
        CE::DuplicateCode(k) => Error::DuplicateCode(k),
        other => Error::YamlInvalid(other.to_string()),
    }
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
    use serde::Serialize;

    fn write(level: &str, event: &str, fields: serde_json::Value) {
        super::DEFAULT.log_sys(level, event, fields);
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

fn redact_detail(
    detail: HashMap<String, serde_json::Value>,
    extra: Option<&[String]>,
) -> HashMap<String, serde_json::Value> {
    use fasten_core::redact::{Redactor, REDACTOR};
    let v = serde_json::Value::Object(detail.into_iter().collect());
    let redacted = match extra {
        Some(keys) if !keys.is_empty() => {
            let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
            Redactor::new(&refs, "", &[]).redact_value(&v)
        }
        _ => REDACTOR.redact_value(&v),
    };
    match redacted {
        serde_json::Value::Object(map) => map.into_iter().collect(),
        _ => unreachable!("redact_value on Object always returns Object"),
    }
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
    /// P1-15: durable audit store. When set together with
    /// `audit_store_failure_strategy = "queue"`, `EmitBuilder::submit()`
    /// pushes rows onto a bounded in-memory queue drained in the
    /// background.
    pub audit_store: Option<Arc<dyn AuditStore>>,
    /// "queue" (default) or "raise". `raise` makes `submit()` call
    /// `insert` synchronously and wrap errors in `AuditStoreError`.
    /// Empty / None falls back to `FASTEN_AUDIT_STORE_FAILURE_STRATEGY`.
    pub audit_store_failure_strategy: Option<String>,
    /// Queue capacity (queued + in-flight retry). Default: 100.
    pub queue_capacity: Option<usize>,
    /// Initial retry delay. Default: 100 ms.
    pub queue_retry_initial: Option<Duration>,
    /// Cap on retry delay. Default: 60 s.
    pub queue_retry_max: Option<Duration>,
    /// Disable ±20 % jitter (default: jitter ON).
    pub disable_queue_jitter: bool,
    /// Max insert attempts before a row is dead-lettered. Default: 50.
    pub queue_drain_max_attempts: Option<usize>,
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
        ..Default::default()
    })
}

/// Initialise fasten with a Config. Required before `emit()`.
///
/// When `cfg.audit_store` is provided and `cfg.audit_store_failure_strategy`
/// is `"queue"` (default), this installs the shared fasten-core background
/// drainer thread (see `fasten_core::drainer` for the full P1-15 contract).
pub fn init(cfg: Config) -> Result<(), Error> { DEFAULT.init(cfg) }

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

    /// Submit using the init-time globals (P1-15). In `queue` mode the
    /// row goes to the in-process drainer; in `raise` mode it's
    /// inserted synchronously and any error is wrapped in
    /// [`AuditStoreError`].
    ///
    /// Mirrors the row to stdout (`{"shape":"audit",...}`) regardless
    /// of mode so adopters always see the audit on the log stream.
    pub fn submit(self) -> Result<Row, AuditStoreError> {
        let cfg = DEFAULT.current_config().map_err(|e| AuditStoreError { source: e })?;
        let row = self
            .build_row(&cfg)
            .map_err(|e| AuditStoreError { source: e })?;

        // Stdout write happens BEFORE any store routing. Two reasons:
        //   1. Under sustained queue-full outage, drainer.put() blocks
        //      on the slot semaphore. If stdout came after, even
        //      Docker / journald log capture stalls — adopters lose the
        //      recoverable audit trail at the worst possible moment.
        //   2. In raise mode, the row should still reach stdout even
        //      if the sync insert errors — preserves the "stdout is
        //      always honest" contract.
        Self::write_audit_stdout(&row);

        let strategy = cfg
            .audit_store_failure_strategy
            .as_deref()
            .unwrap_or("queue");
        if strategy == "queue" {
            if let Some(d) = DEFAULT.active_drainer() {
                let core_row = crate::engine::sdk_row_to_core(&row);
                d.enqueue(core_row);
            } else if let Some(s) = cfg.audit_store.as_ref() {
                // Defensive fallback — strategy says queue but drainer
                // isn't installed. Sync insert so the row isn't dropped.
                if let Err(e) = s.insert(&row) {
                    return Err(AuditStoreError { source: e });
                }
            }
        } else if let Some(s) = cfg.audit_store.as_ref() {
            if let Err(e) = s.insert(&row) {
                return Err(AuditStoreError { source: e });
            }
        }
        Ok(row)
    }

    fn build_row(self, cfg: &Config) -> Result<Row, Error> {
        let meta = meta_of(&self.code).ok_or_else(|| Error::UnknownCode(self.code.clone()))?;
        let hex = uuid::Uuid::new_v4().simple().to_string();
        let id = format!("evt-{}", &hex[..20]);
        let request_id = current_request_id().unwrap_or_else(mint_id);
        let detail = if meta.pii_in_detail {
            let passthrough: std::collections::HashSet<&str> =
                meta.detail_passthrough_keys.iter().map(String::as_str).collect();
            let kept: HashMap<String, serde_json::Value> = self
                .detail
                .into_iter()
                .filter(|(k, _)| passthrough.contains(k.as_str()))
                .collect();
            let mut out = redact_detail(kept, cfg.extra_redact_keys.as_deref());
            out.insert("_redacted".into(), serde_json::Value::String(REDACT_REPLACEMENT.into()));
            out.insert("_pii_in_detail".into(), serde_json::Value::Bool(true));
            out
        } else {
            redact_detail(self.detail, cfg.extra_redact_keys.as_deref())
        };
        let row = Row {
            wire_version: "1".into(),
            id: id.clone(),
            origin_id: id,
            monotonic_seq: DEFAULT.seq_next(),
            timestamp: Utc::now(),
            code: self.code,
            action: meta.action,
            severity: self.severity.unwrap_or(meta.severity),
            service_id: cfg.service_id.clone(),
            source_node_id: cfg.node_id.clone(),
            tenant_id: cfg.tenant_id.clone(),
            actor: self.actor,
            actor_kind: self.actor_kind,
            target: self.target,
            category: meta.category,
            domain: meta.domain,
            method: self.method,
            request_id,
            detail,
            pii_in_detail: meta.pii_in_detail,
            shipped_at: None,
        };
        Ok(row)
    }

    fn write_audit_stdout(row: &Row) {
        if let Ok(mut payload) = serde_json::to_value(row) {
            if let serde_json::Value::Object(map) = &mut payload {
                map.insert("shape".into(), serde_json::Value::String("audit".into()));
            }
            println!("{}", payload);
        }
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
            detail_passthrough_keys: Vec::new(),
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

    // ── P1-5: pii_in_detail enforcement ───────────────────────────────────

    // #1 register() forces RetentionClass::Short for PII codes.
    #[test]
    fn p1_5_register_forces_short() {
        register(
            "p1_5_force".into(),
            [(
                "P1_5_PII_FORCE_SHORT".into(),
                Meta {
                    domain: "p1_5_force".into(),
                    category: "x".into(),
                    action: "x".into(),
                    severity: Severity::Info,
                    description: "x".into(),
                    emitter: "t".into(),
                    pii_in_detail: true,
                    retention_class: RetentionClass::Long,
                    ..Default::default()
                },
            )],
        )
        .expect("register");
        let m = meta_of("P1_5_PII_FORCE_SHORT").expect("meta");
        assert_eq!(m.retention_class, RetentionClass::Short);
    }

    // Non-PII code keeps adopter-set retention.
    #[test]
    fn p1_5_non_pii_keeps_retention() {
        register(
            "p1_5_nonpii".into(),
            [(
                "P1_5_NON_PII_LONG".into(),
                Meta {
                    domain: "p1_5_nonpii".into(),
                    category: "x".into(),
                    action: "x".into(),
                    severity: Severity::Info,
                    description: "x".into(),
                    emitter: "t".into(),
                    pii_in_detail: false,
                    retention_class: RetentionClass::Long,
                    ..Default::default()
                },
            )],
        )
        .expect("register");
        assert_eq!(
            meta_of("P1_5_NON_PII_LONG").unwrap().retention_class,
            RetentionClass::Long
        );
    }

    // #2 emit() force-redacts whole detail; passthrough keys survive.
    #[test]
    fn p1_5_emit_force_redacts_with_passthrough() {
        register(
            "p1_5_emit".into(),
            [(
                "P1_5_PII_PARTIAL".into(),
                Meta {
                    domain: "p1_5_emit".into(),
                    category: "x".into(),
                    action: "x".into(),
                    severity: Severity::Info,
                    description: "x".into(),
                    emitter: "t".into(),
                    pii_in_detail: true,
                    detail_passthrough_keys: vec!["region".into()],
                    ..Default::default()
                },
            )],
        )
        .expect("register");

        init(Config {
            service_id: "svc".into(),
            node_id: "node".into(),
            ..Default::default()
        })
        .expect("init");

        let mut detail: HashMap<String, serde_json::Value> = HashMap::new();
        detail.insert("city".into(), serde_json::json!("Mumbai"));
        detail.insert("region".into(), serde_json::json!("MH"));
        detail.insert("api_key".into(), serde_json::json!("sk-secret"));

        let row = EmitBuilder::new("P1_5_PII_PARTIAL", "u-42")
            .detail(detail)
            .submit()
            .expect("emit");

        // PII flag mirrored on the row.
        assert!(row.pii_in_detail, "row.pii_in_detail must be true for PII codes");
        // Passthrough survives.
        assert_eq!(row.detail.get("region"), Some(&serde_json::json!("MH")));
        // Non-passthrough stripped.
        assert!(!row.detail.contains_key("city"), "city must not survive force-redact");
        assert!(
            !row.detail.contains_key("api_key"),
            "api_key not in passthrough — must not survive"
        );
        // Markers present.
        assert_eq!(row.detail.get("_redacted"), Some(&serde_json::json!("***")));
        assert_eq!(row.detail.get("_pii_in_detail"), Some(&serde_json::json!(true)));
    }

    // #2 passthrough that names a secret key is still redacted by the secret-key scrubber.
    #[test]
    fn p1_5_passthrough_secret_still_redacted() {
        register(
            "p1_5_pthsec".into(),
            [(
                "P1_5_PII_PASSTHROUGH_SECRET".into(),
                Meta {
                    domain: "p1_5_pthsec".into(),
                    category: "x".into(),
                    action: "x".into(),
                    severity: Severity::Info,
                    description: "x".into(),
                    emitter: "t".into(),
                    pii_in_detail: true,
                    detail_passthrough_keys: vec!["api_key".into()],
                    ..Default::default()
                },
            )],
        )
        .expect("register");
        init(Config {
            service_id: "svc".into(),
            node_id: "node".into(),
            ..Default::default()
        })
        .expect("init");

        let mut detail: HashMap<String, serde_json::Value> = HashMap::new();
        detail.insert("api_key".into(), serde_json::json!("sk-secret"));

        let row = EmitBuilder::new("P1_5_PII_PASSTHROUGH_SECRET", "u-42")
            .detail(detail)
            .submit()
            .expect("emit");
        assert_eq!(row.detail.get("api_key"), Some(&serde_json::json!("***")));
    }

    // Non-PII code keeps detail; only secret keys get redacted.
    #[test]
    fn p1_5_non_pii_keeps_detail() {
        register(
            "p1_5_nonpii_detail".into(),
            [(
                "P1_5_NON_PII_BASIC".into(),
                Meta {
                    domain: "p1_5_nonpii_detail".into(),
                    category: "x".into(),
                    action: "x".into(),
                    severity: Severity::Info,
                    description: "x".into(),
                    emitter: "t".into(),
                    pii_in_detail: false,
                    ..Default::default()
                },
            )],
        )
        .expect("register");
        init(Config {
            service_id: "svc".into(),
            node_id: "node".into(),
            ..Default::default()
        })
        .expect("init");

        let mut detail: HashMap<String, serde_json::Value> = HashMap::new();
        detail.insert("city".into(), serde_json::json!("Mumbai"));
        detail.insert("api_key".into(), serde_json::json!("sk-secret"));

        let row = EmitBuilder::new("P1_5_NON_PII_BASIC", "u-42")
            .detail(detail)
            .submit()
            .expect("emit");
        assert!(!row.pii_in_detail);
        assert_eq!(row.detail.get("city"), Some(&serde_json::json!("Mumbai")));
        assert_eq!(row.detail.get("api_key"), Some(&serde_json::json!("***")));
        assert!(!row.detail.contains_key("_redacted"));
        assert!(!row.detail.contains_key("_pii_in_detail"));
    }
}

#[cfg(feature = "store-postgres")]
pub mod postgres_store;
#[cfg(feature = "store-postgres")]
pub use postgres_store::PostgresStore;

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
