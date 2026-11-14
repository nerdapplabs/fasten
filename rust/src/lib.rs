//! fasten: audit and correlation SDK for Rust services.
//!
//! Audit rows carry the 5 Ws + H anchors and a request_id for correlation.
//! The core is sync; stores and yaml catalogs are optional features.
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

pub mod retention;
pub use retention::{parse_duration, RedactionCandidate, AUDIT_ROW_REDACTED};

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
/// Returns `true` at once when no drainer is installed.
pub fn flush(timeout: std::time::Duration) -> bool { DEFAULT.flush(timeout) }

/// Snapshot of the active drainer, or `None` when none is installed.
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
    "access[_-]?key",
    "session[_-]?id",
    "cookie",
    "credential",
    "pwd",
    "passphrase",
    "dsn$",
    "^key$",
    "^auth$",
];
// ── END FASTEN GENERATED ──────────────────────────────────────────────────

// The generated enums have no Default derive; these let callers write
// `Meta { ..Default::default() }`.

#[allow(clippy::derivable_impls)]
impl Default for Severity {
    fn default() -> Self { Severity::Info }
}

#[allow(clippy::derivable_impls)]
impl Default for RetentionClass {
    fn default() -> Self { RetentionClass::Medium }
}

// A plain string; each service defines its own domains ("user", "billing").
pub type Domain = String;

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

/// Audit row; the wire shape is spec/row-schema.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    pub wire_version: String,

    pub id: String,
    pub origin_id: String,
    pub monotonic_seq: u64,

    #[serde(with = "canonical_ts_serde")]
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

    // The Rust SDK does not seal rows (spec §2.1), so both stay empty.
    #[serde(default)]
    pub prev_hash: String,
    #[serde(default)]
    pub hash: String,

    #[serde(default, skip_serializing_if = "Option::is_none", with = "canonical_ts_serde::option")]
    pub shipped_at: Option<DateTime<Utc>>,
}

/// Canonical timestamp form shared by every SDK (spec §4.3):
/// `YYYY-MM-DDTHH:MM:SS.ffffffZ`.
pub fn canonical_ts(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

mod canonical_ts_serde {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::canonical_ts(dt))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        DateTime::<Utc>::deserialize(d)
    }

    pub mod option {
        use super::*;

        pub fn serialize<S: Serializer>(dt: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error> {
            match dt {
                Some(dt) => s.serialize_str(&crate::canonical_ts(dt)),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<DateTime<Utc>>, D::Error> {
            Option::<DateTime<Utc>>::deserialize(d)
        }
    }
}

/// Per-code metadata.
///
/// `id` may be left empty; `register()` fills it from the key. If set, it
/// must match the key.
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
#[non_exhaustive]
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
    #[error("not supported: {0}")]
    Unsupported(String),
    #[error("{0}")]
    InvalidRetention(String),
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
/// The codes are validated by a fresh `fasten_core::catalog::CodeRegistry`
/// so the rules live in one place, then added to this SDK's registry.
/// Nothing is added if any code fails.
pub fn register<I>(domain: Domain, codes: I) -> Result<(), Error>
where
    I: IntoIterator<Item = (String, Meta)>,
{
    use fasten_core::catalog::CodeRegistry as CoreReg;
    let codes: Vec<(String, Meta)> = codes.into_iter().collect();

    // A throw-away registry, so the global one in fasten-core is untouched.
    let core_map: HashMap<String, fasten_core::catalog::Meta> =
        codes.iter().map(|(id, m)| (id.clone(), to_core_meta(m))).collect();
    CoreReg::new().register(&domain, core_map).map_err(map_core_catalog_err)?;

    // Reject codes registered by earlier calls.
    let mut guard = registry().write().expect("registry poisoned");
    for (id, _) in &codes {
        if guard.contains_key(id.as_str()) {
            return Err(Error::DuplicateCode(id.clone()));
        }
    }

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

/// Codes whose rows may carry personal data: `pii_in_detail`, or retention
/// class Short. Sorted.
pub fn pii_codes() -> Vec<String> {
    let guard = registry().read().expect("registry poisoned");
    let mut out: Vec<String> = guard
        .iter()
        .filter(|(_, m)| m.pii_in_detail || m.retention_class == RetentionClass::Short)
        .map(|(id, _)| id.clone())
        .collect();
    out.sort();
    out
}

/// `id,domain,severity`, sorted, one per line. Used by the cross-language
/// consistency check.
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

// The request id is thread-local, so it does not follow `tokio::spawn`:
//
//     with_request_id("abc".into(), || {
//         tokio::spawn(async move {
//             // current_request_id() is None here
//             fasten::EmitBuilder::new("CODE", "target").submit().unwrap();
//         });
//     });
//
// Read the id before spawning and call `with_request_id` again inside the task.

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

// NDJSON sys lines on stdout without needing `tracing` or `log`. Each line
// gets request_id from current_request_id() and service_id from the config
// (empty before init()).

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

pub(crate) fn redact_value(
    v: &serde_json::Value,
    extra: Option<&[String]>,
    replacement: Option<&str>,
) -> serde_json::Value {
    use fasten_core::redact::{Redactor, REDACTOR};
    // An empty replacement means the built-in "***". Build a custom Redactor
    // only when there are extra keys or a custom replacement.
    let repl = replacement.unwrap_or("");
    let has_extra = extra.is_some_and(|k| !k.is_empty());
    if has_extra || !repl.is_empty() {
        let refs: Vec<&str> = extra
            .map(|k| k.iter().map(String::as_str).collect())
            .unwrap_or_default();
        Redactor::new(&refs, repl, &[]).redact_value(v)
    } else {
        REDACTOR.redact_value(v)
    }
}

fn redact_detail(
    detail: HashMap<String, serde_json::Value>,
    extra: Option<&[String]>,
    replacement: Option<&str>,
) -> HashMap<String, serde_json::Value> {
    let v = serde_json::Value::Object(detail.into_iter().collect());
    match redact_value(&v, extra, replacement) {
        serde_json::Value::Object(map) => map.into_iter().collect(),
        _ => unreachable!("redact_value on Object always returns Object"),
    }
}

/// Adopter-supplied store. Sync trait so the core compiles without tokio.
pub trait AuditStore: Send + Sync {
    fn insert(&self, row: &Row) -> Result<(), Error>;

    /// Rows older than `before` with a code in `codes` whose detail can be
    /// redacted, ordered by `monotonic_seq` (spec §7.1).
    fn list_redaction_candidates(
        &self,
        _before: DateTime<Utc>,
        _codes: &[String],
    ) -> Result<Vec<RedactionCandidate>, Error> {
        Err(Error::Unsupported("list_redaction_candidates".into()))
    }

    /// Rows older than `before` with a code in `codes` that still hold
    /// detail but are sealed under a form other than "2", so cannot be
    /// redacted (spec §7.1). Reported, not touched.
    fn count_skipped_legacy_form(
        &self,
        _before: DateTime<Utc>,
        _codes: &[String],
    ) -> Result<u64, Error> {
        Ok(0)
    }

    /// Set `detail` to JSON null on these rows. Returns the ids.
    fn redact_rows(&self, _ids: &[String]) -> Result<Vec<String>, Error> {
        Err(Error::Unsupported("redact_rows".into()))
    }
}

#[derive(Clone, Default)]
pub struct Config {
    pub service_id: String,
    pub node_id: String,
    pub tenant_id: Option<String>,
    pub extra_redact_keys: Option<Vec<String>>,
    /// Custom redaction replacement token (None means the built-in "***").
    /// `config_from_env` reads it from FASTEN_REDACT_REPLACEMENT.
    pub redact_replacement: Option<String>,
    /// Durable audit store. With `audit_store_failure_strategy = "queue"`,
    /// `EmitBuilder::submit()` puts rows on a bounded in-memory queue that is
    /// drained in the background.
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
    /// Disable the +/-20% retry jitter (on by default).
    pub disable_queue_jitter: bool,
    /// Max insert attempts before a row is dead-lettered. Default: 50.
    pub queue_drain_max_attempts: Option<usize>,
    /// PII horizon, e.g. `"30d"`. Rows whose code is in [`pii_codes`] get
    /// their detail redacted once older than this (spec §7). Needs an audit
    /// store. None falls back to `FASTEN_RETENTION_PII`.
    pub retention_pii: Option<String>,
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
    let replacement = std::env::var("FASTEN_REDACT_REPLACEMENT")
        .ok()
        .filter(|s| !s.is_empty());
    Ok(Config {
        service_id,
        node_id,
        tenant_id: std::env::var("FASTEN_TENANT_ID").ok(),
        extra_redact_keys: extra,
        redact_replacement: replacement,
        retention_pii: std::env::var("FASTEN_RETENTION_PII").ok().filter(|s| !s.is_empty()),
        ..Default::default()
    })
}

/// Initialise fasten with a Config. Required before `emit()`.
///
/// When `cfg.audit_store` is set and the strategy is `"queue"` (the
/// default), this starts the fasten-core drainer thread (see
/// `fasten_core::drainer`).
pub fn init(cfg: Config) -> Result<(), Error> { DEFAULT.init(cfg) }

/// Redact PII rows older than `before` and write an `AUDIT_ROW_REDACTED`
/// row for each (spec §7). Returns the redacted ids.
pub fn redact_expired(before: DateTime<Utc>, reason: &str) -> Result<Vec<String>, Error> {
    DEFAULT.redact_expired(before, reason)
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

    /// Build the row and send it to the configured store. In `queue` mode
    /// it goes to the drainer; in `raise` mode it is inserted synchronously
    /// and errors are wrapped in [`AuditStoreError`]. In `queue` mode, a row
    /// the drainer can't take is inserted synchronously; if that fails,
    /// `audit_sync_fallback_failed` is emitted and the row is still returned.
    ///
    /// The row is also written to stdout (`{"shape":"audit",...}`) in
    /// either mode.
    pub fn submit(self) -> Result<Row, AuditStoreError> {
        self.submit_to(&DEFAULT)
    }

    pub(crate) fn submit_to(self, engine: &Engine) -> Result<Row, AuditStoreError> {
        let cfg = engine.current_config().map_err(|e| AuditStoreError { source: e })?;
        let row = self
            .build_row(&cfg)
            .map_err(|e| AuditStoreError { source: e })?;

        // Write stdout first: enqueue() blocks while the queue is full, and
        // in raise mode the insert may fail. Either way the row should
        // still reach the log stream.
        Self::write_audit_stdout(&row);

        let strategy = cfg
            .audit_store_failure_strategy
            .as_deref()
            .unwrap_or("queue");
        if strategy == "queue" {
            if let Some(d) = engine.active_drainer() {
                let core_row = crate::engine::sdk_row_to_core(&row);
                if !d.enqueue(core_row) {
                    // The drainer is stopping (a re-init or shutdown), so
                    // store the row here. With no store (a re-init to a
                    // config without one) stdout has the row, as it does
                    // on the no-store path.
                    if let Some(s) = cfg.audit_store.as_ref() {
                        engine.store_inline(&**s, &row);
                    }
                }
            } else if let Some(s) = cfg.audit_store.as_ref() {
                // No drainer installed; insert synchronously rather than
                // drop the row.
                if let Err(e) = s.insert(&row) {
                    engine.fallback_failed(&row, e);
                }
            }
        } else if let Some(s) = cfg.audit_store.as_ref() {
            if let Err(e) = s.insert(&row) {
                return Err(AuditStoreError { source: e });
            }
        }
        Ok(row)
    }

    pub(crate) fn build_row(self, cfg: &Config) -> Result<Row, Error> {
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
            let mut out = redact_detail(
                kept,
                cfg.extra_redact_keys.as_deref(),
                cfg.redact_replacement.as_deref(),
            );
            out.insert("_redacted".into(), serde_json::Value::String(REDACT_REPLACEMENT.into()));
            out.insert("_pii_in_detail".into(), serde_json::Value::Bool(true));
            out
        } else {
            redact_detail(
                self.detail,
                cfg.extra_redact_keys.as_deref(),
                cfg.redact_replacement.as_deref(),
            )
        };
        let row = Row {
            wire_version: "1".into(),
            id: id.clone(),
            origin_id: id,
            // Spec §8: the store allocates the seq.
            monotonic_seq: 0,
            // Microseconds, the precision the stores keep (spec §4.3).
            timestamp: chrono::SubsecRound::trunc_subsecs(Utc::now(), 6),
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
            prev_hash: String::new(),
            hash: String::new(),
            shipped_at: None,
        };
        Ok(row)
    }

    pub(crate) fn write_audit_stdout(row: &Row) {
        if let Ok(mut payload) = serde_json::to_value(row) {
            if let serde_json::Value::Object(map) = &mut payload {
                map.insert("shape".into(), serde_json::Value::String("audit".into()));
            }
            println!("{}", payload);
        }
    }

}

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
        let out = redact_detail(d, None, None);
        assert_eq!(out["email"], serde_json::json!("a@b.com"));
        assert_eq!(out["api_key"], serde_json::json!("***"));
        assert_eq!(out["nested"]["token"], serde_json::json!("***"));
        assert_eq!(out["nested"]["ok"], serde_json::json!("keep"));
    }

    #[test]
    fn redact_custom_replacement_and_extra_keys() {
        let mut d = HashMap::new();
        d.insert("password".into(), serde_json::json!("p"));
        d.insert("badge".into(), serde_json::json!("b"));
        d.insert("ok".into(), serde_json::json!("v"));
        let extra = vec!["badge".to_string()];
        let out = redact_detail(d, Some(&extra), Some("[X]"));
        assert_eq!(out["password"], serde_json::json!("[X]"));
        assert_eq!(out["badge"], serde_json::json!("[X]"));
        assert_eq!(out["ok"], serde_json::json!("v"));

        // A custom replacement without extra keys.
        let mut d2 = HashMap::new();
        d2.insert("secret".into(), serde_json::json!("s"));
        d2.insert("ok".into(), serde_json::json!("v"));
        let out2 = redact_detail(d2, None, Some("##"));
        assert_eq!(out2["secret"], serde_json::json!("##"));
        assert_eq!(out2["ok"], serde_json::json!("v"));
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

    #[test]
    fn register_fills_id_from_key() {
        register(
            "fill_id".into(),
            [(
                "FILLED_FROM_KEY".into(),
                Meta {
                    domain: "fill_id".into(),
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
        let m = meta_of("FILLED_FROM_KEY").unwrap();
        assert_eq!(m.id, "FILLED_FROM_KEY");
    }

    #[test]
    fn register_id_mismatch_raises() {
        let result = register(
            "id_mismatch".into(),
            [(
                "ID_MISMATCH_KEY".into(),
                Meta {
                    id: "WRONG_ID".into(),
                    domain: "id_mismatch".into(),
                    severity: Severity::Info,
                    ..Default::default()
                },
            )],
        );
        match result {
            Err(Error::IdMismatch { key, got }) => {
                assert_eq!(key, "ID_MISMATCH_KEY");
                assert_eq!(got, "WRONG_ID");
            }
            other => panic!("expected IdMismatch, got {:?}", other),
        }
    }

    #[test]
    fn register_invalid_key_shape_raises() {
        let result = register(
            "bad_key".into(),
            [(
                "lowercase_bad".into(),
                Meta {
                    domain: "bad_key".into(),
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

    #[test]
    fn pii_register_forces_short() {
        register(
            "pii_force".into(),
            [(
                "PII_FORCE_SHORT".into(),
                Meta {
                    domain: "pii_force".into(),
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
        let m = meta_of("PII_FORCE_SHORT").expect("meta");
        assert_eq!(m.retention_class, RetentionClass::Short);
    }

    #[test]
    fn non_pii_keeps_retention() {
        register(
            "nonpii".into(),
            [(
                "NON_PII_LONG".into(),
                Meta {
                    domain: "nonpii".into(),
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
            meta_of("NON_PII_LONG").unwrap().retention_class,
            RetentionClass::Long
        );
    }

    // A PII code's detail is dropped except passthrough keys.
    #[test]
    fn pii_emit_keeps_only_passthrough() {
        register(
            "pii_emit".into(),
            [(
                "PII_PARTIAL".into(),
                Meta {
                    domain: "pii_emit".into(),
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

        let row = EmitBuilder::new("PII_PARTIAL", "u-42")
            .detail(detail)
            .submit()
            .expect("emit");

        assert!(row.pii_in_detail, "row.pii_in_detail must be true for PII codes");
        assert_eq!(row.detail.get("region"), Some(&serde_json::json!("MH")));
        assert!(!row.detail.contains_key("city"), "city must not survive force-redact");
        assert!(
            !row.detail.contains_key("api_key"),
            "api_key is not a passthrough key"
        );
        assert_eq!(row.detail.get("_redacted"), Some(&serde_json::json!("***")));
        assert_eq!(row.detail.get("_pii_in_detail"), Some(&serde_json::json!(true)));
    }

    // A passthrough key that looks like a secret is still redacted.
    #[test]
    fn pii_passthrough_secret_still_redacted() {
        register(
            "pii_pthsec".into(),
            [(
                "PII_PASSTHROUGH_SECRET".into(),
                Meta {
                    domain: "pii_pthsec".into(),
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

        let row = EmitBuilder::new("PII_PASSTHROUGH_SECRET", "u-42")
            .detail(detail)
            .submit()
            .expect("emit");
        assert_eq!(row.detail.get("api_key"), Some(&serde_json::json!("***")));
    }

    #[test]
    fn non_pii_keeps_detail() {
        register(
            "nonpii_detail".into(),
            [(
                "NON_PII_BASIC".into(),
                Meta {
                    domain: "nonpii_detail".into(),
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

        let row = EmitBuilder::new("NON_PII_BASIC", "u-42")
            .detail(detail)
            .submit()
            .expect("emit");
        assert!(!row.pii_in_detail);
        assert_eq!(row.detail.get("city"), Some(&serde_json::json!("Mumbai")));
        assert_eq!(row.detail.get("api_key"), Some(&serde_json::json!("***")));
        assert!(!row.detail.contains_key("_redacted"));
        assert!(!row.detail.contains_key("_pii_in_detail"));
    }

    // ── #124: store-assigned seq, PII redaction ───────────────────────────

    fn plain_meta(domain: &str) -> Meta {
        Meta { domain: domain.into(), severity: Severity::Info, ..Default::default() }
    }

    // Spec §8: emit leaves seq, prev_hash and hash to the store.
    #[test]
    fn emit_returns_seq_zero_unsealed() {
        register("seq0".into(), [("SEQ0_EVENT".into(), plain_meta("seq0"))]).unwrap();
        init(Config { service_id: "svc".into(), node_id: "node".into(), ..Default::default() })
            .unwrap();
        for _ in 0..3 {
            let row = EmitBuilder::new("SEQ0_EVENT", "t").submit().expect("emit");
            assert_eq!(row.monotonic_seq, 0);
            assert_eq!(row.prev_hash, "");
            assert_eq!(row.hash, "");
            let v = serde_json::to_value(&row).unwrap();
            assert_eq!(v["prev_hash"], serde_json::json!(""));
            assert_eq!(v["hash"], serde_json::json!(""));
        }
    }

    fn sys_events(service_id: &str, event: &str) -> usize {
        engine::SYS_CAPTURE
            .lock()
            .unwrap()
            .iter()
            .filter(|v| v["service_id"] == service_id && v["event"] == event)
            .count()
    }

    #[test]
    fn init_logs_chain_unavailable_once() {
        let e = Engine::new();
        let cfg = Config {
            service_id: "svc-chain-log".into(),
            node_id: "n".into(),
            ..Default::default()
        };
        e.init(cfg.clone()).unwrap();
        let line = engine::SYS_CAPTURE
            .lock()
            .unwrap()
            .iter()
            .find(|v| v["service_id"] == "svc-chain-log")
            .cloned()
            .expect("sys line");
        assert_eq!(line["event"], "audit_chain_unavailable");
        assert_eq!(line["level"], "error");
        assert!(line["reason"].as_str().unwrap().contains("does not seal"));
        assert_eq!(sys_events("svc-chain-log", "audit_chain_unavailable"), 1);
        e.init(cfg).unwrap();
        assert_eq!(sys_events("svc-chain-log", "audit_chain_unavailable"), 2);
    }

    #[test]
    fn pii_codes_lists_pii_and_short() {
        register(
            "piicodes".into(),
            [
                ("PIICODES_PII".into(), Meta { pii_in_detail: true, ..plain_meta("piicodes") }),
                (
                    "PIICODES_SHORT".into(),
                    Meta { retention_class: RetentionClass::Short, ..plain_meta("piicodes") },
                ),
                (
                    "PIICODES_LONG".into(),
                    Meta { retention_class: RetentionClass::Long, ..plain_meta("piicodes") },
                ),
            ],
        )
        .unwrap();
        let codes = pii_codes();
        assert!(codes.contains(&"PIICODES_PII".to_string()));
        assert!(codes.contains(&"PIICODES_SHORT".to_string()));
        assert!(!codes.contains(&"PIICODES_LONG".to_string()));
        let mut sorted = codes.clone();
        sorted.sort();
        assert_eq!(codes, sorted);
    }

    #[test]
    fn init_rejects_bad_retention_pii() {
        let e = Engine::new();
        let r = e.init(Config {
            service_id: "svc".into(),
            node_id: "n".into(),
            retention_pii: Some("30 days".into()),
            ..Default::default()
        });
        assert!(matches!(r, Err(Error::InvalidRetention(_))));
    }

    #[test]
    fn store_without_redaction_is_unsupported() {
        struct InsertOnly;
        impl AuditStore for InsertOnly {
            fn insert(&self, _: &Row) -> Result<(), Error> { Ok(()) }
        }
        register(
            "unsup".into(),
            [("UNSUP_PII".into(), Meta { pii_in_detail: true, ..plain_meta("unsup") })],
        )
        .unwrap();
        let e = Engine::new();
        e.init(Config {
            service_id: "svc".into(),
            node_id: "n".into(),
            audit_store: Some(Arc::new(InsertOnly)),
            audit_store_failure_strategy: Some("raise".into()),
            ..Default::default()
        })
        .unwrap();
        assert!(matches!(e.redact_expired(Utc::now(), "x"), Err(Error::Unsupported(_))));
    }

    // Records what the purger does, in order.
    #[derive(Default)]
    struct MemStore {
        log: std::sync::Mutex<Vec<String>>,
    }

    impl AuditStore for MemStore {
        fn insert(&self, row: &Row) -> Result<(), Error> {
            self.log.lock().unwrap().push(format!("insert {} {}", row.code, row.target));
            Ok(())
        }
        fn list_redaction_candidates(
            &self,
            _before: DateTime<Utc>,
            codes: &[String],
        ) -> Result<Vec<RedactionCandidate>, Error> {
            let mut log = self.log.lock().unwrap();
            let first = !log.iter().any(|l| l.starts_with("list"));
            log.push("list".into());
            assert!(codes.contains(&"PURGER_PII".to_string()));
            Ok(if first {
                vec![RedactionCandidate { id: "evt-pii-1".into(), monotonic_seq: 7 }]
            } else {
                vec![]
            })
        }
        fn redact_rows(&self, ids: &[String]) -> Result<Vec<String>, Error> {
            self.log.lock().unwrap().push(format!("redact {}", ids.join(",")));
            Ok(ids.to_vec())
        }
    }

    // retention_pii starts a purger that records, then redacts; reset stops it.
    #[test]
    fn retention_pii_runs_purger() {
        register(
            "purger".into(),
            [("PURGER_PII".into(), Meta { pii_in_detail: true, ..plain_meta("purger") })],
        )
        .unwrap();
        let store = Arc::new(MemStore::default());
        let e = Engine::new();
        e.init(Config {
            service_id: "svc-purger".into(),
            node_id: "n".into(),
            audit_store: Some(store.clone()),
            audit_store_failure_strategy: Some("raise".into()),
            retention_pii: Some("30d".into()),
            ..Default::default()
        })
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !store.log.lock().unwrap().iter().any(|l| l.starts_with("redact")) {
            assert!(std::time::Instant::now() < deadline, "purger never redacted");
            std::thread::sleep(Duration::from_millis(10));
        }
        let started = std::time::Instant::now();
        e.reset_for_tests();
        assert!(started.elapsed() < Duration::from_secs(2), "purger did not stop promptly");
        let log = store.log.lock().unwrap().clone();
        assert_eq!(
            log,
            vec![
                "list".to_string(),
                format!("insert {AUDIT_ROW_REDACTED} evt-pii-1"),
                "redact evt-pii-1".to_string(),
            ]
        );
    }

    // Many candidates, each insert slow.
    #[derive(Default)]
    struct SlowStore {
        log: std::sync::Mutex<Vec<String>>,
    }

    impl AuditStore for SlowStore {
        fn insert(&self, row: &Row) -> Result<(), Error> {
            std::thread::sleep(Duration::from_millis(20));
            self.log.lock().unwrap().push(format!("insert {}", row.target));
            Ok(())
        }
        fn list_redaction_candidates(
            &self,
            _: DateTime<Utc>,
            _: &[String],
        ) -> Result<Vec<RedactionCandidate>, Error> {
            Ok((0..1000)
                .map(|i| RedactionCandidate { id: format!("evt-{i}"), monotonic_seq: i })
                .collect())
        }
        fn redact_rows(&self, ids: &[String]) -> Result<Vec<String>, Error> {
            self.log.lock().unwrap().push(format!("redact {}", ids.join(",")));
            Ok(ids.to_vec())
        }
    }

    fn purger_config(service_id: &str, store: Arc<dyn AuditStore>) -> Config {
        Config {
            service_id: service_id.into(),
            node_id: "n".into(),
            audit_store: Some(store),
            audit_store_failure_strategy: Some("raise".into()),
            retention_pii: Some("30d".into()),
            ..Default::default()
        }
    }

    // reset stops a purger with a backlog after the row it is on.
    #[test]
    fn purger_stops_between_rows() {
        register(
            "slowpurge".into(),
            [("SLOWPURGE_PII".into(), Meta { pii_in_detail: true, ..plain_meta("slowpurge") })],
        )
        .unwrap();
        let store = Arc::new(SlowStore::default());
        let e = Engine::new();
        e.init(purger_config("svc-slowpurge", store.clone())).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !store.log.lock().unwrap().iter().any(|l| l.starts_with("redact")) {
            assert!(std::time::Instant::now() < deadline, "purger never redacted");
            std::thread::sleep(Duration::from_millis(5));
        }
        let started = std::time::Instant::now();
        e.reset_for_tests();
        assert!(started.elapsed() < Duration::from_millis(500), "purger did not stop promptly");
        let log = store.log.lock().unwrap().clone();
        let inserts = log.iter().filter(|l| l.starts_with("insert")).count();
        let redacts = log.iter().filter(|l| l.starts_with("redact")).count();
        assert!(redacts < 1000, "purger ran the whole backlog");
        // Every row it started was recorded, then redacted.
        assert_eq!(inserts, redacts);
        for pair in log.chunks(2) {
            let id = pair[0].strip_prefix("insert ").expect("insert first");
            assert_eq!(pair[1], format!("redact {id}"));
        }
    }

    // A store call that never returns.
    struct HungStore {
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        entered: std::sync::atomic::AtomicBool,
    }

    impl AuditStore for HungStore {
        fn insert(&self, _: &Row) -> Result<(), Error> { Ok(()) }
        fn list_redaction_candidates(
            &self,
            _: DateTime<Utc>,
            _: &[String],
        ) -> Result<Vec<RedactionCandidate>, Error> {
            self.entered.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = self.release.lock().unwrap().recv_timeout(Duration::from_secs(30));
            Ok(vec![])
        }
    }

    #[test]
    fn hung_purger_does_not_block_reset() {
        register(
            "hungpurge".into(),
            [("HUNGPURGE_PII".into(), Meta { pii_in_detail: true, ..plain_meta("hungpurge") })],
        )
        .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let store = Arc::new(HungStore {
            release: std::sync::Mutex::new(rx),
            entered: std::sync::atomic::AtomicBool::new(false),
        });
        let e = Engine::new();
        e.init(purger_config("svc-hungpurge", store.clone())).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !store.entered.load(std::sync::atomic::Ordering::SeqCst) {
            assert!(std::time::Instant::now() < deadline, "purger never listed");
            std::thread::sleep(Duration::from_millis(5));
        }
        let started = std::time::Instant::now();
        e.reset_for_tests();
        assert!(started.elapsed() < Duration::from_secs(3), "reset blocked on a hung purger");
        drop(tx);
    }
    fn ts_row(ts: &str, shipped: serde_json::Value) -> Row {
        serde_json::from_value(serde_json::json!({
            "wire_version": "1", "id": "i", "origin_id": "i", "monotonic_seq": 1,
            "timestamp": ts, "code": "C", "action": "a", "severity": "Info",
            "service_id": "s", "source_node_id": "n", "tenant_id": null,
            "actor": "u", "actor_kind": "user", "target": "t", "category": "c",
            "domain": "d", "method": "m", "request_id": "r", "detail": {},
            "shipped_at": shipped,
        }))
        .unwrap()
    }

    // Spec §4.3: six fractional digits on the wire, whole seconds included.
    #[test]
    fn row_serializes_canonical_timestamps() {
        let row = ts_row("2026-01-02T03:04:05Z", serde_json::json!("2026-01-02T03:04:05.120Z"));
        let v = serde_json::to_value(&row).unwrap();
        assert_eq!(v["timestamp"], "2026-01-02T03:04:05.000000Z");
        assert_eq!(v["shipped_at"], "2026-01-02T03:04:05.120000Z");

        let row = ts_row("2026-01-02T03:04:05.120Z", serde_json::Value::Null);
        let v = serde_json::to_value(&row).unwrap();
        assert_eq!(v["timestamp"], "2026-01-02T03:04:05.120000Z");
        assert!(v.get("shipped_at").is_none());

        let back: Row = serde_json::from_value(v).unwrap();
        assert_eq!(back.timestamp, row.timestamp);
        assert!(back.shipped_at.is_none());
    }

    #[test]
    fn sys_line_uses_canonical_timestamp() {
        let cfg = Config { service_id: "svc-sys-ts".into(), ..Default::default() };
        engine::sys_line(Some(&cfg), "info", "sys_ts_probe", serde_json::json!({}));
        let line = engine::SYS_CAPTURE
            .lock()
            .unwrap()
            .iter()
            .find(|v| v["service_id"] == "svc-sys-ts")
            .cloned()
            .expect("sys line");
        let ts = line["timestamp"].as_str().unwrap();
        assert_eq!(ts.len(), "2026-01-02T03:04:05.000000Z".len(), "{ts}");
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[19..20], ".");
    }

    // Records inserted row ids, or fails every insert.
    #[derive(Default)]
    struct IdStore {
        fail: bool,
        ids: std::sync::Mutex<Vec<String>>,
    }

    impl AuditStore for IdStore {
        fn insert(&self, row: &Row) -> Result<(), Error> {
            if self.fail {
                return Err(Error::AuditStoreInsert("down".into()));
            }
            self.ids.lock().unwrap().push(row.id.clone());
            Ok(())
        }
    }

    fn sys_lines(service_id: &str, event: &str) -> Vec<serde_json::Value> {
        engine::SYS_CAPTURE
            .lock()
            .unwrap()
            .iter()
            .filter(|v| v["service_id"] == service_id && v["event"] == event)
            .cloned()
            .collect()
    }

    fn queue_config(service_id: &str, store: Arc<dyn AuditStore>) -> Config {
        Config {
            service_id: service_id.into(),
            node_id: "n".into(),
            audit_store: Some(store),
            ..Default::default()
        }
    }

    // A row the stopped drainer refuses is stored inline.
    #[test]
    fn submit_stores_inline_when_drainer_stopped() {
        register("inline".into(), [("INLINE_EVENT".into(), plain_meta("inline"))]).unwrap();
        let store = Arc::new(IdStore::default());
        let e = Engine::new();
        e.init(queue_config("svc-inline", store.clone())).unwrap();
        e.active_drainer().unwrap().stop(Duration::from_secs(2));

        let row = EmitBuilder::new("INLINE_EVENT", "t").submit_to(&e).expect("submit");
        assert_eq!(*store.ids.lock().unwrap(), vec![row.id.clone()]);
        let lines = sys_lines("svc-inline", "audit_drain_stored_inline");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["row_id"], serde_json::json!(row.id));
        e.reset_for_tests();
    }

    // In queue mode a failed inline insert is reported and submit returns Ok.
    #[test]
    fn submit_ok_when_drainer_stopped_and_insert_fails() {
        register("inline_fail".into(), [("INLINE_FAIL".into(), plain_meta("inline_fail"))])
            .unwrap();
        let store = Arc::new(IdStore { fail: true, ..Default::default() });
        let e = Engine::new();
        e.init(queue_config("svc-inline-fail", store)).unwrap();
        e.active_drainer().unwrap().stop(Duration::from_secs(2));

        let row = EmitBuilder::new("INLINE_FAIL", "t").submit_to(&e).expect("submit");
        let lines = sys_lines("svc-inline-fail", "audit_sync_fallback_failed");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["error_type"], "AuditStoreInsert");
        assert_eq!(lines[0]["row_id"], serde_json::json!(row.id));
        assert!(lines[0].get("error").is_none());
        e.reset_for_tests();
    }

    // Same with no drainer installed.
    #[test]
    fn submit_ok_when_no_drainer_and_insert_fails() {
        register("no_drainer".into(), [("NO_DRAINER".into(), plain_meta("no_drainer"))])
            .unwrap();
        let store = Arc::new(IdStore { fail: true, ..Default::default() });
        let e = Engine::new();
        e.init(queue_config("svc-no-drainer", store)).unwrap();
        e.uninstall_drainer();

        let row = EmitBuilder::new("NO_DRAINER", "t").submit_to(&e).expect("submit");
        let lines = sys_lines("svc-no-drainer", "audit_sync_fallback_failed");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["error_type"], "AuditStoreInsert");
        assert_eq!(lines[0]["row_id"], serde_json::json!(row.id));
        e.reset_for_tests();
    }

    // Raise mode returns the insert error.
    #[test]
    fn submit_errors_in_raise_mode_when_insert_fails() {
        register("raise_fail".into(), [("RAISE_FAIL".into(), plain_meta("raise_fail"))])
            .unwrap();
        let store = Arc::new(IdStore { fail: true, ..Default::default() });
        let e = Engine::new();
        e.init(Config {
            audit_store_failure_strategy: Some("raise".into()),
            ..queue_config("svc-raise-fail", store)
        })
        .unwrap();

        let err = EmitBuilder::new("RAISE_FAIL", "t").submit_to(&e).unwrap_err();
        assert!(matches!(err.source, Error::AuditStoreInsert(_)));
        assert!(sys_lines("svc-raise-fail", "audit_sync_fallback_failed").is_empty());
        e.reset_for_tests();
    }

    // Re-init reports a row the old drainer dead-lettered during its flush.
    #[test]
    fn reinit_reports_unstored_rows() {
        register("reinit".into(), [("REINIT_EVENT".into(), plain_meta("reinit"))]).unwrap();
        let store: Arc<dyn AuditStore> = Arc::new(IdStore { fail: true, ..Default::default() });
        let cfg = Config {
            queue_retry_initial: Some(Duration::from_millis(200)),
            queue_drain_max_attempts: Some(3),
            disable_queue_jitter: true,
            ..queue_config("svc-reinit", store)
        };
        let e = Engine::new();
        e.init(cfg.clone()).unwrap();
        EmitBuilder::new("REINIT_EVENT", "t").submit_to(&e).expect("submit");
        e.init(cfg).unwrap();

        let lines = sys_lines("svc-reinit", "audit_drain_install_incomplete");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["level"], "warn");
        assert_eq!(lines[0]["flushed"], true);
        assert_eq!(lines[0]["unstored"], 1);
        e.reset_for_tests();
    }

    // A clean re-init reports nothing.
    #[test]
    fn reinit_after_clean_flush_is_quiet() {
        let store: Arc<dyn AuditStore> = Arc::new(IdStore::default());
        let e = Engine::new();
        e.init(queue_config("svc-reinit-ok", store.clone())).unwrap();
        e.init(queue_config("svc-reinit-ok", store)).unwrap();
        assert!(sys_lines("svc-reinit-ok", "audit_drain_install_incomplete").is_empty());
        e.reset_for_tests();
    }

    // A failed drainer insert is retried and shows the store error's type.
    #[test]
    fn drainer_reports_store_error_type() {
        register("drain_type".into(), [("DRAIN_TYPE".into(), plain_meta("drain_type"))]).unwrap();
        let store: Arc<dyn AuditStore> = Arc::new(IdStore { fail: true, ..Default::default() });
        let cfg = Config {
            queue_retry_initial: Some(Duration::from_millis(10)),
            queue_retry_max: Some(Duration::from_millis(10)),
            disable_queue_jitter: true,
            ..queue_config("svc-drain-type", store)
        };
        let e = Engine::new();
        e.init(cfg).unwrap();
        EmitBuilder::new("DRAIN_TYPE", "t").submit_to(&e).expect("submit");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while e.queue_stats().unwrap().retry_count_active < 2 {
            assert!(std::time::Instant::now() < deadline, "row was not retried");
            std::thread::sleep(Duration::from_millis(5));
        }
        let stats = e.queue_stats().unwrap();
        assert_eq!(stats.last_error.as_deref(), Some("AuditStoreInsert"));
        assert_eq!(stats.dead_lettered_total, 0);
        e.reset_for_tests();
    }

    // A refused row is not an error when a re-init has dropped the store.
    #[test]
    fn submit_ok_when_drainer_stopped_and_store_gone() {
        register("store_gone".into(), [("STORE_GONE".into(), plain_meta("store_gone"))]).unwrap();
        let e = Engine::new();
        e.init(queue_config("svc-store-gone", Arc::new(IdStore::default()))).unwrap();
        e.active_drainer().unwrap().stop(Duration::from_secs(2));
        e.config.lock().unwrap().as_mut().unwrap().audit_store = None;

        EmitBuilder::new("STORE_GONE", "t").submit_to(&e).expect("submit");
        assert!(sys_lines("svc-store-gone", "audit_sync_fallback_failed").is_empty());
        assert!(sys_lines("svc-store-gone", "audit_drain_stored_inline").is_empty());
        e.reset_for_tests();
    }

    // Holds the first insert until opened, then stores every row.
    #[derive(Default)]
    struct GateStore {
        open: std::sync::Mutex<bool>,
        open_cv: std::sync::Condvar,
        started: std::sync::atomic::AtomicBool,
        ids: std::sync::Mutex<Vec<String>>,
    }

    impl GateStore {
        fn release(&self) {
            *self.open.lock().unwrap() = true;
            self.open_cv.notify_all();
        }
    }

    impl AuditStore for GateStore {
        fn insert(&self, row: &Row) -> Result<(), Error> {
            if !self.started.swap(true, std::sync::atomic::Ordering::SeqCst) {
                let mut open = self.open.lock().unwrap();
                while !*open {
                    open = self.open_cv.wait(open).unwrap();
                }
            }
            self.ids.lock().unwrap().push(row.id.clone());
            Ok(())
        }
    }

    // A submit blocked on a full queue that a re-init's stop wakes stores
    // its row inline.
    #[test]
    fn blocked_submit_woken_by_reinit_is_stored() {
        register("reinit_blocked".into(), [("REINIT_BLOCKED".into(), plain_meta("reinit_blocked"))])
            .unwrap();
        let store = Arc::new(GateStore::default());
        let cfg = Config {
            queue_capacity: Some(1),
            ..queue_config("svc-reinit-blocked", store.clone())
        };
        let e = Engine::new();
        e.init(cfg.clone()).unwrap();
        // Holds the only slot while its insert waits on the gate.
        let first = EmitBuilder::new("REINIT_BLOCKED", "t").submit_to(&e).expect("submit");

        let (tx, rx) = std::sync::mpsc::channel();
        let submitting = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|sc| {
            sc.spawn(|| {
                submitting.store(true, std::sync::atomic::Ordering::SeqCst);
                tx.send(EmitBuilder::new("REINIT_BLOCKED", "t").submit_to(&e)).unwrap()
            });
            // Wait for the second submit to start on the full queue.
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !submitting.load(std::sync::atomic::Ordering::SeqCst)
                || e.queue_stats().unwrap().depth < 1
            {
                assert!(std::time::Instant::now() < deadline, "submit did not start");
                std::thread::sleep(Duration::from_millis(1));
            }
            std::thread::sleep(Duration::from_millis(20));
            sc.spawn(|| e.init(cfg.clone()).unwrap());
            // The re-init's flush times out after 5s; its stop wakes the submit.
            let blocked = rx.recv_timeout(Duration::from_secs(20));
            store.release();
            let row = blocked.expect("blocked submit returned").expect("submit");
            assert!(store.ids.lock().unwrap().contains(&row.id), "row was dropped");
            let inline = sys_lines("svc-reinit-blocked", "audit_drain_stored_inline");
            assert!(inline.iter().any(|l| l["row_id"] == serde_json::json!(row.id)));
        });
        assert!(store.ids.lock().unwrap().contains(&first.id));
        e.reset_for_tests();
    }

    #[test]
    fn log_lines_are_redacted() {
        let e = Engine::new();
        e.init(Config {
            service_id: "svc-log-redact".into(),
            node_id: "n".into(),
            extra_redact_keys: Some(vec!["badge".into()]),
            ..Default::default()
        })
        .unwrap();
        e.log_sys("info", "x", serde_json::json!({
            "password": "p",
            "nested": {"token": "t", "ok": "v"},
            "badge": "b",
        }));
        let line = sys_lines("svc-log-redact", "x").pop().expect("log line");
        assert_eq!(line["password"], "***");
        assert_eq!(line["nested"]["token"], "***");
        assert_eq!(line["nested"]["ok"], "v");
        assert_eq!(line["badge"], "***");
        e.reset_for_tests();
    }

    // Log lines go to stdout; SDK sys events go to stderr.
    #[test]
    fn sys_events_skip_stdout() {
        let e = Engine::new();
        e.init(Config {
            service_id: "svc-streams".into(),
            node_id: "n".into(),
            ..Default::default()
        })
        .unwrap();
        e.log_sys("info", "app_event", serde_json::json!({}));
        let events: Vec<serde_json::Value> = engine::SYS_STDOUT
            .lock()
            .unwrap()
            .iter()
            .filter(|v| v["service_id"] == "svc-streams")
            .map(|v| v["event"].clone())
            .collect();
        assert_eq!(events, vec![serde_json::json!("app_event")]);
        assert_eq!(sys_events("svc-streams", "audit_chain_unavailable"), 1);
        e.reset_for_tests();
    }
}

#[cfg(feature = "store-postgres")]
pub mod postgres_store;
#[cfg(feature = "store-postgres")]
pub use postgres_store::PostgresStore;

// Yaml catalogs, behind the `codes-yaml` feature:
//
//   fasten-sdk = { version = "1", features = ["codes-yaml"] }
//   fasten::codes::load("fleet.codes.yaml")?;
//   fasten::codes::reload()?;

#[cfg(feature = "codes-yaml")]
pub mod codes_yaml;

#[cfg(feature = "codes-yaml")]
pub mod codes {
    pub use super::codes_yaml::{load, reload};
}
