//! rivet — audit + correlation SDK for Rust services.
//!
//! Same shape as Python / Go / Node.js references: 6 audit anchors (5 Ws + H)
//! + correlation, opt-in shims per transport, pluggable store + transport,
//! mountable reader.
//!
//! See `../README.md` for the full design.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// --- 6 audit anchors as typed row ----------------------------------------

/// Classical audit dimensions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Anchor {
    Who,         // actor, actor_kind
    What,        // code, action
    When,        // timestamp, monotonic_seq
    Where,       // source_node_id, service_id, site_id
    Whom,        // target, category, domain
    How,         // method
    Correlation, // request_id
}

/// Canonical audit row. Lossless conversion to CloudEvent + OTel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    pub id: String,
    pub edge_row_id: String,
    pub monotonic_seq: u64,

    pub timestamp: DateTime<Utc>,

    pub code: String,
    pub action: String,
    pub severity: Severity,

    pub service_id: String,
    pub source_node_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_id: Option<String>,

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Domain {
    Node,
    Sync,
    Fleet,
    Agent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Debug,
    Info,
    Warn,
    Error,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetentionClass {
    Short,  // 30d default
    Medium, // 180d default
    Long,   // 1095d (3y) default
}

#[derive(Debug, Clone)]
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

/// Registry error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("duplicate code: {0}")]
    DuplicateCode(String),
    #[error("unknown code: {0}")]
    UnknownCode(String),
    #[error("code {code} declares domain={got:?} but registered under {want:?}")]
    DomainMismatch { code: String, got: Domain, want: Domain },
    #[error("missing required anchor: {0:?}")]
    MissingAnchor(Anchor),
    #[error("init not called")]
    NotInitialised,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Register a batch of codes for a domain. Call once per domain at startup.
pub fn register(_domain: Domain, _codes: impl IntoIterator<Item = (String, Meta)>) -> Result<(), Error> {
    // TODO: thread-safe OnceLock<RwLock<HashMap>> registry + validation
    Ok(())
}

/// Dump `id,domain,severity` sorted one-per-line — feeds cross-language gate.
pub fn dump() -> String {
    // TODO
    String::new()
}

// --- Correlation context -------------------------------------------------

tokio::task_local! {
    static REQUEST_ID: String;
}

/// Mint a 12-char request id.
pub fn mint_id() -> String {
    uuid::Uuid::new_v4().simple().to_string().chars().take(12).collect()
}

/// Read the ambient request_id (empty if unset).
pub fn current_request_id() -> String {
    REQUEST_ID.try_with(|v| v.clone()).unwrap_or_default()
}

/// Run `fut` with `rid` set as ambient correlation.
#[cfg(feature = "async")]
pub async fn with_request_id<F, T>(rid: String, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    REQUEST_ID.scope(rid, fut).await
}

// --- Init + Emit ---------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Config {
    pub service_id: String,
    pub node_id: String,
    pub site_id: Option<String>,
    // audit_store + api_store in real impl hold a Box<dyn AuditRepository>
}

/// Read env vars; return Config.
pub fn config_from_env() -> Result<Config, Error> {
    Ok(Config {
        service_id: std::env::var("RIVET_SERVICE_ID").unwrap_or_default(),
        node_id: std::env::var("RIVET_NODE_ID").unwrap_or_default(),
        site_id: std::env::var("RIVET_SITE_ID").ok(),
    })
}

/// Fluent-style Emit builder. Enforces presence of code + target + detail
/// at compile time (anchors filled from ctx/config).
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
            method: "http".into(),
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

    /// Actually emit. Async because store writes may be async.
    #[cfg(feature = "async")]
    pub async fn emit(self) -> Result<Row, Error> {
        // TODO: lookup Meta, auto-fill anchors, redact, insert into store, mirror to stdout
        Err(Error::NotInitialised)
    }
}

// --- Store interfaces ----------------------------------------------------

#[cfg(feature = "async")]
#[async_trait::async_trait]
pub trait AuditRepository: Send + Sync {
    async fn insert(&self, row: &Row) -> Result<(), Error>;
    async fn query(&self, filter: &Filter) -> Result<Vec<Row>, Error>;
    async fn list_unshipped(&self, limit: usize) -> Result<Vec<Row>, Error>;
    async fn mark_shipped(&self, ids: &[String]) -> Result<(), Error>;
    async fn purge(&self, before: DateTime<Utc>, respect_unshipped: bool) -> Result<usize, Error>;
}

#[cfg(feature = "async")]
#[async_trait::async_trait]
pub trait AuditOutboxRepository: Send + Sync {
    async fn enqueue(&self, row: &Row) -> Result<(), Error>;
    async fn next_batch(&self, n: usize) -> Result<Vec<Row>, Error>;
    async fn ack(&self, ids: &[String]) -> Result<(), Error>;
    async fn requeue(&self, ids: &[String]) -> Result<(), Error>;
    async fn depth(&self) -> Result<usize, Error>;
}

/// Query filter.
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
