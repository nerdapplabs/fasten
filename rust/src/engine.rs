//! `Engine` holds the runtime state: config, drainer and PII purger.
//!
//! The free functions in `lib.rs` (`init`, `flush`, ...) and
//! `EmitBuilder::submit()` all use [`DEFAULT`].

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};

use fasten_core::drainer::{Drainer, DrainerConfig};

use crate::retention::{parse_duration, Purger};
use crate::streams::{StreamPurger, StreamStore, Streams};
use crate::{current_request_id, AuditStore, Config, Error, IngestResult, ReplicatedRow};

/// How often a stream store is purged for age.
const STREAM_PURGE_INTERVAL: Duration = Duration::from_secs(3600);

/// How long re-init waits for the previous streams' queued writes.
const STREAM_RETIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// Python's repr of a sorted list of names, for error texts that match it.
fn py_list(names: &[&str]) -> String {
    let mut v: Vec<&str> = names.to_vec();
    v.sort_unstable();
    v.dedup();
    format!("[{}]", v.iter().map(|n| format!("'{n}'")).collect::<Vec<_>>().join(", "))
}

/// Refuse a `persist_streams` name other than "api" and "sys".
fn check_stream_names(named: &[String]) -> Result<(), Error> {
    let names: Vec<&str> = named.iter().map(String::as_str).collect();
    let unknown: Vec<&str> = names.iter().copied().filter(|n| *n != "api" && *n != "sys").collect();
    if unknown.is_empty() {
        return Ok(());
    }
    Err(Error::InvalidConfig(format!(
        "fasten.init: persist_streams={}: unknown stream(s) {}. Only ['api', 'sys'] are valid (audit persistence is driven by audit_store, not persist_streams).",
        py_list(&names),
        py_list(&unknown)
    )))
}

/// Check `persist_streams` against the attached stores, with Python's
/// errors: every named stream needs a store and every store must be named.
fn check_persist_streams(named: Option<&[String]>, api: bool, sys: bool) -> Result<(), Error> {
    let Some(named) = named else { return Ok(()) };
    let names: Vec<&str> = named.iter().map(String::as_str).collect();
    let have: Vec<&str> = [("api", api), ("sys", sys)].into_iter().filter(|(_, h)| *h).map(|(n, _)| n).collect();
    let missing: Vec<&str> = names.iter().copied().filter(|n| !have.contains(n)).collect();
    let unlisted: Vec<&str> = have.iter().copied().filter(|n| !names.contains(n)).collect();
    if missing.is_empty() && unlisted.is_empty() {
        return Ok(());
    }
    let mut bits = Vec::new();
    if !missing.is_empty() {
        bits.push(format!("named in persist_streams but no store attached: {}", py_list(&missing)));
    }
    if !unlisted.is_empty() {
        bits.push(format!("store attached but not in persist_streams: {}", py_list(&unlisted)));
    }
    Err(Error::InvalidConfig(format!("fasten.init: persist_streams / stores mismatch: {}", bits.join("; "))))
}

/// What the reader reads for one request.
pub(crate) struct ReaderState {
    pub(crate) cfg: Option<Config>,
    pub(crate) streams: Option<Arc<Streams>>,
}

trait LockOrRecover<T: ?Sized> {
    fn lock_or_recover(&self) -> std::sync::MutexGuard<'_, T>;
}
impl<T: ?Sized> LockOrRecover<T> for Mutex<T> {
    fn lock_or_recover(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|e| e.into_inner())
    }
}

pub(crate) fn sdk_row_to_core(r: &crate::Row) -> fasten_core::Row {
    fasten_core::Row {
        wire_version:   r.wire_version.clone(),
        id:             r.id.clone(),
        origin_id:      r.origin_id.clone(),
        monotonic_seq:  r.monotonic_seq,
        timestamp:      crate::canonical_ts(&r.timestamp),
        code:           r.code.clone(),
        action:         r.action.clone(),
        severity:       r.severity.to_string(), // lowercase
        service_id:     r.service_id.clone(),
        source_node_id: r.source_node_id.clone(),
        tenant_id:      r.tenant_id.clone(),
        actor:          r.actor.clone(),
        actor_kind:     r.actor_kind.clone(),
        target:         r.target.clone(),
        category:       r.category.clone(),
        domain:         r.domain.clone(),
        method:         r.method.clone(),
        request_id:     r.request_id.clone(),
        detail:         serde_json::Value::Object(r.detail.clone().into_iter().collect()),
        pii_in_detail:  r.pii_in_detail,
        shipped_at:     r.shipped_at.as_ref().map(crate::canonical_ts),
        prev_hash:      Some(r.prev_hash.clone()),
        hash:           Some(r.hash.clone()),
        canonical_form_id: Some(r.canonical_form_id.clone()).filter(|f| !f.is_empty()),
        detail_salt:    r.detail_salt.clone(),
        detail_commitment: r.detail_commitment.clone(),
        extra:          HashMap::new(),
    }
}

fn core_to_sdk_row(r: &fasten_core::Row) -> crate::Row {
    let severity = match r.severity.as_str() {
        "debug"    => crate::Severity::Debug,
        "warn"     => crate::Severity::Warn,
        "error"    => crate::Severity::Error,
        "critical" => crate::Severity::Critical,
        _          => crate::Severity::Info,
    };
    let detail: HashMap<String, serde_json::Value> = match &r.detail {
        serde_json::Value::Object(m) => m.clone().into_iter().collect(),
        _ => HashMap::new(),
    };
    crate::Row {
        wire_version:   r.wire_version.clone(),
        id:             r.id.clone(),
        origin_id:      r.origin_id.clone(),
        monotonic_seq:  r.monotonic_seq,
        timestamp:      r.timestamp.parse().unwrap_or_else(|_| Utc::now()),
        code:           r.code.clone(),
        action:         r.action.clone(),
        severity,
        service_id:     r.service_id.clone(),
        source_node_id: r.source_node_id.clone(),
        tenant_id:      r.tenant_id.clone(),
        actor:          r.actor.clone(),
        actor_kind:     r.actor_kind.clone(),
        target:         r.target.clone(),
        category:       r.category.clone(),
        domain:         r.domain.clone(),
        method:         r.method.clone(),
        request_id:     r.request_id.clone(),
        detail,
        pii_in_detail:  r.pii_in_detail,
        prev_hash:      r.prev_hash.clone().unwrap_or_default(),
        hash:           r.hash.clone().unwrap_or_default(),
        canonical_form_id: r.canonical_form_id.clone().unwrap_or_default(),
        detail_salt:    r.detail_salt.clone(),
        detail_commitment: r.detail_commitment.clone(),
        shipped_at:     r.shipped_at.as_deref().and_then(|s| s.parse().ok()),
    }
}

/// Insert `row` through the store's allocating insert and return it as
/// stored. When the store sealed it, the sealed row is written to stdout,
/// after the unsealed line `submit` wrote (spec §8). A failed write of that
/// line is reported, not returned: the row is stored.
pub(crate) fn store_row(store: &dyn AuditStore, row: &crate::Row) -> Result<crate::Row, Error> {
    let stored = store.allocate_and_insert_originated(row)?;
    if !stored.hash.is_empty() {
        crate::EmitBuilder::write_audit_stdout(&stored);
    } else if row.monotonic_seq == 0 && store.seals() && !UNSEALED_REPORTED.swap(true, Ordering::Relaxed) {
        // The store says it seals but gave back an unsealed row. Said once
        // per process, with the first such row.
        sys_line(None, "error", "audit_chain_row_unsealed", serde_json::json!({
            "row_id": stored.id,
            "service_id": stored.service_id,
            "reason": "the audit store reports seals() but returned the row without a hash",
        }));
    }
    Ok(stored)
}

static UNSEALED_REPORTED: AtomicBool = AtomicBool::new(false);

// Lets the fasten-core drainer write through an SDK `AuditStore`.

struct SdkStoreAdapter(Arc<dyn AuditStore>);

impl fasten_core::store::Store for SdkStoreAdapter {
    fn insert(&self, row: &fasten_core::Row) -> Result<(), fasten_core::Error> {
        let sdk_row = core_to_sdk_row(row);
        // Type only: a store error message can quote row values. The
        // drainer retries the row, unless the store rejected it.
        store_row(&*self.0, &sdk_row).map(|_| ()).map_err(|e| {
            let kind = crate::retention::error_type(&e).into();
            match e {
                crate::Error::AuditStoreRejected(_) => fasten_core::Error::RowRejected(kind),
                _ => fasten_core::Error::Store(kind),
            }
        })
    }
    fn ping(&self) -> Result<(), fasten_core::Error> { Ok(()) }
    fn query(&self, _: &fasten_core::store::Filter)
        -> Result<Vec<fasten_core::Row>, fasten_core::Error> { Ok(vec![]) }
    fn count(&self, _: &fasten_core::store::Filter)
        -> Result<u64, fasten_core::Error> { Ok(0) }
    fn list_unshipped(&self, _: u32)
        -> Result<Vec<fasten_core::Row>, fasten_core::Error> { Ok(vec![]) }
    fn mark_shipped(&self, _: &[String]) -> Result<(), fasten_core::Error> { Ok(()) }
    // Audit rows are never purged for age (spec §7); PII is redacted instead.
    fn purge(&self, _: &str, _: bool) -> Result<u64, fasten_core::Error> { Ok(0) }
    fn max_monotonic_seq(&self) -> Result<u64, fasten_core::Error> { Ok(0) }
}

/// A store opened from a DSN variable, and that DSN.
type EnvStore<S> = Option<(String, Arc<S>)>;

/// The stores opened from FASTEN_AUDIT_DSN, FASTEN_API_DSN and
/// FASTEN_SYSLOG_DSN, kept so that init with the same DSN keeps the store
/// and its connection.
struct EnvStores {
    audit:  EnvStore<dyn AuditStore>,
    api:    EnvStore<dyn StreamStore>,
    syslog: EnvStore<dyn StreamStore>,
    /// How many inits have installed their stores, so `close` can tell
    /// whether one ran after it started.
    installs: u64,
}

/// The value of the DSN variable `name` in `env`, unless it is empty.
fn env_dsn<'a>(env: &'a [(String, String)], name: &str) -> Option<&'a str> {
    env.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty())
}

/// The store init uses for the DSN variable `name`: `explicit` when set,
/// else the one `held` was opened from the same DSN, else a new one from
/// `open`. Returns it and what to hold after this init. An unset or empty
/// variable opens nothing.
fn store_from_env<S: ?Sized>(
    explicit: Option<Arc<S>>,
    env: &[(String, String)],
    name: &str,
    held: &EnvStore<S>,
    open: impl FnOnce(&str) -> Result<Arc<S>, Error>,
) -> Result<(Option<Arc<S>>, EnvStore<S>), Error> {
    let dsn = env_dsn(env, name);
    let (Some(dsn), None) = (dsn, explicit.as_ref()) else {
        return Ok((explicit, None));
    };
    let store = match held {
        Some((same, store)) if same == dsn => Arc::clone(store),
        _ => open(dsn)?,
    };
    Ok((Some(Arc::clone(&store)), Some((dsn.to_string(), store))))
}

/// Variables already reported as not read, once per process.
static UNREAD_DSN_REPORTED: Mutex<Option<HashSet<String>>> = Mutex::new(None);

/// The `FASTEN_*` variables of the process environment that hold text.
fn fasten_env() -> Vec<(String, String)> {
    std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .filter(|(k, _)| k.starts_with("FASTEN_"))
        .collect()
}

/// The store adapter the drainer writes through, for tests.
#[cfg(test)]
pub(crate) fn adapter_for_tests(store: Arc<dyn AuditStore>) -> impl fasten_core::store::Store {
    SdkStoreAdapter(store)
}

pub struct Engine {
    pub(crate) config:  Mutex<Option<Config>>,
    pub(crate) drainer: Mutex<Option<Arc<Drainer>>>,
    purger:             Mutex<Option<Purger>>,
    env_stores:         Mutex<EnvStores>,
    streams:            Mutex<Option<Arc<Streams>>>,
    stream_purgers:     Mutex<Vec<StreamPurger>>,
    /// An audit row failed to reach the current store: a failed inline
    /// insert, or rows a stopped drainer left. Cleared by an init with a
    /// different store.
    audit_swallowed:    AtomicBool,
}

impl Engine {
    pub const fn new() -> Self {
        Self {
            config:  Mutex::new(None),
            drainer: Mutex::new(None),
            purger:  Mutex::new(None),
            env_stores: Mutex::new(EnvStores { audit: None, api: None, syslog: None, installs: 0 }),
            streams: Mutex::new(None),
            stream_purgers: Mutex::new(Vec::new()),
            audit_swallowed: AtomicBool::new(false),
        }
    }

    /// Initialise with `cfg`. With no `cfg.audit_store`, the audit store is
    /// opened from `FASTEN_AUDIT_DSN` when it is set (see
    /// [`crate::audit_store_from_dsn`]), and likewise the stream stores from
    /// `FASTEN_API_DSN` and `FASTEN_SYSLOG_DSN`; a store in `cfg` wins. An
    /// init with the same DSN keeps the store opened before; with another
    /// one, or none, that store is closed once its writer lets go of it.
    pub fn init(&self, cfg: Config) -> Result<(), Error> {
        self.init_with_env(cfg, &fasten_env())
    }

    /// [`Engine::init`] with `env` as the `FASTEN_*` variables.
    pub(crate) fn init_with_env(&self, mut cfg: Config, env: &[(String, String)]) -> Result<(), Error> {
        if cfg.service_id.is_empty() || cfg.node_id.is_empty() {
            return Err(Error::NotInitialised);
        }
        let strategy = cfg
            .audit_store_failure_strategy
            .clone()
            .or_else(|| std::env::var("FASTEN_AUDIT_STORE_FAILURE_STRATEGY").ok())
            .unwrap_or_else(|| "queue".into())
            .to_lowercase();
        if strategy != "queue" && strategy != "raise" {
            return Err(Error::InvalidStrategy(strategy));
        }
        let retention_pii = cfg
            .retention_pii
            .clone()
            .or_else(|| std::env::var("FASTEN_RETENTION_PII").ok())
            .filter(|s| !s.is_empty());
        let pii_horizon = retention_pii.as_deref().map(parse_duration).transpose()?;
        let env_or = |given: &Option<String>, name: &str| {
            given.clone().or_else(|| std::env::var(name).ok()).filter(|s| !s.is_empty())
        };
        let retention_api = env_or(&cfg.retention_api, "FASTEN_RETENTION_API");
        let retention_syslog = env_or(&cfg.retention_syslog, "FASTEN_RETENTION_SYSLOG");
        let api_horizon = retention_api.as_deref().map(parse_duration).transpose()?;
        let sys_horizon = retention_syslog.as_deref().map(parse_duration).transpose()?;
        let search_enabled = cfg.search_enabled
            || std::env::var("FASTEN_SEARCH_ENABLED")
                .is_ok_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"));
        let persist_streams = cfg.persist_streams.clone().or_else(|| {
            std::env::var("FASTEN_PERSIST_STREAMS").ok().filter(|s| !s.is_empty()).map(|s| {
                s.split(',').map(str::trim).filter(|x| !x.is_empty()).map(str::to_string).collect()
            })
        });
        // Unknown names first, before any store is opened.
        if let Some(named) = &persist_streams {
            check_stream_names(named)?;
        }
        // Every check runs before a store is opened, and every store is
        // opened before any is let go of, so a failed init creates no file
        // and leaves the stores of the last one as they were: each DSN is
        // parsed and checked against the features built in and the tables
        // its store takes, and a SQLite file in a directory that does not
        // exist is refused here too.
        let mut parsed = Vec::new();
        for (name, given, default_table) in [
            ("FASTEN_AUDIT_DSN", cfg.audit_store.is_some(), "audit_log"),
            ("FASTEN_API_DSN", cfg.api_store.is_some(), "api_log"),
            ("FASTEN_SYSLOG_DSN", cfg.syslog_store.is_some(), "syslog"),
        ] {
            let dsn = env_dsn(env, name);
            if let (Some(dsn), false) = (dsn, given) {
                let d = crate::parse_dsn(dsn, default_table).map_err(|e| Error::InvalidConfig(format!("{name}: {e}")))?;
                parsed.push((name, d));
            }
        }
        for (name, d) in &parsed {
            crate::dsn::check_env_dsn(name, d, *name != "FASTEN_AUDIT_DSN")?;
        }
        let from_env = |name: &str| parsed.iter().any(|(n, _)| *n == name);
        check_persist_streams(
            persist_streams.as_deref(),
            cfg.api_store.is_some() || from_env("FASTEN_API_DSN"),
            cfg.syslog_store.is_some() || from_env("FASTEN_SYSLOG_DSN"),
        )?;
        let mut held = self.env_stores.lock_or_recover();
        let (audit_store, audit_env) = store_from_env(cfg.audit_store.take(), env, "FASTEN_AUDIT_DSN", &held.audit, |dsn| {
            crate::dsn::open_audit_store("FASTEN_AUDIT_DSN", dsn)
        })?;
        let (api_store, api_env) = store_from_env(cfg.api_store.take(), env, "FASTEN_API_DSN", &held.api, |dsn| {
            crate::streams::open_stream_store("FASTEN_API_DSN", dsn, "api_log")
        })?;
        let (syslog_store, syslog_env) =
            store_from_env(cfg.syslog_store.take(), env, "FASTEN_SYSLOG_DSN", &held.syslog, |dsn| {
                crate::streams::open_stream_store("FASTEN_SYSLOG_DSN", dsn, "syslog")
            })?;
        let installs = held.installs.wrapping_add(1);
        *held = EnvStores { audit: audit_env, api: api_env, syslog: syslog_env, installs };
        cfg.audit_store = audit_store;

        let store = cfg.audit_store.clone();
        let capacity     = cfg.queue_capacity.unwrap_or(100);
        let retry_initial = cfg.queue_retry_initial.unwrap_or(Duration::from_millis(100));
        let retry_max     = cfg.queue_retry_max.unwrap_or(Duration::from_secs(60));
        let retry_jitter  = !cfg.disable_queue_jitter;
        let max_attempts  = cfg.queue_drain_max_attempts.unwrap_or(50);

        let mut cfg_stored = cfg;
        cfg_stored.audit_store_failure_strategy = Some(strategy.clone());
        cfg_stored.retention_pii = retention_pii;
        cfg_stored.retention_api = retention_api;
        cfg_stored.retention_syslog = retention_syslog;
        cfg_stored.search_enabled = search_enabled;
        cfg_stored.persist_streams = persist_streams;
        cfg_stored.api_store = api_store.clone();
        cfg_stored.syslog_store = syslog_store.clone();
        // The config is replaced while the env store lock is held, so a
        // close in between cannot release the new stores from the old
        // config and leave them in this one. close takes the same two
        // locks in the same order.
        let previous = self.config.lock_or_recover().replace(cfg_stored.clone());
        drop(held);

        self.stop_purger();
        self.stop_stream_purgers();

        // A gap in the previous store's history says nothing about another.
        let same_store = match (previous.as_ref().and_then(|c| c.audit_store.as_ref()), store.as_ref()) {
            (Some(a), Some(b)) => std::ptr::addr_eq(Arc::as_ptr(a), Arc::as_ptr(b)),
            (None, None) => true,
            _ => false,
        };
        if !same_store {
            self.audit_swallowed.store(false, Ordering::Relaxed);
        }

        let streams = Arc::new(Streams::new(&cfg_stored.service_id, api_store.clone(), syslog_store.clone()));
        let old_streams = self.streams.lock_or_recover().replace(streams);
        if let Some(old) = old_streams {
            old.close(std::time::Instant::now() + STREAM_RETIRE_TIMEOUT);
        }
        {
            let mut purgers = self.stream_purgers.lock_or_recover();
            for (name, st, horizon) in [("api", &api_store, api_horizon), ("sys", &syslog_store, sys_horizon)] {
                if let (Some(st), Some(h)) = (st, horizon) {
                    purgers.push(StreamPurger::start(name, Arc::clone(st), h, cfg_stored.clone(), STREAM_PURGE_INTERVAL));
                }
            }
        }

        self.report_unread_dsn_env(env);

        // Say once per init that rows are not chained: there is no store to
        // allocate against (spec §8.1), or the store does not seal (§8.2).
        let unchained = match &store {
            None => Some(
                "no audit store configured (spec 8.1): Config::audit_store not set and FASTEN_AUDIT_DSN unset; \
                 rows are written to stdout unsealed",
            ),
            Some(s) if !s.seals() => {
                Some("the audit store does not seal rows (spec 2.1); rows are written unsealed")
            }
            Some(_) => None,
        };
        if let Some(reason) = unchained {
            self.sys_event("error", "audit_chain_unavailable", serde_json::json!({ "reason": reason }));
        }

        if strategy == "queue" {
            if let Some(s) = store {
                self.install_drainer(s, DrainerConfig {
                    capacity, retry_initial, retry_max, retry_jitter, max_attempts,
                });
            } else {
                self.uninstall_drainer();
            }
        } else {
            self.uninstall_drainer();
        }

        if let Some(horizon) = pii_horizon.filter(|_| cfg_stored.audit_store.is_some()) {
            *self.purger.lock_or_recover() = Some(Purger::start(cfg_stored, horizon));
        }
        Ok(())
    }

    /// Report, once per process, each set `FASTEN_*` variable named like a
    /// DSN variable that init does not read: a misspelt one leaves the app
    /// without the store it meant to open. The value is not reported.
    fn report_unread_dsn_env(&self, env: &[(String, String)]) {
        for (name, value) in env {
            if value.is_empty() || !crate::dsn::unread_dsn_name(name) {
                continue;
            }
            let first = UNREAD_DSN_REPORTED.lock_or_recover().get_or_insert_with(HashSet::new).insert(name.clone());
            if first {
                self.sys_event("warn", "env_dsn_not_read", serde_json::json!({
                    "variable": name,
                    "reason": format!("init opens stores from {} only", crate::dsn::DSN_ENV.join(", ")),
                }));
            }
        }
    }

    /// The configured audit store, or an error naming `op`.
    fn audit_store(&self, op: &str) -> Result<(Config, Arc<dyn AuditStore>), Error> {
        let cfg = self.current_config()?;
        let store = cfg.audit_store.clone().ok_or_else(|| {
            Error::Unsupported(format!("{op}: no audit store; set Config::audit_store or FASTEN_AUDIT_DSN"))
        })?;
        Ok((cfg, store))
    }

    /// This engine's unshipped audit rows, exactly as they were sealed, that
    /// it originated (its service and node id), oldest first, for shipping
    /// to another node (spec §5). `limit == 0` returns all.
    pub fn list_unshipped(&self, limit: usize) -> Result<Vec<ReplicatedRow>, Error> {
        let (cfg, store) = self.audit_store("list_unshipped")?;
        store.list_unshipped_sealed(limit, Some((&cfg.service_id, &cfg.node_id)))
    }

    /// Mark rows of the audit store as shipped.
    pub fn mark_shipped(&self, ids: &[String]) -> Result<(), Error> {
        self.audit_store("mark_shipped")?.1.mark_shipped(ids)
    }

    /// Verify a batch of rows from other nodes and store its verified prefix
    /// in the audit store. A row from this engine's node is a break: its
    /// rows come from its emit path, never from replication. See
    /// [`AuditStore::ingest_replicated`].
    pub fn ingest_replicated(&self, rows: &[ReplicatedRow]) -> Result<IngestResult, Error> {
        let (cfg, store) = self.audit_store("ingest_replicated")?;
        store.ingest_replicated(rows, Some(&cfg.node_id))
    }

    /// Redact PII rows older than `before` and record each one (spec §7).
    /// Returns the redacted ids.
    pub fn redact_expired(&self, before: DateTime<Utc>, reason: &str) -> Result<Vec<String>, Error> {
        crate::retention::redact_expired(&self.current_config()?, before, reason)
    }

    pub(crate) fn stop_purger(&self) {
        let old = self.purger.lock_or_recover().take();
        if let Some(p) = old {
            p.stop();
        }
    }

    pub fn current_config(&self) -> Result<Config, Error> {
        self.config.lock_or_recover().clone().ok_or(Error::NotInitialised)
    }

    pub(crate) fn active_drainer(&self) -> Option<Arc<Drainer>> {
        self.drainer.lock_or_recover().clone()
    }

    pub(crate) fn install_drainer(&self, store: Arc<dyn AuditStore>, cfg: DrainerConfig) {
        let new = Drainer::new(Box::new(SdkStoreAdapter(store)), cfg);
        let old = { let mut slot = self.drainer.lock_or_recover(); slot.replace(new) };
        if let Some(old) = old {
            let unstored_before = old.unstored_total();
            let flushed = old.flush(Duration::from_secs(5));
            old.stop(Duration::from_secs(2));
            let unstored = old.unstored_total() - unstored_before;
            if unstored > 0 {
                self.audit_swallowed.store(true, Ordering::Relaxed);
            }
            if !flushed || unstored > 0 {
                self.sys_event("warn", "audit_drain_install_incomplete", serde_json::json!({
                    "flushed": flushed,
                    "unstored": unstored,
                }));
            }
        }
    }

    pub fn uninstall_drainer(&self) {
        let old = { let mut slot = self.drainer.lock_or_recover(); slot.take() };
        if let Some(d) = old {
            d.stop(Duration::from_secs(2));
        }
    }

    pub fn queue_stats(&self) -> Option<fasten_core::drainer::QueueStats> {
        Some(self.active_drainer()?.stats())
    }

    /// Block until queued audit rows and stream writes are stored, or
    /// `timeout` elapses. True when nothing is left.
    pub fn flush(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let drained = match self.active_drainer() {
            Some(d) => d.flush(timeout),
            None    => true,
        };
        let streams = self.streams.lock_or_recover().clone();
        let written = streams.is_none_or(|s| s.flush(deadline));
        drained && written
    }

    /// Flush within `timeout`, then stop the drainer, the purgers and the
    /// stream writers, and release the stores opened from
    /// `FASTEN_AUDIT_DSN`, `FASTEN_API_DSN` and `FASTEN_SYSLOG_DSN`. True
    /// when everything queued was stored.
    ///
    /// Until the next `init`, log lines and api rows go to stdout only. An
    /// audit row goes to stdout, and is stored only when the config passed
    /// to `init` holds the audit store itself: then it is inserted inline
    /// as it is emitted. A row for a store opened from `FASTEN_AUDIT_DSN`
    /// goes to stdout only, unsealed. The next `init` opens the DSN stores
    /// again.
    pub fn close(&self, timeout: Duration) -> bool {
        // Read first: the stores of an init that runs while this closes stay.
        let installs = self.env_stores.lock_or_recover().installs;
        let deadline = std::time::Instant::now() + timeout;
        let flushed = self.flush(timeout);
        self.stop_purger();
        self.stop_stream_purgers();
        let streams = self.streams.lock_or_recover().take();
        let written = streams.is_none_or(|s| s.close(deadline));
        let old = { let mut slot = self.drainer.lock_or_recover(); slot.take() };
        // Spec §10: close returns false when a row was lost at stop, as
        // install_drainer already reports for a drainer it retires.
        let mut stored = true;
        if let Some(d) = old {
            let unstored_before = d.unstored_total();
            d.stop(deadline.saturating_duration_since(std::time::Instant::now()));
            if d.unstored_total() > unstored_before {
                self.audit_swallowed.store(true, Ordering::Relaxed);
                stored = false;
            }
        }
        #[cfg(test)]
        if let Some(f) = BEFORE_RELEASE.with(|h| h.borrow_mut().take()) {
            f();
        }
        self.release_env_stores(installs);
        flushed && written && stored
    }

    /// Let go of the stores opened from DSN variables, in the env store
    /// table and in the config, unless an init has installed stores since
    /// `installs` was read. A store dropped here closes once the last call
    /// using it returns.
    fn release_env_stores(&self, installs: u64) {
        let mut env = self.env_stores.lock_or_recover();
        if env.installs != installs {
            return;
        }
        let (audit, api, syslog) = (env.audit.take(), env.api.take(), env.syslog.take());
        fn same<S: ?Sized>(a: &Option<Arc<S>>, b: &EnvStore<S>) -> bool {
            match (a, b) {
                (Some(a), Some((_, b))) => std::ptr::addr_eq(Arc::as_ptr(a), Arc::as_ptr(b)),
                _ => false,
            }
        }
        // The env store lock is still held, so no init installs stores
        // before the config is changed.
        if let Some(cfg) = self.config.lock_or_recover().as_mut() {
            if same(&cfg.audit_store, &audit) {
                cfg.audit_store = None;
            }
            if same(&cfg.api_store, &api) {
                cfg.api_store = None;
            }
            if same(&cfg.syslog_store, &syslog) {
                cfg.syslog_store = None;
            }
        }
        drop(env);
    }

    pub fn reset_for_tests(&self) {
        self.stop_purger();
        self.stop_stream_purgers();
        self.uninstall_drainer();
        if let Some(s) = self.streams.lock_or_recover().take() {
            s.close(std::time::Instant::now() + Duration::from_secs(2));
        }
        self.audit_swallowed.store(false, Ordering::Relaxed);
        *self.config.lock_or_recover() = None;
        let mut env = self.env_stores.lock_or_recover();
        let installs = env.installs;
        *env = EnvStores { audit: None, api: None, syslog: None, installs };
    }

    fn stop_stream_purgers(&self) {
        let old: Vec<StreamPurger> = std::mem::take(&mut *self.stream_purgers.lock_or_recover());
        for p in old {
            p.stop();
        }
    }

    /// Write a log line (`fasten::log`) to stdout, and to the sys stream.
    pub fn log_sys(&self, level: &str, event: &str, fields: serde_json::Value) {
        let cfg = self.config.lock_or_recover().clone();
        let streams = self.streams.lock_or_recover().clone();
        write_sys(true, cfg.as_ref(), level, event, fields, streams.as_deref());
    }

    /// Write an api row (`fasten::log::api`): to stdout as
    /// `{"shape":"api",...}`, and to the api stream. `fields` is the row,
    /// typically `method`, `path`, `status` and `duration_ms`; `timestamp`,
    /// `service_id` and the current `request_id` are added when missing. A
    /// row without a request id gets a sentinel one (spec §7). The row is
    /// redacted first, as sys lines are.
    pub fn log_api(&self, fields: serde_json::Value) {
        let cfg = self.config.lock_or_recover().clone();
        let streams = self.streams.lock_or_recover().clone();
        let mut row = match fields {
            serde_json::Value::Object(m) => m,
            _ => serde_json::Map::new(),
        };
        row.entry("timestamp").or_insert_with(|| crate::canonical_ts(&Utc::now()).into());
        if let Some(c) = &cfg {
            row.entry("service_id").or_insert_with(|| c.service_id.clone().into());
        }
        if let Some(rid) = current_request_id() {
            row.entry("request_id").or_insert(rid.into());
        }
        if let Some(s) = &streams {
            s.stamp(&mut row);
        }
        let row = redact_map(row, cfg.as_ref());
        if let Some(s) = &streams {
            s.api.push(row.clone());
        }
        let mut line = row;
        line.insert("shape".into(), "api".into());
        let line = serde_json::Value::Object(line);
        #[cfg(test)]
        API_STDOUT.lock_or_recover().push(line.clone());
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout().lock(), "{line}");
    }

    /// Write an SDK sys event to stderr, and to the sys stream.
    pub(crate) fn sys_event(&self, level: &str, event: &str, fields: serde_json::Value) {
        let cfg = self.config.lock_or_recover().clone();
        let streams = self.streams.lock_or_recover().clone();
        write_sys(false, cfg.as_ref(), level, event, fields, streams.as_deref());
    }

    /// The config and streams one reader request reads.
    pub(crate) fn reader_state(&self) -> ReaderState {
        ReaderState {
            cfg: self.config.lock_or_recover().clone(),
            streams: self.streams.lock_or_recover().clone(),
        }
    }

    /// Whether stored audit history has gaps: a row failed to reach the
    /// store, or the drainer dead-lettered one.
    pub(crate) fn audit_degraded(&self) -> bool {
        self.audit_swallowed.load(Ordering::Relaxed)
            || self.queue_stats().is_some_and(|q| q.dead_lettered_total > 0)
    }

    /// Store a row the drainer refused and return it as stored. A failure
    /// is reported, not returned, and gives the row back as it was.
    pub(crate) fn store_inline(&self, store: &dyn AuditStore, row: crate::Row) -> crate::Row {
        match store_row(store, &row) {
            // Follows the drainer's audit_drain_abandoned.
            Ok(stored) => {
                self.sys_event("info", "audit_drain_stored_inline", serde_json::json!({
                    "row_id": row.id,
                }));
                stored
            }
            Err(e) => {
                self.fallback_failed(&row, e);
                row
            }
        }
    }

    /// Report a queue-mode row submit could not store inline.
    pub(crate) fn fallback_failed(&self, row: &crate::Row, e: Error) {
        self.audit_swallowed.store(true, Ordering::Relaxed);
        // Type only: a store error message can quote row values.
        self.sys_event("error", "audit_sync_fallback_failed", serde_json::json!({
            "error_type": crate::retention::error_type(&e),
            "row_id": row.id,
        }));
    }
}

/// Write an SDK sys event to stderr.
pub(crate) fn sys_line(cfg: Option<&Config>, level: &str, event: &str, fields: serde_json::Value) {
    write_sys(false, cfg, level, event, fields, None);
}

fn redact_map(row: serde_json::Map<String, serde_json::Value>, cfg: Option<&Config>) -> serde_json::Map<String, serde_json::Value> {
    let v = crate::redact_value(
        &serde_json::Value::Object(row),
        cfg.and_then(|c| c.extra_redact_keys.as_deref()),
        cfg.and_then(|c| c.redact_replacement.as_deref()),
    );
    match v {
        serde_json::Value::Object(m) => m,
        _ => serde_json::Map::new(),
    }
}

// The whole line is redacted: a secret can be in any field. With streams,
// a line without a request id gets a sentinel one and the row is kept in
// the sys stream.
fn write_sys(
    stdout: bool,
    cfg: Option<&Config>,
    level: &str,
    event: &str,
    fields: serde_json::Value,
    streams: Option<&Streams>,
) {
    let mut row = serde_json::Map::new();
    row.insert("level".into(), level.into());
    row.insert("event".into(), event.into());
    row.insert("request_id".into(), current_request_id().unwrap_or_default().into());
    row.insert("service_id".into(), cfg.map(|c| c.service_id.as_str()).unwrap_or_default().into());
    row.insert("timestamp".into(), crate::canonical_ts(&Utc::now()).into());
    if let serde_json::Value::Object(extra) = fields {
        for (k, v) in extra { row.insert(k, v); }
    }
    if let Some(s) = streams {
        s.stamp(&mut row);
    }
    let mut row = redact_map(row, cfg);
    if let Some(s) = streams {
        s.sys.push(row.clone());
    }
    row.insert("shape".into(), "sys".into());
    let payload = serde_json::Value::Object(row);
    #[cfg(test)]
    {
        SYS_CAPTURE.lock_or_recover().push(payload.clone());
        if stdout {
            SYS_STDOUT.lock_or_recover().push(payload.clone());
        }
    }
    if stdout {
        println!("{payload}");
    } else {
        // Not eprintln: a closed stderr must not panic the caller, which may
        // be reporting a row it has already stored.
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr().lock(), "{payload}");
    }
}

#[cfg(test)]
thread_local! {
    /// Run by `close` on this thread after it stops the writers and before
    /// it releases the stores opened from DSN variables.
    pub(crate) static BEFORE_RELEASE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) static SYS_CAPTURE: Mutex<Vec<serde_json::Value>> = Mutex::new(Vec::new());
#[cfg(test)]
pub(crate) static SYS_STDOUT: Mutex<Vec<serde_json::Value>> = Mutex::new(Vec::new());
#[cfg(test)]
pub(crate) static API_STDOUT: Mutex<Vec<serde_json::Value>> = Mutex::new(Vec::new());
/// Every audit line written to stdout.
#[cfg(test)]
pub(crate) static AUDIT_STDOUT: Mutex<Vec<serde_json::Value>> = Mutex::new(Vec::new());

/// Services whose audit lines go to a writer that fails, as a closed stdout
/// does.
#[cfg(test)]
static STDOUT_CLOSED: Mutex<Vec<String>> = Mutex::new(Vec::new());

#[cfg(test)]
pub(crate) fn close_stdout_for(service_id: &str) {
    STDOUT_CLOSED.lock_or_recover().push(service_id.to_string());
}

#[cfg(test)]
pub(crate) fn stdout_closed_for(service_id: &str) -> bool {
    STDOUT_CLOSED.lock_or_recover().iter().any(|s| s == service_id)
}

#[cfg(test)]
pub(crate) struct ClosedPipe;

#[cfg(test)]
impl std::io::Write for ClosedPipe {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Default for Engine {
    fn default() -> Self { Self::new() }
}

/// The engine behind the free functions (`init`, `flush`, ...).
pub static DEFAULT: Engine = Engine::new();

#[cfg(test)]
mod tests {
    use super::*;
    use fasten_core::store::Store;

    struct FailStore;
    impl AuditStore for FailStore {
        fn insert(&self, _: &crate::Row) -> Result<(), Error> {
            Err(Error::AuditStoreInsert("down".into()))
        }
    }

    // A failed insert is retried and reported by its type.
    #[test]
    fn adapter_maps_store_errors_to_retryable() {
        crate::register("adapter".into(), [("ADAPTER_EVENT".into(), crate::Meta {
            domain: "adapter".into(),
            ..Default::default()
        })])
        .unwrap();
        let cfg = Config { service_id: "s".into(), node_id: "n".into(), ..Default::default() };
        let row = crate::EmitBuilder::new("ADAPTER_EVENT", "t").build_row(&cfg).unwrap();
        let row = sdk_row_to_core(&row);
        let err = SdkStoreAdapter(Arc::new(FailStore)).insert(&row).unwrap_err();
        assert!(matches!(&err, fasten_core::Error::Store(t) if t == "AuditStoreInsert"), "{err:?}");
    }
}

#[cfg(test)]
mod adapter_tests {
    use super::*;
    use fasten_core::store::Store as _;

    struct Refusing(bool);

    impl AuditStore for Refusing {
        fn insert(&self, _: &crate::Row) -> Result<(), crate::Error> {
            Err(if self.0 {
                crate::Error::AuditStoreRejected("value too long".into())
            } else {
                crate::Error::AuditStoreInsert("down".into())
            })
        }
    }

    /// A store's AuditStoreRejected reaches the drainer as RowRejected, which
    /// it dead-letters at once; any other error is retried.
    #[test]
    fn rejected_reaches_the_drainer_as_row_rejected() {
        let row = fasten_core::Row::default();
        let err = SdkStoreAdapter(Arc::new(Refusing(true))).insert(&row).unwrap_err();
        assert!(matches!(err, fasten_core::Error::RowRejected(ref t) if t == "AuditStoreRejected"), "{err:?}");
        let err = SdkStoreAdapter(Arc::new(Refusing(false))).insert(&row).unwrap_err();
        assert!(matches!(err, fasten_core::Error::Store(ref t) if t == "AuditStoreInsert"), "{err:?}");
    }

    /// A row that could not be sealed is retried, and the drainer's
    /// `last_error` says it was the seal, not the database.
    #[test]
    fn a_seal_failure_reaches_the_drainer_by_its_own_name() {
        struct Unsealable;
        impl AuditStore for Unsealable {
            fn insert(&self, _: &crate::Row) -> Result<(), crate::Error> {
                Err(crate::Error::Seal("random source unavailable".into()))
            }
        }
        let err = SdkStoreAdapter(Arc::new(Unsealable)).insert(&fasten_core::Row::default()).unwrap_err();
        assert!(matches!(err, fasten_core::Error::Store(ref t) if t == "Seal"), "{err:?}");
    }
}
