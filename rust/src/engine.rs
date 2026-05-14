//! Engine — wraps all per-deployment runtime state (config, seq, drainer).
//!
//! The module-level free functions (`init`, `flush`, …) in `lib.rs` delegate
//! to [`DEFAULT`]. Applications needing multiple isolated fasten deployments
//! can construct `Engine` instances directly.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use chrono::{SecondsFormat, Utc};

use fasten_core::drainer::{Drainer, DrainerConfig};

use crate::{current_request_id, AuditStore, Config, Error};

// ── Poison-recovery helper ────────────────────────────────────────────────────

trait LockOrRecover<T: ?Sized> {
    fn lock_or_recover(&self) -> std::sync::MutexGuard<'_, T>;
}
impl<T: ?Sized> LockOrRecover<T> for Mutex<T> {
    fn lock_or_recover(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|e| e.into_inner())
    }
}

// ── Row conversion: SDK Row ↔ fasten_core::Row ────────────────────────────────

pub(crate) fn sdk_row_to_core(r: &crate::Row) -> fasten_core::Row {
    fasten_core::Row {
        wire_version:   r.wire_version.clone(),
        id:             r.id.clone(),
        origin_id:      r.origin_id.clone(),
        monotonic_seq:  r.monotonic_seq,
        timestamp:      r.timestamp.to_rfc3339_opts(SecondsFormat::Millis, true),
        code:           r.code.clone(),
        action:         r.action.clone(),
        severity:       r.severity.to_string(), // Display impl → lowercase
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
        shipped_at:     r.shipped_at
            .map(|dt| dt.to_rfc3339_opts(SecondsFormat::Millis, true)),
        ..Default::default()
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
        shipped_at:     r.shipped_at.as_deref().and_then(|s| s.parse().ok()),
    }
}

// ── SdkStoreAdapter: bridges Arc<dyn AuditStore> → fasten_core::Store ─────────

struct SdkStoreAdapter(Arc<dyn AuditStore>);

impl fasten_core::store::Store for SdkStoreAdapter {
    fn insert(&self, row: &fasten_core::Row) -> Result<(), fasten_core::Error> {
        let sdk_row = core_to_sdk_row(row);
        self.0.insert(&sdk_row)
            .map_err(|e| fasten_core::Error::InvalidTableName(e.to_string()))
    }
    fn ping(&self) -> Result<(), fasten_core::Error> { Ok(()) }
    fn query(&self, _: &fasten_core::store::Filter)
        -> Result<Vec<fasten_core::Row>, fasten_core::Error> { Ok(vec![]) }
    fn count(&self, _: &fasten_core::store::Filter)
        -> Result<u64, fasten_core::Error> { Ok(0) }
    fn list_unshipped(&self, _: u32)
        -> Result<Vec<fasten_core::Row>, fasten_core::Error> { Ok(vec![]) }
    fn mark_shipped(&self, _: &[String]) -> Result<(), fasten_core::Error> { Ok(()) }
    fn purge(&self, _: &str, _: bool) -> Result<u64, fasten_core::Error> { Ok(0) }
    fn max_monotonic_seq(&self) -> Result<u64, fasten_core::Error> { Ok(0) }
}

// ── Engine ���───────────────────────────────────────────────────────────────────

pub struct Engine {
    pub(crate) config:  Mutex<Option<Config>>,
    pub(crate) seq:     AtomicU64,
    pub(crate) drainer: Mutex<Option<Arc<Drainer>>>,
}

impl Engine {
    pub const fn new() -> Self {
        Self {
            config:  Mutex::new(None),
            seq:     AtomicU64::new(0),
            drainer: Mutex::new(None),
        }
    }

    pub fn init(&self, cfg: Config) -> Result<(), Error> {
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

        let store = cfg.audit_store.clone();
        let capacity     = cfg.queue_capacity.unwrap_or(100);
        let retry_initial = cfg.queue_retry_initial.unwrap_or(Duration::from_millis(100));
        let retry_max     = cfg.queue_retry_max.unwrap_or(Duration::from_secs(60));
        let retry_jitter  = !cfg.disable_queue_jitter;
        let max_attempts  = cfg.queue_drain_max_attempts.unwrap_or(50);

        let mut cfg_stored = cfg;
        cfg_stored.audit_store_failure_strategy = Some(strategy.clone());
        *self.config.lock_or_recover() = Some(cfg_stored);

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
        Ok(())
    }

    pub fn current_config(&self) -> Result<Config, Error> {
        self.config.lock_or_recover().clone().ok_or(Error::NotInitialised)
    }

    pub fn seq_next(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(crate) fn active_drainer(&self) -> Option<Arc<Drainer>> {
        self.drainer.lock_or_recover().clone()
    }

    pub(crate) fn install_drainer(&self, store: Arc<dyn AuditStore>, cfg: DrainerConfig) {
        let new = Drainer::new(Box::new(SdkStoreAdapter(store)), cfg);
        let old = { let mut slot = self.drainer.lock_or_recover(); slot.replace(new) };
        if let Some(old) = old {
            old.flush(Duration::from_secs(5));
            old.stop(Duration::from_secs(2));
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

    pub fn flush(&self, timeout: Duration) -> bool {
        match self.active_drainer() {
            Some(d) => d.flush(timeout),
            None    => true,
        }
    }

    pub fn reset_for_tests(&self) {
        self.uninstall_drainer();
        *self.config.lock_or_recover() = None;
        self.seq.store(0, Ordering::SeqCst);
    }

    pub fn log_sys(&self, level: &str, event: &str, fields: serde_json::Value) {
        let service_id = self.current_config().map(|c| c.service_id).unwrap_or_default();
        let mut payload = serde_json::json!({
            "shape": "sys",
            "level": level,
            "event": event,
            "request_id": current_request_id().unwrap_or_default(),
            "service_id": service_id,
            "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        });
        if let serde_json::Value::Object(merge_into) = &mut payload {
            if let serde_json::Value::Object(extra) = fields {
                for (k, v) in extra { merge_into.insert(k, v); }
            }
        }
        println!("{payload}");
    }
}

impl Default for Engine {
    fn default() -> Self { Self::new() }
}

/// The default engine used by all free-function API calls (`init`, `emit`, …).
pub static DEFAULT: Engine = Engine::new();
