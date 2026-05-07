//! Engine — wraps all per-deployment runtime state (config, seq, drainer).
//!
//! The module-level free functions (`init`, `flush`, …) in `lib.rs` delegate
//! to [`DEFAULT`]. Applications needing multiple isolated fasten deployments
//! can construct `Engine` instances directly.
//!
//! **Drainer lifetime note**: The `sys_log` callback passed to the drainer
//! requires `'static` bounds. `Engine::init()` satisfies this by capturing
//! `service_id` by value rather than holding a reference to `self`, so the
//! callback remains valid for the drainer thread's lifetime regardless of
//! how the `Engine` instance is stored.

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use chrono::Utc;

use crate::{
    audit_queue::{Drainer, QueueStats},
    current_request_id, AuditStore, Config, Error,
};

/// Type alias for the drainer's sys-log callback, avoiding repetition of the
/// verbose bound across engine and audit_queue call sites.
pub(crate) type SysLogFn = Box<dyn Fn(&str, &str, &serde_json::Value) + Send + Sync>;

/// Drainer tuning parameters, grouped to keep `install_drainer` below
/// clippy's argument-count threshold and to make re-init call sites readable.
pub(crate) struct DrainerConfig {
    pub(crate) capacity: usize,
    pub(crate) retry_initial: Duration,
    pub(crate) retry_max: Duration,
    pub(crate) retry_jitter: bool,
    pub(crate) max_attempts: usize,
}

pub(crate) use self::lock_ext::LockOrRecover;

mod lock_ext {
    use std::sync::{Mutex, MutexGuard};

    /// Acquire a mutex even if it was poisoned by a previous panic.
    ///
    /// A panic in adopter code (store insert, sys-log callback) must not
    /// prevent the drainer or any caller from making progress on every
    /// subsequent operation. Using this pattern instead of `.unwrap()` ensures
    /// poison never propagates out of Mutex::lock.
    pub(crate) trait LockOrRecover<T: ?Sized> {
        fn lock_or_recover(&self) -> MutexGuard<'_, T>;
    }

    impl<T: ?Sized> LockOrRecover<T> for Mutex<T> {
        fn lock_or_recover(&self) -> MutexGuard<'_, T> {
            self.lock().unwrap_or_else(|e| e.into_inner())
        }
    }
}

// ── Engine ───────────────────────────────────────────────────────────────────

pub struct Engine {
    pub(crate) config: Mutex<Option<Config>>,
    pub(crate) seq: AtomicU64,
    pub(crate) drainer: Mutex<Option<Arc<Drainer>>>,
}

impl Engine {
    pub const fn new() -> Self {
        Self {
            config: Mutex::new(None),
            seq: AtomicU64::new(0),
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
        let capacity = cfg.queue_capacity.unwrap_or(100);
        let retry_initial = cfg.queue_retry_initial.unwrap_or(Duration::from_millis(100));
        let retry_max = cfg.queue_retry_max.unwrap_or(Duration::from_secs(60));
        let retry_jitter = !cfg.disable_queue_jitter;
        let max_attempts = cfg.queue_drain_max_attempts.unwrap_or(50);

        // Capture service_id for the drainer sys_log closure. Capturing by
        // value (not &self) satisfies the 'static bound on the callback.
        let svc_id_for_log = cfg.service_id.clone();

        let mut cfg_stored = cfg;
        cfg_stored.audit_store_failure_strategy = Some(strategy.clone());
        *self.config.lock_or_recover() = Some(cfg_stored);

        if strategy == "queue" {
            if let Some(s) = store {
                let sys_log: SysLogFn = Box::new(move |level: &str, event: &str, fields: &serde_json::Value| {
                    Self::emit_sys_stderr(level, event, fields, &svc_id_for_log);
                });
                self.install_drainer(s, sys_log, DrainerConfig {
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
        self.config
            .lock_or_recover()
            .clone()
            .ok_or(Error::NotInitialised)
    }

    pub fn seq_next(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(crate) fn active_drainer(&self) -> Option<Arc<Drainer>> {
        self.drainer.lock_or_recover().clone()
    }

    pub(crate) fn install_drainer(
        &self,
        store: Arc<dyn AuditStore>,
        sys_log: SysLogFn,
        cfg: DrainerConfig,
    ) {
        // Race-safe re-init: build the new drainer FIRST, swap the slot
        // atomically, then flush + shutdown the old one OUTSIDE the lock.
        let new = Drainer::new(store, sys_log, cfg);
        let old = {
            let mut slot = self.drainer.lock_or_recover();
            slot.replace(new)
        };
        if let Some(old) = old {
            old.flush(Duration::from_secs(5));
            old.shutdown(Duration::from_secs(2));
        }
    }

    pub fn uninstall_drainer(&self) {
        let old = {
            let mut slot = self.drainer.lock_or_recover();
            slot.take()
        };
        if let Some(d) = old {
            d.shutdown(Duration::from_secs(2));
        }
    }

    pub fn queue_stats(&self) -> Option<QueueStats> {
        self.active_drainer().map(|d| d.stats())
    }

    pub fn flush(&self, timeout: Duration) -> bool {
        match self.active_drainer() {
            Some(d) => d.flush(timeout),
            None => true,
        }
    }

    /// Reset all runtime state for test isolation.
    ///
    /// Stops the active drainer (best-effort flush), clears config, and resets
    /// the monotonic sequence counter. Mirrors `reset_for_tests()` / `ResetForTests()`
    /// / `resetForTests()` in Python / Go / JS.
    pub fn reset_for_tests(&self) {
        self.uninstall_drainer();
        *self.config.lock_or_recover() = None;
        self.seq.store(0, Ordering::SeqCst);
    }

    /// Structured log line to stdout (shape: sys). Used by the `log` module.
    pub fn log_sys(&self, level: &str, event: &str, fields: serde_json::Value) {
        let service_id = self.current_config()
            .map(|c| c.service_id)
            .unwrap_or_default();
        let mut payload = serde_json::json!({
            "shape": "sys",
            "level": level,
            "event": event,
            "request_id": current_request_id().unwrap_or_default(),
            "service_id": service_id,
            "timestamp": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
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

    /// Write a {shape:sys} line to stderr. Used as the drainer callback;
    /// stderr is mandatory — stdout backpressure would stall the drainer.
    fn emit_sys_stderr(level: &str, event: &str, fields: &serde_json::Value, service_id: &str) {
        let mut payload = serde_json::Map::new();
        payload.insert("shape".into(), serde_json::Value::String("sys".into()));
        payload.insert("level".into(), serde_json::Value::String(level.into()));
        payload.insert("event".into(), serde_json::Value::String(event.into()));
        payload.insert(
            "request_id".into(),
            current_request_id()
                .map(serde_json::Value::String)
                .unwrap_or(serde_json::Value::Null),
        );
        payload.insert("service_id".into(), serde_json::Value::String(service_id.into()));
        payload.insert(
            "timestamp".into(),
            serde_json::Value::String(Utc::now().to_rfc3339()),
        );
        if let serde_json::Value::Object(extras) = fields {
            for (k, v) in extras {
                payload.insert(k.clone(), v.clone());
            }
        }
        eprintln!("{}", serde_json::Value::Object(payload));
    }
}

impl Default for Engine {
    fn default() -> Self { Self::new() }
}

/// The default engine used by all free-function API calls (`init`, `emit`, …).
pub static DEFAULT: Engine = Engine::new();
