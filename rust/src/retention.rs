//! PII retention: redact expired audit rows (spec §7).
//!
//! Audit rows are never deleted for age. A row whose code may carry personal
//! data has its `detail` destroyed once it passes the PII horizon, and an
//! `AUDIT_ROW_REDACTED` row records each redaction (spec §7.2).

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::{pii_codes, Config, EmitBuilder, Error, Meta, RetentionClass, Severity};

/// A row a PII horizon would redact. `monotonic_seq` travels with the id
/// because the §7.2 record carries `redacted_seq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionCandidate {
    pub id: String,
    pub monotonic_seq: u64,
}

/// fasten's own code for the §7.2 redaction record.
pub const AUDIT_ROW_REDACTED: &str = "AUDIT_ROW_REDACTED";
const REDACTION_DOMAIN: &str = "fasten";

const PURGE_INTERVAL: Duration = Duration::from_secs(3600);

/// Parse a retention duration: `"30d"`, `"24h"`, `"90m"`, `"3600s"`.
/// No compound forms, no zero or negative values.
pub fn parse_duration(s: &str) -> Result<Duration, Error> {
    let bad = |why: &str| Error::InvalidRetention(format!("retention duration {s:?}: {why}"));
    let token = s.trim().to_ascii_lowercase();
    let unit = match token.chars().last() {
        Some('s') => 1u64,
        Some('m') => 60,
        Some('h') => 3600,
        Some('d') => 86_400,
        _ => return Err(bad("unit must be one of s/m/h/d (e.g. \"7d\", \"24h\")")),
    };
    if token.len() < 2 {
        return Err(bad("unit must be one of s/m/h/d (e.g. \"7d\", \"24h\")"));
    }
    let n: i64 = token[..token.len() - 1]
        .parse()
        .map_err(|_| bad("expected an integer before the unit"))?;
    if n <= 0 {
        return Err(bad("must be positive"));
    }
    let secs = (n as u64).checked_mul(unit).ok_or_else(|| bad("too large"))?;
    let d = Duration::from_secs(secs);
    chrono::Duration::from_std(d).map_err(|_| bad("too large"))?;
    Ok(d)
}

fn ensure_redaction_code() -> Result<(), Error> {
    if crate::meta_of(AUDIT_ROW_REDACTED).is_some() {
        return Ok(());
    }
    let meta = Meta {
        domain: REDACTION_DOMAIN.into(),
        category: "retention".into(),
        action: "redact".into(),
        severity: Severity::Warn,
        description: "Audit row detail destroyed under a retention policy".into(),
        emitter: "fasten".into(),
        retention_class: RetentionClass::Long,
        ..Default::default()
    };
    match crate::register(REDACTION_DOMAIN.into(), [(AUDIT_ROW_REDACTED.to_string(), meta)]) {
        // Another thread registered it first.
        Ok(()) | Err(Error::DuplicateCode(_)) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Redact PII rows older than `before` and record each one. Returns the ids
/// redacted. The record is inserted straight into the store, not through the
/// queue, so it is durable before the row's detail is destroyed.
pub(crate) fn redact_expired(
    cfg: &Config,
    before: DateTime<Utc>,
    reason: &str,
) -> Result<Vec<String>, Error> {
    let store = cfg
        .audit_store
        .as_ref()
        .ok_or_else(|| Error::Unsupported("redact_expired: no audit store configured".into()))?;
    let codes = pii_codes();
    if codes.is_empty() {
        return Ok(Vec::new());
    }
    ensure_redaction_code()?;
    let reason = if reason.is_empty() { "retention" } else { reason };
    let mut redacted = Vec::new();
    // One row at a time, record then destroy, so a failed destroy can only
    // repeat the record for that one row.
    for c in store.list_redaction_candidates(before, &codes)? {
        let mut detail = HashMap::new();
        detail.insert("redacted_seq".into(), serde_json::json!(c.monotonic_seq));
        detail.insert("reason".into(), serde_json::json!(reason));
        detail.insert("redacted_id".into(), serde_json::json!(c.id));
        let row = EmitBuilder::new(AUDIT_ROW_REDACTED, c.id.clone())
            .detail(detail)
            .build_row(cfg)?;
        EmitBuilder::write_audit_stdout(&row);
        store.insert(&row)?;
        redacted.extend(store.redact_rows(std::slice::from_ref(&c.id))?);
    }
    Ok(redacted)
}

fn error_type(e: &Error) -> &'static str {
    match e {
        Error::AuditStoreInsert(_) => "AuditStoreInsert",
        Error::Unsupported(_) => "Unsupported",
        Error::Json(_) => "Json",
        _ => "Error",
    }
}

/// Background thread that runs `redact_expired` now and then every hour.
pub(crate) struct Purger {
    stop: Arc<(Mutex<bool>, Condvar)>,
    handle: Option<JoinHandle<()>>,
}

impl Purger {
    pub(crate) fn start(cfg: Config, horizon: Duration) -> Self {
        Self::start_with_interval(cfg, horizon, PURGE_INTERVAL)
    }

    pub(crate) fn start_with_interval(cfg: Config, horizon: Duration, interval: Duration) -> Self {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let flag = Arc::clone(&stop);
        // parse_duration already checked the horizon fits a chrono::Duration.
        let horizon = chrono::Duration::from_std(horizon).unwrap_or(chrono::Duration::MAX);
        let handle = std::thread::Builder::new()
            .name("fasten-retention-audit".into())
            .spawn(move || loop {
                let before = Utc::now()
                    .checked_sub_signed(horizon)
                    .unwrap_or(DateTime::<Utc>::MIN_UTC);
                if let Err(e) = redact_expired(&cfg, before, "retention") {
                    // Type only: a store error message can quote row values.
                    crate::engine::sys_line(
                        &cfg.service_id,
                        "error",
                        "retention_purge_failed",
                        serde_json::json!({
                            "stream": "audit/pii-redaction",
                            "error_type": error_type(&e),
                        }),
                    );
                }
                let (lock, cv) = &*flag;
                let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                let (guard, _) = cv
                    .wait_timeout_while(guard, interval, |stopped| !*stopped)
                    .unwrap_or_else(|e| e.into_inner());
                if *guard {
                    return;
                }
            })
            .ok();
        Self { stop, handle }
    }

    pub(crate) fn stop(mut self) {
        let (lock, cv) = &*self.stop;
        *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
        cv.notify_all();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_accepts_units() {
        assert_eq!(parse_duration("30d").unwrap(), Duration::from_secs(30 * 86_400));
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86_400));
        assert_eq!(parse_duration("90m").unwrap(), Duration::from_secs(5_400));
        assert_eq!(parse_duration("3600s").unwrap(), Duration::from_secs(3_600));
        assert_eq!(parse_duration(" 7D ").unwrap(), Duration::from_secs(7 * 86_400));
    }

    #[test]
    fn parse_duration_rejects_bad_input() {
        for s in ["", "d", "30", "0d", "-1d", "1d12h", "1w", "x5d", "1.5h", "99999999999999999d"] {
            assert!(
                matches!(parse_duration(s), Err(Error::InvalidRetention(_))),
                "{s:?} should be rejected"
            );
        }
    }
}
