//! Catalog YAML loader (P1-11).
//!
//! Optional feature — gated behind the `codes-yaml` cargo feature so
//! adopters who stay on programmatic [`super::register`] never pull
//! `serde_yaml` into their build.
//!
//! ```ignore
//! // in Cargo.toml:
//! // fasten = { version = "1", features = ["codes-yaml"] }
//! fasten::codes::load("fleet.codes.yaml")?;
//! fasten::codes::reload()?;
//! ```
//!
//! Reload semantics match Python / Go / JS:
//! - **Atomic**: parse + validate fully into a fresh map; only swap if
//!   everything succeeds. Concurrent emit() readers see either old or
//!   new, never partial state.
//! - **Fault-tolerant**: any error during reload (parse, invalid
//!   severity, missing field) leaves the previous catalog active and
//!   returns the error.
//! - **NOT additive**: codes removed from the yaml become unknown after
//!   reload. Programmatic `register()` codes are tracked separately and
//!   survive reload.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::Deserialize;

use super::{
    is_upper_snake, registry, Domain, Error, Meta, RetentionClass, Severity,
};

static LOADED_PATHS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
static YAML_CODES: Mutex<Option<HashSet<String>>> = Mutex::new(None);

#[derive(Deserialize)]
struct YamlFile {
    domain: String,
    #[serde(default)]
    emitter: String,
    #[serde(default)]
    codes: HashMap<String, YamlCodeEntry>,
}

#[derive(Deserialize, Default)]
struct YamlCodeEntry {
    #[serde(default)]
    domain: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    emitter: String,
    #[serde(default)]
    retention_class: String,
    #[serde(default)]
    high_volume: bool,
    #[serde(default)]
    pii_in_detail: bool,
}

fn parse_severity(s: &str) -> Result<Severity, Error> {
    Ok(match s {
        "" | "info" => Severity::Info,
        "debug" => Severity::Debug,
        "warn" => Severity::Warn,
        "error" => Severity::Error,
        "critical" => Severity::Critical,
        other => {
            return Err(Error::YamlInvalid(format!(
                "severity={other:?} is not one of {{debug,info,warn,error,critical}}"
            )))
        }
    })
}

fn parse_retention(s: &str) -> Result<RetentionClass, Error> {
    Ok(match s {
        "" | "medium" => RetentionClass::Medium,
        "short" => RetentionClass::Short,
        "long" => RetentionClass::Long,
        other => {
            return Err(Error::YamlInvalid(format!(
                "retention_class={other:?} is not one of {{short,medium,long}}"
            )))
        }
    })
}

fn build_from_paths(paths: &[PathBuf]) -> Result<HashMap<String, Meta>, Error> {
    let mut fresh: HashMap<String, Meta> = HashMap::new();

    for path in paths {
        let text = fs::read_to_string(path)
            .map_err(|e| Error::YamlInvalid(format!("reading {}: {e}", path.display())))?;
        let doc: YamlFile = serde_yaml::from_str(&text)
            .map_err(|e| Error::YamlInvalid(format!("parsing {}: {e}", path.display())))?;

        if doc.domain.is_empty() {
            return Err(Error::YamlInvalid(format!(
                "{} — top-level 'domain' is required",
                path.display()
            )));
        }

        for (code, raw) in doc.codes {
            if !is_upper_snake(&code) {
                return Err(Error::YamlInvalid(format!(
                    "{}:{code} — code key must be UPPER_SNAKE_CASE",
                    path.display()
                )));
            }
            if fresh.contains_key(&code) {
                return Err(Error::YamlInvalid(format!(
                    "{}:{code} — duplicate code in yaml",
                    path.display()
                )));
            }
            let sev = parse_severity(&raw.severity).map_err(|e| {
                Error::YamlInvalid(format!("{}:{code} — {e}", path.display()))
            })?;
            let rc = parse_retention(&raw.retention_class).map_err(|e| {
                Error::YamlInvalid(format!("{}:{code} — {e}", path.display()))
            })?;
            if !raw.domain.is_empty() && raw.domain != doc.domain {
                return Err(Error::YamlInvalid(format!(
                    "{}:{code} — domain={:?} disagrees with file-level domain={:?}",
                    path.display(),
                    raw.domain,
                    doc.domain
                )));
            }
            let emitter = if raw.emitter.is_empty() {
                doc.emitter.clone()
            } else {
                raw.emitter
            };
            let id = code.clone();
            fresh.insert(
                code,
                Meta {
                    id,
                    domain: doc.domain.clone() as Domain,
                    category: raw.category,
                    action: raw.action,
                    severity: sev,
                    description: raw.description,
                    emitter,
                    retention_class: rc,
                    high_volume: raw.high_volume,
                    pii_in_detail: raw.pii_in_detail,
                    declared_unused: false,
                },
            );
        }
    }
    Ok(fresh)
}

/// Initial load of a yaml catalog file. Errors raise loudly (startup, restart-safe).
///
/// Subsequent [`reload`] calls re-read this path along with any other
/// paths previously passed to `load`. Programmatic `register` calls
/// remain in the registry and survive `reload`.
pub fn load(path: impl Into<PathBuf>) -> Result<(), Error> {
    let path = path.into();
    let fresh = build_from_paths(std::slice::from_ref(&path))?;

    let yaml_codes_arc = YAML_CODES.lock().expect("yaml_codes poisoned");
    let mut yaml_codes_guard = yaml_codes_arc;
    let yaml_codes = yaml_codes_guard.get_or_insert_with(HashSet::new);

    {
        let mut reg = registry().write().expect("registry poisoned");
        for code in fresh.keys() {
            if reg.contains_key(code) && !yaml_codes.contains(code) {
                return Err(Error::YamlInvalid(format!(
                    "{}:{code} — duplicate code (already registered programmatically)",
                    path.display()
                )));
            }
        }
        for (code, meta) in fresh {
            reg.insert(code.clone(), meta);
            yaml_codes.insert(code);
        }
    }

    let mut paths = LOADED_PATHS.lock().expect("loaded_paths poisoned");
    if !paths.contains(&path) {
        paths.push(path);
    }
    Ok(())
}

/// Re-read every previously-loaded yaml path and atomically swap the registry.
///
/// Atomic + fault-tolerant: build new registry fully + run all
/// validation; if anything fails the previous catalog stays active.
/// Reload is **NOT additive** — codes removed from the yaml become
/// unknown after the swap. Programmatic `register` codes survive.
pub fn reload() -> Result<(), Error> {
    let paths_snapshot: Vec<PathBuf> = {
        let paths = LOADED_PATHS.lock().expect("loaded_paths poisoned");
        if paths.is_empty() {
            return Ok(());
        }
        paths.clone()
    };

    let fresh = build_from_paths(&paths_snapshot)?;

    let mut yaml_codes_guard = YAML_CODES.lock().expect("yaml_codes poisoned");
    let mut reg = registry().write().expect("registry poisoned");

    let prev_yaml_codes = yaml_codes_guard.take().unwrap_or_default();
    let new_keys: HashSet<String> = fresh.keys().cloned().collect();

    // Drop entries that came from yaml in the previous load.
    reg.retain(|k, _| !prev_yaml_codes.contains(k));
    // Insert fresh yaml-derived entries.
    for (code, meta) in fresh {
        reg.insert(code, meta);
    }

    *yaml_codes_guard = Some(new_keys);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    // Global registry + LOADED_PATHS + YAML_CODES are shared module-level
    // state. Cargo runs tests in parallel by default; serialize this
    // module's tests so they don't trample each other's reset_yaml_state.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn fleet_yaml() -> &'static str {
        "domain: fleet
emitter: edge-manager
codes:
  FLEET_NODE_REGISTERED:
    category: node.lifecycle
    action: registered
    severity: info
    description: Edge node claimed and registered
  FLEET_DEPLOY_FAILED:
    category: deploy
    action: failed
    severity: error
    retention_class: long
    description: Deployment failed on edge node
"
    }

    /// Tiny replacement for the `tempfile` crate (which transitively pulls
    /// a getrandom version requiring Rust 1.85). Builds a unique path
    /// under /tmp using a process-local counter.
    struct TempYaml(PathBuf);

    impl TempYaml {
        fn new(contents: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "fasten-codes-yaml-test-{}-{n}.yaml",
                std::process::id()
            ));
            let mut f = std::fs::File::create(&path).expect("create temp");
            f.write_all(contents.as_bytes()).expect("write temp");
            TempYaml(path)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempYaml {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn write_yaml(contents: &str) -> TempYaml {
        TempYaml::new(contents)
    }

    fn reset_yaml_state() {
        YAML_CODES.lock().unwrap().take();
        LOADED_PATHS.lock().unwrap().clear();
        let mut reg = registry().write().unwrap();
        reg.retain(|k, _| !k.starts_with("FLEET_") && !k.starts_with("EXTRA_"));
    }

    #[test]
    fn load_round_trip() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_yaml_state();
        let f = write_yaml(fleet_yaml());
        load(f.path()).expect("load");

        let m = super::super::meta_of("FLEET_NODE_REGISTERED").unwrap();
        assert_eq!(m.domain, "fleet");
        assert_eq!(m.action, "registered");
        assert_eq!(m.severity, Severity::Info);

        let m2 = super::super::meta_of("FLEET_DEPLOY_FAILED").unwrap();
        assert_eq!(m2.severity, Severity::Error);
        assert_eq!(m2.retention_class, RetentionClass::Long);
    }

    #[test]
    fn load_invalid_severity() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_yaml_state();
        let f = write_yaml(
            "domain: x\ncodes:\n  BAD_CODE:\n    severity: huge\n",
        );
        let err = load(f.path()).unwrap_err();
        match err {
            Error::YamlInvalid(msg) => assert!(msg.contains("severity=\"huge\"")),
            other => panic!("expected YamlInvalid, got {other:?}"),
        }
    }

    #[test]
    fn load_lowercase_key() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_yaml_state();
        let f = write_yaml(
            "domain: x\ncodes:\n  lowercase_bad:\n    severity: info\n",
        );
        let err = load(f.path()).unwrap_err();
        match err {
            Error::YamlInvalid(msg) => assert!(msg.contains("UPPER_SNAKE_CASE")),
            other => panic!("expected YamlInvalid, got {other:?}"),
        }
    }

    #[test]
    fn reload_removes_codes() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_yaml_state();
        let f = write_yaml(fleet_yaml());
        load(f.path()).expect("load");
        assert!(super::super::meta_of("FLEET_DEPLOY_FAILED").is_some());

        // Rewrite with FLEET_DEPLOY_FAILED removed.
        std::fs::write(
            f.path(),
            "domain: fleet\ncodes:\n  FLEET_NODE_REGISTERED:\n    severity: info\n    description: x\n",
        )
        .expect("rewrite");
        reload().expect("reload");

        assert!(super::super::meta_of("FLEET_DEPLOY_FAILED").is_none());
        assert!(super::super::meta_of("FLEET_NODE_REGISTERED").is_some());
    }

    #[test]
    fn reload_fault_tolerant() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_yaml_state();
        let f = write_yaml(fleet_yaml());
        load(f.path()).expect("load");
        let before_size = registry().read().unwrap().len();

        // Corrupt the yaml.
        std::fs::write(
            f.path(),
            "domain: fleet\ncodes:\n  FLEET_NODE_REGISTERED:\n    severity: completely_bogus\n",
        )
        .expect("rewrite");
        assert!(reload().is_err());

        // Live registry untouched.
        assert_eq!(registry().read().unwrap().len(), before_size);
        assert!(super::super::meta_of("FLEET_NODE_REGISTERED").is_some());
        assert!(super::super::meta_of("FLEET_DEPLOY_FAILED").is_some());
    }

    #[test]
    fn reload_preserves_programmatic() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_yaml_state();
        let f = write_yaml(fleet_yaml());
        load(f.path()).expect("load");

        super::super::register(
            "extra".into(),
            [(
                "EXTRA_PROG_CODE".into(),
                Meta {
                    domain: "extra".into(),
                    category: "x".into(),
                    action: "x".into(),
                    severity: Severity::Info,
                    description: "x".into(),
                    emitter: "t".into(),
                    ..Default::default()
                },
            )],
        )
        .expect("register");

        std::fs::write(
            f.path(),
            "domain: fleet\ncodes:\n  FLEET_NODE_REGISTERED:\n    severity: info\n    description: x\n",
        )
        .expect("rewrite");
        reload().expect("reload");

        assert!(super::super::meta_of("EXTRA_PROG_CODE").is_some());
        assert!(super::super::meta_of("FLEET_NODE_REGISTERED").is_some());
        assert!(super::super::meta_of("FLEET_DEPLOY_FAILED").is_none());
    }

    #[test]
    fn reload_no_op_without_load() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_yaml_state();
        reload().expect("reload no-op");
    }
}
