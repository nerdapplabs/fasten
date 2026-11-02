//! Load audit codes from yaml files. Behind the `codes-yaml` feature, so
//! users of [`super::register`] alone don't build `serde_yaml`.
//!
//! ```ignore
//! // in Cargo.toml:
//! // fasten = { version = "1", features = ["codes-yaml"] }
//! fasten::codes::load("fleet.codes.yaml")?;
//! fasten::codes::reload()?;
//! ```
//!
//! `reload()` re-reads every loaded file and validates it before swapping
//! the catalog under the registry write lock, so readers see the old or the
//! new catalog, never a mix. On error the old catalog stays. Codes removed
//! from the yaml are dropped; codes added with `register()` are kept.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::Deserialize;

use super::{
    registry, Domain, Error, Meta, RetentionClass, Severity,
};

fn is_upper_snake(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_uppercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

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
                "{}: top-level 'domain' is required",
                path.display()
            )));
        }

        for (code, raw) in doc.codes {
            if !is_upper_snake(&code) {
                return Err(Error::YamlInvalid(format!(
                    "{}:{code}: code key must be UPPER_SNAKE_CASE",
                    path.display()
                )));
            }
            if fresh.contains_key(&code) {
                return Err(Error::YamlInvalid(format!(
                    "{}:{code}: duplicate code in yaml",
                    path.display()
                )));
            }
            let sev = parse_severity(&raw.severity).map_err(|e| {
                Error::YamlInvalid(format!("{}:{code}: {e}", path.display()))
            })?;
            let rc = parse_retention(&raw.retention_class).map_err(|e| {
                Error::YamlInvalid(format!("{}:{code}: {e}", path.display()))
            })?;
            if !raw.domain.is_empty() && raw.domain != doc.domain {
                return Err(Error::YamlInvalid(format!(
                    "{}:{code}: domain={:?} disagrees with file-level domain={:?}",
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
                    detail_passthrough_keys: Vec::new(),
                    declared_unused: false,
                },
            );
        }
    }
    Ok(fresh)
}

/// Load a yaml catalog file and add its codes to the registry.
///
/// [`reload`] re-reads every path passed to `load`. A yaml code can't
/// replace one added with `register()`.
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
                    "{}:{code}: duplicate code (already registered programmatically)",
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

/// Re-read every loaded yaml file and swap the yaml codes in one step.
///
/// On error the previous catalog stays. Codes removed from the yaml are
/// dropped; codes added with `register()` are kept.
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

    // The registry, LOADED_PATHS and YAML_CODES are global, so these tests
    // run one at a time.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn fleet_yaml() -> &'static str {
        "domain: fleet
emitter: fleet-service
codes:
  FLEET_NODE_REGISTERED:
    category: node.lifecycle
    action: registered
    severity: info
    description: Node claimed and registered
  FLEET_DEPLOY_FAILED:
    category: deploy
    action: failed
    severity: error
    retention_class: long
    description: Deployment failed on node
"
    }

    /// Temp file removed on drop, so the tests need no `tempfile` dependency.
    /// The name is unique per process and call.
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
