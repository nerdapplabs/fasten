//! Audit code catalog — typed metadata + per-domain registration.
//!
//! Mirrors Python `fasten.codes` and Go catalog exactly.
//! `GLOBAL_REGISTRY` is the singleton used by the C ABI.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::Error;

// ── UPPER_SNAKE_CASE key validator ────────────────────────────────────────────

#[allow(clippy::expect_used)]
static CODE_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Z][A-Z0-9_]*$").expect("code key regex is valid"));

// ── Meta ──────────────────────────────────────────────────────────────────────

/// Per-code metadata (wire-schema compatible with the Python SDK).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Meta {
    pub domain:               String,
    pub category:             String,
    pub action:               String,
    pub severity:             String,  // "debug"|"info"|"warn"|"error"|"critical"
    pub description:          String,
    pub emitter:              String,

    #[serde(default)]
    pub id:                   String,  // filled from the dict key by register()

    #[serde(default = "default_retention")]
    pub retention_class:      String,  // "short"|"medium"|"long"

    #[serde(default)]
    pub high_volume:          bool,

    #[serde(default)]
    pub pii_in_detail:        bool,

    #[serde(default)]
    pub declared_unused:      bool,

    #[serde(default)]
    pub detail_passthrough_keys: Vec<String>,
}

fn default_retention() -> String {
    "medium".to_owned()
}

// ── CodeRegistry ──────────────────────────────────────────────────────────────

pub struct CodeRegistry {
    store: HashMap<String, Meta>,
}

impl CodeRegistry {
    pub fn new() -> Self {
        Self { store: HashMap::new() }
    }

    /// Register a batch of codes for `domain`.
    ///
    /// `codes` is a `HashMap<code_key, Meta>`.  Validation mirrors Python:
    ///   - key must match `UPPER_SNAKE_CASE` (`^[A-Z][A-Z0-9_]*$`)
    ///   - `Meta.id` empty → filled from key; set → must match key
    ///   - `Meta.domain` must match `domain`
    ///   - duplicate key across all prior registrations → error
    ///   - `pii_in_detail=true` forces `retention_class="short"`
    pub fn register(&mut self, domain: &str, codes: HashMap<String, Meta>) -> Result<(), Error> {
        for (name, mut meta) in codes {
            if !CODE_KEY_RE.is_match(&name) {
                return Err(Error::InvalidKey(name));
            }

            if meta.id.is_empty() {
                meta.id.clone_from(&name);
            } else if meta.id != name {
                return Err(Error::IdMismatch { key: name, id: meta.id });
            }

            if meta.domain != domain {
                return Err(Error::DomainMismatch {
                    key:        name,
                    declared:   meta.domain,
                    registered: domain.to_owned(),
                });
            }

            if meta.pii_in_detail && meta.retention_class != "short" {
                "short".clone_into(&mut meta.retention_class);
            }

            if self.store.contains_key(&name) {
                return Err(Error::DuplicateCode(name));
            }

            self.store.insert(name, meta);
        }
        Ok(())
    }

    pub fn meta_of(&self, code: &str) -> Option<&Meta> {
        self.store.get(code)
    }

    /// `id,domain,severity` sorted one-per-line — feeds cross-language consistency gate.
    pub fn dump(&self) -> String {
        let mut rows: Vec<(String, String, String)> = self
            .store
            .values()
            .map(|m| (m.id.clone(), m.domain.clone(), m.severity.clone()))
            .collect();
        rows.sort_unstable();
        rows.iter()
            .map(|(i, d, s)| format!("{i},{d},{s}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn all(&self) -> &HashMap<String, Meta> {
        &self.store
    }

    pub fn clear(&mut self) {
        self.store.clear();
    }
}

impl Default for CodeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Global singleton ──────────────────────────────────────────────────────────

pub static GLOBAL_REGISTRY: LazyLock<Mutex<CodeRegistry>> =
    LazyLock::new(|| Mutex::new(CodeRegistry::new()));

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(domain: &str) -> Meta {
        Meta {
            domain:               domain.to_owned(),
            category:             "auth".to_owned(),
            action:               "create".to_owned(),
            severity:             "info".to_owned(),
            description:          "desc".to_owned(),
            emitter:              "svc".to_owned(),
            id:                   String::new(),
            retention_class:      "medium".to_owned(),
            high_volume:          false,
            pii_in_detail:        false,
            declared_unused:      false,
            detail_passthrough_keys: vec![],
        }
    }

    #[test]
    fn register_fills_id_from_key() {
        let mut reg = CodeRegistry::new();
        let mut codes = HashMap::new();
        codes.insert("USER_CREATED".to_owned(), meta("user"));
        reg.register("user", codes).unwrap();
        assert_eq!(reg.meta_of("USER_CREATED").unwrap().id, "USER_CREATED");
    }

    #[test]
    fn register_rejects_lowercase_key() {
        let mut reg = CodeRegistry::new();
        let mut codes = HashMap::new();
        codes.insert("user_created".to_owned(), meta("user"));
        assert!(matches!(reg.register("user", codes), Err(Error::InvalidKey(_))));
    }

    #[test]
    fn register_rejects_id_mismatch() {
        let mut reg = CodeRegistry::new();
        let mut codes = HashMap::new();
        let mut m = meta("user");
        m.id = "WRONG_ID".to_owned();
        codes.insert("USER_CREATED".to_owned(), m);
        assert!(matches!(reg.register("user", codes), Err(Error::IdMismatch { .. })));
    }

    #[test]
    fn register_rejects_domain_mismatch() {
        let mut reg = CodeRegistry::new();
        let mut codes = HashMap::new();
        codes.insert("ORDER_PLACED".to_owned(), meta("billing"));
        assert!(matches!(
            reg.register("order", codes),
            Err(Error::DomainMismatch { .. })
        ));
    }

    #[test]
    fn register_rejects_duplicate() {
        let mut reg = CodeRegistry::new();
        let mut codes = HashMap::new();
        codes.insert("USER_CREATED".to_owned(), meta("user"));
        reg.register("user", codes).unwrap();
        let mut codes2 = HashMap::new();
        codes2.insert("USER_CREATED".to_owned(), meta("user"));
        assert!(matches!(reg.register("user", codes2), Err(Error::DuplicateCode(_))));
    }

    #[test]
    fn pii_forces_short_retention() {
        let mut reg = CodeRegistry::new();
        let mut m = meta("user");
        m.pii_in_detail = true;
        m.retention_class = "long".to_owned();
        let mut codes = HashMap::new();
        codes.insert("USER_PII".to_owned(), m);
        reg.register("user", codes).unwrap();
        assert_eq!(reg.meta_of("USER_PII").unwrap().retention_class, "short");
    }

    #[test]
    fn dump_sorted_csv() {
        let mut reg = CodeRegistry::new();
        let mut codes = HashMap::new();
        codes.insert("B_EVENT".to_owned(), {
            let mut m = meta("svc");
            m.severity = "warn".to_owned();
            m
        });
        codes.insert("A_EVENT".to_owned(), meta("svc"));
        reg.register("svc", codes).unwrap();
        let out = reg.dump();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "A_EVENT,svc,info");
        assert_eq!(lines[1], "B_EVENT,svc,warn");
    }

    #[test]
    fn clear_empties_registry() {
        let mut reg = CodeRegistry::new();
        let mut codes = HashMap::new();
        codes.insert("X_EVENT".to_owned(), meta("x"));
        reg.register("x", codes).unwrap();
        reg.clear();
        assert!(reg.meta_of("X_EVENT").is_none());
    }
}
