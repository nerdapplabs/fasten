//! Secret-key and value-shape redaction — canonical implementation.
//!
//! Two-pass algorithm (identical to spec/redact-conformance):
//!   1. Key-pattern — dict keys matching REDACT_PATTERNS → replacement token.
//!   2. Value-shape — string values matching known secret shapes → typed token.
//!
//! `REDACTOR` is the global default instance used by the C ABI.
//! `Redactor::new(extra_keys, replacement)` produces a custom instance
//! (used by SDK adapters that call `fasten.init(extra_redact_keys=[...])`)
//!
//! `REDACT_PATTERNS` lists the default key-pattern strings.

use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

use crate::error::Error;

// ── Key-pattern list (mirrors spec/row-schema.json codegen) ─────────────────

pub const DEFAULT_REPLACEMENT: &str = "***";

static REDACT_PATTERNS: &[&str] = &[
    r"api[_-]?key",
    r"password",
    r"passwd",
    r"token",
    r"secret",
    r"authorization",
    r"bearer",
    r"m2m[_-]?key",
    r"cert[_-]?private",
    r"private[_-]?key",
    r"access_key",
    r"session_id",
    r"cookie",
    r"credential",
];

#[allow(clippy::expect_used)]
fn build_key_re(extra: &[&str]) -> Regex {
    let mut parts: Vec<&str> = REDACT_PATTERNS.to_vec();
    parts.extend_from_slice(extra);
    let combined = parts.join("|");
    Regex::new(&format!("(?i)({combined})")).expect("key pattern is valid regex")
}

// ── Value-shape patterns ──────────────────────────────────────────────────────

// CC: 13–19 digit groups with optional space/dash separators.
#[allow(clippy::expect_used)]
static CC_DIGIT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\d[\d\s\-]{11,17}\d\b").expect("CC regex is valid")
});

struct Vp {
    re:   &'static str,
    repl: &'static str,
}

static VALUE_SPECS: &[Vp] = &[
    // JWT: three base64url segments starting with eyJ (standard header + payload)
    Vp { re: r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", repl: "***JWT***" },
    // PEM private key block header
    Vp { re: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----", repl: "***PRIVATE_KEY***" },
    // AWS access key (permanent AKIA or short-lived ASIA)
    Vp { re: r"(?:AKIA|ASIA)[A-Z0-9]{16}", repl: "***AWS_KEY***" },
    // GitHub personal / OAuth / actions token
    Vp { re: r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}", repl: "***GH_TOKEN***" },
    // Stripe live secret key
    Vp { re: r"sk_live_[A-Za-z0-9]{24,}", repl: "***STRIPE_KEY***" },
    // OpenAI API key (sk-... legacy and sk-proj-... org format)
    Vp { re: r"sk-(?:proj-)?[A-Za-z0-9_\-]{32,}", repl: "***OPENAI_KEY***" },
];

struct CompiledVp {
    re:   Regex,
    repl: &'static str,
}

#[allow(clippy::expect_used)]
static VALUE_PATTERNS: LazyLock<Vec<CompiledVp>> = LazyLock::new(|| {
    VALUE_SPECS
        .iter()
        .map(|vp| CompiledVp {
            re:   Regex::new(vp.re).expect("value pattern is valid"),
            repl: vp.repl,
        })
        .collect()
});

// ── Luhn ────────────────────────────────────────────────────────────────────

fn luhn_valid(digits: &str) -> bool {
    let bytes = digits.as_bytes();
    let len = bytes.len();
    let mut total: u32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let mut n = u32::from(b - b'0');
        if (len - 1 - i) % 2 == 1 {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        total += n;
    }
    total % 10 == 0
}

// ── Redactor ─────────────────────────────────────────────────────────────────

pub struct Redactor {
    key_re:      Regex,
    replacement: String,
    /// Custom value patterns appended after the built-in defaults.
    custom_vp:   Vec<(Regex, String)>,
}

impl Default for Redactor {
    fn default() -> Self {
        Self {
            key_re:      build_key_re(&[]),
            replacement: DEFAULT_REPLACEMENT.to_owned(),
            custom_vp:   vec![],
        }
    }
}

impl Redactor {
    /// Custom instance.
    ///
    /// `extra_keys` — plain strings (not regexes); they are regex-escaped.
    /// `replacement` — defaults to `"***"` when empty.
    /// `extra_value_patterns` — `(pattern_str, replacement_token)` pairs appended
    ///   after the built-in value-shape patterns. First match wins.
    #[allow(clippy::expect_used)]
    pub fn new(
        extra_keys:             &[&str],
        replacement:            &str,
        extra_value_patterns:   &[(&str, &str)],
    ) -> Self {
        let escaped: Vec<String> = extra_keys.iter().map(|k| regex::escape(k)).collect();
        let extra_refs: Vec<&str> = escaped.iter().map(String::as_str).collect();
        let custom_vp = extra_value_patterns
            .iter()
            .map(|(pat, repl)| {
                let re = Regex::new(pat).expect("extra_value_pattern is a valid regex");
                (re, (*repl).to_owned())
            })
            .collect();
        Self {
            key_re:      build_key_re(&extra_refs),
            replacement: if replacement.is_empty() {
                DEFAULT_REPLACEMENT.to_owned()
            } else {
                replacement.to_owned()
            },
            custom_vp,
        }
    }

    fn check_value(&self, s: &str) -> Option<String> {
        // CC check: Luhn guard prevents order-number false positives.
        if let Some(m) = CC_DIGIT_RE.find(s) {
            let digits: String = m.as_str().chars().filter(char::is_ascii_digit).collect();
            if (13..=19).contains(&digits.len()) && luhn_valid(&digits) {
                return Some("***CC***".to_owned());
            }
        }
        for vp in VALUE_PATTERNS.iter() {
            if vp.re.is_match(s) {
                return Some(vp.repl.to_owned());
            }
        }
        for (re, repl) in &self.custom_vp {
            if re.is_match(s) {
                return Some(repl.clone());
            }
        }
        None
    }

    pub fn redact_value(&self, value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut out = serde_json::Map::with_capacity(map.len());
                for (k, v) in map {
                    if self.key_re.is_match(k) {
                        out.insert(k.clone(), Value::String(self.replacement.clone()));
                    } else {
                        out.insert(k.clone(), self.redact_value(v));
                    }
                }
                Value::Object(out)
            }
            Value::Array(arr) => {
                Value::Array(arr.iter().map(|v| self.redact_value(v)).collect())
            }
            Value::String(s) => self
                .check_value(s)
                .map_or_else(|| value.clone(), Value::String),
            _ => value.clone(),
        }
    }

    pub fn redact_json(&self, input: &str) -> Result<String, Error> {
        let v: Value = serde_json::from_str(input)?;
        let out = self.redact_value(&v);
        serde_json::to_string(&out).map_err(Error::Json)
    }
}

// ── Global default ────────────────────────────────────────────────────────────

pub static REDACTOR: LazyLock<Redactor> = LazyLock::new(Redactor::default);

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn r() -> Redactor {
        Redactor::default()
    }

    #[test]
    fn key_password_redacted() {
        let out = r().redact_value(&json!({"password": "s3cr3t"}));
        assert_eq!(out["password"], "***");
    }

    #[test]
    fn key_api_key_variants() {
        let out = r().redact_value(&json!({"api_key": "a", "API-KEY": "b", "apikey": "c"}));
        assert_eq!(out["api_key"], "***");
        assert_eq!(out["API-KEY"], "***");
        assert_eq!(out["apikey"], "***");
    }

    #[test]
    fn key_token_redacted() {
        let out = r().redact_value(&json!({"token": "tok123", "name": "Alice"}));
        assert_eq!(out["token"], "***");
        assert_eq!(out["name"], "Alice");
    }

    #[test]
    fn value_jwt_redacted() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123";
        let out = r().redact_value(&json!({"tok": jwt}));
        assert_eq!(out["tok"], "***JWT***");
    }

    #[test]
    fn value_aws_key_redacted() {
        let out = r().redact_value(&json!({"info": "key=AKIAIOSFODNN7EXAMPLE"}));
        assert_eq!(out["info"], "***AWS_KEY***");
    }

    #[test]
    fn value_gh_token_redacted() {
        let tok = format!("ghp_{}", "A".repeat(36));
        let out = r().redact_value(&json!({"info": tok}));
        assert_eq!(out["info"], "***GH_TOKEN***");
    }

    #[test]
    fn value_stripe_key_redacted() {
        let key = format!("sk_live_{}", "A".repeat(24));
        let out = r().redact_value(&json!({"ref": key}));
        assert_eq!(out["ref"], "***STRIPE_KEY***");
    }

    #[test]
    fn value_openai_key_redacted() {
        let key = format!("sk-{}", "A".repeat(32));
        let out = r().redact_value(&json!({"ref": key}));
        assert_eq!(out["ref"], "***OPENAI_KEY***");
    }

    #[test]
    fn value_cc_luhn_redacted() {
        // Visa test number 4539578763621486 — passes Luhn.
        let out = r().redact_value(&json!({"card": "4539578763621486"}));
        assert_eq!(out["card"], "***CC***");
    }

    #[test]
    fn non_luhn_digits_pass_through() {
        // 1234567890123456 fails Luhn (sum % 10 == 4).
        let out = r().redact_value(&json!({"order_id": "1234567890123456"}));
        assert_eq!(out["order_id"], "1234567890123456");
    }

    #[test]
    fn nested_dict_redacted() {
        let out = r().redact_value(&json!({"user": {"password": "abc", "name": "Alice"}}));
        assert_eq!(out["user"]["password"], "***");
        assert_eq!(out["user"]["name"], "Alice");
    }

    #[test]
    fn array_values_redacted() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123";
        let out = r().redact_value(&json!([jwt, "hello"]));
        assert_eq!(out[0], "***JWT***");
        assert_eq!(out[1], "hello");
    }

    #[test]
    fn json_roundtrip() {
        let input = r#"{"password":"s3cr3t","name":"Alice"}"#;
        let out = REDACTOR.redact_json(input).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["password"], "***");
        assert_eq!(v["name"], "Alice");
    }

    #[test]
    fn extra_keys_custom_redactor() {
        let r = Redactor::new(&["my_secret_field"], "REDACTED", &[]);
        let out = r.redact_value(&json!({"my_secret_field": "val", "name": "Bob"}));
        assert_eq!(out["my_secret_field"], "REDACTED");
        assert_eq!(out["name"], "Bob");
    }

    #[test]
    fn extra_value_patterns_applied() {
        let r = Redactor::new(&[], "", &[("custom_[A-Z]{8}", "***CUSTOM***")]);
        let out = r.redact_value(&json!({"ref": "custom_ABCDEFGH"}));
        assert_eq!(out["ref"], "***CUSTOM***");
    }

    #[test]
    fn luhn_valid_visa() {
        assert!(luhn_valid("4539578763621486"));
    }

    #[test]
    fn luhn_invalid() {
        assert!(!luhn_valid("4539578763621487"));
    }
}
