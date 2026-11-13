//! Key-pattern and value-shape redaction (see spec/redact-conformance):
//!   1. Object keys matching `REDACT_PATTERNS` get the replacement token.
//!   2. String values matching a known secret shape get a typed token.
//!
//! `REDACTOR` is the default instance used by the C ABI. `Redactor::new`
//! builds one with extra keys, a custom replacement and extra value patterns.

use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

use crate::error::Error;

// Keep in sync with x-fasten-redact.patterns in spec/row-schema.json.

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
    r"access[_-]?key",
    r"session[_-]?id",
    r"cookie",
    r"credential",
    r"pwd",
    r"passphrase",
    r"dsn$",
    // Whole key only: as substrings they would match primary_key or author.
    r"^key$",
    r"^auth$",
];

#[allow(clippy::expect_used)]
fn build_key_re(extra: &[&str]) -> Regex {
    let mut parts: Vec<&str> = REDACT_PATTERNS.to_vec();
    parts.extend_from_slice(extra);
    let combined = parts.join("|");
    Regex::new(&format!("(?i)({combined})")).expect("key pattern is valid regex")
}

// A run of digit groups split by spaces or dashes. [0-9], not \d: \d matches
// every Unicode digit, and luhn_valid takes ASCII digits only.
#[allow(clippy::expect_used)]
static DIGIT_RUN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[0-9]+(?:[ \-]+[0-9]+)*").expect("digit run regex is valid"));

// Card number layouts printed in groups: 4-4-4-4 with an optional short
// tail, and the 4-6-5 / 4-6-4 layouts. An unbroken group of 13 to 19 digits
// is checked as well.
const CARD_LAYOUTS: &[&[usize]] = &[
    &[4, 4, 4, 4],
    &[4, 4, 4, 4, 1],
    &[4, 4, 4, 4, 2],
    &[4, 4, 4, 4, 3],
    &[4, 6, 5],
    &[4, 6, 4],
];

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Whether `s` holds a card number: a group of 13 to 19 digits, or groups in
/// a card layout, that pass the Luhn check. Digits joined to a letter or `_`
/// are part of an id and are skipped. A grouped layout next to another group
/// of four digits is skipped too, so a list of years or counts is not a card.
fn has_card(s: &str) -> bool {
    let bytes = s.as_bytes();
    for run in DIGIT_RUN_RE.find_iter(s) {
        let open_start = run.start() == 0 || !is_word_byte(bytes[run.start() - 1]);
        let open_end = run.end() == bytes.len() || !is_word_byte(bytes[run.end()]);
        let groups: Vec<&str> = run.as_str().split([' ', '-']).filter(|g| !g.is_empty()).collect();
        for i in 0..groups.len() {
            if i == 0 && !open_start {
                continue;
            }
            let fits_end = |end: usize| end < groups.len() || open_end;
            if (13..=19).contains(&groups[i].len()) && fits_end(i + 1) && luhn_valid(groups[i]) {
                return true;
            }
            for layout in CARD_LAYOUTS {
                let end = i + layout.len();
                if end > groups.len() || !fits_end(end) {
                    continue;
                }
                if (i > 0 && groups[i - 1].len() == 4) || (end < groups.len() && groups[end].len() == 4) {
                    continue;
                }
                if groups[i..end].iter().zip(layout.iter()).all(|(g, &n)| g.len() == n)
                    && luhn_valid(&groups[i..end].concat())
                {
                    return true;
                }
            }
        }
    }
    false
}

// An Authorization header value: Bearer or Basic, then a credential that
// holds a digit or one of + / =, so a sentence that starts "Basic" is not one.
#[allow(clippy::expect_used)]
static AUTH_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^A-Za-z0-9_])(?:Bearer|Basic)[ \t]+([A-Za-z0-9._~+/=\-]{16,})")
        .expect("auth header regex is valid")
});

fn has_auth_header(s: &str) -> bool {
    AUTH_HEADER_RE.captures_iter(s).any(|c| {
        c.get(1)
            .is_some_and(|m| m.as_str().bytes().any(|b| b.is_ascii_digit() || matches!(b, b'+' | b'/' | b'=')))
    })
}

struct Vp {
    re:   &'static str,
    repl: &'static str,
}

static VALUE_SPECS: &[Vp] = &[
    // JWT: three base64url segments starting with eyJ (standard header + payload)
    Vp { re: r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", repl: "***JWT***" },
    // PEM private key block header, encrypted or not
    Vp { re: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |)PRIVATE KEY-----", repl: "***PRIVATE_KEY***" },
    // AWS access key (permanent AKIA or short-lived ASIA)
    Vp { re: r"(?:AKIA|ASIA)[A-Z0-9]{16}", repl: "***AWS_KEY***" },
    // GitHub personal / OAuth / actions token
    Vp { re: r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}", repl: "***GH_TOKEN***" },
    // Stripe live secret key
    Vp { re: r"sk_live_[A-Za-z0-9]{24,}", repl: "***STRIPE_KEY***" },
    // OpenAI API key (sk-... legacy and sk-proj-... org format)
    Vp { re: r"sk-(?:proj-)?[A-Za-z0-9_\-]{32,}", repl: "***OPENAI_KEY***" },
    // GitHub fine-grained personal access token
    Vp { re: r"github_pat_[A-Za-z0-9_]{22,}", repl: "***GH_TOKEN***" },
    // Slack token
    Vp { re: r"xox[abposr]-[A-Za-z0-9\-]{10,}", repl: "***SLACK_TOKEN***" },
    // Credentials in a URL: scheme://user:password@, user may be empty
    Vp { re: r"[A-Za-z0-9+.\-]+://[^\t\n\x0B\x0C\r /:@?#]*:[^\t\n\x0B\x0C\r /@?#]+@", repl: "***URL_CREDENTIALS***" },
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
    /// `extra_keys`: plain strings, not regexes; they are escaped.
    /// `replacement`: defaults to `"***"` when empty.
    /// `extra_value_patterns`: `(pattern, replacement_token)` pairs checked
    ///   after the built-in value shapes. First match wins.
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
        // The Luhn check keeps order numbers and similar ids from matching.
        if has_card(s) {
            return Some("***CC***".to_owned());
        }
        for vp in VALUE_PATTERNS.iter() {
            if vp.re.is_match(s) {
                return Some(vp.repl.to_owned());
            }
        }
        if has_auth_header(s) {
            return Some("***AUTH_HEADER***".to_owned());
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

pub static REDACTOR: LazyLock<Redactor> = LazyLock::new(Redactor::default);

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
        // Visa test number; passes Luhn.
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

    // Non-ASCII digits are not card digits, and must not reach luhn_valid.
    #[test]
    fn non_ascii_digits_are_not_a_card() {
        let arabic_indic = "\u{0664}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\
                            \u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}\u{0661}";
        let out = Redactor::default().redact_value(&json!({"note": arabic_indic}));
        assert_eq!(out["note"], arabic_indic);
    }
}
