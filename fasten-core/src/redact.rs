//! Key-pattern and value-shape redaction (see spec/redact-conformance):
//!   1. Object keys matching `REDACT_PATTERNS` get the replacement token.
//!   2. String values matching a known secret shape get a typed token.
//!   3. Numbers with no fractional part whose digits form a card number
//!      get `***CC***`.
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
    // After a separator and at the end: db_pwd, not PWD or OLDPWD.
    r"[_-]pwd$",
    r"passphrase",
    r"dsn$",
];

#[allow(clippy::expect_used)]
fn build_key_re(extra: &[&str]) -> Regex {
    let mut parts: Vec<&str> = REDACT_PATTERNS.to_vec();
    parts.extend_from_slice(extra);
    let combined = parts.join("|");
    Regex::new(&format!("(?i)({combined})")).expect("key pattern is valid regex")
}

// A run of digit groups split by whitespace (the Unicode White_Space set,
// written out so JS and Swift can match it exactly) or dashes. [0-9], not
// \d: \d matches every Unicode digit, and luhn_valid takes ASCII digits only.
#[allow(clippy::expect_used)]
static DIGIT_RUN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"[0-9]+(?:[\t\n\x0B\x0C\r \x{85}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\-]+[0-9]+)*",
    )
    .expect("digit run regex is valid")
});

fn is_group_sep(c: char) -> bool {
    matches!(c,
        '\t' | '\n' | '\x0B' | '\x0C' | '\r' | ' ' | '\u{85}' | '\u{A0}' | '\u{1680}'
        | '\u{2000}'..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}'
        | '\u{3000}' | '-')
}

/// Whether the card number `digits` starts like one: 3 (Amex, Diners,
/// JCB), 4 (Visa), 5 (Mastercard, Maestro), 6 (Discover, Maestro and
/// others), 2200-2205 (Mir), 2221-2720 (Mastercard), 8100-8299 (India),
/// 8600 (Uzcard), 9704 (Napas), 9792 (Troy), 9860 (Humo), 1946, or 1 with
/// 15 digits (UATP). Other years (19xx, 20xx) and counters do not.
fn card_prefix(digits: &str) -> bool {
    let p = digits.get(..4).and_then(|p| p.parse::<u32>().ok()).unwrap_or(0);
    match digits.as_bytes().first() {
        Some(b'3' | b'4' | b'5' | b'6') => true,
        Some(b'1') => digits.len() == 15 || p == 1946,
        Some(b'2') => (2200..=2205).contains(&p) || (2221..=2720).contains(&p),
        Some(b'8') => (8100..=8299).contains(&p) || p == 8600,
        Some(b'9') => matches!(p, 9704 | 9792 | 9860),
        _ => false,
    }
}

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
/// a card layout, that start with a card prefix and pass the Luhn check.
/// Digits joined to a letter or `_` are part of an id and are skipped. A
/// layout is tried only where it starts or ends its run of digit groups,
/// so a long list of 4-digit values is not read as cards in its middle.
fn has_card(s: &str) -> bool {
    let bytes = s.as_bytes();
    for run in DIGIT_RUN_RE.find_iter(s) {
        let open_start = run.start() == 0 || !is_word_byte(bytes[run.start() - 1]);
        let open_end = run.end() == bytes.len() || !is_word_byte(bytes[run.end()]);
        let groups: Vec<&str> =
            run.as_str().split(is_group_sep).filter(|g| !g.is_empty()).collect();
        for i in 0..groups.len() {
            if i == 0 && !open_start {
                continue;
            }
            let fits_end = |end: usize| end < groups.len() || open_end;
            if (13..=19).contains(&groups[i].len())
                && fits_end(i + 1)
                && card_prefix(groups[i])
                && luhn_valid(groups[i])
            {
                return true;
            }
            for layout in CARD_LAYOUTS {
                let end = i + layout.len();
                if end > groups.len() || !fits_end(end) || (i > 0 && end < groups.len()) {
                    continue;
                }
                if groups[i..end].iter().zip(layout.iter()).all(|(g, &n)| g.len() == n) {
                    let digits = groups[i..end].concat();
                    if card_prefix(&digits) && luhn_valid(&digits) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

// An Authorization header value. Bearer: a credential of 16 or more
// characters that holds a digit or one of + / =, so a sentence that starts
// "Bearer" is not one. Basic: base64 that decodes to UTF-8 text with no
// control characters and a ":" (user:password).
#[allow(clippy::expect_used)]
static BEARER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^A-Za-z0-9_])Bearer[ \t]+([A-Za-z0-9._~+/=\-]{16,})")
        .expect("bearer regex is valid")
});
#[allow(clippy::expect_used)]
static BASIC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^A-Za-z0-9_])Basic[ \t]+([A-Za-z0-9+/]+={0,2})").expect("basic regex is valid")
});

fn has_auth_header(s: &str) -> bool {
    let token = |c: regex::Captures<'_>| c.get(1).map(|m| m.as_str().to_owned());
    BEARER_RE
        .captures_iter(s)
        .filter_map(token)
        .any(|t| t.bytes().any(|b| b.is_ascii_digit() || matches!(b, b'+' | b'/' | b'=')))
        || BASIC_RE.captures_iter(s).filter_map(token).any(|t| is_basic_credential(&t))
}

/// Whether `token` is base64 for `user:password`: its length is a multiple
/// of four, and it decodes to valid UTF-8 with no control characters (C0,
/// DEL or C1) and a ":". With an empty user name (":token", as some access
/// tokens are sent) the password needs 16 or more characters.
fn is_basic_credential(token: &str) -> bool {
    if token.is_empty() || token.len() % 4 != 0 {
        return false;
    }
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut decoded = Vec::with_capacity(token.len() / 4 * 3);
    for b in token.trim_end_matches('=').bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return false,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    let Ok(text) = std::str::from_utf8(&decoded) else {
        return false;
    };
    let user_or_long_password = match text.find(':') {
        Some(0) => text[1..].chars().count() >= 16,
        Some(_) => true,
        None => false,
    };
    user_or_long_password && !text.chars().any(char::is_control)
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
    // OpenAI API key (sk-... legacy and sk-proj-... org format), not part
    // of a longer word such as task-<uuid>; a percent-encoded character
    // before it (%3D, %20) counts as a boundary
    Vp {
        re:   r"(?:^|[^A-Za-z0-9_]|%[0-9A-Fa-f]{2})sk-(?:proj-)?[A-Za-z0-9_\-]{32,}",
        repl: "***OPENAI_KEY***",
    },
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

/// The integer digits of a number with no fractional part: an integer, or
/// a finite float below 1e19 in magnitude such as `4111111111111111.0`.
fn whole_number_digits(n: &serde_json::Number) -> Option<String> {
    if n.is_u64() || n.is_i64() {
        return Some(n.to_string());
    }
    let f = n.as_f64()?;
    (f.is_finite() && f.fract() == 0.0 && f.abs() < 1e19).then(|| format!("{f:.0}"))
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
            // Only the card rule applies to numbers.
            Value::Number(n) if whole_number_digits(n).is_some_and(|d| has_card(&d)) => {
                Value::String("***CC***".to_owned())
            }
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
    fn integer_card_redacted() {
        let out = r().redact_value(&json!({
            "card": 4_111_111_111_111_111_u64,
            "neg": -4_111_111_111_111_111_i64,
            "long": 9_704_000_000_000_000_008_u64,
            "list": [{"n": 4_539_578_763_621_486_u64}],
        }));
        assert_eq!(out["card"], "***CC***");
        assert_eq!(out["neg"], "***CC***");
        assert_eq!(out["long"], "***CC***");
        assert_eq!(out["list"][0]["n"], "***CC***");
    }

    #[test]
    fn number_not_card_kept() {
        let input = json!({
            "count": 42,
            "luhn_fails": 1_234_567_890_123_456_u64,
            "max": u64::MAX,
            "fraction": 4_222_222_222_222.5,
            "large_float": 4.111_111_111_111_111e19,
            "flag": true,
            "none": null,
        });
        assert_eq!(r().redact_value(&input), input);
    }

    #[test]
    fn whole_float_card_redacted() {
        let out = r()
            .redact_json(r#"{"f":4111111111111111.0,"e":4.111111111111111e15,"n":-4111111111111111.0}"#)
            .unwrap();
        let out: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(out, json!({"f": "***CC***", "e": "***CC***", "n": "***CC***"}));
    }

    #[test]
    fn number_card_uses_card_token_with_custom_replacement() {
        let rd = Redactor::new(&[], "[gone]", &[(r"^\d+$", "***NUM***")]);
        let out = rd.redact_value(&json!({"card": 4_111_111_111_111_111_u64, "token": "x", "n": 7}));
        assert_eq!(out, json!({"card": "***CC***", "token": "[gone]", "n": 7}));
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
