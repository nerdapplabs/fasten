//! Row hashing, sealing and chain verification (spec/chain-replication.md).
//!
//! A row hash is the SHA-256 of the row's canonical JSON, which is what
//! Python writes for
//!
//! ```text
//! json.dumps(d, sort_keys=True, separators=(',', ':'), default=str)
//! ```
//!
//! over the row's hashed fields. Each row records the form it was sealed with
//! in `canonical_form_id`:
//!
//! - Form "1" hashes `detail` directly, with the timestamp in
//!   `datetime.isoformat()` form (`+00:00`).
//! - Form "2" (current) hashes `detail_commitment` instead of `detail`, and
//!   the timestamp as written on the wire.
//!
//! `shipped_at` is hashed as null and `pii_in_detail` is never hashed.
//!
//! Numbers are hashed from their JSON tokens, so [`Json`] keeps each number
//! as the text it was written with: `75.0` stays `75.0` and a long integer
//! keeps every digit. Strings are held as Python holds them, so an unpaired
//! surrogate (`"\udcff"`) is kept and hashed as its escape.

use std::borrow::Borrow;
use std::collections::{BTreeMap, HashMap};
use std::fmt::{self, Write as _};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::checkpoint::{checkpoint_break, Checkpoint, CheckpointOptions};
use crate::row::Row;

/// Form stamped by [`seal`]. Form "1" rows still verify.
pub const CURRENT_CANONICAL_FORM_ID: &str = "2";

/// `prev_hash` of a node's first sealed row.
pub const GENESIS: &str = "genesis";

/// Nesting allowed in parsed JSON, the same as `serde_json`'s limit.
const MAX_DEPTH: usize = 128;

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainError {
    /// The text is not JSON. `at` is the byte offset of the problem.
    #[error("json at byte {at}: {what}")]
    Json { at: usize, what: &'static str },

    /// A row field is missing or has the wrong type.
    #[error("row field {0:?}: {1}")]
    Field(&'static str, &'static str),

    /// The system random source failed, so no detail salt could be made.
    #[error("random source unavailable: {0}")]
    Random(String),
}

/// A JSON string as Python's `str` holds it: a sequence of code points that
/// may include unpaired surrogates, which `json.loads` keeps from a
/// `"\udcff"` escape. Ordered by code point, the order Python sorts keys in.
///
/// Held as generalized UTF-8: the UTF-8 of the text, with an unpaired
/// surrogate as the three bytes UTF-8 would give that code point. Byte order
/// is then code point order.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct JsonString(Vec<u8>);

impl JsonString {
    /// The text, or `None` when it holds an unpaired surrogate.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// The text with each unpaired surrogate replaced by U+FFFD.
    pub fn to_string_lossy(&self) -> String {
        self.code_points().map(|c| char::from_u32(c).unwrap_or(char::REPLACEMENT_CHARACTER)).collect()
    }

    /// The code points, an unpaired surrogate as its own value.
    pub fn code_points(&self) -> impl Iterator<Item = u32> + '_ {
        let mut bytes = self.0.iter().copied();
        std::iter::from_fn(move || {
            let first = bytes.next()?;
            let (mut code, more) = match first {
                0x00..=0x7f => (u32::from(first), 0),
                0x80..=0xdf => (u32::from(first & 0x1f), 1),
                0xe0..=0xef => (u32::from(first & 0x0f), 2),
                _ => (u32::from(first & 0x07), 3),
            };
            for _ in 0..more {
                code = (code << 6) | u32::from(bytes.next()? & 0x3f);
            }
            Some(code)
        })
    }

    fn push_str(&mut self, s: &str) {
        self.0.extend_from_slice(s.as_bytes());
    }

    // Append one code point; `code` is a scalar value or a surrogate.
    fn push_code(&mut self, code: u32) {
        match char::from_u32(code) {
            Some(c) => self.push_str(c.encode_utf8(&mut [0; 4])),
            None => self.0.extend_from_slice(&[
                0xe0 | (code >> 12) as u8,
                0x80 | ((code >> 6) & 0x3f) as u8,
                0x80 | (code & 0x3f) as u8,
            ]),
        }
    }
}

impl From<&str> for JsonString {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl From<String> for JsonString {
    fn from(s: String) -> Self {
        Self(s.into_bytes())
    }
}

impl PartialEq<str> for JsonString {
    fn eq(&self, other: &str) -> bool {
        self.0 == other.as_bytes()
    }
}

// Lets a map keyed by JsonString be searched with the bytes of a &str.
impl Borrow<[u8]> for JsonString {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for JsonString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&GO_NUMBERS.render(&Json::String(self.clone())))
    }
}

/// A JSON value whose numbers keep their source text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    /// A number token as written, for example `75.0` or `1e-7`. Python's
    /// `NaN`, `Infinity` and `-Infinity` are number tokens too.
    Number(String),
    String(JsonString),
    Array(Vec<Json>),
    /// Keys are held sorted by code point, the order they are hashed in.
    Object(BTreeMap<JsonString, Json>),
}

/// JSON text for the value: keys sorted, no whitespace, non-ASCII escaped
/// and every number token as it is held. Parsing the text gives the value
/// back, so a store that writes it to the `detail` column keeps the row's
/// hash.
impl fmt::Display for Json {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&GO_NUMBERS.render(self))
    }
}

impl Json {
    /// Parse JSON text as Python's `json.loads` does. A repeated object key
    /// keeps its last value, an unpaired `\u` surrogate escape is kept, and
    /// `NaN`, `Infinity` and `-Infinity` are numbers.
    pub fn parse(text: &str) -> Result<Json, ChainError> {
        let mut p = Parser { src: text, pos: 0 };
        let value = p.value(0)?;
        p.skip_ws();
        if p.pos != text.len() {
            return Err(p.err("trailing characters"));
        }
        Ok(value)
    }

    /// The value for `key` when this is an object that has it.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(map) => map.get(key.as_bytes()),
            _ => None,
        }
    }

    /// The text of a string value; `None` when it holds an unpaired
    /// surrogate.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => s.as_str(),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(items) => Some(items),
            _ => None,
        }
    }
}

/// Numbers take the text `serde_json` writes for them, which is also what the
/// stores write to the `detail` column.
impl From<&serde_json::Value> for Json {
    fn from(v: &serde_json::Value) -> Self {
        match v {
            serde_json::Value::Null => Json::Null,
            serde_json::Value::Bool(b) => Json::Bool(*b),
            serde_json::Value::Number(n) => Json::Number(n.to_string()),
            serde_json::Value::String(s) => Json::String(s.as_str().into()),
            serde_json::Value::Array(items) => Json::Array(items.iter().map(Json::from).collect()),
            serde_json::Value::Object(map) => {
                Json::Object(map.iter().map(|(k, v)| (k.as_str().into(), Json::from(v))).collect())
            }
        }
    }
}

struct Parser<'a> {
    src: &'a str,
    pos: usize,
}

impl Parser<'_> {
    fn err(&self, what: &'static str) -> ChainError {
        ChainError::Json { at: self.pos, what }
    }

    fn peek(&self) -> Option<u8> {
        self.src.as_bytes().get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, ChainError> {
        if depth > MAX_DEPTH {
            return Err(self.err("nested too deeply"));
        }
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Json::String),
            Some(b'N') => self.literal("NaN", Json::Number("NaN".to_string())),
            Some(b'I') => self.literal("Infinity", Json::Number("Infinity".to_string())),
            Some(b'-') if self.src[self.pos..].starts_with("-I") => {
                self.literal("-Infinity", Json::Number("-Infinity".to_string()))
            }
            Some(b'-' | b'0'..=b'9') => self.number().map(Json::Number),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(_) => Err(self.err("unexpected character")),
            None => Err(self.err("unexpected end")),
        }
    }

    fn literal(&mut self, word: &str, value: Json) -> Result<Json, ChainError> {
        if !self.src[self.pos..].starts_with(word) {
            return Err(self.err("unexpected character"));
        }
        self.pos += word.len();
        Ok(value)
    }

    fn object(&mut self, depth: usize) -> Result<Json, ChainError> {
        self.pos += 1;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected an object key"));
            }
            let key = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(self.err("expected ':'"));
            }
            self.pos += 1;
            let value = self.value(depth + 1)?;
            map.insert(key, value);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(map));
                }
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, ChainError> {
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
    }

    fn string(&mut self) -> Result<JsonString, ChainError> {
        self.pos += 1;
        let mut out = JsonString::default();
        let mut run = self.pos;
        loop {
            match self.peek() {
                None => return Err(self.err("unterminated string")),
                Some(b'"') => {
                    out.push_str(&self.src[run..self.pos]);
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    out.push_str(&self.src[run..self.pos]);
                    self.pos += 1;
                    out.push_code(self.escape()?);
                    run = self.pos;
                }
                Some(c) if c < 0x20 => return Err(self.err("control character in string")),
                Some(_) => self.pos += 1,
            }
        }
    }

    // The code point for the escape that follows a backslash. A \u escape
    // of a surrogate with no partner is that surrogate.
    fn escape(&mut self) -> Result<u32, ChainError> {
        let c = self.peek().ok_or_else(|| self.err("unterminated string"))?;
        self.pos += 1;
        Ok(match c {
            b'"' | b'\\' | b'/' => u32::from(c),
            b'b' => 0x08,
            b'f' => 0x0c,
            b'n' => 0x0a,
            b'r' => 0x0d,
            b't' => 0x09,
            b'u' => {
                let hi = self.hex4()?;
                if (0xD800..0xDC00).contains(&hi) && self.src[self.pos..].starts_with("\\u") {
                    let back = self.pos;
                    self.pos += 2;
                    let lo = self.hex4()?;
                    if (0xDC00..0xE000).contains(&lo) {
                        return Ok(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00));
                    }
                    self.pos = back;
                }
                hi
            }
            _ => {
                self.pos -= 1;
                return Err(self.err("invalid escape"));
            }
        })
    }

    fn hex4(&mut self) -> Result<u32, ChainError> {
        let digits = self
            .src
            .as_bytes()
            .get(self.pos..self.pos + 4)
            .filter(|d| d.iter().all(u8::is_ascii_hexdigit))
            .ok_or_else(|| self.err("invalid \\u escape"))?;
        let mut code = 0;
        for d in digits {
            code = code * 16 + char::from(*d).to_digit(16).unwrap_or(0);
        }
        self.pos += 4;
        Ok(code)
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        self.pos - start
    }

    fn number(&mut self) -> Result<String, ChainError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let int_start = self.pos;
        let int_len = self.digits();
        if int_len == 0 || (int_len > 1 && self.src.as_bytes()[int_start] == b'0') {
            return Err(self.err("invalid number"));
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if self.digits() == 0 {
                return Err(self.err("invalid number"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if self.digits() == 0 {
                return Err(self.err("invalid number"));
            }
        }
        Ok(self.src[start..self.pos].to_string())
    }
}

/// How canonical JSON is written. `PY` is the canonical form; the others are
/// older Go encodings that verification falls back to and sealing never uses.
#[derive(Clone, Copy)]
struct Canon {
    /// Rewrite number tokens the way Python renders them.
    py_numbers: bool,
    /// Write DEL (0x7f) as `\u007f`.
    escape_del: bool,
}

const PY: Canon = Canon { py_numbers: true, escape_del: true };
// Numbers as stored, as Go hashed them before it matched CPython's rendering.
const GO_NUMBERS: Canon = Canon { py_numbers: false, escape_del: true };
// DEL written raw, as Go hashed it before it escaped it, with numbers as stored.
const GO_RAW_DEL: Canon = Canon { py_numbers: false, escape_del: false };
// DEL written raw with CPython's numbers, which Python's verifier accepts.
const PY_RAW_DEL: Canon = Canon { py_numbers: true, escape_del: false };

impl Canon {
    fn render(self, v: &Json) -> String {
        let mut out = String::new();
        self.write(v, &mut out);
        out
    }

    fn write(self, v: &Json, out: &mut String) {
        match v {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Number(tok) if self.py_numbers => out.push_str(&py_number_token(tok)),
            Json::Number(tok) => out.push_str(tok),
            Json::String(s) => self.write_str(s, out),
            Json::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    self.write(item, out);
                }
                out.push(']');
            }
            Json::Object(map) => {
                out.push('{');
                for (i, (key, value)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    self.write_str(key, out);
                    out.push(':');
                    self.write(value, out);
                }
                out.push('}');
            }
        }
    }

    // A string as CPython writes it with ensure_ascii: short escapes where it
    // has them, and \uXXXX (UTF-16 units) for everything outside ' '..'~'.
    // An unpaired surrogate is written as its own \uXXXX.
    fn write_str(self, s: &JsonString, out: &mut String) {
        out.push('"');
        for code in s.code_points() {
            match code {
                0x22 => out.push_str("\\\""),
                0x5c => out.push_str("\\\\"),
                0x0a => out.push_str("\\n"),
                0x0d => out.push_str("\\r"),
                0x09 => out.push_str("\\t"),
                0x08 => out.push_str("\\b"),
                0x0c => out.push_str("\\f"),
                0x7f if !self.escape_del => out.push('\u{7f}'),
                // Writing to a String cannot fail.
                0x20..=0x7e => out.push(char::from_u32(code).unwrap_or(' ')),
                0x10000.. => {
                    let v = code - 0x10000;
                    let _ = write!(out, "\\u{:04x}\\u{:04x}", 0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff));
                }
                _ => {
                    let _ = write!(out, "\\u{code:04x}");
                }
            }
        }
        out.push('"');
    }
}

/// Canonical JSON of `v`: sorted keys, no whitespace, non-ASCII and DEL
/// escaped, numbers as Python renders them. An unpaired surrogate is written
/// as its `\uXXXX` escape and `NaN`, `Infinity` and `-Infinity` as they are,
/// as `json.dumps` writes them.
pub fn canonical_json(v: &Json) -> String {
    PY.render(v)
}

// A number token as CPython's json.dumps writes the value json.loads reads
// from it. NaN, Infinity and -Infinity are written as they are. A token with
// no '.', 'e' or 'E' is an int and is kept as written, except "-0", which
// reads as 0. Any other token is a float.
fn py_number_token(tok: &str) -> String {
    if matches!(tok, "NaN" | "Infinity" | "-Infinity") {
        return tok.to_string();
    }
    if !tok.contains(['.', 'e', 'E']) {
        return if tok == "-0" { "0".to_string() } else { tok.to_string() };
    }
    match tok.parse::<f64>() {
        Ok(f) if f.is_infinite() => {
            if f > 0.0 { "Infinity".to_string() } else { "-Infinity".to_string() }
        }
        Ok(f) => py_float_repr(f),
        Err(_) => tok.to_string(),
    }
}

// CPython's repr() of a finite float: the shortest digits that round-trip,
// in fixed notation when the decimal exponent is from -4 to 15 (with ".0" on
// a whole number), otherwise scientific with a signed exponent of at least
// two digits (5e-05, 1e+16).
fn py_float_repr(f: f64) -> String {
    let sci = format!("{:e}", f.abs()); // "1.25e-5"
    let (mantissa, exp) = sci.split_once('e').unwrap_or((sci.as_str(), "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits = mantissa.replace('.', "");
    let mut out = String::new();
    if f.is_sign_negative() {
        out.push('-');
    }
    if (-4..16).contains(&exp) {
        // Digits before the decimal point; zero or less for a value below 1.
        let point = exp + 1;
        match usize::try_from(point) {
            Ok(n) if n >= digits.len() => {
                out.push_str(&digits);
                out.push_str(&"0".repeat(n - digits.len()));
                out.push_str(".0");
            }
            Ok(n) if n > 0 => {
                out.push_str(&digits[..n]);
                out.push('.');
                out.push_str(&digits[n..]);
            }
            _ => {
                out.push_str("0.");
                out.push_str(&"0".repeat(usize::try_from(-point).unwrap_or(0)));
                out.push_str(&digits);
            }
        }
    } else {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let sign = if exp < 0 { '-' } else { '+' };
        let _ = write!(out, "e{sign}{:02}", exp.unsigned_abs());
    }
    out
}

fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let mut out = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// `sha256(salt + canonical JSON of detail)` as hex (spec 1.4).
///
/// Without the salt a short value such as an email address could be
/// recovered by guessing, so redaction clears the salt along with detail.
pub fn detail_commitment(salt: &str, detail: &Json) -> String {
    commitment_with(salt, detail, PY)
}

fn commitment_with(salt: &str, detail: &Json, canon: Canon) -> String {
    sha256_hex(&[salt.as_bytes(), canon.render(detail).as_bytes()])
}

/// A row as the chain hashes it: the wire row's hashed fields and its chain
/// fields, with `detail` as [`Json`] so its number tokens are exact.
///
/// [`crate::Row`] holds `detail` as a `serde_json::Value`, which cannot keep
/// `-0`, an integer past 64 bits, a float past `f64`'s range, `NaN` or an
/// unpaired surrogate as written. Build from JSON text with
/// [`ChainRow::from_json`], or from a stored row and its `detail` column text
/// with [`ChainRow::from_row`], when the row was sealed elsewhere;
/// `From<&Row>` is exact only for a row this process built.
///
/// "No salt" and "no commitment" are `None`; the constructors read an empty
/// string as `None` too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRow {
    pub wire_version: String,
    pub id: String,
    pub origin_id: String,
    pub monotonic_seq: u64,
    /// RFC 3339. Hashed in UTC with six fractional digits, whatever offset
    /// and precision it is written with here.
    pub timestamp: String,
    pub code: String,
    pub action: String,
    pub severity: String,
    pub service_id: String,
    pub source_node_id: String,
    pub tenant_id: Option<String>,
    pub actor: String,
    pub actor_kind: String,
    pub target: String,
    pub category: String,
    pub domain: String,
    pub method: String,
    pub request_id: String,
    /// `Json::Null` once redacted.
    pub detail: Json,
    pub shipped_at: Option<String>,
    /// Empty on a row that predates the field, which is form "1".
    pub canonical_form_id: String,
    pub prev_hash: String,
    /// Empty on an unsealed row.
    pub hash: String,
    pub detail_salt: Option<String>,
    pub detail_commitment: Option<String>,
}

impl ChainRow {
    /// Parse one wire-format row. Fields the chain does not hash, such as
    /// `pii_in_detail`, are ignored.
    pub fn from_json(text: &str) -> Result<Self, ChainError> {
        Self::from_value(&Json::parse(text)?)
    }

    /// Build from a parsed wire-format row. Only `monotonic_seq` is
    /// required. For the rest:
    ///
    /// - a missing or null string field is empty, so a missing `hash` reads
    ///   as an unsealed row;
    /// - a missing `detail` is `{}`, and a null one is a redacted detail;
    /// - a missing, null or empty `wire_version` is "1", and a missing, null
    ///   or empty `prev_hash` is "genesis";
    /// - a missing, null or empty `detail_salt` or `detail_commitment` is
    ///   `None`.
    ///
    /// A row field with an unpaired surrogate is an error; inside `detail`
    /// it is kept.
    pub fn from_value(v: &Json) -> Result<Self, ChainError> {
        let Json::Object(map) = v else {
            return Err(ChainError::Field("row", "not an object"));
        };
        let opt = |key: &'static str| match map.get(key.as_bytes()) {
            None | Some(Json::Null) => Ok(None),
            Some(Json::String(s)) => match s.as_str() {
                Some(s) => Ok(Some(s.to_string())),
                None => Err(ChainError::Field(key, "has an unpaired surrogate")),
            },
            Some(_) => Err(ChainError::Field(key, "not a string")),
        };
        let non_empty = |key: &'static str| opt(key).map(|v| v.filter(|s| !s.is_empty()));
        let text = |key: &'static str| opt(key).map(Option::unwrap_or_default);
        let or = |key: &'static str, default: &str| {
            opt(key).map(|v| v.filter(|s| !s.is_empty()).unwrap_or_else(|| default.to_string()))
        };
        let monotonic_seq = match map.get("monotonic_seq".as_bytes()) {
            Some(Json::Number(tok)) => tok
                .parse::<u64>()
                .map_err(|_| ChainError::Field("monotonic_seq", "not an unsigned integer"))?,
            Some(_) => return Err(ChainError::Field("monotonic_seq", "not a number")),
            None => return Err(ChainError::Field("monotonic_seq", "missing")),
        };
        Ok(Self {
            wire_version: or("wire_version", "1")?,
            id: text("id")?,
            origin_id: text("origin_id")?,
            monotonic_seq,
            timestamp: text("timestamp")?,
            code: text("code")?,
            action: text("action")?,
            severity: text("severity")?,
            service_id: text("service_id")?,
            source_node_id: text("source_node_id")?,
            tenant_id: opt("tenant_id")?,
            actor: text("actor")?,
            actor_kind: text("actor_kind")?,
            target: text("target")?,
            category: text("category")?,
            domain: text("domain")?,
            method: text("method")?,
            request_id: text("request_id")?,
            detail: map.get("detail".as_bytes()).cloned().unwrap_or_else(|| Json::Object(BTreeMap::new())),
            shipped_at: opt("shipped_at")?,
            canonical_form_id: text("canonical_form_id")?,
            prev_hash: or("prev_hash", GENESIS)?,
            hash: text("hash")?,
            detail_salt: non_empty("detail_salt")?,
            detail_commitment: non_empty("detail_commitment")?,
        })
    }

    /// Build from a row as a store read it and the text of its `detail`
    /// column. Every field but `detail` comes from `row`; `detail` is parsed
    /// from `detail_text`, so its number tokens and strings are the ones
    /// that were hashed. This is how the stores build the rows `chain_rows`
    /// returns.
    pub fn from_row(row: &Row, detail_text: &str) -> Result<Self, ChainError> {
        let mut out = Self::from(row);
        out.detail = Json::parse(detail_text)?;
        Ok(out)
    }

    /// Copy the chain fields of this row onto `row`. An empty salt or
    /// commitment is copied as `None`.
    pub fn stamp(&self, row: &mut Row) {
        let non_empty = |v: &Option<String>| v.clone().filter(|s| !s.is_empty());
        row.prev_hash = Some(self.prev_hash.clone());
        row.hash = Some(self.hash.clone());
        row.canonical_form_id = Some(self.form_id().to_string());
        row.detail_salt = non_empty(&self.detail_salt);
        row.detail_commitment = non_empty(&self.detail_commitment);
    }

    /// Whether `other` is the same event: every hashed field but the chain
    /// fields, `monotonic_seq` and `shipped_at` is equal, with timestamps
    /// compared as instants. A redacted `detail` on either side matches any
    /// detail. The stores use it to tell a retried insert from a different
    /// row under a stored id.
    pub fn same_event(&self, other: &ChainRow) -> bool {
        let content = |row: &ChainRow| {
            let mut row = ChainRow {
                monotonic_seq: 0,
                shipped_at: None,
                canonical_form_id: String::new(),
                prev_hash: String::new(),
                ..row.clone()
            };
            if self.detail == Json::Null || other.detail == Json::Null {
                row.detail = Json::Null;
            }
            hashed_fields(&row, FORM_1)
        };
        content(self) == content(other)
    }

    fn form_id(&self) -> &str {
        if self.canonical_form_id.is_empty() { "1" } else { &self.canonical_form_id }
    }
}

/// Exact only for a row this process built: `detail` takes the number text
/// `serde_json` writes for the value it holds. A row read back with
/// [`crate::Store::query`] has already lost any token `serde_json` cannot
/// hold, so a chain built this way from stored rows can report a break on a
/// row that is intact. Read stored rows with [`crate::Store::chain_rows`],
/// or build them with [`ChainRow::from_row`].
impl From<&Row> for ChainRow {
    fn from(row: &Row) -> Self {
        Self {
            wire_version: if row.wire_version.is_empty() { "1".to_string() } else { row.wire_version.clone() },
            id: row.id.clone(),
            origin_id: row.origin_id.clone(),
            monotonic_seq: row.monotonic_seq,
            timestamp: row.timestamp.clone(),
            code: row.code.clone(),
            action: row.action.clone(),
            severity: row.severity.clone(),
            service_id: row.service_id.clone(),
            source_node_id: row.source_node_id.clone(),
            tenant_id: row.tenant_id.clone(),
            actor: row.actor.clone(),
            actor_kind: row.actor_kind.clone(),
            target: row.target.clone(),
            category: row.category.clone(),
            domain: row.domain.clone(),
            method: row.method.clone(),
            request_id: row.request_id.clone(),
            detail: Json::from(&row.detail),
            shipped_at: row.shipped_at.clone(),
            canonical_form_id: row.canonical_form_id.clone().unwrap_or_default(),
            prev_hash: row.prev_hash.clone().unwrap_or_else(|| GENESIS.to_string()),
            hash: row.hash.clone().unwrap_or_default(),
            detail_salt: row.detail_salt.clone().filter(|s| !s.is_empty()),
            detail_commitment: row.detail_commitment.clone().filter(|s| !s.is_empty()),
        }
    }
}

// A timestamp in the wire form (spec 4.3): UTC, six fractional digits, "Z".
// Text that is not RFC 3339 is returned as it is.
fn canonical_ts(ts: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(ts) {
        Ok(t) => t
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        Err(_) => ts.to_string(),
    }
}

// A wire timestamp as form "1" hashes it, which is Python's
// datetime.isoformat(): "+00:00", with microseconds only when nonzero.
fn iso_ts(wire: &str) -> String {
    let Some(body) = wire.strip_suffix('Z') else {
        return wire.to_string();
    };
    format!("{}+00:00", body.strip_suffix(".000000").unwrap_or(body))
}

/// One way a row was hashed. The first shape of a form is the one it seals
/// with; the rest are accepted on verification only.
#[derive(Clone, Copy)]
struct Shape {
    /// Form "2": `detail_commitment` in place of `detail`.
    commits_detail: bool,
    /// Timestamps as `+00:00` isoformat rather than the wire form.
    iso_ts: bool,
    /// The stored `shipped_at` rather than null.
    shipped_at: bool,
}

const FORM_1: Shape = Shape { commits_detail: false, iso_ts: true, shipped_at: false };
const FORM_2: Shape = Shape { commits_detail: true, iso_ts: false, shipped_at: false };
// Form "1" over the wire "Z" timestamp, as Python sealed it at first.
const FORM_1_WIRE_TS: Shape = Shape { iso_ts: false, ..FORM_1 };

fn form_shape(form_id: &str) -> Option<Shape> {
    match form_id {
        "1" => Some(FORM_1),
        "2" => Some(FORM_2),
        _ => None,
    }
}

fn text(s: &str) -> Json {
    Json::String(s.into())
}

fn opt_text(s: Option<&str>) -> Json {
    s.map_or(Json::Null, text)
}

// The fields one shape hashes, as a JSON object.
fn hashed_fields(row: &ChainRow, shape: Shape) -> Json {
    let ts = |wire: &str| {
        let wire = canonical_ts(wire);
        Json::String(if shape.iso_ts { iso_ts(&wire) } else { wire }.into())
    };
    let shipped_at = match &row.shipped_at {
        Some(at) if shape.shipped_at => ts(at),
        _ => Json::Null,
    };
    let mut d: BTreeMap<JsonString, Json> = [
        ("action", text(&row.action)),
        ("actor", text(&row.actor)),
        ("actor_kind", text(&row.actor_kind)),
        ("canonical_form_id", text(row.form_id())),
        ("category", text(&row.category)),
        ("code", text(&row.code)),
        ("domain", text(&row.domain)),
        ("id", text(&row.id)),
        ("method", text(&row.method)),
        ("monotonic_seq", Json::Number(row.monotonic_seq.to_string())),
        ("origin_id", text(&row.origin_id)),
        ("prev_hash", text(&row.prev_hash)),
        ("request_id", text(&row.request_id)),
        ("service_id", text(&row.service_id)),
        ("severity", text(&row.severity)),
        ("shipped_at", shipped_at),
        ("source_node_id", text(&row.source_node_id)),
        ("target", text(&row.target)),
        ("tenant_id", opt_text(row.tenant_id.as_deref())),
        ("timestamp", ts(&row.timestamp)),
        ("wire_version", text(&row.wire_version)),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v))
    .collect();
    if shape.commits_detail {
        d.insert("detail_commitment".into(), opt_text(row.detail_commitment.as_deref()));
    } else {
        d.insert("detail".into(), row.detail.clone());
    }
    Json::Object(d)
}

fn hash_with(row: &ChainRow, shape: Shape, canon: Canon) -> String {
    sha256_hex(&[canon.render(&hashed_fields(row, shape)).as_bytes()])
}

/// The hash of `row` under its `canonical_form_id`, or `None` for a form
/// this version does not know.
///
/// This is the hash a writer computes today. It is not the test
/// [`verify_chain`] applies: verification also accepts the encodings older
/// releases hashed with, and for form "2" checks `detail` against its
/// commitment, which this hash does not cover. Use `verify_chain` to decide
/// whether a row is intact.
pub fn row_hash(row: &ChainRow) -> Option<String> {
    form_shape(row.form_id()).map(|shape| hash_with(row, shape, PY))
}

// 32 random bytes as hex.
fn new_detail_salt() -> Result<String, ChainError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| ChainError::Random(e.to_string()))?;
    let mut out = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    Ok(out)
}

/// A copy of `row` sealed after `prev_hash`.
///
/// Overwrites `canonical_form_id` (the current form), `prev_hash`,
/// `detail_commitment` and `hash`. A non-empty `detail_salt` is kept, so a
/// row can be sealed again to the same hash; otherwise a new one is drawn.
/// `monotonic_seq` is hashed as the row carries it: set it before sealing,
/// to one more than the highest seq on the node.
pub fn seal(prev_hash: &str, row: &ChainRow) -> Result<ChainRow, ChainError> {
    let salt = match row.detail_salt.as_deref() {
        Some(salt) if !salt.is_empty() => salt.to_string(),
        _ => new_detail_salt()?,
    };
    let mut sealed = row.clone();
    sealed.canonical_form_id = CURRENT_CANONICAL_FORM_ID.to_string();
    sealed.prev_hash = prev_hash.to_string();
    sealed.detail_commitment = Some(detail_commitment(&salt, &row.detail));
    sealed.detail_salt = Some(salt);
    sealed.hash = hash_with(&sealed, FORM_2, PY);
    Ok(sealed)
}

/// A copy of the store row `row` sealed after `prev_hash`, at the
/// `monotonic_seq` it carries; see [`seal`] for the fields it overwrites.
/// The stores call this inside the insert transaction, once they have
/// allocated the seq and read the node's tip.
pub fn seal_row(prev_hash: &str, row: &Row) -> Result<Row, ChainError> {
    let mut sealed = row.clone();
    seal(prev_hash, &ChainRow::from(row))?.stamp(&mut sealed);
    Ok(sealed)
}

/// Result of [`verify_chain`].
///
/// `ok` says no break was found among the rows given. It is also true for
/// no rows, and for rows that were never sealed, so read `sealed_rows` with
/// it: `ok` with `sealed_rows == 0` means nothing was checked.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChainVerifyResult {
    pub ok: bool,
    /// How many rows were passed in, counting repeated copies of a row and
    /// unsealed rows.
    pub total_rows: usize,
    /// How many of them are sealed (have a hash), counting each row once
    /// per node and id. These are the rows the walk checks.
    pub sealed_rows: usize,
    /// `monotonic_seq` of the first row that breaks the chain.
    pub first_break_at: Option<u64>,
    /// `source_node_id` of the chain that breaks there.
    pub first_break_node: Option<String>,
    pub reason: Option<String>,
}

// A break: where it is, on which node, and why.
pub(crate) struct Break {
    pub(crate) seq: u64,
    pub(crate) node: String,
    pub(crate) reason: String,
}

// Keep in `first` whichever break is at the lower seq.
fn lower(found: Option<Break>, first: &mut Option<Break>) {
    if let Some(found) = found {
        if first.as_ref().is_none_or(|f| found.seq < f.seq) {
            *first = Some(found);
        }
    }
}

// Whether any string the row holds has DEL in it.
fn has_del(row: &ChainRow) -> bool {
    let strings = [
        &row.wire_version, &row.id, &row.origin_id, &row.timestamp, &row.code, &row.action,
        &row.severity, &row.service_id, &row.source_node_id, &row.actor, &row.actor_kind,
        &row.target, &row.category, &row.domain, &row.method, &row.request_id,
        &row.canonical_form_id, &row.prev_hash, &row.hash,
    ];
    let optional = [&row.tenant_id, &row.shipped_at, &row.detail_salt, &row.detail_commitment];
    strings.iter().any(|s| s.contains('\u{7f}'))
        || optional.iter().any(|s| s.as_deref().is_some_and(|s| s.contains('\u{7f}')))
        || GO_RAW_DEL.render(&row.detail).contains('\u{7f}')
}

// Whether row.hash is the row's hash under canon: its form's own, or one of
// the older shapes.
fn hash_matches(row: &ChainRow, shape: Shape, canon: Canon) -> bool {
    let is = |shape: Shape| hash_with(row, shape, canon) == row.hash;
    if is(shape) {
        return true;
    }
    let form_1 = !shape.commits_detail;
    if form_1 && is(FORM_1_WIRE_TS) {
        return true;
    }
    // Sealed with shipped_at already set, and hashed over that value.
    row.shipped_at.is_some()
        && (is(Shape { shipped_at: true, ..shape })
            || (form_1 && is(Shape { shipped_at: true, ..FORM_1_WIRE_TS })))
}

// Check a sealed row on its own: its form, its detail commitment and its
// hash. Returns why it fails, or None if it checks out.
fn row_break(row: &ChainRow) -> Option<String> {
    let form_id = row.form_id();
    let Some(shape) = form_shape(form_id) else {
        return Some(format!("row {}: unknown canonical_form_id \"{form_id}\"", row.id));
    };

    // Each check runs with the canonical encoding first, then with the older
    // Go encodings. The raw-DEL ones can only differ when the row holds DEL.
    let mut del: Option<bool> = None;
    let mut matches = |check: &dyn Fn(Canon) -> bool| {
        if check(PY) || check(GO_NUMBERS) {
            return true;
        }
        *del.get_or_insert_with(|| has_del(row)) && (check(GO_RAW_DEL) || check(PY_RAW_DEL))
    };

    // Form "2" hashes detail_commitment, not detail, so a changed detail with
    // the commitment left as it was still matches the hash. While detail is
    // present the commitment is recomputed and compared; a missing salt is a
    // break, since redaction clears detail and salt together (spec 7.1).
    if shape.commits_detail && row.detail != Json::Null {
        let Some(salt) = row.detail_salt.as_deref().filter(|s| !s.is_empty()) else {
            return Some(format!(
                "row {}: detail present but detail_salt is missing — commitment cannot be verified",
                row.id
            ));
        };
        let stored = row.detail_commitment.as_deref().unwrap_or("");
        if !matches(&|canon| commitment_with(salt, &row.detail, canon) == stored) {
            return Some(format!("row {}: detail does not match its commitment", row.id));
        }
    }

    if !matches(&|canon| hash_matches(row, shape, canon)) {
        return Some(format!("row {}: hash mismatch", row.id));
    }
    None
}

// The first break in one node's chain, sorted by monotonic_seq, as
// (monotonic_seq, reason); None if the chain verifies.
fn first_break(sorted: &[&ChainRow]) -> Option<(u64, String)> {
    let first_sealed = sorted.iter().filter(|r| !r.hash.is_empty()).map(|r| r.monotonic_seq).min();
    let mut seen: HashMap<u64, &str> = HashMap::new();
    for (i, row) in sorted.iter().enumerate() {
        let seq = row.monotonic_seq;
        if row.hash.is_empty() {
            if first_sealed.is_some_and(|first| seq >= first) {
                return Some((seq, format!("row {}: no hash after the node's chain started", row.id)));
            }
            continue; // written before chaining, or stdout-only
        }
        // monotonic_seq is unique within a node, so two sealed rows sharing
        // one came from two allocators (spec 2.1).
        if let Some(other) = seen.insert(seq, &row.id).filter(|other| *other != row.id) {
            return Some((
                seq,
                format!(
                    "duplicate monotonic_seq {seq} on node '{}': rows {other} and {}. \
                     Two engines allocated independently (spec §2.1).",
                    row.source_node_id, row.id
                ),
            ));
        }
        if let Some(reason) = row_break(row) {
            return Some((seq, reason));
        }
        if i > 0 {
            let prev = sorted[i - 1];
            if !prev.hash.is_empty() && row.prev_hash != prev.hash {
                return Some((
                    seq,
                    format!("row {}: prev_hash does not match preceding row {}", row.id, prev.id),
                ));
            }
            // Only a node's first sealed row may skip the check above: it
            // links to "genesis" when the unsealed row before it is at seq-1,
            // and a purged head leaves a gap where the rows start.
            if prev.hash.is_empty() && prev.monotonic_seq + 1 == seq && row.prev_hash != GENESIS {
                return Some((seq, format!("row {}: first sealed row does not link to genesis", row.id)));
            }
        }
    }
    None
}

/// Walk the hash chain of each node in `rows` and report the first break.
///
/// Detects a changed field, and an inserted, removed or reordered row. A cut
/// tail or a full re-seal from genesis is detected only against checkpoints
/// published earlier outside the store; see [`verify_chain_with_checkpoints`].
///
/// - Chains are per `source_node_id`; each is walked in `monotonic_seq` order.
/// - A row given more than once is checked once: a sealed copy wins over an
///   unsealed one, and two sealed copies must have the same, valid hash.
/// - An unsealed row (empty `hash`) is skipped below its node's first sealed
///   seq and breaks the chain at or above it. A sealed row right after an
///   unsealed one must link to "genesis".
/// - A row with an unknown `canonical_form_id` breaks the chain.
/// - With several nodes, `first_break_at` is the lowest seq at which any
///   breaks, and `first_break_node` the node it is on.
/// - `ok` is true when there is nothing to check; `sealed_rows` says how
///   many rows were.
pub fn verify_chain(rows: &[ChainRow]) -> ChainVerifyResult {
    verify_chain_with_checkpoints(rows, &[], CheckpointOptions::default())
}

/// [`verify_chain`], with `rows` also checked against `checkpoints` (spec 9).
///
/// Each checkpoint within a node's rows must match the row at its seq. Unless
/// `opts.partial` is set, `rows` are taken as the whole chain: every
/// checkpointed node must have rows, and no checkpoint may be below its
/// node's oldest row or above its newest. Rows after a node's newest
/// checkpoint are not covered by it. Under retention, pass only the
/// checkpoints taken since the latest purge
/// ([`crate::checkpoint::checkpoints_since`]): an older one below the purged
/// rows fails. `first_break_at` is the lowest seq of any break; at one seq a
/// chain break is reported before a checkpoint break.
pub fn verify_chain_with_checkpoints(
    rows: &[ChainRow],
    checkpoints: &[Checkpoint],
    opts: CheckpointOptions,
) -> ChainVerifyResult {
    // One copy per (node, id), in first-seen order.
    let mut by_node: BTreeMap<&str, Vec<&ChainRow>> = BTreeMap::new();
    let mut kept: HashMap<(&str, &str), usize> = HashMap::new();
    let mut first: Option<Break> = None;

    let mut dup: Option<Break> = None;
    for row in rows {
        let node = by_node.entry(&row.source_node_id).or_default();
        let Some(&at) = kept.get(&(row.source_node_id.as_str(), row.id.as_str())) else {
            kept.insert((&row.source_node_id, &row.id), node.len());
            node.push(row);
            continue;
        };
        let old = node[at];
        if old.hash.is_empty() && !row.hash.is_empty() {
            node[at] = row;
        } else if !old.hash.is_empty() && !row.hash.is_empty() {
            let reason = if row.hash == old.hash {
                row_break(row)
            } else {
                Some(format!("row {}: two sealed copies with different hashes", row.id))
            };
            let seq = row.monotonic_seq.min(old.monotonic_seq);
            lower(reason.map(|reason| Break { seq, node: row.source_node_id.clone(), reason }), &mut dup);
        }
    }

    let mut sealed_rows = 0;
    for (name, node) in &mut by_node {
        node.sort_by_key(|r| r.monotonic_seq);
        sealed_rows += node.iter().filter(|r| !r.hash.is_empty()).count();
        let found = first_break(node).map(|(seq, reason)| Break { seq, node: (*name).to_string(), reason });
        lower(found, &mut first);
    }
    lower(dup, &mut first);
    lower(checkpoint_break(&by_node, checkpoints, opts.partial), &mut first);

    let (first_break_at, first_break_node, reason) = match first {
        Some(b) => (Some(b.seq), Some(b.node), Some(b.reason)),
        None => (None, None, None),
    };
    ChainVerifyResult {
        ok: reason.is_none(),
        total_rows: rows.len(),
        sealed_rows,
        first_break_at,
        first_break_node,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(detail: &str) -> ChainRow {
        let mut row = ChainRow::from_json(
            r#"{"wire_version": "1", "id": "evt-1", "origin_id": "evt-1", "monotonic_seq": 1,
                "timestamp": "2026-06-15T10:30:45.123456Z", "code": "SENSOR_READ",
                "action": "read", "severity": "info", "service_id": "gateway",
                "source_node_id": "node-1", "actor": "plc-7", "actor_kind": "device",
                "target": "sensor/42", "category": "telemetry", "domain": "plant",
                "method": "mqtt", "request_id": "req-1"}"#,
        )
        .unwrap();
        row.detail = Json::parse(detail).unwrap();
        row
    }

    // Seal the way an older release did, with another encoding or shape.
    fn sealed_with(mut row: ChainRow, shape: Shape, canon: Canon) -> ChainRow {
        if shape.commits_detail {
            row.canonical_form_id = "2".to_string();
            row.detail_salt = Some("c".repeat(64));
            row.detail_commitment = Some(commitment_with(&"c".repeat(64), &row.detail, canon));
        } else {
            row.canonical_form_id = "1".to_string();
        }
        row.hash = hash_with(&row, shape, canon);
        row
    }

    // Whether the row verifies with the canonical encoding alone.
    fn matches_canonical(row: &ChainRow) -> bool {
        let commitment = row.detail_salt.as_deref().map(|salt| detail_commitment(salt, &row.detail));
        row_hash(row).as_deref() == Some(row.hash.as_str()) && commitment == row.detail_commitment
    }

    #[test]
    fn rows_sealed_with_go_numbers_verify() {
        let detail = r#"{"tiny": 0.00005, "tinier": 1e-7, "neg_zero": -0, "frac": 12.5}"#;
        for shape in [FORM_1, FORM_2] {
            let sealed = sealed_with(row(detail), shape, GO_NUMBERS);
            assert_ne!(PY.render(&sealed.detail), GO_NUMBERS.render(&sealed.detail));
            assert!(!matches_canonical(&sealed));
            assert!(verify_chain(&[sealed.clone()]).ok);

            let mut changed = sealed;
            changed.detail = Json::parse(&detail.replace("0.00005", "0.00006")).unwrap();
            assert!(!verify_chain(&[changed]).ok);
        }
    }

    #[test]
    fn rows_sealed_with_raw_del_verify() {
        for canon in [GO_RAW_DEL, PY_RAW_DEL] {
            for shape in [FORM_1, FORM_2] {
                let in_detail = sealed_with(row(r#"{"k": "a\u007fb", "n": 0.00005}"#), shape, canon);
                assert!(!matches_canonical(&in_detail));
                assert!(verify_chain(&[in_detail.clone()]).ok);

                let mut in_target = row(r#"{"k": 1}"#);
                in_target.target = "sensor/\u{7f}".to_string();
                let in_target = sealed_with(in_target, shape, canon);
                assert!(!matches_canonical(&in_target));
                assert!(verify_chain(&[in_target.clone()]).ok);

                let mut changed = in_detail;
                changed.detail = Json::parse(r#"{"k": "a\u007fc", "n": 0.00005}"#).unwrap();
                assert!(!verify_chain(&[changed]).ok);
                let mut changed = in_target;
                changed.target = "sensor/\u{7f}x".to_string();
                assert!(!verify_chain(&[changed]).ok);
            }
        }
    }

    // The commitment under one encoding and the hash under another, as a
    // row written across a Go upgrade has them: each is checked on its own.
    #[test]
    fn raw_del_commitment_and_hash_are_checked_apart() {
        for (commit_canon, hash_canon) in [(GO_RAW_DEL, PY), (PY, GO_RAW_DEL), (PY_RAW_DEL, GO_NUMBERS)] {
            let mut sealed = row(r#"{"note": "a\u007fb"}"#);
            sealed.target = "order/\u{7f}42".to_string();
            sealed.canonical_form_id = "2".to_string();
            sealed.detail_salt = Some("b".repeat(64));
            sealed.detail_commitment = Some(commitment_with(&"b".repeat(64), &sealed.detail, commit_canon));
            sealed.hash = hash_with(&sealed, FORM_2, hash_canon);
            let res = verify_chain(&[sealed.clone()]);
            assert!(res.ok, "{res:?}");

            let mut moved = sealed.clone();
            moved.target = "order/\u{7f}43".to_string();
            assert!(verify_chain(&[moved]).reason.unwrap_or_default().contains("hash mismatch"));
            let mut changed = sealed;
            changed.detail = Json::parse(r#"{"note": "a\u007fc"}"#).unwrap();
            assert!(verify_chain(&[changed]).reason.unwrap_or_default().contains("commitment"));
        }
    }

    #[test]
    fn same_event_ignores_the_chain_fields() {
        let a = row(r#"{"k": 1.0}"#);
        let mut sealed = seal(GENESIS, &ChainRow { monotonic_seq: 7, ..a.clone() }).unwrap();
        sealed.shipped_at = Some("2026-06-16T08:00:00.250000Z".to_string());
        sealed.timestamp = "2026-06-15T12:30:45.123456+02:00".to_string();
        assert!(a.same_event(&sealed) && sealed.same_event(&a));
        // Redacted on one side: the detail is not compared.
        let redacted = ChainRow { detail: Json::Null, detail_salt: None, ..sealed.clone() };
        assert!(a.same_event(&redacted) && redacted.same_event(&a));
        for other in [
            ChainRow { target: "sensor/43".into(), ..a.clone() },
            ChainRow { detail: Json::parse(r#"{"k": 2.0}"#).unwrap(), ..a.clone() },
            ChainRow { timestamp: "2026-06-15T10:30:45.123457Z".into(), ..a.clone() },
            ChainRow { tenant_id: Some("acme".into()), ..a.clone() },
        ] {
            assert!(!a.same_event(&other), "{other:?}");
        }
    }

    #[test]
    fn text_of_a_del_escape_is_not_del() {
        // The six characters \u007f in a string are hashed as written.
        let detail = Json::parse(r#"{"k": "a\\u007fb"}"#).unwrap();
        assert_eq!(PY.render(&detail), r#"{"k":"a\\u007fb"}"#);
        assert_eq!(PY_RAW_DEL.render(&detail), PY.render(&detail));
    }

    #[test]
    fn rows_sealed_over_shipped_at_verify() {
        let mut shipped = row(r#"{"k": 1}"#);
        shipped.shipped_at = Some("2026-06-16T08:00:00.250000Z".to_string());
        for shape in [FORM_1, FORM_1_WIRE_TS, FORM_2] {
            let sealed = sealed_with(shipped.clone(), Shape { shipped_at: true, ..shape }, PY);
            assert!(!matches_canonical(&sealed));
            assert!(verify_chain(&[sealed.clone()]).ok);

            let mut moved = sealed;
            moved.shipped_at = Some("2026-06-16T08:00:00.250001Z".to_string());
            assert!(!verify_chain(&[moved]).ok);
        }
    }

    #[test]
    fn form_1_timestamp_is_isoformat() {
        assert_eq!(iso_ts("2026-06-15T10:30:45.123456Z"), "2026-06-15T10:30:45.123456+00:00");
        assert_eq!(iso_ts("2026-06-15T10:30:45.000000Z"), "2026-06-15T10:30:45+00:00");
        assert_eq!(canonical_ts("2026-06-15T10:30:45+00:00"), "2026-06-15T10:30:45.000000Z");
        assert_eq!(canonical_ts("2026-06-15T12:30:45.5+02:00"), "2026-06-15T10:30:45.500000Z");
        assert_eq!(canonical_ts("2026-06-15T10:30:45.123456789Z"), "2026-06-15T10:30:45.123456Z");
        assert_eq!(canonical_ts("not a time"), "not a time");
    }
}
