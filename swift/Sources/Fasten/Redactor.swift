import Foundation

/// PII / secret redactor — mirrors Python's fasten.redact.Redactor.
///
/// Pass 1 — key-pattern: dict keys matching a secret-name regex get their
/// values replaced unconditionally.
/// Pass 2 — value-shape: string values matching known secret shapes (JWT,
/// private key, AWS/GH tokens, CC, Stripe, OpenAI) are replaced with a
/// type-hinting token (e.g. "***JWT***").
public final class Redactor: @unchecked Sendable {

    // 14 default PII key patterns (same as Python SDK).
    private static let defaultKeyPatterns: [String] = [
        #"api[_-]?key"#, "password", "passwd", "token", "secret",
        "authorization", "bearer", #"m2m[_-]?key"#, #"cert[_-]?private"#,
        #"private[_-]?key"#, "access_key", "session_id", "cookie", "credential",
    ]

    // Value-shape patterns: (name, regex, replacement).
    private static let defaultValuePatterns: [(String, NSRegularExpression, String)] = {
        func re(_ p: String) -> NSRegularExpression {
            try! NSRegularExpression(pattern: p)
        }
        return [
            ("JWT",       re(#"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"#),  "***JWT***"),
            ("PRIV_KEY",  re(#"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"#),  "***PRIVATE_KEY***"),
            ("AWS_KEY",   re(#"(?:AKIA|ASIA)[A-Z0-9]{16}"#),                               "***AWS_KEY***"),
            ("GH_TOKEN",  re(#"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}"#),               "***GH_TOKEN***"),
            ("STRIPE",    re(#"sk_live_[A-Za-z0-9]{24,}"#),                                "***STRIPE_KEY***"),
            ("OPENAI",    re(#"sk-(?:proj-)?[A-Za-z0-9_-]{32,}"#),                        "***OPENAI_KEY***"),
        ]
    }()

    private let keyPattern: NSRegularExpression
    private let replacement: String
    private let valuePatterns: [(String, NSRegularExpression, String)]

    public init(
        extraKeys: [String] = [],
        replacement: String = "***",
        extraValuePatterns: [(String, String, String)] = []
    ) {
        self.replacement = replacement
        let allKeys = Self.defaultKeyPatterns + extraKeys
        let combined = allKeys.joined(separator: "|")
        self.keyPattern = try! NSRegularExpression(pattern: combined, options: .caseInsensitive)
        self.valuePatterns = Self.defaultValuePatterns + extraValuePatterns.compactMap {
            (name, pat, repl) in (try? NSRegularExpression(pattern: pat)).map { (name, $0, repl) }
        }
    }

    public func redact(_ dict: [String: Any]) -> [String: Any] {
        var out: [String: Any] = [:]
        for (k, v) in dict {
            if keyMatchesSecret(k) {
                out[k] = replacement
            } else {
                out[k] = redactValue(v)
            }
        }
        return out
    }

    private func keyMatchesSecret(_ key: String) -> Bool {
        let range = NSRange(key.startIndex..., in: key)
        return keyPattern.firstMatch(in: key, range: range) != nil
    }

    private func redactValue(_ v: Any) -> Any {
        switch v {
        case let s as String:
            if let shaped = checkValueShape(s) { return shaped }
            return s
        case let d as [String: Any]:
            return redact(d)
        case let arr as [Any]:
            return arr.map { redactValue($0) }
        default:
            return v
        }
    }

    private func checkValueShape(_ s: String) -> String? {
        // Credit card: 13-19 digit groups, Luhn-validated.
        let ccPat = try! NSRegularExpression(pattern: #"\b\d[\d\s\-]{11,17}\d\b"#)
        let nsS = s as NSString
        if let m = ccPat.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) {
            let digits = nsS.substring(with: m.range).filter(\.isNumber)
            if (13...19).contains(digits.count) && luhnValid(digits) {
                return "***CC***"
            }
        }
        // Named value patterns.
        for (_, re, repl) in valuePatterns {
            if re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil {
                return repl
            }
        }
        return nil
    }

    private func luhnValid(_ digits: String) -> Bool {
        var total = 0
        for (i, ch) in digits.reversed().enumerated() {
            var n = ch.wholeNumberValue ?? 0
            if i % 2 == 1 { n *= 2; if n > 9 { n -= 9 } }
            total += n
        }
        return total % 10 == 0
    }
}
