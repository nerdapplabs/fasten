import Foundation

/// PII / secret redactor — pure Swift, no native dependencies.
///
/// Applies two redaction passes in order:
///   1. Key-pattern: keys matching spec/row-schema.json x-fasten-redact patterns → replace with `replacement`
///   2. Value-shape: string values matching known secret shapes (P1-24) → replace with type token
///
/// Recursively walks nested `[String: Any]` dictionaries and arrays.
public final class Redactor: @unchecked Sendable {

    private let keyPatterns:       [NSRegularExpression]
    private let replacement:       String
    private let extraValueRules:   [(NSRegularExpression, String)]

    // Patterns from spec/row-schema.json x-fasten-redact.patterns — case-insensitive substring match on keys.
    private static let defaultKeyPatterns: [NSRegularExpression] = {
        let specs = [
            "api[_-]?key", "password", "passwd", "token", "secret",
            "authorization", "bearer", "m2m[_-]?key", "cert[_-]?private",
            "private[_-]?key", "access_key", "session_id", "cookie", "credential",
        ]
        return specs.compactMap { try? NSRegularExpression(pattern: $0, options: .caseInsensitive) }
    }()

    // Built-in value-shape rules (P1-24); applied to string values regardless of key.
    private static let valueShapeRules: [(NSRegularExpression, String)] = {
        let defs: [(String, String)] = [
            (#"^eyJ[A-Za-z0-9_=+/\-]+\.[A-Za-z0-9_=+/\-]+\.[A-Za-z0-9_=+/\-]*$"#, "***JWT***"),
            (#"-----BEGIN [A-Z ]+PRIVATE KEY-----"#,                                  "***PRIVATE_KEY***"),
            (#"^AKIA[0-9A-Z]{16}$"#,                                                  "***AWS_KEY***"),
            (#"^gh[a-z]_[A-Za-z0-9]{36,}$"#,                                         "***GH_TOKEN***"),
            (#"^sk_(live|test)_[A-Za-z0-9]{24,}$"#,                                  "***STRIPE_KEY***"),
            (#"^sk-[A-Za-z0-9]{48,}$"#,                                               "***OPENAI_KEY***"),
        ]
        return defs.compactMap { (pat, repl) in
            guard let re = try? NSRegularExpression(pattern: pat) else { return nil }
            return (re, repl)
        }
    }()

    public init(
        extraKeys:           [String]                  = [],
        replacement:         String                    = "***",
        extraValuePatterns:  [(String, String, String)] = []
    ) {
        self.replacement = replacement
        let extraKeyREs = extraKeys.compactMap {
            try? NSRegularExpression(pattern: NSRegularExpression.escapedPattern(for: $0),
                                     options: .caseInsensitive)
        }
        self.keyPatterns = Redactor.defaultKeyPatterns + extraKeyREs
        self.extraValueRules = extraValuePatterns.compactMap { (_, pat, repl) in
            guard let re = try? NSRegularExpression(pattern: pat) else { return nil }
            return (re, repl)
        }
    }

    public func redact(_ dict: [String: Any]) -> [String: Any] {
        _redactDict(dict)
    }

    private func _redactDict(_ dict: [String: Any]) -> [String: Any] {
        var out: [String: Any] = [:]
        for (key, val) in dict {
            out[key] = _keyMatches(key) ? replacement : _redactValue(val)
        }
        return out
    }

    private func _redactValue(_ val: Any) -> Any {
        if let s = val as? String {
            return _redactString(s)
        } else if let d = val as? [String: Any] {
            return _redactDict(d)
        } else if let a = val as? [Any] {
            return a.map { _redactValue($0) }
        }
        return val
    }

    private func _redactString(_ s: String) -> Any {
        let range = NSRange(s.startIndex..., in: s)
        for (re, token) in Redactor.valueShapeRules {
            if re.firstMatch(in: s, range: range) != nil { return token }
        }
        if _looksLikeCC(s) { return "***CC***" }
        for (re, token) in extraValueRules {
            if re.firstMatch(in: s, range: range) != nil { return token }
        }
        return s
    }

    private func _keyMatches(_ key: String) -> Bool {
        let range = NSRange(key.startIndex..., in: key)
        return keyPatterns.contains { $0.firstMatch(in: key, range: range) != nil }
    }

    private func _looksLikeCC(_ s: String) -> Bool {
        guard s.count >= 13 && s.count <= 16 && s.allSatisfy(\.isNumber) else { return false }
        return _luhn(s)
    }

    private func _luhn(_ s: String) -> Bool {
        let digits = s.compactMap { $0.wholeNumberValue }
        var sum = 0
        for (i, d) in digits.reversed().enumerated() {
            if i % 2 == 1 { let v = d * 2; sum += v > 9 ? v - 9 : v }
            else           { sum += d }
        }
        return sum % 10 == 0
    }
}
