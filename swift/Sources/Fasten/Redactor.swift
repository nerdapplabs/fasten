import Foundation

/// Redacts `detail` values, walking nested dictionaries and arrays:
///   1. A key matching a key pattern gets `replacement` as its value.
///   2. Otherwise a string value that looks like a known secret (JWT, AWS key,
///      card number, ...) is replaced with a token such as "***JWT***".
public final class Redactor: @unchecked Sendable {

    private let keyPatterns:       [NSRegularExpression]
    private let replacement:       String
    private let extraValueRules:   [(NSRegularExpression, String)]

    // spec/row-schema.json x-fasten-redact.patterns; case-insensitive, matched anywhere in the key.
    private static let defaultKeyPatterns: [NSRegularExpression] = {
        let specs = [
            "api[_-]?key", "password", "passwd", "token", "secret",
            "authorization", "bearer", "m2m[_-]?key", "cert[_-]?private",
            "private[_-]?key", "access[_-]?key", "session[_-]?id", "cookie", "credential",
            // \z, not $: ICU's $ also matches before a final newline.
            "pwd", "passphrase", "dsn\\z",
            // Whole key only: as substrings they would match primary_key or author.
            "^key\\z", "^auth\\z",
        ]
        return specs.compactMap { try? NSRegularExpression(pattern: $0, options: .caseInsensitive) }
    }()

    // Applied to string values whatever the key, after the card and JWT
    // checks and before the URL and Authorization checks: the same order as
    // fasten-core/src/redact.rs. Unanchored, so they match inside longer strings.
    private static let valueShapeRules: [(NSRegularExpression, String)] = {
        let defs: [(String, String)] = [
            // PEM private key block header, encrypted or not
            (#"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |)PRIVATE KEY-----"#,   "***PRIVATE_KEY***"),
            // AWS access key: permanent AKIA or short-lived ASIA
            (#"(?:AKIA|ASIA)[A-Z0-9]{16}"#,                                           "***AWS_KEY***"),
            // GitHub token: ghp/gho/ghu/ghs/ghr, exactly 36 alphanumeric chars
            (#"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}"#,                            "***GH_TOKEN***"),
            // Stripe live secret key (24+ chars after prefix)
            (#"sk_live_[A-Za-z0-9]{24,}"#,                                            "***STRIPE_KEY***"),
            // OpenAI API key (legacy sk-... and org sk-proj-... formats, 32+ suffix chars)
            (#"sk-(?:proj-)?[A-Za-z0-9_\-]{32,}"#,                                   "***OPENAI_KEY***"),
            // GitHub fine-grained personal access token
            (#"github_pat_[A-Za-z0-9_]{22,}"#,                                        "***GH_TOKEN***"),
            // Slack token
            (#"xox[abposr]-[A-Za-z0-9\-]{10,}"#,                                      "***SLACK_TOKEN***"),
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
        // The Luhn check keeps order numbers and similar ids from matching.
        if Redactor.hasCard(s) { return "***CC***" }
        if Redactor.hasJwt(s) { return "***JWT***" }
        for (re, token) in Redactor.valueShapeRules {
            if re.firstMatch(in: s, range: range) != nil { return token }
        }
        if Redactor.hasUrlCredentials(s) { return "***URL_CREDENTIALS***" }
        if Redactor.hasAuthHeader(s) { return "***AUTH_HEADER***" }
        for (re, token) in extraValueRules {
            if re.firstMatch(in: s, range: range) != nil { return token }
        }
        return s
    }

    // An Authorization header value: Bearer or Basic, then a credential that
    // holds a digit or one of + / =, as in fasten-core.
    private static let authHeader = try! NSRegularExpression(
        pattern: #"(?:^|[^A-Za-z0-9_])(?:Bearer|Basic)[ \t]+([A-Za-z0-9._~+/=\-]{16,})"#)
    private static let credentialMark = CharacterSet(charactersIn: "0123456789+/=")

    static func hasAuthHeader(_ s: String) -> Bool {
        let ns = s as NSString
        for m in authHeader.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
            if ns.substring(with: m.range(at: 1)).rangeOfCharacter(from: credentialMark) != nil { return true }
        }
        return false
    }

    // A run of digit groups split by spaces or dashes.
    private static let digitRun = try! NSRegularExpression(pattern: #"[0-9]+(?:[ \-]+[0-9]+)*"#)

    // Card layouts printed in groups, as in fasten-core.
    private static let cardLayouts: [[Int]] = [
        [4, 4, 4, 4], [4, 4, 4, 4, 1], [4, 4, 4, 4, 2], [4, 4, 4, 4, 3], [4, 6, 5], [4, 6, 4],
    ]

    private static func isWordUnit(_ u: unichar) -> Bool {
        (u >= 0x30 && u <= 0x39) || (u >= 0x41 && u <= 0x5A) || (u >= 0x61 && u <= 0x7A) || u == 0x5F
    }

    // Whether s holds a card number: a group of 13 to 19 digits, or groups in
    // a card layout, that pass the Luhn check. Same rules as fasten-core:
    // digits joined to a letter or "_" are skipped.
    static func hasCard(_ s: String) -> Bool {
        let ns = s as NSString
        for m in digitRun.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
            let start = m.range.location, end = m.range.location + m.range.length
            let openStart = start == 0 || !isWordUnit(ns.character(at: start - 1))
            let openEnd = end == ns.length || !isWordUnit(ns.character(at: end))
            // The run is ASCII digits, spaces and dashes only.
            let groups: [[UInt8]] = Array(ns.substring(with: m.range).utf8)
                .split(whereSeparator: { $0 == 0x20 || $0 == 0x2D }).map(Array.init)
            func fitsEnd(_ e: Int) -> Bool { e < groups.count || openEnd }
            for i in groups.indices {
                if i == 0 && !openStart { continue }
                if (13...19).contains(groups[i].count) && fitsEnd(i + 1) && luhn(groups[i]) { return true }
                for layout in cardLayouts {
                    let e = i + layout.count
                    if e > groups.count || !fitsEnd(e) { continue }
                    if zip(groups[i..<e], layout).allSatisfy({ $0.count == $1 })
                        && luhn(Array(groups[i..<e].joined())) {
                        return true
                    }
                }
            }
        }
        return false
    }

    // A base64url run, dots included, which may hold a JWT.
    private static let jwtRun = try! NSRegularExpression(pattern: #"[A-Za-z0-9_.\-]+"#)

    // A JWT: eyJ... "." eyJ... "." signature, in base64url. A linear scan
    // with the same match as fasten-core's regex.
    static func hasJwt(_ s: String) -> Bool {
        guard s.contains(".eyJ") else { return false }
        let ns = s as NSString
        for m in jwtRun.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
            let run = ns.substring(with: m.range)
            guard run.contains(".eyJ") else { continue }
            let parts = run.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
            var k = 0
            while k + 2 < parts.count {
                if let h = parts[k].range(of: "eyJ"), h.upperBound < parts[k].endIndex,
                   parts[k + 1].hasPrefix("eyJ"), parts[k + 1].count > 3, !parts[k + 2].isEmpty {
                    return true
                }
                k += 1
            }
        }
        return false
    }

    private static let schemeChars = CharacterSet(charactersIn:
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+.-")

    // Credentials in a URL: scheme://user:password@, user may be empty. The
    // same match as fasten-core's regex, as a scan from each "://": a regex
    // call per "://" would copy the whole string each time on Linux.
    static func hasUrlCredentials(_ s: String) -> Bool {
        let ns = s as NSString
        var from = 0
        while from < ns.length {
            let r = ns.range(of: "://", range: NSRange(location: from, length: ns.length - from))
            if r.location == NSNotFound { return false }
            if r.location > 0,
               let prev = Unicode.Scalar(ns.character(at: r.location - 1)),
               schemeChars.contains(prev),
               userinfoFollows(ns, at: r.location + r.length) {
                return true
            }
            from = r.location + 1
        }
        return false
    }

    // Whether ns has user:password@ at i: no whitespace, "/", "?" or "#"
    // before the "@", a ":" before it, and at least one character between
    // the first ":" and the "@".
    private static func userinfoFollows(_ ns: NSString, at i: Int) -> Bool {
        var colon = -1
        var j = i
        while j < ns.length {
            switch ns.character(at: j) {
            case 0x09...0x0D, 0x20, 0x2F, 0x3F, 0x23: return false  // \t\n\v\f\r space / ? #
            case 0x3A: if colon < 0 { colon = j }                    // :
            case 0x40: return colon >= 0 && j > colon + 1            // @
            default: break
            }
            j += 1
        }
        return false
    }

    private func _keyMatches(_ key: String) -> Bool {
        let range = NSRange(key.startIndex..., in: key)
        return keyPatterns.contains { $0.firstMatch(in: key, range: range) != nil }
    }

    // digits: ASCII digit bytes.
    private static func luhn(_ digits: [UInt8]) -> Bool {
        var sum = 0
        for (i, b) in digits.reversed().enumerated() {
            let d = Int(b - 0x30)
            if i % 2 == 1 { let v = d * 2; sum += v > 9 ? v - 9 : v }
            else           { sum += d }
        }
        return sum % 10 == 0
    }
}
