import Foundation

public typealias Code = String

public enum Severity: String, Codable, Sendable {
    case debug, info, warn, error
}

public enum RetentionClass: String, Codable, Sendable {
    case short_  = "short"
    case medium  = "medium"
    case long_   = "long"
}

public enum ActorKind: String, Codable, Sendable {
    case user, service, system, device
}

public enum Method: String, Codable, Sendable {
    case sdk, http, mqtt, scheduler, cli, grpc, amqp, kafka
}

public struct Meta: Sendable {
    public let id:             Code
    public let domain:         String
    public let category:       String
    public let action:         String
    public let severity:       Severity
    public let description:    String
    public let emitter:        String
    public let retentionClass: RetentionClass

    public init(
        id:             Code,
        domain:         String,
        category:       String,
        action:         String,
        severity:       Severity       = .info,
        description:    String,
        emitter:        String,
        retentionClass: RetentionClass = .medium
    ) {
        self.id             = id
        self.domain         = domain
        self.category       = category
        self.action         = action
        self.severity       = severity
        self.description    = description
        self.emitter        = emitter
        self.retentionClass = retentionClass
    }
}

// Thread-safe global code registry — pure Swift, no native dependencies.
final class CodeRegistry: @unchecked Sendable {
    static let shared = CodeRegistry()
    private var cache: [Code: Meta] = [:]
    private let lock = Lock()

    private static let upperSnakeRE: NSRegularExpression = {
        try! NSRegularExpression(pattern: "^[A-Z][A-Z0-9_]*$")
    }()

    func register(_ domain: String, _ codes: [Code: Meta]) {
        // Two-pass: validate all before committing any.
        for (key, meta) in codes {
            let range = NSRange(key.startIndex..., in: key)
            guard CodeRegistry.upperSnakeRE.firstMatch(in: key, range: range) != nil else {
                fputs("fasten: invalid code key '\(key)' — must be UPPER_SNAKE_CASE\n", stderr)
                return
            }
            guard key == meta.id else {
                fputs("fasten: code key '\(key)' does not match meta.id '\(meta.id)'\n", stderr)
                return
            }
            guard meta.domain == domain else {
                fputs("fasten: code '\(key)' has domain '\(meta.domain)' but registered under '\(domain)'\n", stderr)
                return
            }
        }
        lock.withLock { codes.forEach { cache[$0.key] = $0.value } }
    }

    func lookup(_ code: Code) -> Meta? {
        lock.withLock { cache[code] }
    }

    func clear() {
        lock.withLock { cache.removeAll() }
    }
}
