import Foundation

public typealias Code = String

public enum Severity: String, Codable, Sendable {
    case debug, info, warn, error
}

public enum RetentionClass: String, Codable, Sendable {
    case short_, long_
    // YAML/string aliases
    public init?(string: String) {
        switch string.lowercased() {
        case "short": self = .short_
        case "long":  self = .long_
        default:      return nil
        }
    }
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
        id: Code,
        domain: String,
        category: String,
        action: String,
        severity: Severity = .info,
        description: String,
        emitter: String,
        retentionClass: RetentionClass = .long_
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

// Thread-safe global code registry.
final class CodeRegistry: @unchecked Sendable {
    static let shared = CodeRegistry()
    private var catalog: [Code: Meta] = [:]
    private let lock = Lock()

    func register(_ codes: [Code: Meta]) {
        lock.withLock { catalog.merge(codes) { _, new in new } }
    }

    func lookup(_ code: Code) -> Meta? {
        lock.withLock { catalog[code] }
    }
}
