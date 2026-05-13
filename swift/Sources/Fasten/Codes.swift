import Foundation
import CFastenCore

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
        severity:       Severity = .info,
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

// JSON representation used when round-tripping through the Rust registry.
private struct RustMeta: Codable {
    var id:             String
    var domain:         String
    var category:       String
    var action:         String
    var severity:       String
    var description:    String
    var emitter:        String
    var retention_class: String

    init(from meta: Meta) {
        id             = meta.id
        domain         = meta.domain
        category       = meta.category
        action         = meta.action
        severity       = meta.severity.rawValue
        description    = meta.description
        emitter        = meta.emitter
        retention_class = meta.retentionClass.rawValue
    }

    var toMeta: Meta {
        Meta(
            id:             id,
            domain:         domain,
            category:       category,
            action:         action,
            severity:       Severity(rawValue: severity) ?? .info,
            description:    description,
            emitter:        emitter,
            retentionClass: RetentionClass(rawValue: retention_class) ?? .medium
        )
    }
}

// Thread-safe global code registry — wraps the Rust global registry plus a
// local cache for zero-allocation lookups on the hot emit path.
final class CodeRegistry: @unchecked Sendable {
    static let shared = CodeRegistry()
    private var cache: [Code: Meta] = [:]
    private let lock = Lock()

    func register(_ domain: String, _ codes: [Code: Meta]) {
        let rustCodes = Dictionary(uniqueKeysWithValues: codes.map { (k, v) in
            (k, RustMeta(from: v))
        })
        guard let codesData = try? JSONEncoder().encode(rustCodes),
              let codesJson = String(data: codesData, encoding: .utf8)
        else { return }

        var errBuf = [UInt8](repeating: 0, count: 4096)
        let rc: Int32 = errBuf.withUnsafeMutableBufferPointer { errPtr in
            fasten_register_codes_buf(
                domain, codesJson,
                errPtr.baseAddress, UInt32(errPtr.count)
            )
        }
        if rc != 0 {
            let msg = String(bytes: errBuf.prefix { $0 != 0 }, encoding: .utf8) ?? "register failed"
            fputs("fasten: register_codes failed (rc=\(rc)): \(msg)\n", stderr)
            return
        }
        lock.withLock { codes.forEach { cache[$0.key] = $0.value } }
    }

    func lookup(_ code: Code) -> Meta? {
        lock.withLock { cache[code] }
    }

    func clear() {
        fasten_registry_clear()
        lock.withLock { cache.removeAll() }
    }
}
