import Foundation

/// Wire-format audit row — matches spec/row-schema.json v1.
public struct AuditRow: Codable, Sendable {
    public let wireVersion:    String
    public let id:             String
    public let originID:       String
    public let monotonicSeq:   Int
    public let timestamp:      String      // ISO-8601 UTC
    public let code:           String
    public let action:         String
    public let severity:       String
    public let serviceID:      String
    public let sourceNodeID:   String
    public let tenantID:       String?
    public let actor:          String
    public let actorKind:      String
    public let target:         String
    public let category:       String
    public let domain:         String
    public let method:         String
    public let requestID:      String
    public let detail:         [String: AnyCodable]
    public let shippedAt:      String?
    public let prevHash:       String
    public let hash:           String

    enum CodingKeys: String, CodingKey {
        case wireVersion   = "wire_version"
        case id, originID  = "origin_id"
        case monotonicSeq  = "monotonic_seq"
        case timestamp, code, action, severity
        case serviceID     = "service_id"
        case sourceNodeID  = "source_node_id"
        case tenantID      = "tenant_id"
        case actor, actorKind = "actor_kind"
        case target, category, domain, method
        case requestID     = "request_id"
        case detail, shippedAt = "shipped_at"
        case prevHash      = "prev_hash"
        case hash
    }
}

/// Syslog row — for /logs/sys stream.
public struct SysRow: Codable, Sendable {
    public let timestamp:  String
    public let level:      String
    public let event:      String
    public let serviceID:  String?
    public let nodeID:     String?
    public let requestID:  String?
    public let fields:     [String: AnyCodable]

    enum CodingKeys: String, CodingKey {
        case timestamp, level, event
        case serviceID = "service_id"
        case nodeID    = "node_id"
        case requestID = "request_id"
        case fields
    }
}

/// Type-erased Codable value for heterogeneous JSON dictionaries.
public struct AnyCodable: Codable, Sendable, CustomStringConvertible {
    public let value: Any

    public var description: String { "\(value)" }

    public init(_ value: Any) { self.value = value }

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if      let v = try? c.decode(Bool.self)              { value = v }
        else if let v = try? c.decode(Int.self)               { value = v }
        else if let v = try? c.decode(Double.self)            { value = v }
        else if let v = try? c.decode(String.self)            { value = v }
        else if let v = try? c.decode([String: AnyCodable].self) { value = v }
        else if let v = try? c.decode([AnyCodable].self)      { value = v }
        else                                                   { value = NSNull() }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch value {
        case let v as Bool:                 try c.encode(v)
        case let v as Int:                  try c.encode(v)
        case let v as Double:               try c.encode(v)
        case let v as String:               try c.encode(v)
        case let v as [String: AnyCodable]: try c.encode(v)
        case let v as [AnyCodable]:         try c.encode(v)
        default:                            try c.encodeNil()
        }
    }
}

extension Dictionary where Key == String, Value == Any {
    func toAnyCodable() -> [String: AnyCodable] {
        mapValues { AnyCodable($0) }
    }
}
