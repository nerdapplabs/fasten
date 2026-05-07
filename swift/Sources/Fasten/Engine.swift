import Foundation
import Crypto

/// Thread-safe fasten engine — all SDK state lives here.
final class Engine: @unchecked Sendable {

    var serviceID:  String = ""
    var nodeID:     String = ""
    var tenantID:   String?

    private(set) var store:     (any AuditStore)?
    private(set) var transport: StdoutTransport = StdoutTransport()
    private(set) var redactor:  Redactor = Redactor()
    private(set) var queue:     AuditQueue?

    private var seq:        Int = 0
    private var prevHash:   String = "genesis"
    private let lock        = Lock()

    func configure(
        serviceID: String,
        nodeID: String,
        tenantID: String? = nil,
        store: (any AuditStore)? = nil,
        extraRedactKeys: [String] = [],
        redactReplacement: String = "***",
        strategy: FailureStrategy = .queue,
        queueCapacity: Int = 500
    ) {
        queue?.stop()
        lock.withLock {
            self.serviceID = serviceID
            self.nodeID    = nodeID
            self.tenantID  = tenantID
            self.store     = store
            self.redactor  = Redactor(extraKeys: extraRedactKeys, replacement: redactReplacement)
            self.seq       = store?.maxMonotonicSeq() ?? 0
            self.prevHash  = "genesis"
        }
        if let s = store {
            self.queue = AuditQueue(store: s, transport: transport,
                                    capacity: queueCapacity, strategy: strategy)
        }
    }

    func emit(
        code: Code,
        target: String,
        actor: String,
        actorKind: ActorKind = .user,
        detail: [String: Any] = [:],
        method: Method = .sdk,
        severity: Severity? = nil
    ) throws {
        let meta = CodeRegistry.shared.lookup(code)
        guard let meta else {
            throw FastenError("unknown code \(code) — call Fasten.register() first")
        }

        let redactedDetail = redactor.redact(detail)
        let requestID = _currentRequestID() ?? _mintID()
        let rowID     = _mintID()
        let ts        = isoNow()
        let sev       = severity ?? meta.severity

        // Compute hash chain under lock.
        let (nextSeq, ph, rowHash) = lock.withLock { () -> (Int, String, String) in
            seq += 1
            let s = seq
            let ph = prevHash
            // Canonical JSON for hashing (sorted keys, no whitespace).
            let canonical: [String: Any] = [
                "id": rowID, "code": code, "monotonic_seq": s,
                "timestamp": ts, "actor": actor, "target": target,
                "request_id": requestID, "prev_hash": ph,
            ]
            let data = (try? JSONSerialization.data(withJSONObject: canonical,
                                                    options: [.sortedKeys])) ?? Data()
            let digest = SHA256.hash(data: data)
            let h = digest.map { String(format: "%02x", $0) }.joined()
            prevHash = h
            return (s, ph, h)
        }

        let detailCodable = redactedDetail.toAnyCodable()

        let row = AuditRow(
            wireVersion:  "1",
            id:           rowID,
            originID:     rowID,
            monotonicSeq: nextSeq,
            timestamp:    ts,
            code:         code,
            action:       meta.action,
            severity:     sev.rawValue,
            serviceID:    serviceID,
            sourceNodeID: nodeID,
            tenantID:     tenantID,
            actor:        actor,
            actorKind:    actorKind.rawValue,
            target:       target,
            category:     meta.category,
            domain:       meta.domain,
            method:       method.rawValue,
            requestID:    requestID,
            detail:       detailCodable,
            shippedAt:    nil,
            prevHash:     ph,
            hash:         rowHash
        )

        if let q = queue {
            try q.enqueue(row)
        } else {
            transport.emit(row)
        }
    }

    func log(level: String, event: String, fields: [String: Any]) {
        let requestID = _currentRequestID()
        transport.log(level: level, event: event,
                      serviceID: serviceID.isEmpty ? nil : serviceID,
                      nodeID: nodeID.isEmpty ? nil : nodeID,
                      requestID: requestID, fields: fields)
    }

    func flush(timeout: TimeInterval) -> Bool {
        queue?.flush(timeout: timeout) ?? true
    }

    func reset() {
        queue?.stop()
        lock.withLock {
            serviceID = ""; nodeID = ""; tenantID = nil
            store = nil; queue = nil
            seq = 0; prevHash = "genesis"
            redactor = Redactor()
        }
    }
}

/// Shared default engine — module-level functions delegate here.
let _defaultEngine = Engine()

/// FastenError wraps any fasten-specific failure.
public struct FastenError: Error, CustomStringConvertible {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { "FastenError: \(message)" }
}
