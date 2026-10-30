import Foundation

/// Thread-safe fasten engine — all SDK state lives here.
final class Engine: @unchecked Sendable {

    var serviceID:  String = ""
    var nodeID:     String = ""
    var tenantID:   String?

    private(set) var store:     (any AuditStore)?
    private(set) var transport: StdoutTransport = StdoutTransport()
    private(set) var redactor:  Redactor = Redactor()
    private var drainer:        QueueDrainer?
    private var strategy:       FailureStrategy = .queue

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
        // Flush + stop old drainer before reconfiguring so in-flight rows are not dropped.
        if let old = drainer {
            old.flush(timeout: 5.0)
            old.close()
            drainer = nil
        }
        lock.withLock {
            self.serviceID = serviceID
            self.nodeID    = nodeID
            self.tenantID  = tenantID
            self.store     = store
            self.strategy  = strategy
            self.redactor  = Redactor(extraKeys: extraRedactKeys, replacement: redactReplacement)
        }
        log(level: "error", event: "audit_chain_unavailable", fields: [
            "store":  store.map { "\(type(of: $0))" } ?? "none",
            "reason": "the Swift SDK does not seal rows (spec 2.1); rows are written unsealed",
        ])
        if strategy == .queue, let s = store {
            drainer = QueueDrainer(
                store:          s,
                capacity:       queueCapacity,
                retryInitialMs: 100,
                retryMaxMs:     60_000,
                retryJitter:    true,
                maxAttempts:    50
            )
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

        let row = makeRow(code: code, meta: meta, target: target, actor: actor,
                          actorKind: actorKind, detail: detail, method: method,
                          severity: severity)

        if let d = drainer {
            transport.emit(row)
            d.enqueue(row)
        } else if strategy == .raise, let s = store {
            try s.insert(row)
            transport.emit(row)
        } else {
            transport.emit(row)
        }
    }

    // seq comes from the store (spec 2.1). Swift does not seal, so prev_hash
    // and hash stay empty and verify_chain skips these rows.
    private func makeRow(
        code: Code, meta: Meta, target: String, actor: String,
        actorKind: ActorKind, detail: [String: Any], method: Method,
        severity: Severity?
    ) -> AuditRow {
        let rowID = _mintID()
        return AuditRow(
            wireVersion:  "1",
            id:           rowID,
            originID:     rowID,
            monotonicSeq: 0,
            timestamp:    isoNow(),
            code:         code,
            action:       meta.action,
            severity:     (severity ?? meta.severity).rawValue,
            serviceID:    serviceID,
            sourceNodeID: nodeID,
            tenantID:     tenantID,
            actor:        actor,
            actorKind:    actorKind.rawValue,
            target:       target,
            category:     meta.category,
            domain:       meta.domain,
            method:       method.rawValue,
            requestID:    _currentRequestID() ?? _mintID(),
            detail:       redactor.redact(detail).toAnyCodable(),
            shippedAt:    nil,
            prevHash:     "",
            hash:         ""
        )
    }

    static let redactionCode: Code = "AUDIT_ROW_REDACTED"

    /// Redacts detail on PII rows older than `before` (spec 7). For each row it
    /// first writes an AUDIT_ROW_REDACTED record straight to the store, then
    /// redacts that row, so a failure never leaves destroyed data unrecorded.
    /// Returns the redacted ids.
    func redactExpired(before: Date, reason: String) throws -> [String] {
        guard let store = lock.withLock({ self.store }) else {
            throw FastenError("redactExpired needs an audit store")
        }
        if CodeRegistry.shared.lookup(Self.redactionCode) == nil {
            CodeRegistry.shared.register("fasten", [Self.redactionCode: Meta(
                id: Self.redactionCode, domain: "fasten", category: "retention",
                action: "redact", severity: .warn,
                description: "Audit row detail destroyed under a retention policy",
                emitter: "fasten", retentionClass: .long_)])
        }
        guard let meta = CodeRegistry.shared.lookup(Self.redactionCode) else {
            throw FastenError("cannot register \(Self.redactionCode)")
        }
        let codes = CodeRegistry.shared.piiCodes()
        let refused = try store.countRefusedLegacyRows(before: before, codes: codes)
        if refused > 0 {
            log(level: "warn", event: "pii_redaction_skipped_legacy_form", fields: [
                "rows": refused,
                "reason": "canonical_form_id != 2; detail is inside the hash, so redacting "
                    + "would break the chain. The personal data in these rows still exists.",
            ])
        }
        let candidates = try store.listRedactionCandidates(before: before, codes: codes)
        var redacted: [String] = []
        for c in candidates {
            let record = makeRow(
                code: Self.redactionCode, meta: meta, target: c.id, actor: "system",
                actorKind: .service,
                detail: ["redacted_seq": c.monotonicSeq, "reason": reason, "redacted_id": c.id],
                method: .sdk, severity: nil)
            transport.emit(record)
            try store.insert(record)
            redacted += try store.redactRows(ids: [c.id])
        }
        return redacted
    }

    func log(level: String, event: String, fields: [String: Any]) {
        let requestID = _currentRequestID()
        transport.log(level: level, event: event,
                      serviceID: serviceID.isEmpty ? nil : serviceID,
                      nodeID: nodeID.isEmpty ? nil : nodeID,
                      requestID: requestID, fields: fields)
    }

    func flush(timeout: TimeInterval) -> Bool {
        drainer?.flush(timeout: timeout) ?? true
    }

    func reset() {
        if let d = drainer {
            d.close()
            drainer = nil
        }
        CodeRegistry.shared.clear()
        lock.withLock {
            serviceID = ""; nodeID = ""; tenantID = nil
            store = nil; strategy = .queue
            redactor = Redactor()
        }
    }
}

/// Shared default engine — module-level functions delegate here.
let _defaultEngine = Engine()

/// FastenError wraps any fasten-specific failure. Its localizedDescription is
/// the message, which the drainer keeps as last_error.
public struct FastenError: Error, LocalizedError, CustomStringConvertible {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { "FastenError: \(message)" }
    public var errorDescription: String? { message }
}
