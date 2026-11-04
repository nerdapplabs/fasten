import Foundation

/// Holds all SDK state. The Fasten enum forwards to a shared instance.
final class Engine: @unchecked Sendable {

    var serviceID:  String = ""
    var nodeID:     String = ""
    var tenantID:   String?

    private(set) var store:     (any AuditStore)?
    private(set) var transport: StdoutTransport = StdoutTransport()
    private(set) var redactor:  Redactor = Redactor()
    private var drainer:        QueueDrainer?
    private var retiring:       [QueueDrainer] = []   // old drainers a re-init is stopping
    private var strategy:       FailureStrategy = .queue

    // Internal so tests can shorten them.
    var installFlushTimeout: TimeInterval = 5.0
    var stopTimeout:         TimeInterval = 1.0
    var retryInitialMs:      Double       = 100
    var maxAttempts:         Int          = 50

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
        // Spec §10: build the new drainer and swap it in under the lock, so
        // no emit sees the slot empty, then flush and stop the old one.
        var next: QueueDrainer? = nil
        if strategy == .queue, let s = store {
            next = QueueDrainer(
                store:          s,
                capacity:       queueCapacity,
                retryInitialMs: retryInitialMs,
                retryMaxMs:     60_000,
                retryJitter:    true,
                maxAttempts:    maxAttempts,
                sysLog: { [weak self] level, event, fields in
                    self?.log(level: level, event: event, fields: fields)
                }
            )
        }
        // The old drainer's unstored count is read at the swap, so a row
        // pending then that dead-letters before retire() is still counted.
        let (old, unstoredBefore): (QueueDrainer?, Int) = lock.withLock {
            self.serviceID = serviceID
            self.nodeID    = nodeID
            self.tenantID  = tenantID
            self.store     = store
            self.strategy  = strategy
            self.redactor  = Redactor(extraKeys: extraRedactKeys, replacement: redactReplacement)
            let old = drainer
            drainer = next
            if let old { retiring.append(old) }
            return (old, old?.unstoredTotal ?? 0)
        }
        log(level: "error", event: "audit_chain_unavailable", fields: [
            "store":  store.map { "\(type(of: $0))" } ?? "none",
            "reason": "the Swift SDK does not seal rows (spec 2.1); rows are written unsealed",
        ])
        if let old { retire(old, unstoredBefore: unstoredBefore) }
    }

    // Give the old queue up to 5 s to drain so rows already emitted reach the old store.
    private func retire(_ old: QueueDrainer, unstoredBefore: Int) {
        let flushed = old.flush(timeout: installFlushTimeout)
        old.close(timeout: stopTimeout)
        let unstored = old.unstoredTotal - unstoredBefore
        if !flushed || unstored > 0 {
            log(level: "warn", event: "audit_drain_install_incomplete",
                fields: ["flushed": flushed, "unstored": unstored])
        }
        lock.withLock { retiring.removeAll { $0 === old } }
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

        let (d, strategy, store) = lock.withLock { (drainer, self.strategy, self.store) }
        if let d {
            transport.emit(row)
            // A stopped drainer refuses the row; store it here instead.
            if !d.enqueue(row) { storeInline(row, in: d.store, refused: true) }
        } else if strategy == .raise, let s = store {
            try s.insert(row)
            transport.emit(row)
        } else if let s = store {
            // Queue mode after close().
            transport.emit(row)
            storeInline(row, in: s, refused: false)
        } else {
            transport.emit(row)
        }
    }

    private func storeInline(_ row: AuditRow, in store: any AuditStore, refused: Bool) {
        do {
            try store.insert(row)
            if refused {
                log(level: "info", event: "audit_drain_stored_inline", fields: ["row_id": row.id])
            }
        } catch {
            log(level: "error", event: "audit_sync_fallback_failed",
                fields: ["error": describeError(error), "row_id": row.id])
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
        let (serviceID, nodeID, tenantID, redactor) =
            lock.withLock { (self.serviceID, self.nodeID, self.tenantID, self.redactor) }
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
    /// Returns the redacted ids. `codes` defaults to the registry's PII codes.
    func redactExpired(before: Date, reason: String, codes: [Code]? = nil) throws -> [String] {
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
        let codes = codes ?? CodeRegistry.shared.piiCodes()
        if codes.isEmpty {
            log(level: "warn", event: "pii_redaction_no_codes", fields: [
                "reason": "no PII codes registered in this process and none passed; nothing redacted",
            ])
            return []
        }
        let refused = try store.countRefusedLegacyRows(before: before, codes: codes)
        if refused > 0 {
            log(level: "warn", event: "pii_redaction_skipped_legacy_form", fields: [
                "rows": refused,
                "reason": "canonical_form_id != 2; redacting would break the chain. The "
                    + "personal data in these rows still exists. On a table only Swift wrote, "
                    + "SQLiteStore.clearLegacySwiftHashes() makes them redactable.",
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
        let (serviceID, nodeID, redactor) = lock.withLock { (self.serviceID, self.nodeID, self.redactor) }
        transport.log(level: level, event: event,
                      serviceID: serviceID.isEmpty ? nil : serviceID,
                      nodeID: nodeID.isEmpty ? nil : nodeID,
                      requestID: requestID, fields: fields,
                      // The whole line, as Go and Python do: a secret can be in the event.
                      redact: redactor.redact)
    }

    /// Also waits for old drainers a concurrent re-init is still flushing.
    func flush(timeout: TimeInterval) -> Bool {
        let all = lock.withLock { retiring + (drainer.map { [$0] } ?? []) }
        let deadline = Date().addingTimeInterval(timeout)
        var ok = true
        for d in all {
            ok = d.flush(timeout: max(0, deadline.timeIntervalSinceNow)) && ok
        }
        return ok
    }

    /// Stops the drainer and any old ones a re-init is retiring (spec §10),
    /// all within `timeout`. Returns false if any of them lost a row.
    /// Later emits in queue mode write to the store inline.
    func close(timeout: TimeInterval) -> Bool {
        let all = lock.withLock { () -> [QueueDrainer] in
            let d = drainer
            drainer = nil
            return retiring + (d.map { [$0] } ?? [])
        }
        // Stop them all first so they drain in parallel.
        for d in all { d.requestStop() }
        let deadline = Date().addingTimeInterval(timeout)
        var ok = true
        for d in all {
            ok = d.close(timeout: max(0, deadline.timeIntervalSinceNow)) && ok
        }
        return ok
    }

    // Without this, an engine dropped before close() would leave its drain
    // thread waiting forever. It does not wait for the rows.
    deinit {
        drainer?.requestStop()
        for d in retiring { d.requestStop() }
    }

    func reset() {
        _ = close(timeout: stopTimeout)
        CodeRegistry.shared.clear()
        lock.withLock {
            serviceID = ""; nodeID = ""; tenantID = nil
            store = nil; strategy = .queue
            redactor = Redactor()
        }
    }
}

/// The engine behind the static Fasten API.
let _defaultEngine = Engine()

/// Error thrown by fasten itself (unknown code, bad table name, SQLite errors).
/// Its localizedDescription is the message; the drainer's last_error is
/// "FastenError: <message>".
public struct FastenError: Error, LocalizedError, CustomStringConvertible {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { "FastenError: \(message)" }
    public var errorDescription: String? { message }
}
