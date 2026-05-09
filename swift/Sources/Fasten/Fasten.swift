import Foundation

/// fasten — audit + correlation SDK for Swift.
///
/// ```swift
/// import Fasten
///
/// // 1. Register codes (once, at app start)
/// Fasten.register("user", codes: [
///     "USER_CREATED": Meta(id: "USER_CREATED", domain: "user",
///                          category: "account", action: "create",
///                          description: "New user", emitter: "auth-svc"),
/// ])
///
/// // 2. Configure
/// let store = try SQLiteStore(path: "./fasten-audit.db")
/// try Fasten.configure(serviceID: "auth-svc", nodeID: "host-01", store: store)
///
/// // 3. Emit
/// try Fasten.emit("USER_CREATED", target: "u-42", actor: "admin",
///                 detail: ["email": "alice@example.com"])
/// Fasten.log.info("signup_complete", fields: ["user_id": "u-42"])
///
/// // 4. Propagate request_id
/// Fasten.withRequestID(Fasten.mintID()) {
///     try? Fasten.emit("USER_CREATED", target: "u-42", actor: "admin")
/// }
///
/// // 5. Shutdown
/// Fasten.flush(timeout: 5.0)
/// ```
public enum Fasten {

    // ── Setup ─────────────────────────────────────────────────────────────

    /// Register audit codes.  Call once per domain at process start.
    public static func register(_ domain: String, codes: [Code: Meta]) {
        CodeRegistry.shared.register(domain, codes)
    }

    /// Configure fasten.  Must be called before `emit()`.
    ///
    /// - Parameters:
    ///   - serviceID: Logical service name (e.g. "auth-service").
    ///   - nodeID:    Instance/hostname identifier.
    ///   - tenantID:  Optional tenant for multi-tenant deployments.
    ///   - store:     Audit store; `nil` = stdout-only (no persistence).
    ///   - strategy:  `.queue` (default, non-blocking) or `.raise`.
    ///   - extraRedactKeys: Additional key names to redact in `detail`.
    public static func configure(
        serviceID: String,
        nodeID: String,
        tenantID: String? = nil,
        store: (any AuditStore)? = nil,
        strategy: FailureStrategy = .queue,
        queueCapacity: Int = 500,
        extraRedactKeys: [String] = [],
        redactReplacement: String = "***"
    ) throws {
        _defaultEngine.configure(
            serviceID: serviceID, nodeID: nodeID, tenantID: tenantID,
            store: store, extraRedactKeys: extraRedactKeys,
            redactReplacement: redactReplacement,
            strategy: strategy, queueCapacity: queueCapacity
        )
    }

    // ── Emit ──────────────────────────────────────────────────────────────

    /// Emit an audit row.  Non-blocking in `.queue` mode.
    public static func emit(
        _ code: Code,
        target: String,
        actor: String,
        actorKind: ActorKind = .user,
        detail: [String: Any] = [:],
        method: Method = .sdk,
        severity: Severity? = nil
    ) throws -> Void {
        try _defaultEngine.emit(code: code, target: target, actor: actor,
                                actorKind: actorKind, detail: detail,
                                method: method, severity: severity)
    }

    // ── Structured logging ────────────────────────────────────────────────

    public enum log {
        public static func debug(_ event: String, fields: [String: Any] = [:]) {
            _defaultEngine.log(level: "debug", event: event, fields: fields)
        }
        public static func info(_ event: String, fields: [String: Any] = [:]) {
            _defaultEngine.log(level: "info", event: event, fields: fields)
        }
        public static func warn(_ event: String, fields: [String: Any] = [:]) {
            _defaultEngine.log(level: "warn", event: event, fields: fields)
        }
        public static func error(_ event: String, fields: [String: Any] = [:]) {
            _defaultEngine.log(level: "error", event: event, fields: fields)
        }
    }

    // ── Context ───────────────────────────────────────────────────────────

    /// Run `body` with a pinned request_id (async-safe via TaskLocal).
    public static func withRequestID<T>(
        _ id: String,
        operation body: () throws -> T
    ) rethrows -> T {
        let scope = RequestScope(id: id)
        defer { scope.end() }
        return try body()
    }

    /// Run `body` with a pinned request_id in a structured-concurrency Task.
    public static func withRequestID<T>(
        _ id: String,
        operation body: () async throws -> T
    ) async rethrows -> T {
        try await FastenContext.$requestID.withValue(id) {
            try await body()
        }
    }

    /// Returns the current request_id or nil.
    public static var currentRequestID: String? { _currentRequestID() }

    /// Mint a new unique request_id.
    public static func mintID() -> String { _mintID() }

    // ── Lifecycle ─────────────────────────────────────────────────────────

    /// Block until all queued rows are drained (or timeout elapses).
    /// Returns true iff fully drained.
    @discardableResult
    public static func flush(timeout: TimeInterval = 5.0) -> Bool {
        _defaultEngine.flush(timeout: timeout)
    }

    /// Reset the default engine — for tests only.
    public static func _resetForTests() {
        _defaultEngine.reset()
    }
}
