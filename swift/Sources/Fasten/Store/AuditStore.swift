import Foundation

/// Minimal persistence contract — same shape as every other SDK's AuditRepository.
public protocol AuditStore: Sendable {
    func insert(_ row: AuditRow) throws
    func ping() throws
    func maxMonotonicSeq() -> Int
}

/// In-memory store — tests + stdout-only deployments.
public final class MemoryStore: AuditStore, @unchecked Sendable {
    private var rows: [AuditRow] = []
    private let lock = Lock()

    public init() {}

    public func insert(_ row: AuditRow) throws {
        lock.withLock { rows.append(row) }
    }

    public func ping() throws {}

    public func maxMonotonicSeq() -> Int {
        lock.withLock { rows.map(\.monotonicSeq).max() ?? 0 }
    }

    public func all() -> [AuditRow] { lock.withLock { rows } }
}
