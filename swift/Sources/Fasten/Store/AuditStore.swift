import Foundation

/// A row `listRedactionCandidates` would redact. `monotonicSeq` goes into the
/// AUDIT_ROW_REDACTED detail (spec 7.2); it is only unique per source node.
public struct RedactionCandidate: Sendable, Equatable {
    public let id: String
    public let monotonicSeq: Int

    public init(id: String, monotonicSeq: Int) {
        self.id = id
        self.monotonicSeq = monotonicSeq
    }
}

/// Minimal persistence contract — same shape as every other SDK's AuditRepository.
///
/// `insert` with `monotonicSeq == 0` must assign the next seq for the row's
/// `source_node_id` inside the insert transaction (spec 2.1). A non-zero seq
/// is written as given.
public protocol AuditStore: Sendable {
    func insert(_ row: AuditRow) throws
    func ping() throws
    func maxMonotonicSeq() -> Int

    /// Rows of `codes` older than `before` whose detail can be redacted
    /// without breaking a chain: unsealed rows, or form "2" rows.
    func listRedactionCandidates(before: Date, codes: [Code]) throws -> [RedactionCandidate]

    /// Set `detail` to null on the given rows (spec 7.1). Never deletes.
    /// Idempotent; returns `ids`.
    func redactRows(ids: [String]) throws -> [String]
}

extension AuditStore {
    public func listRedactionCandidates(before: Date, codes: [Code]) throws -> [RedactionCandidate] {
        throw FastenError("\(type(of: self)) does not support redaction (spec 7.1)")
    }

    public func redactRows(ids: [String]) throws -> [String] {
        throw FastenError("\(type(of: self)) does not support redaction (spec 7.1)")
    }
}

/// In-memory store — tests + stdout-only deployments.
public final class MemoryStore: AuditStore, @unchecked Sendable {
    private var rows: [AuditRow] = []
    private var redacted: Set<String> = []
    private let lock = Lock()

    public init() {}

    public func insert(_ row: AuditRow) throws {
        lock.withLock {
            var r = row
            if r.monotonicSeq == 0 {
                let max = rows.filter { $0.sourceNodeID == row.sourceNodeID }
                    .map(\.monotonicSeq).max() ?? 0
                r = row.withMonotonicSeq(max + 1)
            }
            rows.append(r)
        }
    }

    public func ping() throws {}

    public func maxMonotonicSeq() -> Int {
        lock.withLock { rows.map(\.monotonicSeq).max() ?? 0 }
    }

    public func listRedactionCandidates(before: Date, codes: [Code]) throws -> [RedactionCandidate] {
        let cutoff = canonicalTS(before)
        let wanted = Set(codes)
        return lock.withLock {
            rows.filter {
                $0.hash.isEmpty && wanted.contains($0.code)
                    && $0.timestamp < cutoff && !redacted.contains($0.id)
            }
            .sorted { $0.monotonicSeq < $1.monotonicSeq }
            .map { RedactionCandidate(id: $0.id, monotonicSeq: $0.monotonicSeq) }
        }
    }

    public func redactRows(ids: [String]) throws -> [String] {
        let wanted = Set(ids)
        lock.withLock {
            for i in rows.indices where wanted.contains(rows[i].id) && rows[i].hash.isEmpty {
                rows[i] = rows[i].withDetail([:])
                redacted.insert(rows[i].id)
            }
        }
        return ids
    }

    public func all() -> [AuditRow] { lock.withLock { rows } }

    /// True once `redactRows` has destroyed this row's detail.
    public func isRedacted(_ id: String) -> Bool { lock.withLock { redacted.contains(id) } }
}
