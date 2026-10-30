import Foundation

/// Stdout NDJSON transport — same wire format as all other SDKs.
final class StdoutTransport: @unchecked Sendable {
    private let lock = Lock()
    /// Where lines go; tests swap it to capture output.
    var write: (String) -> Void = { print($0) }
    private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys]
        return e
    }()

    func emit(_ row: AuditRow) {
        guard let data = try? encoder.encode(row),
              let line = String(data: data, encoding: .utf8) else { return }
        lock.withLock { write(line) }
    }

    func log(level: String, event: String, serviceID: String?, nodeID: String?,
             requestID: String?, fields: [String: Any]) {
        var obj: [String: Any] = [
            "timestamp": isoNow(),
            "level": level,
            "event": event,
        ]
        if let s = serviceID  { obj["service_id"] = s }
        if let n = nodeID     { obj["node_id"]    = n }
        if let r = requestID  { obj["request_id"] = r }
        obj.merge(fields) { _, new in new }

        guard let data = try? JSONSerialization.data(withJSONObject: obj,
                                                     options: [.sortedKeys]),
              let line = String(data: data, encoding: .utf8) else { return }
        lock.withLock { write(line) }
    }
}

func isoNow() -> String {
    ISO8601DateFormatter().string(from: Date())
}

/// Spec 4.3 canonical form, e.g. 2026-08-21T10:00:00.500000Z. Used for
/// cutoffs so they compare correctly against rows from the other SDKs.
func canonicalTS(_ date: Date) -> String {
    let t = date.timeIntervalSince1970
    let secs = t.rounded(.down)
    let micros = Int(((t - secs) * 1_000_000).rounded(.down))
    let base = ISO8601DateFormatter().string(from: Date(timeIntervalSince1970: secs))
    return String(base.dropLast()) + String(format: ".%06dZ", micros)
}
