import Foundation

/// Stdout NDJSON transport — same wire format as all other SDKs.
final class StdoutTransport: @unchecked Sendable {
    private let lock = Lock()
    private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys]
        return e
    }()

    func emit(_ row: AuditRow) {
        guard let data = try? encoder.encode(row),
              let line = String(data: data, encoding: .utf8) else { return }
        lock.withLock { print(line) }
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
        lock.withLock { print(line) }
    }
}

func isoNow() -> String {
    ISO8601DateFormatter().string(from: Date())
}
