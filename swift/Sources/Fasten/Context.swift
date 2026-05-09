import Foundation

/// request_id propagation via Swift's structured concurrency (@TaskLocal).
///
/// Usage:
///   Fasten.withRequestID("req-abc") {
///       await Fasten.emit("USER_CREATED", target: "u-42", actor: "admin")
///   }
///   // or in synchronous code via RequestScope:
///   let scope = RequestScope(id: Fasten.mintID())
///   defer { scope.end() }
enum FastenContext {
    @TaskLocal static var requestID: String? = nil
}

/// Synchronous RAII scope for request_id — for code that can't use async/await.
public final class RequestScope {
    private let previous: String?

    public init(id: String) {
        previous = Thread.current.threadDictionary["fasten.request_id"] as? String
        Thread.current.threadDictionary["fasten.request_id"] = id
    }

    deinit { end() }

    public func end() {
        if let p = previous {
            Thread.current.threadDictionary["fasten.request_id"] = p
        } else {
            Thread.current.threadDictionary.removeObject(forKey: "fasten.request_id")
        }
    }
}

func _currentRequestID() -> String? {
    // Prefer async TaskLocal; fall back to thread-local for sync callers.
    if let id = FastenContext.requestID { return id }
    return Thread.current.threadDictionary["fasten.request_id"] as? String
}

func _mintID() -> String {
    "evt-" + UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(16).lowercased()
}

public func mintID() -> String { _mintID() }
