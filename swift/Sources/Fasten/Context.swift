import Foundation

/// Holds the request_id for async code. Synchronous code uses RequestScope,
/// which stores it in the current thread's dictionary.
///
///   try await Fasten.withRequestID("req-abc") {
///       try await handle(request)  // emit() calls in here get "req-abc"
///   }
///
///   let scope = RequestScope(id: Fasten.mintID())
///   defer { scope.end() }
enum FastenContext {
    @TaskLocal static var requestID: String? = nil
}

/// Sets the request_id on the current thread until end() or deinit restores
/// the previous value. For code that doesn't use async/await.
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
    // The TaskLocal wins; fall back to the thread dictionary for sync callers.
    if let id = FastenContext.requestID { return id }
    return Thread.current.threadDictionary["fasten.request_id"] as? String
}

func _mintID() -> String {
    "evt-" + UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(16).lowercased()
}

public func mintID() -> String { _mintID() }
