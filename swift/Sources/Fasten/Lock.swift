import Foundation

/// NSLock wrapper with a closure-based withLock, available on Apple and Linux.
final class Lock: @unchecked Sendable {
    private let _lock = NSLock()

    @discardableResult
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        _lock.lock()
        defer { _lock.unlock() }
        return try body()
    }
}
