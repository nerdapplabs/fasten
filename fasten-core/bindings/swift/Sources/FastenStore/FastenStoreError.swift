/// Thrown when the native store backend returns an error.
public struct FastenStoreError: Error, CustomStringConvertible {
    public let message: String

    public init(_ message: String) {
        self.message = message
    }

    public var description: String { "FastenStoreError: \(message)" }
}
