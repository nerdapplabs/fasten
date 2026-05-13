import Foundation
import CFastenCore

/// PII / secret redactor — delegates to libfasten_core for a single
/// canonical implementation shared across all language SDKs.
///
/// The public API is identical to the previous NSRegularExpression-based
/// implementation; the only behavioural difference is that redaction is now
/// performed by the same Rust engine used by Python, Go, C++, and JS.
public final class Redactor: @unchecked Sendable {

    private let extraKeysJson: String   // serialised JSON array, never empty
    private let replacement: String     // empty → Rust uses default "***"
    private let extraVpJson: String     // serialised JSON array of {pattern,replacement}

    public init(
        extraKeys: [String] = [],
        replacement: String = "***",
        extraValuePatterns: [(String, String, String)] = []
    ) {
        self.replacement = replacement == "***" ? "" : replacement
        self.extraKeysJson = (try? JSONEncoder().encode(extraKeys))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
        let vps = extraValuePatterns.map { (_, pat, repl) in
            ["pattern": pat, "replacement": repl]
        }
        self.extraVpJson = (try? JSONEncoder().encode(vps))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
    }

    public func redact(_ dict: [String: Any]) -> [String: Any] {
        guard !dict.isEmpty,
              let inData = try? JSONSerialization.data(withJSONObject: dict),
              let inJson = String(data: inData, encoding: .utf8)
        else { return dict }

        let outSize = max(4096, inData.count * 2 + 1024)
        var outBuf  = [UInt8](repeating: 0, count: outSize)
        var errBuf  = [UInt8](repeating: 0, count: 4096)

        let useDefault = extraKeysJson == "[]" && replacement.isEmpty && extraVpJson == "[]"
        let n: Int32 = outBuf.withUnsafeMutableBufferPointer { outPtr in
            errBuf.withUnsafeMutableBufferPointer { errPtr in
                if useDefault {
                    return fasten_redact_buf(
                        inJson,
                        outPtr.baseAddress, UInt32(outPtr.count),
                        errPtr.baseAddress, UInt32(errPtr.count)
                    )
                } else {
                    return fasten_redact_full_buf(
                        inJson,
                        extraKeysJson,
                        replacement,
                        extraVpJson,
                        outPtr.baseAddress, UInt32(outPtr.count),
                        errPtr.baseAddress, UInt32(errPtr.count)
                    )
                }
            }
        }

        guard n > 0,
              let outData = String(bytes: outBuf[0..<Int(n)], encoding: .utf8).map({ Data($0.utf8) }),
              let result = try? JSONSerialization.jsonObject(with: outData) as? [String: Any]
        else { return dict }

        return result
    }
}
