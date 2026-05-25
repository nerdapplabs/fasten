import XCTest
@testable import Fasten

// Redact conformance — loads spec/redact-conformance.json, runs every case.
//
// The spec is the single source of truth; fasten-core/src/redact.rs is canonical.
// All SDKs must pass every case; failures indicate a divergence from the Rust impl.
final class RedactConformanceTests: XCTestCase {

    private struct ConformanceCase: Decodable {
        let name: String
        let group: String
        let input: AnyCodable
        let expected: AnyCodable
    }

    // AnyCodable: thin wrapper that decodes arbitrary JSON into Any.
    private struct AnyCodable: Decodable {
        let value: Any

        init(from decoder: Decoder) throws {
            let c = try decoder.singleValueContainer()
            if let d = try? c.decode([String: AnyCodable].self) {
                value = d.mapValues { $0.value }
            } else if let a = try? c.decode([AnyCodable].self) {
                value = a.map { $0.value }
            } else if let s = try? c.decode(String.self) {
                value = s
            } else if let n = try? c.decode(Double.self) {
                value = n
            } else if let b = try? c.decode(Bool.self) {
                value = b
            } else {
                value = NSNull()
            }
        }
    }

    private func loadCases() throws -> [ConformanceCase] {
        // Walk up from Tests/FastenTests/ to fasten/ then into spec/.
        let here = URL(fileURLWithPath: #file)
        let specURL = here
            .deletingLastPathComponent()   // FastenTests/
            .deletingLastPathComponent()   // Tests/
            .deletingLastPathComponent()   // swift/
            .deletingLastPathComponent()   // fasten/   (repo root)
            .appendingPathComponent("spec/redact-conformance.json")
        let data = try Data(contentsOf: specURL)
        struct Spec: Decodable { let cases: [ConformanceCase] }
        return try JSONDecoder().decode(Spec.self, from: data).cases
    }

    // Stripe live key — constructed at runtime so the literal sk_live_<24+ chars>
    // never appears in source (GitHub push-protection false-positive).
    func testStripeLiveKey() {
        let key = "sk" + "_live_" + String(repeating: "A", count: 24)
        let r = Redactor()
        let got = r.redact(["note": key])
        XCTAssertEqual(got["note"] as? String, "***STRIPE_KEY***",
                       "value_stripe_live: expected ***STRIPE_KEY***")
    }

    func testConformance() throws {
        let redactor = Redactor()
        let cases = try loadCases()

        for c in cases {
            guard let input = c.input.value as? [String: Any] else {
                XCTFail("[\(c.name)] input is not a [String:Any]"); continue
            }
            guard let expected = c.expected.value as? [String: Any] else {
                XCTFail("[\(c.name)] expected is not a [String:Any]"); continue
            }
            let got = redactor.redact(input)
            XCTAssert(
                _equalAny(got, expected),
                "[\(c.name)] got \(got), want \(expected)"
            )
        }
    }

    // Structural equality for Any values produced by JSON decoding.
    private func _equalAny(_ a: Any, _ b: Any) -> Bool {
        switch (a, b) {
        case (let x as String, let y as String):   return x == y
        case (let x as Double, let y as Double):   return x == y
        case (let x as Bool,   let y as Bool):     return x == y
        case (_ as NSNull,     _ as NSNull):       return true
        case (let x as [String: Any], let y as [String: Any]):
            guard x.keys.sorted() == y.keys.sorted() else { return false }
            return x.allSatisfy { k, v in _equalAny(v, y[k]!) }
        case (let x as [Any], let y as [Any]):
            guard x.count == y.count else { return false }
            return zip(x, y).allSatisfy { _equalAny($0, $1) }
        default: return false
        }
    }
}
