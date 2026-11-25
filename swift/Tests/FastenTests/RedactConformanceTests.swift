import XCTest
@testable import Fasten

// Runs every case in spec/redact-conformance.json. The Rust implementation in
// fasten-core/src/redact.rs passes them all, so a failure here means the Swift
// redactor differs from it.
final class RedactConformanceTests: XCTestCase {

    private struct ConformanceCase: Decodable {
        let name: String
        let group: String
        let check_numbers: Bool?
        let input: AnyCodable
        let expected: AnyCodable
    }

    // Decodes arbitrary JSON into Any.
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
            } else if let i = try? c.decode(Int.self) {
                value = i
            } else if let u = try? c.decode(UInt64.self) {
                value = u
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
        // Walk up from Tests/FastenTests/ to the repo root, then into spec/.
        let here = URL(fileURLWithPath: #file)
        let specURL = here
            .deletingLastPathComponent()   // FastenTests/
            .deletingLastPathComponent()   // Tests/
            .deletingLastPathComponent()   // swift/
            .deletingLastPathComponent()   // repo root
            .appendingPathComponent("spec/redact-conformance.json")
        let data = try Data(contentsOf: specURL)
        struct Spec: Decodable { let cases: [ConformanceCase] }
        return try JSONDecoder().decode(Spec.self, from: data).cases
    }

    // Built at runtime so no sk_live_ literal appears in source, which GitHub
    // push protection would flag.
    func testStripeLiveKey() {
        let key = "sk" + "_live_" + String(repeating: "A", count: 24)
        let r = Redactor()
        let got = r.redact(["note": key])
        XCTAssertEqual(got["note"] as? String, "***STRIPE_KEY***",
                       "value_stripe_live: expected ***STRIPE_KEY***")
    }

    func testNumbersKeptByDefault() {
        let got = Redactor().redact(["card": 4_111_111_111_111_111, "f": 4_111_111_111_111_111.0])
        XCTAssertEqual(got["card"] as? Int, 4_111_111_111_111_111)
        XCTAssertEqual(got["f"] as? Double, 4_111_111_111_111_111.0)
    }

    func testNumberCardValues() {
        let r = Redactor(checkNumbers: true)
        let got = r.redact([
            "card": 4_111_111_111_111_111,
            "u64": UInt64(9_704_000_000_000_000_008),
            "whole_float": 4_111_111_111_111_111.0,
            "ns_float": NSNumber(value: 4_111_111_111_111_111.0),
            "decimal": NSDecimalNumber(string: "4111111111111111"),
            "luhn_fails": 1_234_567_890_123_456,
            "fraction": 4_111_111_111_111_111.5,
            "below_int64_min": -9.704000000000016e18,
            "flag": true,
        ])
        XCTAssertEqual(got["below_int64_min"] as? String, "***CC***")
        XCTAssertEqual(got["card"] as? String, "***CC***")
        XCTAssertEqual(got["u64"] as? String, "***CC***")
        XCTAssertEqual(got["whole_float"] as? String, "***CC***")
        XCTAssertEqual(got["ns_float"] as? String, "***CC***")
        XCTAssertEqual(got["decimal"] as? String, "***CC***")
        XCTAssertEqual(got["luhn_fails"] as? Int, 1_234_567_890_123_456)
        XCTAssertEqual(got["fraction"] as? Double, 4_111_111_111_111_111.5)
        XCTAssertEqual(got["flag"] as? Bool, true)
    }

    func testNumberCardWithCustomReplacement() {
        let got = Redactor(replacement: "[gone]", checkNumbers: true)
            .redact(["card": 4_111_111_111_111_111, "token": "x"])
        XCTAssertEqual(got["card"] as? String, "***CC***")
        XCTAssertEqual(got["token"] as? String, "[gone]")
    }

    func testConformance() throws {
        let cases = try loadCases()

        for c in cases {
            let redactor = Redactor(checkNumbers: c.check_numbers ?? false)
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
        case (let x as Int,    let y as Int):      return x == y
        case (let x as UInt64, let y as UInt64):   return x == y
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

    func testLongValuesRedactQuickly() {
        let r = Redactor()
        // Each just under the 64 KiB cap, so the value is scanned.
        for note in [String(repeating: "eyJ", count: 20_000) + ".eyJ.x",
                     String(repeating: "1 ", count: 30_000),
                     String(repeating: "a://b:", count: 10_000),
                     String(repeating: "Bearer ", count: 9_000)] {
            let t0 = Date()
            let out = r.redact(["note": note])
            let s = Date().timeIntervalSince(t0)
            XCTAssertLessThan(s, 2.0, "redacting \(note.count) chars took \(s) s")
            XCTAssertNil(out["_truncated"], "the value must be under the cap")
        }
    }

    /// A value over FASTEN_MAX_DETAIL_BYTES (64 KiB by default) is replaced
    /// by a truncation marker, as in Python and Go.
    func testValueOverTheCapBecomesAMarker() {
        let out = Redactor().redact(["note": String(repeating: "x", count: 70_000)])
        XCTAssertEqual(out["_truncated"] as? Bool, true)
        XCTAssertEqual(out["_max_detail_bytes"] as? Int, 65_536)
        XCTAssertNil(out["note"])
        let kept = Redactor().redact(["note": String(repeating: "x", count: 60_000)])
        XCTAssertEqual((kept["note"] as? String)?.count, 60_000)
    }

    /// The size is the JSON that gets written: 40,000 newlines are about
    /// 80 KB once escaped, and a Date next to them (written as null) does
    /// not change how they are measured.
    func testSizeIsMeasuredAsWrittenJSON() {
        let newlines = String(repeating: "\n", count: 40_000)
        for detail: [String: Any] in [["note": newlines], ["note": newlines, "t": Date()]] {
            XCTAssertEqual(Redactor().redact(detail)["_truncated"] as? Bool, true, "\(detail.keys.sorted())")
        }
        let ints = Redactor().redact(["n": Array(repeating: 7, count: 9_000), "t": Date()])
        XCTAssertNil(ints["_truncated"], "9000 small ints are about 18 KB as JSON")
    }
}
