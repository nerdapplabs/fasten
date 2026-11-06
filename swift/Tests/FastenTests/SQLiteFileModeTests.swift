#if !os(Windows)
import Foundation
import XCTest
@testable import Fasten

/// Under the usual 022 umask SQLite alone would create these files 0644.
final class SQLiteFileModeTests: XCTestCase {
    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("fasten-mode-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    private func mode(_ path: String) throws -> Int {
        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        return (attrs[.posixPermissions] as! NSNumber).intValue
    }

    func testNewFileIs0600() throws {
        let path = dir.appendingPathComponent("audit.db").path
        _ = try SQLiteStore(path: path)
        XCTAssertEqual(try mode(path), 0o600)
    }

    func testExistingFileKeepsItsMode() throws {
        let path = dir.appendingPathComponent("audit.db").path
        XCTAssertTrue(FileManager.default.createFile(
            atPath: path, contents: nil, attributes: [.posixPermissions: 0o644]))
        _ = try SQLiteStore(path: path)
        XCTAssertEqual(try mode(path), 0o644)
    }

    func testFileURIIs0600() throws {
        let path = dir.appendingPathComponent("my audit.db").path
        let uri = "file://" + path.replacingOccurrences(of: " ", with: "%20") + "?cache=private"
        _ = try SQLiteStore(path: uri)
        XCTAssertEqual(try mode(path), 0o600)
    }

    func testReadOnlyFileURICreatesNothing() throws {
        let path = dir.appendingPathComponent("audit.db").path
        XCTAssertThrowsError(try SQLiteStore(path: "file:\(path)?mode=ro"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
    }

    func testFileURIWithoutAFileToCreateCreatesNothing() throws {
        let path = dir.appendingPathComponent("audit.db").path
        _ = try? SQLiteStore(path: "file:\(path)?vfs=memdb")
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        // Checked on the helper: some SQLite versions (macOS 3.51) create an
        // empty file for immutable=1 themselves.
        XCTAssertNil(SQLiteStore.uriFilePath("file:\(path)?immutable=1"))
    }

    func testFileURIKeepsAnInvalidEscape() throws {
        let path = dir.appendingPathComponent("a%zz%+fb.db").path
        _ = try SQLiteStore(path: "file:\(path)")
        XCTAssertEqual(try mode(path), 0o600)
    }

    func testFileURIPathEndsAtNUL() throws {
        _ = try SQLiteStore(path: "file:\(dir.path)/a%00x.db")
        XCTAssertEqual(try mode(dir.appendingPathComponent("a").path), 0o600)
    }

    func testFileURIImmutableForms() {
        for (value, creates) in [("TRUE", false), ("7", false), ("0", true), ("off", true)] {
            let got = SQLiteStore.uriFilePath("file:/d/a.db?immutable=\(value)")
            XCTAssertEqual(got == Array("/d/a.db".utf8), creates, value)
        }
    }

    /// %FF is not UTF-8. macOS refuses such a name; Linux stores the raw byte.
    func testFileURINonUTF8NameIsNotReplaced() throws {
        let store = try? SQLiteStore(path: "file:\(dir.path)/a%FFb.db")
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: dir.appendingPathComponent("a\u{FFFD}b.db").path))
        if store != nil {
            var st = stat()
            let raw = Array(dir.path.utf8) + Array("/a".utf8) + [0xFF] + Array("b.db".utf8) + [0]
            let rc = raw.withUnsafeBufferPointer {
                $0.withMemoryRebound(to: CChar.self) { stat($0.baseAddress!, &st) }
            }
            XCTAssertEqual(rc, 0)
            XCTAssertEqual(Int(st.st_mode) & 0o777, 0o600)
        }
    }
}
#endif
