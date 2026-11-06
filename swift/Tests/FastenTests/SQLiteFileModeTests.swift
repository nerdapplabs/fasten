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
}
#endif
