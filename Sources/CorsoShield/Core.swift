import Foundation
import CryptoKit
import Darwin

struct Detection: Codable, Identifiable {
    var id = UUID()
    let path: String
    let signature: String
    var digest: String?
}
struct Report: Codable, Identifiable {
    var id = UUID()
    var date = Date()
    let targets: [String]
    let exitCode: Int32
    let output: String
    let detections: [Detection]
    var status: String { exitCode == 0 ? "No detections reported (check limits and warnings)" : exitCode == 1 ? "Detections found" : "Incomplete / error" }
}
enum Shield {
    static let fm = FileManager.default
    static var root: URL { if let test = ProcessInfo.processInfo.environment["CORSO_TEST_ROOT"] { return URL(fileURLWithPath: test) }; return fm.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Corso Shield") }
    static var database: URL { root.appendingPathComponent("Database") }
    static func setup() throws {
        for name in ["Database", "Reports", "Quarantine", "Logs"] {
            try fm.createDirectory(at: root.appendingPathComponent(name), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        let config = "DatabaseDirectory \(database.path)\nDatabaseMirror database.clamav.net\nChecks 1\nScriptedUpdates yes\nTestDatabases yes\n"
        try config.write(to: root.appendingPathComponent("freshclam.conf"), atomically: true, encoding: .utf8)
    }
    static func binary(_ name: String) throws -> URL {
        for prefix in ["/opt/homebrew/bin", "/usr/local/bin"] {
            let u = URL(fileURLWithPath: prefix).appendingPathComponent(name)
            if fm.isExecutableFile(atPath: u.path) { return u }
        }
        throw NSError(domain: "CorsoShield", code: 1, userInfo: [NSLocalizedDescriptionKey: "Install ClamAV first: brew install clamav"])
    }
    static func run(_ executable: URL, _ arguments: [String], log: URL) throws -> (Int32, String) {
        fm.createFile(atPath: log.path, contents: nil, attributes: [.posixPermissions: 0o600])
        let handle = try FileHandle(forWritingTo: log)
        defer { try? handle.close() }
        // Serialize engine processes across the GUI and background service.
        let lock = open(root.appendingPathComponent("engine.lock").path, O_CREAT | O_RDWR, 0o600)
        guard lock >= 0 else { throw ServiceError.message("Cannot open engine lock") }
        defer { close(lock) }
        if executable.lastPathComponent == "clamscan" || executable.lastPathComponent == "freshclam" {
            guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw ServiceError.message("Another scan or update is running. Try later.") }
        }
        let p = Process()
        p.executableURL = executable; p.arguments = arguments
        p.standardOutput = handle; p.standardError = handle
        var env = ProcessInfo.processInfo.environment; env["LC_ALL"] = "C"; p.environment = env
        try p.run(); p.waitUntilExit()
        return (p.terminationStatus, (try? String(contentsOf: log, encoding: .utf8)) ?? "Output was not valid UTF-8; see log.")
    }
    static func parse(_ text: String) -> [Detection] {
        text.components(separatedBy: .newlines).compactMap { line in
            guard line.hasSuffix(" FOUND"), let range = line.range(of: ": ", options: .backwards) else { return nil }
            return Detection(path: String(line[..<range.lowerBound]), signature: String(line[range.upperBound...].dropLast(6)))
        }
    }
    static func digest(_ url: URL) throws -> String {
        let h = try FileHandle(forReadingFrom: url); defer { try? h.close() }
        var hash = SHA256()
        while let data = try h.read(upToCount: 1024 * 1024), !data.isEmpty { hash.update(data: data) }
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }
    static func quickTargets() -> [String] {
        ["Downloads", "Desktop"].map { fm.homeDirectoryForCurrentUser.appendingPathComponent($0).path }.filter { fm.fileExists(atPath: $0) }
    }
    static func scan(_ targets: [String]) throws -> Report {
        try setup()
        guard !targets.isEmpty else { throw NSError(domain: "CorsoShield", code: 2, userInfo: [NSLocalizedDescriptionKey: "No scan targets selected."]) }
        let log = root.appendingPathComponent("Logs/scan-\(UUID()).log")
        let (code, output) = try run(binary("clamscan"), ["--database=\(database.path)", "--recursive", "--infected", "--stdout", "--follow-dir-symlinks=0", "--follow-file-symlinks=0", "--max-filesize=100M", "--max-scansize=400M", "--"] + targets, log: log)
        var found = parse(output)
        for i in found.indices { found[i].digest = try? digest(URL(fileURLWithPath: found[i].path)) }
        let report = Report(targets: targets, exitCode: code, output: output, detections: found)
        try JSONEncoder().encode(report).write(to: root.appendingPathComponent("Reports/\(report.id).json"), options: .atomic)
        return report
    }
    static func update() throws -> String {
        try setup()
        let (code, output) = try run(binary("freshclam"), ["--config-file=\(root.appendingPathComponent("freshclam.conf").path)", "--stdout"], log: root.appendingPathComponent("Logs/update-\(UUID()).log"))
        guard code == 0 else { throw NSError(domain: "FreshClam", code: Int(code), userInfo: [NSLocalizedDescriptionKey: output]) }
        try Date().ISO8601Format().write(to: root.appendingPathComponent("last-update.txt"), atomically: true, encoding: .utf8)
        return output
    }
    static func reports() -> [Report] {
        let files = (try? fm.contentsOfDirectory(at: root.appendingPathComponent("Reports"), includingPropertiesForKeys: nil)) ?? []
        return files.compactMap { u in (try? Data(contentsOf: u)).flatMap { try? JSONDecoder().decode(Report.self, from: $0) } }.sorted { $0.date > $1.date }
    }
    static func quarantine(_ detection: Detection) throws {
        let source = URL(fileURLWithPath: detection.path)
        let values = try source.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        let attrs = try fm.attributesOfItem(atPath: source.path)
        guard (attrs[.referenceCount] as? NSNumber)?.intValue == 1, values.isRegularFile == true, values.isSymbolicLink != true, let expected = detection.digest, try digest(source) == expected,
              source.deletingLastPathComponent().resolvingSymlinksInPath().path == source.deletingLastPathComponent().standardizedFileURL.path,
              source.resolvingSymlinksInPath().path.hasPrefix(fm.homeDirectoryForCurrentUser.path + "/"),
              !source.standardizedFileURL.path.hasPrefix(root.path + "/") else {
            throw NSError(domain: "Quarantine", code: 1, userInfo: [NSLocalizedDescriptionKey: "File changed, is not a regular user file, or cannot be safely quarantined. Scan again."])
        }
        let folder = root.appendingPathComponent("Quarantine/\(UUID())")
        try fm.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try JSONEncoder().encode(detection).write(to: folder.appendingPathComponent("metadata.json"), options: .atomic)
        try fm.moveItem(at: source, to: folder.appendingPathComponent("payload.disabled"))
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: folder.appendingPathComponent("payload.disabled").path)
        defer { try? fm.setAttributes([.posixPermissions: 0o000], ofItemAtPath: folder.appendingPathComponent("payload.disabled").path) }
        guard try digest(folder.appendingPathComponent("payload.disabled")) == expected else {
            throw ServiceError.message("File changed during quarantine; retained in quarantine for manual review.")
        }
        try fm.setAttributes([.posixPermissions: 0o000], ofItemAtPath: folder.appendingPathComponent("payload.disabled").path)
    }
    static func schedule(enabled: Bool, scans: Bool, hour: Int) throws {
        try setup()
        let dir = fm.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        for (suffix, arg, h, active) in [("update", "--update", 10, enabled), ("scan", "--quick", hour, enabled && scans)] {
            let label = "local.corso.shield.\(suffix)"
            let url = dir.appendingPathComponent(label + ".plist")
            let domain = "gui/\(getuid())"
            _ = try run(URL(fileURLWithPath: "/bin/launchctl"), ["bootout", domain, url.path], log: root.appendingPathComponent("Logs/schedule.log"))
            if fm.fileExists(atPath: url.path) { try fm.removeItem(at: url) }
            if active {
                let executable = Bundle.main.executableURL!.path
                let plist: [String: Any] = ["Label": label, "ProgramArguments": [executable, arg], "StartCalendarInterval": ["Hour": h, "Minute": 15], "ProcessType": "Background", "StandardOutPath": root.appendingPathComponent("Logs/\(suffix)-agent.log").path, "StandardErrorPath": root.appendingPathComponent("Logs/\(suffix)-agent-error.log").path]
                try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0).write(to: url, options: .atomic)
                let (code, out) = try run(URL(fileURLWithPath: "/bin/launchctl"), ["bootstrap", domain, url.path], log: root.appendingPathComponent("Logs/schedule.log"))
                if code != 0 { throw NSError(domain: "Schedule", code: Int(code), userInfo: [NSLocalizedDescriptionKey: out]) }
            }
        }
    }
}
