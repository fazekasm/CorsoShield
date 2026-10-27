import Foundation
import Darwin

enum ServiceError: LocalizedError {
    case message(String)
    var errorDescription: String? { if case .message(let text) = self { return text }; return nil }
}
struct ServiceState: Codable {
    var lastUpdate: Date? = nil
    var lastScan: Date? = nil
}
extension Shield {
    static func restore(_ id: String) throws {
        guard UUID(uuidString: id) != nil else { throw ServiceError.message("Invalid quarantine ID") }
        let folder = root.appendingPathComponent("Quarantine/" + id)
        let metadata = try JSONDecoder().decode(Detection.self, from: Data(contentsOf: folder.appendingPathComponent("metadata.json")))
        let target = URL(fileURLWithPath: metadata.path).standardizedFileURL
        let parent = target.deletingLastPathComponent()
        guard target.path.hasPrefix(fm.homeDirectoryForCurrentUser.path + "/"),
              !target.path.hasPrefix(root.path + "/"),
              parent.resolvingSymlinksInPath().path == parent.path,
              fm.fileExists(atPath: parent.path),
              !fm.fileExists(atPath: target.path) else { throw ServiceError.message("Restore refused: destination exists, is outside home, or parent is missing or linked") }
        let payload = folder.appendingPathComponent("payload.disabled")
        guard try payload.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink != true else { throw ServiceError.message("Linked payload refused") }
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: payload.path)
        defer { if fm.fileExists(atPath: payload.path) { try? fm.setAttributes([.posixPermissions: 0o000], ofItemAtPath: payload.path) } }
        guard let expected = metadata.digest, try digest(payload) == expected else { throw ServiceError.message("Quarantine integrity check failed") }
        // Exclusive copy refuses overwrite even if the destination appeared after validation.
        let input = try FileHandle(forReadingFrom: payload); defer { try? input.close() }
        let fd = open(target.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw ServiceError.message("Cannot create restore destination exclusively") }
        let output = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            while let data = try input.read(upToCount: 1024 * 1024), !data.isEmpty { try output.write(contentsOf: data) }
            try output.synchronize(); try output.close()
            guard try digest(target) == expected else { throw ServiceError.message("Restored copy integrity check failed") }
        } catch { try? fm.removeItem(at: target); throw error }
        // Retain the inert original and metadata as a recovery/audit record.
    }
    static func background(enabled: Bool) throws {
        if enabled { try SetupPermissions.requireReady(SetupPermissions.assess()) }
        try schedule(enabled: false, scans: false, hour: 18)
        let dir = fm.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents")
        let url = dir.appendingPathComponent("local.corso.shield.background.plist")
        let domain = "gui/\(getuid())"
        _ = try run(URL(fileURLWithPath: "/bin/launchctl"), ["bootout", domain, url.path], log: root.appendingPathComponent("Logs/service-install.log"))
        if fm.fileExists(atPath: url.path) { try fm.removeItem(at: url) }
        guard enabled else { return }
        let plist: [String: Any] = ["Label": "local.corso.shield.background", "ProgramArguments": [Bundle.main.executableURL!.path, "--service"], "RunAtLoad": true, "KeepAlive": true, "ThrottleInterval": 60, "ProcessType": "Background", "LowPriorityIO": true, "Nice": 15]
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0).write(to: url, options: .atomic)
        let (code, output) = try run(URL(fileURLWithPath: "/bin/launchctl"), ["bootstrap", domain, url.path], log: root.appendingPathComponent("Logs/service-install.log"))
        guard code == 0 else { throw ServiceError.message(output) }
    }
    static func service() throws {
        try SetupPermissions.requireReady(SetupPermissions.assess())
        try setup()
        let lock = open(root.appendingPathComponent("service.lock").path, O_CREAT | O_RDWR, 0o600)
        guard lock >= 0 else { throw ServiceError.message("Cannot open service lock") }
        defer { close(lock) }
        guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw ServiceError.message("Service already running") }
        _ = nice(15)
        let stateURL = root.appendingPathComponent("service-state.json")
        var state = (try? JSONDecoder().decode(ServiceState.self, from: Data(contentsOf: stateURL))) ?? ServiceState()
        var observed: [String: String] = [:], scanned: [String: String] = [:]
        var retryUpdate = Date.distantPast, retryScan = Date.distantPast
        var nextIndicators = Date.distantPast
        while true {
            autoreleasepool {
                let now = Date()
                func log(_ text: String) {
                    // One bounded status record; scan/update logs retain details.
                    try? (now.ISO8601Format() + " " + text).write(to: root.appendingPathComponent("Logs/service-status.txt"), atomically: true, encoding: .utf8)
                }
                if now >= nextIndicators {
                    nextIndicators = now.addingTimeInterval(900)
                    do { let snapshot = try ThreatChecks.inspect(); log("Security indicators: \(snapshot.findings.count) finding(s); see security-indicators.json") } catch { log("Security indicators failed: " + error.localizedDescription) }
                }
                if now.timeIntervalSince(state.lastUpdate ?? .distantPast) >= 86400 && now >= retryUpdate {
                    retryUpdate = now.addingTimeInterval(3600)
                    do { _ = try update(); state.lastUpdate = Date(); log("Signatures updated") } catch { log("Update failed: " + error.localizedDescription) }
                }
                if now.timeIntervalSince(state.lastScan ?? .distantPast) >= 86400 && now >= retryScan {
                    retryScan = now.addingTimeInterval(3600)
                    do { let report = try scan(quickTargets()); if report.exitCode < 2 { state.lastScan = Date() }; log(report.status) } catch { log(error.localizedDescription) }
                }
                let downloads = fm.homeDirectoryForCurrentUser.appendingPathComponent("Downloads")
                var current: [String: String] = [:], batch: [String] = []
                if let files = fm.enumerator(at: downloads, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey, .contentModificationDateKey], options: [.skipsHiddenFiles, .skipsPackageDescendants]) {
                    var count = 0
                    for case let url as URL in files {
                        count += 1; if count > 5000 { log("Download monitor capped at 5000 entries; run custom scan for full coverage"); break }
                        guard let v = try? url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey, .contentModificationDateKey]), v.isRegularFile == true, v.isSymbolicLink != true,
                              !["download", "crdownload", "part", "tmp"].contains(url.pathExtension.lowercased()) else { continue }
                        let stamp = "\(v.fileSize ?? 0):\(v.contentModificationDate?.timeIntervalSince1970 ?? 0)"
                        current[url.path] = stamp
                        if observed[url.path] == stamp && scanned[url.path] != stamp && batch.count < 20 { batch.append(url.path) }
                    }
                }
                if !batch.isEmpty {
                    do { let report = try scan(batch); if report.exitCode < 2 { for path in batch { scanned[path] = current[path] } }; log("Download scan: " + report.status) } catch { log(error.localizedDescription) }
                }
                observed = current; scanned = scanned.filter { current[$0.key] == $0.value }
                try? JSONEncoder().encode(state).write(to: stateURL, options: .atomic)
                // Keep newest 100 scan reports/logs, excluding quarantined payloads.
                for name in ["Logs", "Reports"] {
                    let files = (try? fm.contentsOfDirectory(at: root.appendingPathComponent(name), includingPropertiesForKeys: [.contentModificationDateKey])) ?? []
                    let history = files.filter { $0.lastPathComponent.hasPrefix("scan-") || $0.lastPathComponent.hasPrefix("update-") || $0.pathExtension == "json" }.sorted { ((try? $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast) > ((try? $1.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast) }
                    for file in history.dropFirst(100) { try? fm.removeItem(at: file) }
                }
            }
            Thread.sleep(forTimeInterval: 60)
        }
    }
}
