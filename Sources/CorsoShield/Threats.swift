import Foundation
import Darwin

struct ThreatFinding: Codable {
    let category: String
    let evidence: String
}
struct ThreatSnapshot: Codable {
    var date = Date()
    let findings: [ThreatFinding]
    let coverage: [String]
    var summary: String {
        (["Security indicators: \(findings.count) finding(s). These are review signals, not confirmed infections."] + findings.map { "[\($0.category)] \($0.evidence)" } + coverage.map { "Coverage: " + $0 }).joined(separator: "\n")
    }
}
enum ThreatChecks {
    struct CommandResult { let code: Int32; let text: String; let limited: Bool }
    // Fixed executables/arguments only; never execute inspected command lines or plists.
    static func command(_ path: String, _ args: [String]) throws -> CommandResult {
        let url = Shield.root.appendingPathComponent("Logs/probe-\(UUID()).tmp")
        Shield.fm.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600])
        defer { try? Shield.fm.removeItem(at: url) }
        let handle = try FileHandle(forWritingTo: url); defer { try? handle.close() }
        let process = Process(); process.executableURL = URL(fileURLWithPath: path); process.arguments = args
        process.standardOutput = handle; process.standardError = handle
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        try process.run()
        let deadline = Date().addingTimeInterval(8)
        var limited = false
        while process.isRunning {
            let size = (try? Shield.fm.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.intValue ?? 0
            if Date() > deadline || size > 4 * 1024 * 1024 {
                limited = true; process.terminate(); Thread.sleep(forTimeInterval: 0.1)
                if process.isRunning { kill(process.processIdentifier, SIGKILL) }; break
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        process.waitUntilExit()
        let input = try FileHandle(forReadingFrom: url); defer { try? input.close() }
        let data = try input.read(upToCount: 4 * 1024 * 1024) ?? Data()
        return CommandResult(code: process.terminationStatus, text: String(decoding: data, as: UTF8.self), limited: limited)
    }
    static func networkPIDs(_ text: String) -> Set<Int> {
        var result = Set<Int>()
        var pid: Int?
        for line in text.split(separator: "\n") {
            if line.first == "p" { pid = Int(line.dropFirst()) }
            if line.first == "n", line.contains("->"), let pid = pid { result.insert(pid) }
        }
        return result
    }
    static func shellPattern(_ text: String) -> Bool {
        let s = text.lowercased()
        return s.contains("/dev/tcp/") || s.contains("/dev/udp/") ||
            (s.contains("socket" ) && s.contains("connect") && (s.contains("dup2") || s.contains("subprocess"))) ||
            (s.contains("socat") && (s.contains("exec:") || s.contains("system:")) && (s.contains("tcp") || s.contains("udp"))) ||
            ((s.contains("nc ") || s.contains("ncat ") || s.contains("netcat ")) && (s.contains(" -e ") || s.contains(" --exec ") || s.contains(" -c ")))
    }
    static func processFindings(_ ps: String, connected: Set<Int>) -> [ThreatFinding] {
        ps.split(separator: "\n").compactMap { line in
            let parts = line.split(maxSplits: 2, whereSeparator: { $0.isWhitespace })
            guard parts.count == 3, let pid = Int(parts[0]), Int(parts[1]) != nil else { return nil }
            let args = String(parts[2]); let executable = args.split(whereSeparator: { $0.isWhitespace }).first.map(String.init) ?? ""
            let name = URL(fileURLWithPath: executable).lastPathComponent.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
            let shell = ["sh", "bash", "zsh", "dash", "ksh", "fish"].contains(name)
            if shellPattern(args) {
                return ThreatFinding(category: "Reverse-shell indicator", evidence: "PID \(pid): command contains network/shell redirection or socket-to-process wiring. \(connected.contains(pid) ? "Established TCP socket also observed." : "No correlated established TCP socket observed.")")
            }
            if shell && connected.contains(pid) {
                return ThreatFinding(category: "Network-connected shell", evidence: "PID \(pid): shell owns an established TCP socket. Legitimate tools can cause this; inspect locally before taking action.")
            }
            return nil
        }
    }
    static func sipFinding(_ text: String) -> ThreatFinding? {
        let s = text.lowercased()
        guard s.contains("system integrity protection status:"), s.contains("disabled") || s.contains("custom configuration") else { return nil }
        return ThreatFinding(category: "Rootkit risk indicator", evidence: "System Integrity Protection is disabled or customized. This increases exposure but does not establish a rootkit infection.")
    }
    static func inspect() throws -> ThreatSnapshot {
        try Shield.setup()
        var findings: [ThreatFinding] = [], coverage = ["User-space snapshot only; hidden kernel/firmware activity cannot be ruled out. Other users' processes and protected paths may be inaccessible."]
        var connected = Set<Int>()
        do {
            let sockets = try command("/usr/sbin/lsof", ["-nP", "-a", "-iTCP", "-sTCP:ESTABLISHED", "-Fpn"])
            connected = networkPIDs(sockets.text)
            coverage.append("TCP visibility is permission-limited; lsof exit \(sockets.code). Exit 1 can mean no visible matching sockets. UDP/listening-only shells and short-lived activity can be missed.")
            if sockets.limited { coverage.append("Socket probe exceeded time/output limit.") }
        } catch { coverage.append("Socket probe unavailable: " + error.localizedDescription) }
        do {
            let ps = try command("/bin/ps", ["-axo", "pid=,ppid=,args="])
            if ps.code == 0 && !ps.limited { findings += processFindings(ps.text, connected: connected) }
            else { coverage.append("Process probe incomplete; no clean result asserted.") }
        } catch { coverage.append("Process probe unavailable: " + error.localizedDescription) }
        do {
            let sip = try command("/usr/bin/csrutil", ["status"])
            if sip.code == 0 && !sip.limited, let finding = sipFinding(sip.text) { findings.append(finding) }
            if sip.code != 0 || sip.limited || !sip.text.lowercased().contains("system integrity protection status:") { coverage.append("SIP status unavailable or unrecognized.") }
        } catch { coverage.append("SIP probe unavailable: " + error.localizedDescription) }
        // Installed third-party kernel extensions: integrity evidence, not a loaded-kernel inventory.
        let directory = URL(fileURLWithPath: "/Library/Extensions")
        do {
            let entries = try Shield.fm.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.isSymbolicLinkKey]).filter { $0.pathExtension == "kext" }.sorted { $0.path < $1.path }
            if entries.count > 16 { coverage.append("Kernel-extension inventory capped at 16 bundles.") }
            for bundle in entries.prefix(16) {
                if (try? bundle.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true { coverage.append("Skipped linked kernel extension: " + bundle.lastPathComponent); continue }
                let result = try command("/usr/bin/codesign", ["--verify", "--deep", "--strict", bundle.path])
                if result.limited { coverage.append("Extension verification timed out: " + bundle.lastPathComponent) }
                else if result.code != 0 {
                    findings.append(ThreatFinding(category: "Kernel-extension integrity indicator", evidence: "\(bundle.path): signature verification failed or could not complete (exit \(result.code)). May be unsigned, damaged, inaccessible or malicious; not proof it is loaded or a rootkit. Verifier: \(String(result.text.prefix(512)).replacingOccurrences(of: "\n", with: " "))"))
                }
            }
            coverage.append("Checked \(min(entries.count, 16)) installed /Library/Extensions bundles. Valid signatures do not establish safety; loaded/hidden kernel components are not inspected.")
        } catch { coverage.append("Kernel-extension inventory incomplete: " + error.localizedDescription) }
        let snapshot = ThreatSnapshot(findings: findings, coverage: coverage)
        try JSONEncoder().encode(snapshot).write(to: Shield.root.appendingPathComponent("security-indicators.json"), options: .atomic)
        return snapshot
    }
}
