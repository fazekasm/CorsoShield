import Foundation
import CryptoKit
import Security
import IOKit
import Darwin

struct NetworkSettings: Codable, Equatable {
    let service: String
    let dns: [String] // Empty means DHCP/default DNS.
    let proxyEnabled: Bool
    let proxyHost: String
    let proxyPort: Int
}
struct SettingsBaseline: Codable {
    let schema: Int
    let id: UUID
    let date: Date
    let device: String
    let settings: NetworkSettings
}
struct AuthenticatedBaseline: Codable {
    let payload: Data
    let tag: Data
}
enum SettingsRecovery {
    static let fm = FileManager.default
    static var directory: URL { Shield.root.appendingPathComponent("Baselines") }
    static func key() throws -> SymmetricKey {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                  kSecAttrService as String: "local.corso.shield.settings",
                                  kSecAttrAccount as String: "baseline-hmac-v1"]
        var lookup = query; lookup[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data { return SymmetricKey(data: data) }
        guard status == errSecItemNotFound else { throw ServiceError.message("Cannot access baseline authentication key (Keychain status \(status)).") }
        var bytes = Data(count: 32)
        let randomStatus = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard randomStatus == errSecSuccess else { throw ServiceError.message("Cannot generate baseline key") }
        var add = query; add[kSecValueData as String] = bytes
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else { throw ServiceError.message("Cannot save baseline key to Keychain") }
        return SymmetricKey(data: bytes)
    }
    static func device() throws -> String {
        let entry = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        guard entry != 0 else { throw ServiceError.message("Cannot identify this Mac") }
        defer { IOObjectRelease(entry) }
        guard let value = IORegistryEntryCreateCFProperty(entry, "IOPlatformUUID" as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? String else { throw ServiceError.message("Cannot identify this Mac") }
        return SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }
    static func seal(_ baseline: SettingsBaseline, using key: SymmetricKey) throws -> Data {
        let data = try JSONEncoder().encode(baseline)
        return try JSONEncoder().encode(AuthenticatedBaseline(payload: data, tag: Data(HMAC<SHA256>.authenticationCode(for: data, using: key))))
    }
    static func unseal(_ data: Data, using key: SymmetricKey, device: String) throws -> SettingsBaseline {
        let envelope = try JSONDecoder().decode(AuthenticatedBaseline.self, from: data)
        guard HMAC<SHA256>.isValidAuthenticationCode(envelope.tag, authenticating: envelope.payload, using: key) else { throw ServiceError.message("Baseline authentication failed; no settings changed") }
        let baseline = try JSONDecoder().decode(SettingsBaseline.self, from: envelope.payload)
        guard baseline.schema == 1, baseline.device == device else { throw ServiceError.message("Baseline belongs to a different Mac or schema") }
        try validate(baseline.settings)
        return baseline
    }
    static func validate(_ value: NetworkSettings) throws {
        guard !value.service.isEmpty, value.service.count <= 256, !value.service.contains("\n"), !value.service.hasPrefix("-"),
              value.dns.count <= 16, value.dns.allSatisfy({ address in
                  var v4 = in_addr(), v6 = in6_addr()
                  return inet_pton(AF_INET, address, &v4) == 1 || inet_pton(AF_INET6, address, &v6) == 1
              }), value.proxyPort >= 0 && value.proxyPort <= 65535,
              value.proxyHost.count <= 253, !value.proxyHost.contains(where: { $0.isWhitespace }),
              !value.proxyHost.contains("@"), !value.proxyHost.hasPrefix("-"),
              (!value.proxyEnabled || (!value.proxyHost.isEmpty && value.proxyPort > 0)) else { throw ServiceError.message("Unsupported or invalid network baseline") }
    }
    static func parseDNS(_ text: String) throws -> [String] {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasPrefix("There aren't any DNS Servers set on ") { return [] }
        let entries = text.components(separatedBy: .newlines).filter { !$0.isEmpty }
        guard !entries.isEmpty else { throw ServiceError.message("DNS response was empty") }
        try validate(NetworkSettings(service: "test", dns: entries, proxyEnabled: false, proxyHost: "", proxyPort: 0))
        return entries
    }
    static func parseProxy(_ text: String, service: String, dns: [String]) throws -> NetworkSettings {
        var fields: [String: String] = [:]
        for line in text.components(separatedBy: .newlines) {
            if let split = line.range(of: ": ") { fields[String(line[..<split.lowerBound])] = String(line[split.upperBound...]) }
        }
        guard let enabled = fields["Enabled"], ["Yes", "No"].contains(enabled), let host = fields["Server"], let port = Int(fields["Port"] ?? ""),
              fields["Authenticated Proxy Enabled"] == "0" else { throw ServiceError.message("Unsupported proxy response or authenticated proxy; credentials are never captured") }
        let result = NetworkSettings(service: service, dns: dns, proxyEnabled: enabled == "Yes", proxyHost: host, proxyPort: port)
        try validate(result); return result
    }
    static func network(_ args: [String]) throws -> String {
        try Shield.setup()
        let result = try ThreatChecks.command("/usr/sbin/networksetup", args)
        guard result.code == 0, !result.limited,
              !result.text.contains("** Error:"), !result.text.contains("You need administrator access") else {
            throw ServiceError.message("Network settings command failed; administrator authorization may be required. " + String(result.text.prefix(512)))
        }
        return result.text
    }
    static func read(_ service: String) throws -> NetworkSettings {
        try validate(NetworkSettings(service: service, dns: [], proxyEnabled: false, proxyHost: "", proxyPort: 0))
        let services = try network(["-listallnetworkservices"]).components(separatedBy: .newlines)
        guard services.contains(service) else { throw ServiceError.message("Network service not found or disabled; use its exact name from System Settings") }
        let dns = try parseDNS(network(["-getdnsservers", service]))
        return try parseProxy(network(["-getwebproxy", service]), service: service, dns: dns)
    }
    static func save(_ settings: NetworkSettings) throws -> SettingsBaseline {
        try Shield.setup(); try validate(settings)
        try fm.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let baseline = SettingsBaseline(schema: 1, id: UUID(), date: Date(), device: try device(), settings: settings)
        try seal(baseline, using: key()).write(to: directory.appendingPathComponent(baseline.id.uuidString + ".json"), options: .atomic)
        return baseline
    }
    static func load(_ id: String) throws -> SettingsBaseline {
        guard let uuid = UUID(uuidString: id) else { throw ServiceError.message("Invalid baseline ID") }
        return try unseal(Data(contentsOf: directory.appendingPathComponent(uuid.uuidString + ".json")), using: key(), device: device())
    }
    static func preview(_ id: String) throws -> (String, NetworkSettings) {
        let baseline = try load(id), current = try read(baseline.settings.service)
        return ("Trusted snapshot from \(baseline.date.formatted()). Only DNS and HTTP proxy for \(current.service) are covered.\nCurrent: \(describe(current))\nRestore: \(describe(baseline.settings))\nVPN, HTTPS/SOCKS/PAC proxies, browser settings and system files are not changed.", current)
    }
    static func describe(_ value: NetworkSettings) -> String {
        "DNS: \(value.dns.isEmpty ? "DHCP/default" : value.dns.joined(separator: ", ")); HTTP proxy: \(value.proxyEnabled ? "enabled" : "disabled") \(value.proxyHost):\(value.proxyPort)"
    }
    static func apply(_ value: NetworkSettings) throws {
        try validate(value)
        _ = try network(["-setdnsservers", value.service] + (value.dns.isEmpty ? ["Empty"] : value.dns))
        if !value.proxyHost.isEmpty && value.proxyPort > 0 { _ = try network(["-setwebproxy", value.service, value.proxyHost, String(value.proxyPort)]) }
        _ = try network(["-setwebproxystate", value.service, value.proxyEnabled ? "on" : "off"])
        let after = try read(value.service)
        guard after.dns == value.dns, after.proxyEnabled == value.proxyEnabled,
              (!value.proxyEnabled || (after.proxyHost == value.proxyHost && after.proxyPort == value.proxyPort)) else { throw ServiceError.message("Settings read-back did not match requested recovery") }
    }
    static func restore(_ id: String, expectedCurrent: NetworkSettings) throws -> String {
        let baseline = try load(id)
        guard try read(baseline.settings.service) == expectedCurrent else { throw ServiceError.message("Settings changed since preview; review again") }
        let backup = try save(expectedCurrent)
        do {
            try apply(baseline.settings)
            return "Verified DNS and HTTP proxy recovery. Pre-change backup: \(backup.id.uuidString)"
        } catch {
            let problem = error.localizedDescription
            var rollbackFailure: String?
            do { try apply(expectedCurrent) } catch { rollbackFailure = error.localizedDescription }
            if let rollbackFailure = rollbackFailure { throw ServiceError.message("Recovery failed: \(problem). Rollback also failed: \(rollbackFailure). Backup: \(backup.id.uuidString). Use System Settings to recover connectivity.") }
            throw ServiceError.message("Recovery failed: \(problem). Previous settings restored. Backup: \(backup.id.uuidString)")
        }
    }
}

struct CleanupResult: Codable {
    var date = Date()
    var isolated: [String] = []
    var failures: [String] = []
}
extension Shield {
    static func removeThreats(_ detections: [Detection]) throws -> String {
        try setup()
        guard !detections.isEmpty, detections.count <= 1000 else { throw ServiceError.message("Select a scan report containing 1–1000 detections") }
        var result = CleanupResult()
        for detection in detections {
            do { try quarantine(detection); result.isolated.append(detection.path) }
            catch { result.failures.append(detection.path + ": " + error.localizedDescription) }
        }
        let id = UUID().uuidString
        try JSONEncoder().encode(result).write(to: root.appendingPathComponent("Reports/cleanup-" + id + ".json"), options: .atomic)
        return "Removed from original locations into quarantine: \(result.isolated.count). Failed: \(result.failures.count).\n" + result.failures.joined(separator: "\n") + "\nRescan afterward. This does not terminate running malware, remove persistence, repair infected documents or guarantee a clean system."
    }
}
