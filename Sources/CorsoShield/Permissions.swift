import Foundation
import Darwin

struct SetupReceipt: Codable {
    let buildIdentity: String
    let fullDiskAccessConfirmedByUser: Bool
    let limitedScopeAccepted: Bool
    let recoveryKeychainReviewed: Bool?
    let date: Date
}
struct SetupAssessment {
    let installed: Bool
    let engines: Bool
    let storage: Bool
    let currentReceipt: Bool
    let probeReadable: Bool
    let probeDenied: Bool
    let limitedScopeAccepted: Bool
    var ready: Bool { installed && engines && storage && currentReceipt && ((probeReadable && !probeDenied) || limitedScopeAccepted) }
    var summary: String {
        "Installed application location: \(installed ? "OK" : "install this app in Applications first")\nClamAV and FreshClam: \(engines ? "found" : "missing; install ClamAV")\nPrivate app storage: \(storage ? "writable" : "not writable")\nPermission review for this exact app build/location: \(currentReceipt ? "recorded" : "required")\nProtected sample access: \(probeDenied ? "denied" : probeReadable ? "readable" : "unavailable / not verified")\n\(ready ? "Ready for the explicitly configured scan scope." : "Setup incomplete; background scanning is not enabled.")\nReadable samples and your confirmation do not prove system-wide Full Disk Access or child-engine access. Review scan warnings. Network recovery authorization is checked only when used; this setup does not grant root privileges."
    }
}
enum SetupPermissions {
    static var receiptURL: URL { Shield.root.appendingPathComponent("permission-setup.json") }
    static func buildIdentity() throws -> String {
        guard let executable = Bundle.main.executableURL else { throw ServiceError.message("Application identity unavailable") }
        return Bundle.main.bundleURL.standardizedFileURL.path + ":" + (try Shield.digest(executable))
    }
    static func assess() -> SetupAssessment {
        let app = Bundle.main.bundleURL.standardizedFileURL.path
        let userApps = Shield.fm.homeDirectoryForCurrentUser.appendingPathComponent("Applications").path + "/"
        let installed = app.hasSuffix(".app") && (app.hasPrefix("/Applications/") || app.hasPrefix(userApps))
        let engines = (try? Shield.binary("clamscan")) != nil && (try? Shield.binary("freshclam")) != nil
        var storage = false
        do {
            try Shield.setup()
            let test = Shield.root.appendingPathComponent("Logs/setup-\(UUID()).tmp")
            try Data().write(to: test, options: .atomic); try Shield.fm.removeItem(at: test); storage = true
        } catch {}
        let receipt = (try? Data(contentsOf: receiptURL)).flatMap { try? JSONDecoder().decode(SetupReceipt.self, from: $0) }
        let current = receipt?.buildIdentity == (try? buildIdentity()) && receipt?.fullDiskAccessConfirmedByUser == true
        // Open only; do not read or persist content from these protected files.
        let candidates = ["Library/Safari/Bookmarks.plist", "Library/Application Support/com.apple.TCC/TCC.db"]
        var readable = false, denied = false
        for suffix in candidates {
            let path = Shield.fm.homeDirectoryForCurrentUser.appendingPathComponent(suffix).path
            let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            if fd >= 0 { close(fd); readable = true }
            else if errno == EPERM || errno == EACCES { denied = true }
        }
        return SetupAssessment(installed: installed, engines: engines, storage: storage, currentReceipt: current, probeReadable: readable, probeDenied: denied, limitedScopeAccepted: current && receipt?.limitedScopeAccepted == true)
    }
    static func record(userConfirmedFDA: Bool, limitedScopeAccepted: Bool, recoveryKeychainReviewed: Bool = false) throws {
        guard userConfirmedFDA else { throw ServiceError.message("Review Full Disk Access in System Settings before completing setup") }
        try Shield.setup()
        let receipt = SetupReceipt(buildIdentity: try buildIdentity(), fullDiskAccessConfirmedByUser: true, limitedScopeAccepted: limitedScopeAccepted, recoveryKeychainReviewed: recoveryKeychainReviewed, date: Date())
        try JSONEncoder().encode(receipt).write(to: receiptURL, options: .atomic)
    }
    static func requireReady(_ assessment: SetupAssessment) throws {
        guard assessment.ready else { throw ServiceError.message("Complete Permission setup in the installed Corso Shield app for this version.\n" + assessment.summary) }
    }
}
