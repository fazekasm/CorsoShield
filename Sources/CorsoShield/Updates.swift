import Foundation
import Sparkle

@MainActor final class AppUpdates: NSObject, ObservableObject, SPUUpdaterDelegate {
    private var controller: SPUStandardUpdaterController!
    @Published var lifecycleMessage = ""
    private var resumeMarker: URL { Shield.root.appendingPathComponent("resume-service-after-update") }
    override init() {
        super.init()
        resumeServiceIfNeeded()
        controller = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: self, userDriverDelegate: nil)
    }
    func check() { controller.checkForUpdates(nil) }
    private func resumeServiceIfNeeded() {
        guard Shield.fm.fileExists(atPath: resumeMarker.path) else { return }
        do {
            try Shield.background(enabled: true)
            try Shield.fm.removeItem(at: resumeMarker)
            lifecycleMessage = "Background service restarted after update."
        } catch { lifecycleMessage = "Could not restart background service after update: " + error.localizedDescription }
    }
    func updater(_ updater: SPUUpdater, willInstallUpdate item: SUAppcastItem) {
        let plist = Shield.fm.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents/local.corso.shield.background.plist")
        guard Shield.fm.fileExists(atPath: plist.path) else { return }
        do {
            try Shield.setup()
            try Data().write(to: resumeMarker, options: .atomic)
            let (code, _) = try Shield.run(URL(fileURLWithPath: "/bin/launchctl"), ["bootout", "gui/\(getuid())", plist.path], log: Shield.root.appendingPathComponent("Logs/update-service.log"))
            lifecycleMessage = code == 0 ? "Background service paused for application update." : "Service stop returned \(code); restart will be attempted on next launch."
        } catch { lifecycleMessage = "Update service handoff error: " + error.localizedDescription }
    }
    func updater(_ updater: SPUUpdater, didAbortWithError error: Error) {
        let ns = error as NSError
        lifecycleMessage = (ns.domain == SUSparkleErrorDomain && ns.code == SUError.noUpdateError.rawValue) ? "Corso Shield is up to date." : "App update did not complete: " + error.localizedDescription
        resumeServiceIfNeeded()
    }
}
