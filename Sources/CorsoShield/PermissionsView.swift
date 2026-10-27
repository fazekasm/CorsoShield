import SwiftUI
import AppKit

struct PermissionsPanel: View {
    @Environment(\.dismiss) var dismiss
    @State var confirmed = false
    @State var acceptLimited = false
    @State var recoveryRequested = true
    @State var assessment: SetupAssessment?
    @State var message = "Install the app in its permanent Applications location, then grant access to that exact app. This checklist is shown again after its executable or installed location changes."
    @State var busy = false
    func check() {
        busy = true
        Task { assessment = await Task.detached { SetupPermissions.assess() }.value; busy = false }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Set up permissions for this version").font(.title2)
            Text("1. Install ClamAV if missing. 2. Open Full Disk Access and add/enable this installed Corso Shield app. 3. Return here and check access. macOS requires your approval; Corso cannot grant it automatically.")
            HStack {
                Button("Open Full Disk Access") { NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!) }
                Button("Show installed app") { NSWorkspace.shared.activateFileViewerSelecting([Bundle.main.bundleURL]) }
                Button("Check access") { check() }
            }.disabled(busy)
            ScrollView { Text(assessment?.summary ?? "Check access to see current requirements.").textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }.frame(height: 210)
            Toggle("I reviewed and enabled Corso Shield in Full Disk Access", isOn: $confirmed)
            Toggle("Prepare settings recovery Keychain access during setup", isOn: $recoveryRequested)
            Toggle("I explicitly accept limited/unverified scan coverage if samples remain unavailable or denied", isOn: $acceptLimited)
            Button("Check recovery Keychain access") {
                busy = true
                Task {
                    do { _ = try await Task.detached { try SettingsRecovery.key() }.value; message = "Recovery Keychain access succeeded. No baseline was captured or network settings changed." }
                    catch { message = error.localizedDescription }
                    busy = false
                }
            }.disabled(busy)
            Text("Optional recovery: Keychain may request access when saving a baseline. Network settings recovery can require additional administrator authorization at the time of use. No camera, microphone, contacts or Accessibility permission is needed.").font(.caption)
            Text(message).font(.caption).textSelection(.enabled)
            HStack {
                Button("Save review and recheck") {
                    busy = true; let fda = confirmed, limited = acceptLimited, recovery = recoveryRequested
                    Task {
                        do { try await Task.detached { if recovery { _ = try SettingsRecovery.key() }; try SetupPermissions.record(userConfirmedFDA: fda, limitedScopeAccepted: limited, recoveryKeychainReviewed: recovery) }.value; message = "Review saved for this exact build. Check the result before enabling background scans." }
                        catch { message = error.localizedDescription }
                        assessment = await Task.detached { SetupPermissions.assess() }.value; busy = false
                    }
                }.disabled(!confirmed || busy)
                Button("Enable background scans") {
                    busy = true
                    Task {
                        do { try await Task.detached { try Shield.background(enabled: true) }.value; message = "Background scans enabled for the reviewed scope. macOS permission changes may require restarting the app and service." }
                        catch { message = error.localizedDescription }
                        busy = false
                    }
                }.disabled(assessment?.ready != true || busy)
                Spacer(); Button("Close") { dismiss() }.disabled(busy)
            }
        }.padding(20).frame(width: 760).onAppear { check() }
    }
}
