import SwiftUI
import AppKit

@MainActor final class Model: ObservableObject {
    @Published var busy = false
    @Published var message = "Update signatures before your first scan."
    @Published var reports = Shield.reports()
    func perform(_ work: @escaping () throws -> String) {
        guard !busy else { return }; busy = true; message = "Working… Large scans and first updates can take several minutes."
        Task {
            let result = await Task.detached { () -> String in
                do { return try work() } catch { return error.localizedDescription }
            }.value
            message = result; reports = Shield.reports(); busy = false
        }
    }
    func scan(_ paths: [String]) { perform { let r = try Shield.scan(paths); return r.status + "\n" + r.output } }
}
struct Content: View {
    @EnvironmentObject var updates: AppUpdates
    @StateObject var model = Model()
    @State var selected: Report?
    @State var pending: Detection?
    @State var dailyScans = true
    @State var hour = 18
    @State var restoreID = ""
    @State var showRecovery = false
    @State var pendingCleanup: Report?
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack { Image(systemName: "shield.lefthalf.filled").font(.largeTitle).foregroundStyle(.teal); VStack(alignment: .leading) { Text("Corso Shield").font(.largeTitle.bold()); Text("ClamAV scans • Apple protections stay enabled").foregroundStyle(.secondary) } }
            HStack {
                Button("Update signatures") { model.perform { try Shield.update() } }
                Button("Security indicators") { model.perform { try ThreatChecks.inspect().summary } }
                Button("Quick scan") { model.scan(Shield.quickTargets()) }
                Button("Custom scan…") {
                    let panel = NSOpenPanel(); panel.canChooseDirectories = true; panel.canChooseFiles = true; panel.allowsMultipleSelection = true
                    if panel.runModal() == .OK { model.scan(panel.urls.map(\.path)) }
                }
                ProgressView().opacity(model.busy ? 1 : 0).controlSize(.small)
            }.disabled(model.busy)
            Text("Quick scan checks Downloads and Desktop. Files over 100 MB and archive contents over 400 MB may be skipped. Download monitoring is periodic and cannot block files before execution.").font(.caption).foregroundStyle(.secondary)
            GroupBox("macOS background protection (while signed in)") {
                VStack(alignment: .leading) {
                    Text("Automatic mode: daily quick scans and updates, plus Downloads polling every minute. Detections require review. Advanced mode: custom scans and manual quarantine below.").font(.caption)
                    HStack {
                        Button("Enable background service") { model.perform { try Shield.background(enabled: true); return "Background service enabled. Review reports for threats and permission errors." } }
                        Button("Stop background service") { model.perform { try Shield.background(enabled: false); return "Background service stopped." } }
                        Button("Permission setup…") {
                            model.message = "In Full Disk Access, add the installed Corso Shield.app and enable it. Restart the background service afterward. macOS requires your explicit approval; moving or replacing this unsigned development build may require reapproval. A successful Downloads scan does not prove full disk access."
                            NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!)
                        }
                    }
                    HStack {
                        TextField("Quarantine folder UUID to restore", text: $restoreID)
                        Button("Restore reviewed file…") { let id = restoreID; model.perform { try Shield.restore(id); return "Restored with non-executable owner-only permissions. Inert quarantine copy retained." } }
                    }
                    Text("Restore only after independently confirming a false positive; restored content can still be dangerous. Find UUIDs using Open reports and logs.").font(.caption)
                }
            }
            HStack {
                Button("Settings recovery…") { showRecovery = true }
                Button("Check for app updates…") { updates.check() }
                Text("Signed updates from GitHub Releases • checks daily while this app is open").font(.caption)
            }
            if !updates.lifecycleMessage.isEmpty { Text(updates.lifecycleMessage).font(.caption) }
            HSplitView {
                List(model.reports) { report in
                    Button { selected = report } label: {
                        VStack(alignment: .leading) { Text(report.date.formatted()); Text(report.status).font(.caption); Text("\(report.detections.count) detections").font(.caption) }
                    }.buttonStyle(.plain)
                }.frame(minWidth: 230, maxWidth: 280)
                VStack(alignment: .leading) {
                    if let r = selected {
                        Text(r.status).font(.headline)
                        Button("Remove detected files to quarantine…") { pendingCleanup = r }.disabled(model.busy || r.detections.isEmpty)
                        ForEach(r.detections) { d in
                            HStack { VStack(alignment: .leading) { Text(d.signature); Text(d.path).font(.caption).textSelection(.enabled) }; Spacer(); Button("Quarantine…") { pending = d }.disabled(model.busy) }
                        }
                        ScrollView { Text(r.output).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                    } else { Text("Select a saved report to inspect results and quarantine detections.").foregroundStyle(.secondary) }
                }.padding().frame(minWidth: 400)
            }
            ScrollView { Text(model.message).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }.frame(height: 110)
            HStack {
                Button("Open reports and logs") { try? Shield.setup(); NSWorkspace.shared.open(Shield.root) }
                Button("Last security check") { model.perform { try JSONDecoder().decode(ThreatSnapshot.self, from: Data(contentsOf: Shield.root.appendingPathComponent("security-indicators.json"))).summary } }
                Spacer(); Text("No files are removed automatically.").font(.caption)
            }
        }.padding(20).frame(minWidth: 850, minHeight: 650)
        .sheet(isPresented: $showRecovery) { RecoveryPanel() }
        .alert("Remove the detected files?", isPresented: Binding(get: { pendingCleanup != nil }, set: { if !$0 { pendingCleanup = nil } })) {
            Button("Cancel", role: .cancel) { pendingCleanup = nil }
            Button("Move detections to quarantine") { if let r = pendingCleanup { model.perform { try Shield.removeThreats(r.detections) } }; pendingCleanup = nil }
        } message: { Text("This isolates the \(pendingCleanup?.detections.count ?? 0) detected files in this report. Each file is rechecked for changes. False positives can be restored. Running processes and other installed components are not removed; rescan after cleanup.") }
        .alert("Quarantine this file?", isPresented: Binding(get: { pending != nil }, set: { if !$0 { pending = nil } })) {
            Button("Cancel", role: .cancel) { pending = nil }
            Button("Move to quarantine", role: .destructive) {
                if let d = pending { model.perform { try Shield.quarantine(d); return "Moved to quarantine with permissions removed. Metadata records the original path." } }; pending = nil
            }
        } message: { Text("\(pending?.path ?? "")\nThe file will be moved out of its original location. Detections can be false positives. Review the report first.") }
    }
}
@main struct CorsoApp: App {
    @StateObject private var updates = AppUpdates()
    init() {
        if CommandLine.arguments.contains("--enable-background") || CommandLine.arguments.contains("--disable-background") {
            do { try Shield.background(enabled: CommandLine.arguments.contains("--enable-background")); print("Background service configuration saved."); exit(0) } catch { fputs(error.localizedDescription + "\n", stderr); exit(2) }
        }
        if CommandLine.arguments.contains("--security-check") {
            do { let snapshot = try ThreatChecks.inspect(); print(snapshot.summary); exit(snapshot.findings.isEmpty ? 0 : 1) } catch { fputs(error.localizedDescription + "\n", stderr); exit(2) }
        }
        if CommandLine.arguments.contains("--service") {
            do { try Shield.service() } catch { fputs(error.localizedDescription + "\n", stderr); exit(2) }
            exit(0)
        }
        if CommandLine.arguments.contains("--update") || CommandLine.arguments.contains("--quick") {
            do {
                if CommandLine.arguments.contains("--update") { print(try Shield.update()); exit(0) }
                let r = try Shield.scan(Shield.quickTargets()); print(r.status); exit(r.exitCode)
            } catch { fputs(error.localizedDescription + "\n", stderr); exit(2) }
        }
        NSApplication.shared.setActivationPolicy(.regular)
    }
    var body: some Scene { WindowGroup("Corso Shield") { Content().environmentObject(updates) } }
}
