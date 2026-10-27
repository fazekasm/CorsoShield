import SwiftUI

@MainActor final class RecoveryModel: ObservableObject {
    @Published var service = "Wi-Fi"
    @Published var baselineID = ""
    @Published var message = "Save a baseline only after you have independently verified that these settings are trusted. A snapshot taken after infection may preserve malicious settings."
    @Published var busy = false
    @Published var previewCurrent: NetworkSettings?
    @Published var previewID: String?
    func run(_ work: @escaping () throws -> (String, NetworkSettings?, String?)) {
        guard !busy else { return }; busy = true
        Task {
            do {
                let result = try await Task.detached { try work() }.value
                message = result.0; previewCurrent = result.1; previewID = result.1 == nil ? nil : baselineID
                if let id = result.2 { baselineID = id }
            } catch { message = error.localizedDescription; previewCurrent = nil; previewID = nil }
            busy = false
        }
    }
}
struct RecoveryPanel: View {
    @Environment(\.dismiss) var dismiss
    @StateObject var model = RecoveryModel()
    @State var confirmCapture = false
    @State var confirmRestore = false
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Settings recovery").font(.title)
            Text("This version covers DNS and the HTTP proxy for one network service. It does not reset your Mac, repair system files, or change VPN, firewall, browser, HTTPS/SOCKS/PAC settings.")
            TextField("Exact network service name", text: $model.service).disabled(model.busy)
            Button("Save trusted baseline…") { confirmCapture = true }.disabled(model.busy)
            TextField("Saved baseline UUID", text: $model.baselineID).disabled(model.busy)
            HStack {
                Button("Preview recovery") {
                    let id = model.baselineID
                    model.run { let preview = try SettingsRecovery.preview(id); return (preview.0, preview.1, nil) }
                }
                Button("Restore reviewed settings…") { confirmRestore = true }
                    .disabled(model.previewCurrent == nil || model.previewID != model.baselineID)
                Spacer(); Button("Close") { dismiss() }.disabled(model.busy)
            }.disabled(model.busy)
            ScrollView { Text(model.message).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }.frame(minHeight: 160)
            Text("A same-Mac authenticated baseline and a pre-change backup are required. macOS can refuse changes without administrator authorization; Corso never bypasses that requirement. Recovery may interrupt network access.").font(.caption)
        }.padding(20).frame(width: 650)
        .alert("Trust these settings as your baseline?", isPresented: $confirmCapture) {
            Button("Cancel", role: .cancel) {}
            Button("Save baseline") {
                let service = model.service
                model.run { let settings = try SettingsRecovery.read(service); let saved = try SettingsRecovery.save(settings); return ("Saved baseline \(saved.id.uuidString)\n\(SettingsRecovery.describe(settings))", nil, saved.id.uuidString) }
            }
        } message: { Text("Save only from a computer and network configuration you believe are clean. Corso cannot establish that this snapshot is malware-free.") }
        .alert("Apply this settings recovery?", isPresented: $confirmRestore) {
            Button("Cancel", role: .cancel) {}
            Button("Restore settings") {
                if let current = model.previewCurrent, model.previewID == model.baselineID {
                    let id = model.baselineID
                    model.run { (try SettingsRecovery.restore(id, expectedCurrent: current), nil, nil) }
                }
            }
        } message: { Text(model.message + "\nThe current values will be backed up before applying the reviewed baseline.") }
    }
}
