import PokeyPlatform
import ServiceManagement
import SwiftUI
import SystemExtensions

// Host app in /Applications. It only installs and removes the components:
// the sensor system extension (OSSystemExtensionRequest), the pokey-netd
// LaunchDaemon and the pokey-ui LaunchAgent (SMAppService). It never talks to
// the sensor and parses no untrusted data.

/// Plist names inside Contents/Library/LaunchDaemons and LaunchAgents.
enum LaunchPlists {
    static let netd = "netd.plist"
    static let ui = "ui.plist"
}

@MainActor
final class Installer: NSObject, ObservableObject, OSSystemExtensionRequestDelegate {
    @Published var extensionState = "unknown"
    @Published var netdState = ""
    @Published var uiState = ""
    @Published var error: String?

    let config: PokeyConfig?
    private let netd = SMAppService.daemon(plistName: LaunchPlists.netd)
    private let ui = SMAppService.agent(plistName: LaunchPlists.ui)

    override init() {
        var cfg: PokeyConfig?
        var err: String?
        do { cfg = try PokeyConfig.main() } catch { err = String(describing: error) }
        config = cfg
        super.init()
        self.error = err
        refresh()
    }

    func refresh() {
        netdState = Self.describe(netd.status)
        uiState = Self.describe(ui.status)
    }

    func install() {
        guard let config else { return }
        error = nil
        submit(.activationRequest(forExtensionWithIdentifier: config.identifier(.sensor), queue: .main))
        do {
            try netd.register()
            try ui.register()
        } catch {
            self.error = "Registering background items failed: \(error.localizedDescription). "
                + "Approve them in System Settings > General > Login Items."
        }
        refresh()
    }

    func uninstall() {
        guard let config else { return }
        error = nil
        do {
            try ui.unregister()
            try netd.unregister()
        } catch {
            self.error = "Unregistering background items failed: \(error.localizedDescription)"
        }
        submit(.deactivationRequest(forExtensionWithIdentifier: config.identifier(.sensor), queue: .main))
        refresh()
    }

    func openLoginItems() { SMAppService.openSystemSettingsLoginItems() }

    private func submit(_ request: OSSystemExtensionRequest) {
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    nonisolated func request(_ request: OSSystemExtensionRequest,
                             actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            self.extensionState = "waiting for approval in System Settings > Privacy & Security "
                + "(also grant Full Disk Access to the sensor)"
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest,
                             didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Task { @MainActor in
            self.extensionState = result == .completed ? "done" : "done after reboot"
            self.refresh()
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in
            self.extensionState = "failed"
            self.error = error.localizedDescription
        }
    }

    static func describe(_ s: SMAppService.Status) -> String {
        switch s {
        case .notRegistered: return "not registered"
        case .enabled: return "enabled"
        case .requiresApproval: return "requires approval in Login Items"
        case .notFound: return "not found in app bundle"
        @unknown default: return "unknown"
        }
    }
}

struct ContentView: View {
    @ObservedObject var installer: Installer

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Endpoint file monitor").font(.title2)
            LabeledContent("Sensor extension", value: installer.extensionState)
            LabeledContent("Network daemon", value: installer.netdState)
            LabeledContent("Alerts agent", value: installer.uiState)
            if let e = installer.error {
                Text(e).foregroundStyle(.red).textSelection(.enabled)
            }
            HStack {
                Button("Install") { installer.install() }
                Button("Uninstall") { installer.uninstall() }
                Button("Login Items…") { installer.openLoginItems() }
                Spacer()
                Button("Refresh") { installer.refresh() }
            }
            .disabled(installer.config == nil)
        }
        .padding(20)
        .frame(minWidth: 480)
    }
}

@main
struct PokeyHostApp: App {
    @StateObject private var installer = Installer()

    var body: some Scene {
        WindowGroup { ContentView(installer: installer) }
            .windowResizability(.contentSize)
    }
}
