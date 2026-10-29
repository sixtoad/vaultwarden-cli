import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  private var approvalSigner: ApprovalSigner?
  private var providerAdapter: ProviderAdapter?
  private var installationChannel: FlutterMethodChannel?
  private var commandDirectory: URL?
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)

    RegisterGeneratedPlugins(registry: flutterViewController)
    approvalSigner = ApprovalSigner(messenger: flutterViewController.engine.binaryMessenger)
    providerAdapter = ProviderAdapter(messenger: flutterViewController.engine.binaryMessenger)

    installationChannel = FlutterMethodChannel(name: "dev.vaultwarden.companionSlice/installation", binaryMessenger: flutterViewController.engine.binaryMessenger)
    installationChannel?.setMethodCallHandler { [weak self] call, result in
      guard let self else { result(FlutterError(code: "closed", message: "Window closed", details: nil)); return }
      switch call.method {
      case "selectCommandDirectory":
        guard self.commandDirectory == nil else { result(FlutterError(code: "busy", message: "Directory selection already active", details: nil)); return }
        let panel = NSOpenPanel()
        panel.title = "Enable terminal commands in a folder inside your home"
        panel.message = "Choose your user bin folder. This grants access only to the selected folder; system PATH and vault authority are unchanged."
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { result(nil); return }
        // NSOpenPanel starts access to the user-selected directory.
        // releaseCommandDirectory balances that grant after the Rust operation.
        self.commandDirectory = url
        result(url.path)
      case "releaseCommandDirectory":
        self.commandDirectory?.stopAccessingSecurityScopedResource()
        self.commandDirectory = nil
        result(nil)
      default: result(FlutterMethodNotImplemented)
      }
    }
    super.awakeFromNib()
  }
}
