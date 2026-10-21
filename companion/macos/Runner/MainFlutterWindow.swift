import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  private var approvalSigner: ApprovalSigner?
  private var providerAdapter: ProviderAdapter?
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)

    RegisterGeneratedPlugins(registry: flutterViewController)
    approvalSigner = ApprovalSigner(messenger: flutterViewController.engine.binaryMessenger)
    providerAdapter = ProviderAdapter(messenger: flutterViewController.engine.binaryMessenger)

    super.awakeFromNib()
  }
}
