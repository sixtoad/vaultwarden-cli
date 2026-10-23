import AppKit
import Darwin

@MainActor final class ProbeDelegate: NSObject, NSApplicationDelegate {
    let graceful: Bool
    init(graceful: Bool) { self.graceful = graceful }
    func applicationDidFinishLaunching(_ notification: Notification) {
        print("COMPANION_PROVIDER_TLS_PROGRESS:startup:complete")
        print("COMPANION_PROVIDER_TLS_PROGRESS:shutdown:enter")
        fflush(stdout)
        if graceful { NSApp.terminate(nil) }
        else {
            print("COMPANION_PROVIDER_TLS_OK")
            fflush(stdout)
            exit(0)
        }
    }
    func applicationWillTerminate(_ notification: Notification) {
        print("COMPANION_PROVIDER_TLS_PROGRESS:shutdown:complete")
        print("COMPANION_PROVIDER_TLS_OK")
        fflush(stdout)
    }
}

@main struct AppKitStartupProbe {
    @MainActor static func main() {
        print("COMPANION_PROVIDER_TLS_PROGRESS:startup:enter")
        fflush(stdout)
        let application = NSApplication.shared
        let delegate = ProbeDelegate(graceful: CommandLine.arguments.contains("graceful"))
        application.delegate = delegate
        application.setActivationPolicy(.regular)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 320, height: 200),
                              styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "Disposable AppKit startup probe"
        window.makeKeyAndOrderFront(nil)
        withExtendedLifetime((delegate, window)) { application.run() }
    }
}
