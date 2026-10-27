// External CI fixture only: never compiled into the application.
import Cocoa

@main struct PilotFixtureFocus {
    static func main() {
        guard ProcessInfo.processInfo.environment["CI"] == "true",
              CommandLine.arguments.count == 3,
              let pid = Int32(CommandLine.arguments[1]), pid > 0,
              let target = NSRunningApplication(processIdentifier: pid),
              ["foreground", "inactive"].contains(CommandLine.arguments[2]) else { exit(1) }
        let foreground = CommandLine.arguments[2] == "foreground"
        let app = NSApplication.shared
        var window: NSWindow?
        if foreground {
            app.setActivationPolicy(.prohibited)
            guard target.activate(options: [.activateIgnoringOtherApps]) else { exit(1) }
        } else {
            app.setActivationPolicy(.regular)
            window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 320, height: 100),
                              styleMask: [.titled], backing: .buffered, defer: false)
            window?.title = "Disposable CI focus fixture"
            window?.makeKeyAndOrderFront(nil)
            app.activate(ignoringOtherApps: true)
        }
        let started = Date()
        var ready = false
        let timer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { _ in
            if target.isTerminated { app.terminate(nil) }
            if Date().timeIntervalSince(started) > (ready ? 50 : 10) { exit(1) }
            if !ready && (foreground ? target.isActive : app.isActive && !target.isActive) {
                ready = true
                FileHandle.standardOutput.write(Data("COMPANION_PILOT_FOCUS_READY\n".utf8))
            }
        }
        withExtendedLifetime((window, timer)) { app.run() }
    }
}
