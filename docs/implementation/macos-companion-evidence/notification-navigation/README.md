# Notification opens the approvals tab

The operator confirmed that a delivered notification opened the companion window while leaving its previously selected Setup tab visible. The tab view had no explicit selection binding, so opening the existing window did not change the selected tab.

The app now keeps its selected tab in the shared observable model. Both notification clicks and the menu’s Open approvals action select Approvals synchronously before opening the window. Notification handling retains the existing fresh session/list/review sequence; no notification content authorizes a decision. Setup remains available through the normal tab control.

Only `macos/Sources/ApprovalCompanion/App.swift` changed relative to the preceding authentication-response native manifest. Transport, protocol, expiry, password and decision guards are unchanged; their recorded security mutation evidence remains applicable. No focus changes or AppleEvents/Accessibility queries were introduced.

Operator regression still required after the parent updates the authorized installed test app: select Setup, receive a fresh approval notification, click it and confirm Approvals opens with the current request review. Also select Setup and use the menu’s Open approvals action. Native checks do not substitute for these logged-in checks.

Native verification passed on the authorized Mac: 9 XCTest cases, 15 real-bundle transport cases, 0 failures/skips; release build, plist validation and strict ad-hoc signature verification passed. All 13 source hashes matched the repository. Temporary Keychain cleanup and task-specific LaunchServices registration absence were verified. The prepared bundle was not opened or installed by this lane.

[Raw evidence](evidence.tar.gz), [archive hash](evidence.tar.gz.sha256), [source hashes](source-hashes.json), [bundle hashes](bundle-verification.json), [bundle cases](bundle-results.json).
