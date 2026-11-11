---
title: 'Review-request notifications in the macOS companion (#61)'
type: 'feature'
created: '2026-11-09'
status: 'done'
context: ['{project-root}/docs/companion-migration.md', '{project-root}/AGENTS.md']
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The Flutter companion never tells the operator that a request needs review; its polling stops as soon as the window is inactive, so a request submitted while the operator works elsewhere goes unnoticed.

**Approach:** A small native macOS channel over `UNUserNotificationCenter` posts a generic notification (fixed native text, opaque random identifier) for each newly pending request seen by a read-only inbox watch that runs while the window is inactive. Opening it brings the app forward and runs the normal fresh `review` of that exact request; final requests show #69's final-state view.

## Boundaries & Constraints

**Always:** generic copy only ("A request needs your review."); the notification carries an opaque per-process token, never a request id, label, target, agent or value; the token maps to the id in Dart memory only; opening always fetches a fresh review from the provider; one notification per request id per process; notifications off by default and permission requested only by the Settings toggle; the background watch sends only `session` and `list`.

**Ask First:** (autonomous run: decisions logged in the PR instead) menu-bar/background lifetime after window close; Windows/Linux.

**Never:** notification actions/categories (no approve/deny on a notification); reading review content from the notification; posting while the window is foreground; review/decision/history/management/unlock from the watch; a new pub dependency.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| New request while inactive | watch list gains id X, enabled + authorized | one `post(token)`; token maps to X | post failure ignored (in-app list unaffected) |
| Same request next polls | X still listed | nothing posted | N/A |
| Request seen in foreground | list while resumed | recorded as known, never posted | N/A |
| Click, still pending | open(token) | app forward, `review(X)` fresh, approval screen | review refused → "could not be loaded" text |
| Click, decided/expired after firing | provider status final | final-state view, no approval controls | N/A |
| Unknown token (relaunch) | open(token) not in map | Requests list, note shown | N/A |
| Setting off / permission denied | toggle off or OS denied | nothing posted; Settings explains | denied keeps toggle off |

</frozen-after-approval>

## Code Map

- `companion/lib/provider/controller.dart` -- polling; add background watch, inbox observer hook, deferred open.
- `companion/lib/provider/page.dart` -- lifecycle; wire notifier, open handling, Settings panel.
- `companion/lib/platform/notifications.dart` (new) -- `ReviewNotificationPlatform` + method channel.
- `companion/lib/provider/review_notifications.dart` (new) -- dedupe/token/permission/setting logic + Settings view.
- `companion/macos/Runner/ReviewNotificationContract.swift` (new, SwiftPM + Xcode) -- fixed content, token validation.
- `companion/macos/Runner/ReviewNotificationAdapter.swift` (new, Xcode) -- UNUserNotificationCenter, delegate, activation, UserDefaults toggle.
- `companion/macos/Runner/AppDelegate.swift`, `MainFlutterWindow.swift`, `project.pbxproj`, `Package.swift` -- registration.

## Tasks & Acceptance

**Execution:**
- [x] native contract + adapter + registration
- [x] Dart platform, notifier, controller watch, page wiring, Settings panel, capability text
- [x] tests: `test/review_notifications_test.dart`; Swift `native_tests/ReviewNotificationContractTests.swift`
- [x] docs: `docs/companion-migration.md`, `docs/implementation/issue-50-capabilities.md`

**Acceptance Criteria:**
- Given a notification for X fired and X was then approved/expired, when it is opened, then a fresh review shows the final-state view with no password field.
- Given the toggle is off or permission is denied, when a new request appears in the background, then nothing is posted.

## Spec Change Log

- Review round 1 (2 reviewers, no HIGH): patched first-read burst (baseline), switch shown from effective state + denial text on revocation, foreground judged at reply, watch rescheduled while loading and gated on a confirmed reconcile, failed posts retried, pending review cancelled on provider change, no invalidation of an in-flight decision/prompt on click, Swift tests use real UN identifiers. Deferred: per-request withdrawal of delivered notifications. KEEP: token-only payload, native fixed copy, session/list-only watch guard.

## Design Notes

D1 mechanism: own method channel (`UNUserNotificationCenter`), as the existing Runner channels; no plugin (lockfile has none, a plugin adds a federated dependency for 4 calls).
D2 background: the companion is a window app that quits on close and suspends on `inactive`; a read-only watch (session+list, 15 s, backoff to 60 s) runs only while suspended, configured, idle and notifications are enabled+authorized.
D3 payload: opaque random token as identifier; fixed copy lives in Swift so Dart cannot send text.

## Verification

**Commands:**
- `flutter analyze`, `flutter test`, `swift test --package-path companion -Xswiftc -warnings-as-errors`, `flutter build macos --debug` -- all green.
