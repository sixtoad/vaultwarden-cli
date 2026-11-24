# iOS approval client (#60 phase 2)

`companion/ios` is the Flutter iOS platform project of the approval companion.
It reviews and approves provider requests on an iPhone with Face ID or Touch ID.
Phones never install a desktop CLI: there is no installation channel and no
desktop installation control in mobile settings. Phone enrollment itself is #59.

## What is shared and what is iOS-only

The iOS Runner compiles the macOS Runner's portable sources unchanged (by
relative file reference, like the macOS project already does for
`macos/Sources/CompanionCore`):

| Source | Role on iOS |
|---|---|
| `companion/macos/Runner/ProductionApprovalContract.swift` | v2 transcript admission, key binding and tag namespace (`dev.vaultwarden.companion.approval-v2.key.`), one-signature gate |
| `companion/macos/Runner/ProductionApprovalKey.swift` | the Secure Enclave key: create/read/delete/sign, error classification |
| `companion/macos/Runner/ReviewNotificationContract.swift` | generic notification copy, token and tap rules (#61) |
| `companion/macos/Runner/ProviderSettings.swift` | durable configuration and pending-decision recovery |
| `macos/Sources/CompanionCore/{Protocol,Trust}.swift` | `PinnedTransport` and the Keychain client identity |

Two shared files gained iOS branches, leaving macOS behaviour unchanged:
`ProductionApprovalKey.biometry()` admits Touch ID only on macOS and Face ID
or Touch ID on iOS (Optic ID and future sensors are refused), and
`KeychainIdentity.importPKCS12` adds the decoded identity explicitly on iOS
(`SecPKCS12Import` does not persist there). Keychain items outlive an app
reinstall, so on a duplicate the iOS import first looks the identity up
(`kSecClassIdentity`); when the persisted certificate is not byte-identical to
the imported one (a renewed certificate on the same key, or a stale identity
from an earlier install), it deletes that key's certificate and private key
(`kSecAttrPublicKeyHash` / `kSecAttrApplicationLabel`) and adds the imported
identity once. A certificate that collides on issuer and serial with a
different key still fails closed. The queries are pure and tested on the host
(`macos/Tests/CompanionCoreTests/IOSIdentityQueryTests.swift`).

iOS-only code lives in `companion/ios/Runner`:

- `MobileApprovalContract.swift`: UIKit-free rules, tested on the macOS host by
  `swift test` (`companion/mobile_native_tests`) and on a simulator by
  `ios/RunnerTests`. A signature leaves the channel only when it is canonical
  DER and verifies over the exact transcript with the key's public point;
  anything that is not `signed` carries no bytes.
- `MobileApprovalKeyChannel.swift`: the `approvalKey` channel, same methods
  and replies as macOS. `availability` answers `faceID`, `touchID` or
  `unavailable`.
- `MobileProviderAdapter.swift`: the `provider` channel; CA and PKCS#12 come
  from the Files picker (copied into the sandbox, size-bounded, then deleted).
- `MobileReviewNotificationAdapter.swift`: the `notifications` channel.
- `MobileChannels.swift`, `AppDelegate.swift`: registration on the implicit
  engine, plus the `lifecycle` channel's `locked` signal.

## Approval key

Non-exportable Secure Enclave P-256, one per (provider leaf pin, client
certificate pin), `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
`[.privateKeyUsage, .biometryCurrentSet]`: adding or resetting Face ID, or
changing the Touch ID fingers, invalidates it and it must be enrolled again.
Every operation uses a fresh `LAContext` with reuse duration 0 and no
fallback title; the key has no device-passcode alternative. The key signs
only a transcript Rust built that `ProductionTranscript.admits` binds to this
provider, this client and this key; the output is ASN.1 DER. Cancel, failure,
lockout and invalidation return their outcome with no signature, never
approve, and never submit a password.

## Client identity and transport

The PKCS#12 identity is imported into the app's Keychain as
`...WhenUnlockedThisDeviceOnly` (never migrated to a backup or another
device). Only its persistent reference is saved. Unlike the approval key, an
imported private key cannot live in the Secure Enclave. `PinnedTransport`
evaluates the enrolled private CA only, the hostname and validity, then the
SHA-256 leaf pin; there is no system-trust fallback.

### App Transport Security (justification for App Store review)

`Info.plist` sets `NSAllowsArbitraryLoads`, as the macOS companion does. The
app talks to exactly one host, the operator's own self-hosted provider, which
is chosen at runtime during setup, so no `NSExceptionDomains` entry can name it
at build time. That provider is normally served under a private CA the system
does not trust, and ATS evaluates system trust before the app's
`URLSession` delegate can apply the enrolled trust policy. The exemption does
not weaken transport security: `ProviderConfiguration` accepts only `https`
endpoints, the session requires TLS 1.2 or later, and `PinnedTransport`
accepts only a chain to the enrolled CA (anchors only, no network fetch) whose
leaf matches the enrolled SHA-256 pin, plus mutual TLS with the client
identity. No other host is ever contacted. Whether the custom trust delegate
alone works with ATS on is an open on-device check (`ats_on` in the hardware
evidence checklist); if it does, the exemption should be narrowed or dropped.

## Lifecycle

`MobileLifecycle` maps UIKit application notifications:

| Notification | Effect |
|---|---|
| did enter background | cancel an open prompt; provider `invalidate("inactive")`; drop a prepared admin ticket |
| protected data will become unavailable (device lock) | cancel prompt; `invalidate("inactive")`; lifecycle `signal("locked")`; drop ticket |
| will terminate | cancel prompt; `invalidate("close")`; drop ticket |
| will resign active | drop a prepared admin ticket only |

Resign-active does NOT cancel the prompt or retire the review: iOS resigns the
app active to present the Face ID / Touch ID sheet itself, exactly like the
macOS Touch ID sheet, so the shared Dart rule that defers `inactive` while a
prompt is open (`touchId.lifecycleExempt`) is what keeps a valid prompt alive.
Calls, the app switcher and the notification shade reach Flutter as
`inactive`, so iOS sends no `interrupted` signal. A `sign` call is refused while
the app is in the background.

## Notifications

Local notifications only, posted while the app runs (iOS suspends a
backgrounded app; there is no remote push). Fixed title and body, an opaque
token as identifier, no user info, categories or actions. A tap hands Flutter
the token; Flutter loads a fresh review of that exact request. A notification
never approves or denies.

## Building and testing

- `swift test --package-path companion` runs the shared and mobile contract
  tests on the macOS host.
- The `ios-approval-client` job runs `scripts/test-ios-companion.sh` on a
  GitHub-hosted `macos-26` runner with an iPhone simulator. It runs the Swift contract
  tests, the Dart iOS channel-contract tests (`test/ios_approval_client_test.dart`),
  `flutter build ios --no-codesign` (release and debug) with the core
  force-loaded and its bridge symbols checked in the image that holds them, and
  `ios/RunnerTests` on a simulator (re-run once if the first attempt fails, so a
  simulator that fails to boot is not a test failure). Unsigned; no
  provisioning or secrets. The job is not yet required by Merge Ready; it
  joins after a few green runs.
- Locally (no simulator runtime here): `COMPANION_IOS_CORE=absent flutter build
  ios --no-codesign --debug` and `xcodebuild build-for-testing -destination
  'generic/platform=iOS Simulator'` compile the app and the XCTest bundle.
- The Xcode phase `scripts/build-companion-ios-core.sh` builds
  `libcompanion_core.a`, which the Runner force-loads (Dart uses
  `ExternalLibrary.process`). On a host without the iOS Rust targets,
  `COMPANION_IOS_CORE=absent` links an empty archive for a compile-only check;
  that app cannot start its core.

A simulator has no Secure Enclave or enrolled biometry, so CI proves the
contract and attributes, not a hardware signature.

## Signing team

The project commits no `DEVELOPMENT_TEAM` (neither does the macOS project).
CI builds unsigned. To run on a physical iPhone, the operator sets their own
team locally (Xcode: Runner target > Signing & Capabilities > Team, or
`DEVELOPMENT_TEAM=<team id>` on the `xcodebuild` command line) and does not
commit that change.

## Hardware evidence (operator, physical iPhone)

`scripts/ios-approval-hardware-evidence.sh <evidence-dir> [Runner.app]` is an
interactive checklist. The operator builds, signs and installs the app with
their own Apple developer identity; the script records the source revision,
the executable hash, the device and each observed result: enroll, approve
twice (separate prompts), cancel, no passcode fallback, background and lock
during a prompt, notification tap, relaunch (same key fingerprint), ## Signing team

The project commits no `DEVELOPMENT_TEAM` (neither does the macOS project).
CI builds unsigned. To run on a physical iPhone, the operator sets their own
team locally (Xcode: Runner target > Signing & Capabilities > Team, or
`DEVELOPMENT_TEAM=<team id>` on the `xcodebuild` command line) and does not
commit that change.

## Hardware evidence (operator, physical iPhone) It refuses to run in CI or without a
terminal and changes nothing itself. Failures remain failures.
