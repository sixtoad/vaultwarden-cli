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
(`SecPKCS12Import` does not persist there).

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
- `MobileChannels.swift`, `AppDelegate.swift`: registration on the implicit engine.

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
SHA-256 leaf pin; there is no system-trust fallback. ATS arbitrary loads are
enabled for the same reason as on macOS (Info.plist comment).

## Lifecycle

`MobileLifecycle` maps UIKit application notifications:

| Notification | Effect |
|---|---|
| did enter background | cancel an open prompt; `invalidate("background")` to Flutter; drop a prepared admin ticket |
| protected data will become unavailable (device lock) | cancel prompt; `invalidate("locked")`; drop ticket |
| will terminate | cancel prompt; `invalidate("close")`; drop ticket |
| will resign active | drop a prepared admin ticket only |

Resign-active does NOT cancel the prompt or retire the review: iOS resigns the
app active to present the Face ID / Touch ID sheet itself. The shared Dart
lifecycle rules must therefore not retire a review on Flutter's `inactive`
state while a biometric prompt is open on iOS. A `sign` call is refused while
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
- CI job `ios-companion` (`.github/workflows/ci.yml`, `macos-26`): installs the
  `aarch64-apple-ios` and `aarch64-apple-ios-sim` Rust targets, builds the
  core for the device target, `flutter build ios --no-codesign`, and runs
  `ios/RunnerTests` on a simulator. Unsigned; no provisioning or secrets.
- The Xcode phase `scripts/build-companion-ios-core.sh` builds
  `libcompanion_core.a`, which the Runner force-loads (Dart uses
  `ExternalLibrary.process`). On a host without the iOS Rust targets,
  `COMPANION_IOS_CORE=absent` links an empty archive for a compile-only check;
  that app cannot start its core.

A simulator has no Secure Enclave or enrolled biometry, so CI proves the
contract and attributes, not a hardware signature.

## Hardware evidence (operator, physical iPhone)

`scripts/ios-approval-hardware-evidence.sh <evidence-dir> [Runner.app]` is an
interactive checklist. The operator builds, signs and installs the app with
their own Apple developer identity; the script records the source revision,
the executable hash, the device and each observed result: enroll, approve
twice (separate prompts), cancel, no passcode fallback, background and lock
during a prompt, notification tap, relaunch (same key fingerprint), biometric
enrollment change (only with explicit owner authorization: key invalidated),
re-enroll (new fingerprint) and revoke. It refuses to run in CI or without a
terminal and changes nothing itself. Failures remain failures.
