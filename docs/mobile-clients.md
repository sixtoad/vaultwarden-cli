# Mobile approval clients: the platform contract (issue 60)

Android and iOS approval clients reuse the companion's Flutter UI, its Rust
core (`companion/rust`) and its Dart channel clients. What each platform adds
is **native code that implements the same method channels as macOS**, with
the same methods, arguments, closed reply schemas and error behaviour. The
macOS Runner (`companion/macos/Runner`) is the reference implementation.

Nothing a native side returns grants authority. Rust builds and checks every
transcript, and the provider verifies every signature. A native side that
cannot do something exactly as specified returns an error (or `unavailable`),
never a partial or synthesized success.

## Dart side (shared, already selected per platform)

| Dart (`companion/lib/platform/`) | Channel | Notes |
|---|---|---|
| `ProviderPlatform` / `NativeProviderPlatform` (`provider.dart`) | `dev.vaultwarden.companionSlice/provider` | pinned mTLS transport |
| `ApprovalKeyPlatform`, `UserVerificationPlatform` / `NativeApprovalKeyPlatform` (`approval_key.dart`) | `dev.vaultwarden.companionSlice/approvalKey` | hardware approval key |
| `ReviewNotificationPlatform` / `NativeReviewNotificationPlatform` (`notifications.dart`) | `dev.vaultwarden.companionSlice/notifications` | notification entry |
| `DeviceSignalPlatform` / `NativeDeviceSignalPlatform` (`approval_client.dart`) | `dev.vaultwarden.companionSlice/lifecycle` | lock/interruption signals (mobile only) |
| `initializePackagedCore` / `packagedCorePath` (`core_loader.dart`) | — | Rust core loader |

`approvalClientSystems` (`macos`, `android`, `ios`) decides where the native
channel clients are live; Linux and Windows stay transport-less as before.
`mobileSystems` (`android`, `ios`) decides what a phone never shows: desktop
installation controls (`DeviceCapabilities.cliInstall` is false there).

The synthetic Touch ID demonstration (`signer.dart`, channel `.../signer`) and
the disposable pilot (`setupDisposablePilotV1`) are macOS-only and are **not**
part of the mobile contract.

## 1. Provider transport (`.../provider`)

The client identity (private key + leaf certificate) and the CA/pin live only
in platform secure storage: the iOS Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
never synchronizable) or the Android Keystore (non-exportable key; the leaf and
pin in storage only the app can read). Neither the private key nor a PKCS#12
ever crosses into Dart or Rust.

| Method | Arguments | Reply |
|---|---|---|
| `configuration` | none | `{configured:false}` or `{configured:true, endpoint, pin, fingerprint, uncertainId[, managementRecovery]}` (see `NativeProviderPlatform._parse`) |
| `setup` | `{endpoint, pin, passphrase}` | same as `configuration`; a phone that has no file-based import returns `FlutterError(code: "unsupported")` |
| `send` | `Uint8List` body, ≤ 16 KiB | `Uint8List` response, ≤ 1 MiB |
| `settle` | request id (43 base64url chars) | `null` |

Native → Dart: `invalidate` whenever the app leaves the foreground or the
provider session must be retired. The argument is a reason: `close` or
`inactive` (phones and macOS), and on macOS also `sleep` (system sleep). Dart
treats every reason alike (it retires the provider session); a phone sends
`close` or `inactive`.

Transport rules, identical to macOS `PinnedTransport`:

- HTTPS only; the server leaf DER SHA-256 must equal `pin` (64 lowercase hex).
  No system trust fallback, no user-installed CA, no proxy-supplied certificate.
- The client presents exactly the stored identity; `fingerprint` is the SHA-256
  of its leaf DER and is the `approval_client` of every transcript.
- Before a body is sent, persist its uncertain id (`beforeSend` on macOS) so a
  process kill during the exchange reports `uncertainId` on the next
  `configuration`; `settle` clears it.
- One exchange at a time (overlap is an error). Errors carry only a code
  (`provider_unavailable`, ...), never bodies, paths, passwords or OS text.

A phone is normally configured by the guided enrollment journey (#59 phase 3)
rather than by `setup`; that journey adds its own methods when it lands.

## 2. Approval key (`.../approvalKey`)

One key per **(provider, client)**: per `KeyBinding(providerIdentity,
approvalClient)`, both 64 lowercase hex. macOS names it with the tag
`dev.vaultwarden.companion.approval-v2.key.<sha256(providerIdentity || approvalClient) hex>`;
mobile uses the same derivation for its alias.

Key attributes (all required):

- ECDSA **P-256**, generated in hardware: the Secure Enclave on iOS; on Android
  the Keystore with StrongBox when present, otherwise the TEE. A software key
  is `unsafe`, never used. Android checks the level after generation (and on
  every `read`) with `KeyInfo.getSecurityLevel()` (API 31+;
  `KeyInfo.isInsideSecureHardware()` before): only
  `SECURITY_LEVEL_STRONGBOX` or `SECURITY_LEVEL_TRUSTED_ENVIRONMENT` is used;
  anything else (`SOFTWARE`, `UNKNOWN_SECURE`, `UNKNOWN`) is `unsafe`.
- Non-exportable, this device only, never backed up or synchronized.
- **Biometric user verification for every signature**, with no reuse window
  and **no passcode-only approval**:
  - Android: `setUserAuthenticationRequired(true)`,
    `setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)`
    (Class 3 biometrics only, never `AUTH_DEVICE_CREDENTIAL`), auth per use
    through a `BiometricPrompt` `CryptoObject` with
    `setAllowedAuthenticators(BIOMETRIC_STRONG)`.
  - iOS: `SecAccessControl` with `.privateKeyUsage` and `.biometryCurrentSet`
    (never `.userPresence` or `.devicePasscode`, which accept the passcode and
    survive an enrollment change), and a fresh `LAContext` per signature.
- Invalidated by a biometric enrollment change (Android
  `setInvalidatedByBiometricEnrollment(true)`, iOS `.biometryCurrentSet`);
  `read` then reports `invalidated`.

**Decision (#60): no passcode-only approval on phones.** macOS has no passcode
fallback for its approval key (Touch ID only), and a key that the device
passcode alone unlocks would also outlive a biometric enrollment change, which
contradicts the invalidation rule above. Phones therefore never accept the
device credential as the approval verification: `availability` never replies
`deviceCredential` (Dart parses it as `unavailable` on every system), and a
device without enrolled strong biometrics approves with the **provider
password**, which is always offered.

| Method | Arguments | Reply |
|---|---|---|
| `availability` | none | macOS `touchID`; iOS `touchID` or `faceID`; Android `biometric`; otherwise `unavailable` (no biometrics enrolled, locked out, hardware missing) |
| `read`, `create`, `delete` | `{providerIdentity, approvalClient}` | key reply |
| `sign` | `{providerIdentity, approvalClient, session, token, purpose, transcript}` | key reply |
| `cancel` | `{session, token}` | `null` |

Dart accepts only its own system's `availability` values
(`verificationReplies`); macOS stays exactly as strict as before. The reply
also names the verification in the approval messages
(`VerificationWording`: "Face ID", "biometrics", "this device"); macOS keeps
"Touch ID" and "this Mac".

**Key reply** (closed schema, `parseKeyReply`): exactly
`{outcome, publicKey, signature}`. `outcome` is one of `KeyOutcome`
(`present absent created deleted signed invalidated cancelled unavailable
refused failed unsafe`). `publicKey` is empty or the 65-byte SEC1 uncompressed
point; `signature` is non-empty only for `signed` and is the **ASN.1 DER
ECDSA-SHA256** signature (8–72 bytes) over the transcript bytes as given
(the platform hashes; Dart sends the message, not a digest), exactly as
`SecKeyCreateSignature(.ecdsaSignatureMessageX962SHA256)` produces it.

### Bound to the exact request

"Bound to the exact request" means all of the following, and the native side
enforces the parts it can see:

1. The transcript is the v2 transcript of `docs/companion-protocol.md`
   ("Approval transcript"; enrollment uses the proof-of-possession transcript),
   built by Rust from the provider's own review response for one request id,
   one ticket and one generation. Dart never edits it.
2. Before showing the prompt the native side parses the length-prefixed fields
   and refuses (`refused`) unless: field 0 is the domain for `purpose`, the
   provider identity and approval client equal the key's binding, and (approve)
   the key id equals SHA-256 of this key's public point, with the fixed field
   sizes (`ProductionApprovalContract.admits`).
3. One prompt is one signature over that one transcript; it is never cached,
   reused or replayed. `session` (32 lowercase hex) and `token` (strictly
   increasing within a session) identify the attempt; an overlapping or
   out-of-order `sign` is an error and `cancel` acts only on the open
   `(session, token)`.
4. The prompt is cancelled (reply `cancelled`) when the app is backgrounded,
   the screen locks, or `cancel` arrives. A prompt never outlives the unlocked
   foreground session.
5. Dart discards any signature that returns after the attempt was retired
   (see Lifecycle), and Rust refuses a signature whose prepared handle is not
   the current review's (`StaleHandle`).

## 3. Notifications (`.../notifications`)

Same methods as macOS: `status`, `armAuthorization`, `requestAuthorization`,
`enabled`, `setEnabled`, `post {token}`, `withdraw {tokens}`, `watching`,
`listen`; native → Dart `open` with a 22-character base64url token. The native
side owns the only notification text ("A request needs your review."); no
request detail is ever placed in a notification. Permission is asked only after
`armAuthorization` (the Settings toggle), never at launch. On a phone, opening
a notification brings the app forward and Dart loads a fresh review; the
notification itself carries no authority. Remote push transport is #61.

## 4. Lifecycle signals (`.../lifecycle`, mobile only)

Flutter's `AppLifecycleState` arrives on every platform. Mobile also sends
`signal` with `locked` (screen lock / protected data unavailable) or
`interrupted` (a system surface took over without a lifecycle change). Unknown
signals are ignored. macOS sends none: its native signer already cancels on
sleep, lock, session switch and close.

## 5. Rust core

`companion/rust` builds `cdylib` (Android: `jniLibs/<abi>/libcompanion_core.so`,
loaded by bare name), `staticlib` (iOS: linked into the Runner, loaded with
`ExternalLibrary.process`) and `rlib`. Targets: `aarch64-linux-android`,
`aarch64-apple-ios` (and `aarch64-apple-ios-sim` for the simulator). The
desktop installation module compiles on every target but phones never call it.
CI job `mobile-rust-core` checks and builds all three targets.

iOS: `ExternalLibrary.process` looks the bridge symbols up in the running
process at run time, and nothing in the Runner references them at link time,
so the linker dead-strips an ordinary static library. The Runner must keep
them: link the archive with `-force_load
$(PROJECT_DIR)/…/libcompanion_core.a` in `OTHER_LDFLAGS` (per SDK: the device
and simulator archives differ), or turn dead stripping off
(`DEAD_CODE_STRIPPING = NO`) for the Runner. Without it the app builds and
fails at the first Rust call with a missing-symbol error.

## Lifecycle rules (shared Dart, every platform)

See `companion/lib/provider/approval_attempts.dart`. In short:

- A pending authorization is retired on background, lock, interruption,
  navigation, selecting another request, or any provider invalidation.
- A biometric completion is attributed only to the attempt that started it, and
  only while that attempt is still the current, unretired attempt for the same
  request id; anything else sends nothing.
- An approval's result message is shown as-is only with its own request's
  review; on any other review it is prefixed `Earlier request (<operation>,
  <first 8 id characters>…): ` (`TouchIdController.messageFor`), the way the
  request list shows it. It is shown with the first other review loaded after
  the approval ended and cleared by the next review load.
- On return to the foreground a phone re-loads the open request's review from
  the provider; nothing from before the interruption is reused. (Desktop keeps
  its existing behaviour: the retired review asks for an explicit reload.)
- `locked` and `interrupted` retire the attempt and the review at once. A
  `locked` that arrives while Flutter reports the app out of the foreground
  keeps the client suspended until the next `resumed`, including a `resumed`
  that arrives while a system prompt defers lifecycle handling. A `locked`
  that arrives while Flutter still reports `resumed` (the signal raced ahead
  of the lifecycle, or came late after an unlock) is handled like
  `interrupted`: the client resumes at once with a fresh review if it is in
  the foreground. A real lock always takes the app out of `resumed`, which
  suspends it, so the lock still fails closed; latching such a signal could
  leave the phone suspended after an unlock that already happened.
- Phones never show desktop installation controls in Settings
  (`ProviderSettings.installationControls`).

Tests: `companion/test/approval_lifecycle_test.dart` (macOS, Android and iOS
variants of each rule).
