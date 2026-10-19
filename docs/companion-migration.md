# Flutter and Rust companion: first synthetic slice

This is a separate development application, not a replacement for the existing
Swift companion. It shares a Flutter UI and an independent Rust core across
macOS, Windows and Linux. Only macOS has a native signing adapter. Windows and
Linux report biometric signing unavailable and cannot produce an approval.
There is no vault, provider, password, enrollment, network, or execution API in
this application. Existing CLI, Linux-only authority, Swift sources and release
publishing remain unchanged.

## Development

Flutter is pinned to **3.47.7 / Dart 3.13.5**, the stable release identified by
[Flutter's official release metadata](https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json)
on 2026-10-19. Linux SDK SHA-256:
`af7455f540df951184c7953fbe3cf884766e7541dacf8571f9f582db03dd6230`.
The runtime and generator both use flutter_rust_bridge **2.13.0**. Cargo and pub
lockfiles belong to `companion/`; root Cargo files are not part of this change.
The core is tested with Rust 1.88 as well as stable. P-256 verification uses
RustCrypto p256 0.13.2, ECDSA with SHA-256, DER signatures and uncompressed SEC1
public keys.

Run `bash scripts/test-desktop-companion.sh` on the matching desktop host.
Linux needs clang, CMake, Ninja, pkg-config, GTK3 development files and Xvfb.
macOS needs Xcode and Rust targets for both Apple architectures; Windows needs
the Visual Studio desktop C++ workload. This builds the Rust library, runs the
core/Dart tests, builds the application, and runs an integration test that loads
the library from inside the desktop bundle. It never creates a key or opens an
authentication prompt. Public dependencies must be available before offline
mutation tests.

To regenerate bindings, install `flutter_rust_bridge_codegen --version 2.13.0
--locked` and `cargo-expand --version 1.0.112 --locked`, then run
`flutter_rust_bridge_codegen generate` inside `companion/`. Commit generated
Rust/Dart bindings together. Both bridge endpoints check the generated content
hash. The app loads the library beside its own executable, not from the current
working directory. The plain Dart FFI test deliberately loads the development
library in `rust/target/release`.

## Contract and lifecycle

The UI can select only synthetic fixture 1 or 2. Rust supplies their complete
display text and starts a 55-second review window using both monotonic and wall
deadlines. Starting a signing attempt consumes that review immediately. Rust
retains the public key returned by an explicit create/reopen operation; it never
accepts a signing completion's supplied public key as a trust anchor. Reopening
a different identity fails until an explicit successful deletion retires the
old identity. Public key and proof bytes are held only in memory.

The bridge exposes typed operations, work, completion and snapshot records.
There is one process-wide Rust lifecycle and one in-flight native worker. A
work record contains a non-wrapping token, review epoch, fixed fixture ID,
expiry, fresh 32-byte random nonce, and SHA-256 of the retained public key.
Public keys must be 65-byte uncompressed P-256 points; DER signatures are at
most 72 bytes. No generic payload-signing or authenticated-boolean API exists.

Every transcript field is prefixed by its four-byte unsigned big-endian byte
length. Fields, in order:

1. UTF-8 domain `dev.vaultwarden.companion.synthetic.v1`.
2. UTF-8 action `sign` (including the no-interaction negative probe).
3. Fixture ID (four bytes, big endian).
4. Complete fixture title (UTF-8).
5. Complete fixture detail (UTF-8).
6. Review epoch (four bytes, big endian).
7. Attempt token (four bytes, big endian).
8. Expiry in Unix milliseconds (eight bytes, big endian).
9. Random nonce (32 bytes).
10. SHA-256 of retained SEC1 public key (32 bytes).

`companion/fixtures/transcript-v1.hex` freezes fixture 1, epoch 7, token 9,
expiry 1700000000000, nonce `11` repeated 32 times and key ID `22` repeated 32
times. Rust and Swift tests check that exact vector. The native adapter accepts
typed fixture fields and independently constructs this transcript; it does not
accept arbitrary message bytes. This is not the production biometric v2
transcript and conveys no provider authority or remote hardware attestation.

Cancellation, selection changes, sleep and close invalidate the attempt. Expiry
is checked again when a proof returns. Invalidated late proofs cannot increment
the verification count. Admission stays closed until the worker returns; neither
a cancellation reply nor a stale callback frees another worker's slot. Duplicate
callbacks cannot create a second result. Native sleep/close handling also
invalidates its current context before notifying Dart, so a delayed UI event
cannot preserve a signing success.

The noninteractive probe passes only for the specific interaction-required
errors `NSOSStatusErrorDomain/-25308` or
`com.apple.LocalAuthentication/-1004`. Missing keys, generic failures and
unavailable hardware do not count. Any noninteractive signature is unsafe,
including after cancellation. Completed key creation/deletion is reported even
after cancellation; cancellation cannot undo a Keychain mutation. Failed key
operations leave counters and retained identity intact.

## Native identity and operation

Application ID/preferences namespace: `dev.vaultwarden.companionSlice`.
Keychain application tag: `dev.vaultwarden.companionSlice.test-key.v1`.
No preferences or private material are persisted by Dart or Rust. The exact test
tag is the only Keychain identity queried or deleted. Existing inaccessible keys
are never overwritten or silently recreated.

The Mac adapter uses Secure Enclave P-256, device-only unlocked accessibility,
`privateKeyUsage` and `biometryCurrentSet`. Every operation gets a fresh
`LAContext`, zero Touch ID reuse duration and an empty password-fallback title;
the context is invalidated on completion/cancellation. Key management and the
negative probe disallow authentication UI. Private-key bytes are never exported.
Checking availability on launch uses `canEvaluatePolicy`, not authentication.

Explicitly create the disposable key, review request 1, and sign. Review request
2 and sign separately. Reopen only after an explicit action following relaunch.
Delete only the disposable key through the application's Delete test key action.
Do not install over the existing companion. Hardware interactions, fingerprint
set changes and signing-profile changes require operator coordination.

## Evidence and completion boundaries

Automated tests establish protocol/lifecycle behavior, not a physical touch.
`scripts/mutate-desktop-companion.py` changes verification, transcript binding,
expiry, cancellation, duplicate consumption and admission one at a time. Each
mutation must fail an actual test, not compilation; it restores the exact source
bytes and reruns the baseline. CI retains logs and development application
artifacts for three operating systems. The new desktop jobs join Merge Ready;
the existing release-publishing workflow is unchanged.

Local checks on 2026-10-19 used the verified Flutter SDK and an isolated Debian
Linux build container (CMake 3.25.1, Ninja 1.11.1, GTK 3.24.38, Xvfb, Rust 1.88).
No host desktop packages were installed. Six Dart tests include an actual FFI
load and a widget/native-worker cancellation flow; one additional desktop
integration test loads the library from the built bundle. The release bundle
builds successfully; desktop integration uses the debug bundle. Native
macOS/Windows builds and hardware cases are pending until executed on matching
runners. CI configuration alone does not establish a passing run.

| Required evidence | Status |
| --- | --- |
| Rust 1.88 lifecycle and shared transcript vector | 10 tests passed locally with generated bridge |
| Rustfmt and stable Clippy | Passed locally |
| Security mutations and exact restored baseline | Six mutations caught by test failures; restored baseline passed |
| Flutter analysis, widget/platform tests and actual FFI load | Analysis clean; all six tests passed |
| Linux desktop build and packaged bridge integration | Release build and debug packaged integration passed in isolated container |
| macOS build, native contract tests and packaged bridge integration | Pending matching runner |
| Windows build and packaged bridge integration | Pending matching runner |
| Two successive separate touches on the real Mac | Pending coordinated operator evidence |
| No-interaction refusal, cancel/late completion, reopen after exit | Pending coordinated operator evidence |
| Same identity after rebuild and changed bundle/signing profile | Pending coordinated operator evidence |
| Biometric-set change makes old key unusable | Pending separately authorized hardware action |

## Parity and eventual Swift removal

The existing companion stays supported. Replacement requires evidence for:

- Trusted provider configuration, mTLS identity handling, CA/hostname/leaf pin
  negatives, enrollment and recovery without weaker authentication.
- Inbox/review, denial, explicit password approval, vault unlock, uncertain
  delivery/status recovery, expiry, disconnect/reconnect and no replay.
- Tray/menu-bar behavior, background lifetime, startup policy, notification
  routing, sleep/wake, accessibility and multi-display behavior on each desktop.
- Packaging, installer/uninstaller, updates, code signing/notarization, key and
  preferences migration, rollback, crash recovery and dependency auditing.
- Production biometric enrollment/verifier protocol and real restricted-agent
  acceptance, as a separate authorized change.

This slice opens an ordinary desktop window and exits when closed. No tray,
background service, startup registration or notification API is implemented.
Development bundles are CI artifacts only, not installers or release assets.
Evidence for those capabilities is pending, not assumed from Flutter's support.
SwiftUI removal and installed-app replacement remain blocked until the parity
checklist and coordinated native acceptance are complete.
