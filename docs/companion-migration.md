# Flutter and Rust companion: development provider flow

This is a separate development application, not a replacement for the existing
Swift companion. It shares a Flutter UI and an independent Rust core across
macOS, Windows and Linux. macOS now connects to the existing Linux provider using
the unchanged v1 protocol. Windows and Linux clearly report provider transport
unavailable. The previous synthetic signing demonstration remains available as a
separate mode. Existing CLI, Linux secret custody/execution, restricted agent
identity and production provider sources are unchanged.

## Foreground provider flow

The normal entrypoint opens Requests in the Quiet Instrument shell. Open Settings
for advanced development provider setup and the separate synthetic signer. Supply an HTTPS
endpoint and independently verified lowercase server leaf SHA-256, confirm the
client identity is dedicated to this development application, then select the
private CA DER and dedicated PKCS#12 through native file dialogs. The PKCS#12
passphrase is used only for import. The identity must be separately enrolled on
Linux through the existing trusted operator procedure; this application cannot
enroll itself and never looks up the installed Swift app's settings or identity.

The native adapter compiles the existing `macos/Sources/CompanionCore/Trust.swift`
and `Protocol.swift` directly. Private keys never cross the platform channel.
Public configuration and an opaque Keychain identity reference are saved in this
sandbox's `Application Support/dev.vaultwarden.companionSlice.provider/` directory.
The client certificate fingerprint is visible for enrollment comparison and
relaunch checks. Import does not delete any existing Keychain material. Replacing
setup while a decision is unresolved is prohibited, preserving its original
provider identity. No system CA trust is installed or changed.

The Mac sandbox retains file selection and outbound-network entitlements. The
packaged ATS private-CA allowance lets the native delegate perform mandatory
private CA, hostname, certificate-validity and exact leaf-pin verification.
`ProviderConfiguration` still accepts only HTTPS and `PinnedTransport` requires
TLS 1.2+, enrolled client identity, bounded response framing and no redirects.
The ATS entry is not an alternate trust path or an HTTP transport option.

Rust validates closed v1 objects and every canonical review field, preserves
argument boundaries, quotes strings and escapes all non-ASCII/control scalars.
The UI shows the provider's 256-request cap explicitly. Authority/inbox reads
poll every five seconds while foregrounded, backing off to at most 30 seconds
after transport or typed protocol failures; failed session authority never starts
an inbox read. Valid locked authority is not treated as a transport failure.
Setup, selection, inactive/hidden state, sleep, close and disconnect retire
reviews; stale read completions cannot restore authority. Tickets are usable for
at most 55 monotonic seconds measured from the review request start and before
the request's wall-clock deadline. Authority generation changes retire reviews.

Foreground and current-route eligibility are independent: returning focus while
the synthetic route is visible cannot restart provider polling. Native setup
dialogs may finish importing while inactive, but the controller reloads saved
metadata before admitting work. Interrupted startup and failed metadata reads
can be recovered with Refresh/Reload saved setup; a completed replacement never
uses the old displayed provider metadata for new transport work.

Operation admission remains closed through durable native settlement. If clearing
the saved marker fails, Refresh original request status retries status/settlement
against the same configuration and request ID, never decision or unlock. Native
settlement already in flight is completed even after page disposal. Authoritative
approved/running resolves delivery uncertainty but is not terminal execution:
foreground polling follows that original status ID until completion/failure.
Configuration replacement clears completed-status tracking, not unresolved work.

Correction regressions use the real Rust bridge in `test/provider_test.dart`.
`scripts/mutate-provider-controller.py` exercises metadata reconciliation,
settlement admission, route eligibility, saved-ID restoration, typed refresh and
status following, restoring exact source bytes and retesting. Native CI tests
production identity install/reload and failures using only a verified disposable
default Keychain, then restore the original default/search list and remove it;
an install-save mutation must be caught. Packaged CI retains the original 14 TLS
cases and adds controller unlock/inbox/terminal status and two controller relaunch
recovery cases with exact command counts. These additions require matching native
CI execution; earlier operator acceptance does not certify corrected code.
Near-limit rendering/FFI performance remains unmeasured and deferred.

Approve-once requires a fresh password; deny sends no password. Starting either
consumes the review before transport. Wrong-password rejection requires explicit
new review. Unlock is a separate single POST followed by authority reads; old
requests never revive and the agent must submit new work after unlock. Password
fields clear on submission and context changes, transient Rust password storage
is zeroized, and Dart clears the outgoing byte buffer after the native call.
No password, ticket, review or secret is persisted or logged.

Before a decision POST, native code atomically records its request ID beside its
bound configuration. Close/relaunch restores that uncertainty. A lost, malformed,
stale or unavailable decision reply permits only status reads for that original
request; no decision/unlock retry occurs. Pending remains uncertain. Terminal or
committed status resolves it; definite pre-commit rejection permits a fresh
review. Durable recovery is cleared only after Rust validates that resolution.
Unlike the older Swift UI's explicit pending re-review option, this flow follows
the approved status-only recovery policy until authoritative resolution.

## Provider verification and remaining acceptance gates

`companion/rust/tests/provider.rs` plus core unit tests cover schema closure,
full escaped review, limits, ticket consumption, both expiry clocks, generation
changes, stale/duplicate completions, wrong passwords, separate unlock and
request-scoped uncertainty. Flutter tests exercise the generated FFI library,
controller lifecycle, password-field invalidation and unavailable-platform UI.
Debug desktop integration and the AOT release smoke include bounded protocol
fixtures through the packaged library. These fixtures do not execute protected
operations and do not establish real provider acceptance.

Run `python3 scripts/mutate-provider-companion.py <evidence-dir>` without other
companion edits/builds: schema, escaped text, ticket admission, stale reads,
pending uncertainty, request binding, duplicate completions and both expiry clocks
must fail tests individually, restore exact bytes and pass a final baseline.
On Mac, `scripts/test-provider-native.sh` stages the actual shared TLS sources and
new recovery storage together with the existing real URLSession/Keychain TLS
fixture tests. It also mutates leaf-pin and trust evaluation in that isolated
copy. The normal desktop script runs this native suite; CI preserves its logs.

Matching macOS/Windows builds and release archives remain required. Mac CI also
builds `integration_test/provider_tls_smoke.dart` as an AOT application and runs
`scripts/test-provider-packaged.py` against that actual sandboxed Flutter/Rust/native
adapter. It refuses an existing development configuration, imports only synthetic
identities into a new disposable Keychain restricted to that executable, and
restores the original Keychain search list. Fourteen loopback cases cover approval,
denial, wrong password, wrong pin/CA/client/hostname, expired leaf, redirect,
oversize/schema rejection and lost-response/pending recovery across separate app
processes. Command counters must show exactly one decision and status-only
recovery. This is authored verification, not passing evidence until Mac CI runs it.
It is still a transport fixture with no protected execution. Coordinate the exact
Mac release artifact against the isolated
Linux `tests/companion-acceptance.py` fixture and a distinct-UID, non-TTY
`vw-access` agent: approve executes exactly once, denial executes nothing, and
the agent receives only redacted status. Exercise wrong CA/pin/hostname/client,
expired certificate, redirect, malformed reply, lost decision response, relaunch
and fingerprint continuity in the packaged app; count transmitted decision
bodies to demonstrate single-send behavior. This coordinated fixture uses
synthetic backend/authentication despite real transport, state and execution.
Live Vaultwarden smoke requires separately approved configuration. No live
enrollment, deployment, installed-app replacement or physical Touch ID acceptance
is implied by these automated checks. Hardware work remains outside this change.

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
core/Dart tests and debug packaged integration, then builds and executes a release
AOT smoke entrypoint that checks the packaged library, native contract and rendered
fixture using explicit runtime failures. The pinned Flutter SDK's `flutter test`
forces debug mode, so a release build alone is not counted as a release run.
The script rebuilds `lib/main.dart` afterward and archives that ordinary
application for operator acceptance. Python 3.12 is pinned in desktop CI.
It never creates a key or opens an
authentication prompt. Public dependencies must be available before offline
mutation tests.

To regenerate bindings, install `flutter_rust_bridge_codegen --version 2.13.0
--locked` and `cargo-expand --version 1.0.112 --locked`, then run
`flutter_rust_bridge_codegen generate` inside `companion/`. Commit generated
Rust/Dart bindings together. Both bridge endpoints check the generated content
hash. The app loads the library beside its own executable, not from the current
working directory. The plain Dart FFI test deliberately loads the development
library in `rust/target/release`.

## Preserved synthetic contract and lifecycle

The UI can select only synthetic fixture 1 or 2. Rust supplies their complete
display text and starts a 55-second review window using both monotonic and wall
deadlines. Starting a signing attempt consumes that review immediately. Rust
retains the public key returned by an explicit create/reopen operation; it never
accepts a signing completion's supplied public key as a trust anchor. Reopening
a different identity fails until an explicit successful deletion retires the
old identity. Public key and proof bytes are held only in memory.
The UI exposes a selectable SHA-256 fingerprint of the retained SEC1 public key
for comparison across explicit reopen/relaunch/rebuild. Deletion clears it.
Confirmed key absence counts as retirement only during explicit deletion;
missing keys during signing or reopen do not silently reset identity or counters.

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
times. `transcript-v1-fixture-two.hex` freezes the same binding values with
fixture 2 and its distinct complete text. Rust and Swift independently check both
vectors. The native adapter accepts
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

Pending and completed UI results retain the original operation's request number,
independently of the currently selected request. Switching to request 2 while
request 1 is pending shows `Cancelling request 1…`, then
`Last attempt — Request 1: cancelled`. Request 2's card remains selected; the
old result is not presented as its outcome. Signing stays disabled while the
original native operation is outstanding.

The noninteractive probe passes only for the specific interaction-required
errors `NSOSStatusErrorDomain/-25308` or
`com.apple.LocalAuthentication/-1004`. Missing keys, generic failures and
unavailable hardware do not count. Any noninteractive signature is unsafe,
including after cancellation. Completed key creation/deletion is reported even
after cancellation; cancellation cannot undo a Keychain mutation. Failed key
operations leave counters and retained identity intact.
Any unsafe result latches an enduring acceptance-failed warning for the session,
including a late result after cancellation. Further signing/negative probes are
blocked; selection, cancel, reopen and deletion cannot clear that warning.
Explicit deletion remains available for cleanup. Restart begins a new session;
it does not turn the previous failed observation into passing hardware evidence.
The standalone probe applies the same session rule.

Availability is queried without prompting on startup, application resume and
the explicit Refresh availability action. Request generations prevent stale
replies from overwriting newer state. Native-event subscriptions are removed on
widget replacement/disposal; queued obsolete callbacks cannot retire the live
Rust review. A completed worker still returns to Rust after its old widget is
disposed. Malformed returned channel values yield bounded failure completions,
while a noninteractive signature is classified unsafe before other metadata.

## Synthetic native identity and operation

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

Interactive signing first reads the existing key's access-control object without
UI, then explicitly calls `LAContext.evaluateAccessControl` with `.useKeySign`.
The cancellation callback invalidates this same context, targeting the explicit
evaluation rather than an implicit prompt inside `SecKeyCreateSignature`. Once
evaluation returns, the context disallows UI again and the worker re-queries the
key with that context before signing. A successful evaluation alone never
constitutes approval: the protected key must sign and Rust must verify the bound,
unexpired, non-cancelled transcript. This follows Apple's
[access-control evaluation API](https://developer.apple.com/documentation/localauthentication/lacontext/evaluateaccesscontrol(_:operation:localizedreason:reply:))
and [authorize-then-sign sequence](https://developer.apple.com/videos/play/wwdc2022/10108/).
Automated tests cover callback/cancellation ordering, noninteractive signing
mode, and result attribution. Prompt dismissal without a touch and fresh-touch
behavior after this correction still require a physical retest; prior hardware
evidence applies only to the earlier build.

Explicitly create the disposable key, review request 1, and sign. Review request
2 and sign separately. Reopen only after an explicit action following relaunch.
Delete only the disposable key through the application's Delete test key action.
Do not install over the existing companion. Hardware interactions, fingerprint
set changes and signing-profile changes require operator coordination.

## Evidence and completion boundaries

Automated tests establish protocol/lifecycle behavior, not a physical touch.
`scripts/mutate-desktop-companion.py` changes verification, transcript binding,
expiry, cancellation, duplicate consumption, admission and the unsafe latch one at a time. Each
mutation must fail an actual test, not compilation; it restores the exact source
bytes and reruns the baseline. CI retains logs and development application
artifacts for three operating systems. The new desktop jobs join Merge Ready;
the existing release-publishing workflow is unchanged.

Local checks on 2026-10-19 used the verified Flutter SDK and an isolated Debian
Linux build container (CMake 3.25.1, Ninja 1.11.1, GTK 3.24.38, Xvfb, Rust 1.88).
No host desktop packages were installed. Six Dart tests include an actual FFI
load and a widget/native-worker cancellation flow; one additional desktop
integration test loads the library from the built bundle. The release bundle
builds successfully; desktop integration used the debug bundle. The original
desktop/native matrix subsequently passed on revision
`08997f752a80ae1dc458771c8ce2d6c3d46e12d9` in
[CI run 39397597833](https://github.com/sixtoad/vaultwarden-cli/actions/runs/39397597833).
That run predates the review fixes and new release-runtime/archive checks below.
Updated native results require a new matching-runner execution. CI configuration
alone does not establish a passing run.

| Required evidence | Status |
| --- | --- |
| Rust 1.88 lifecycle and both shared transcript vectors | 12 tests passed locally after review fixes with regenerated bridge |
| Rustfmt and stable Clippy | Passed locally |
| Security mutations and exact restored baseline | All seven caught by test failures; exact restoration and baseline retest passed |
| Flutter analysis, widget/platform tests and actual FFI load | Review-fix analysis clean; all 11 tests passed |
| Linux debug integration, release AOT runtime, normal-entry archive | Both launch checks passed in isolated container; Python 3.12 archive round-trip and all five artifact tests passed |
| macOS build, native/probe tests, debug integration, release runtime and archive | Original matrix passed; review-fix matching-runner execution pending |
| Windows build, debug integration, release runtime and archive | Original matrix passed; review-fix matching-runner execution pending |
| Two successive separate touches on the real Mac | Pending coordinated operator evidence |
| No-interaction refusal, cancel/late completion, reopen after exit | Pending coordinated operator evidence |
| Same identity after rebuild and changed bundle/signing profile | Pending coordinated operator evidence |
| Biometric-set change makes old key unusable | Pending separately authorized hardware action |

Review-fix local verification ran on 2026-10-20. The container's minimal Rust
toolchain lacks rustfmt/Clippy, so those checks ran on the host; its older Python
cannot run the archive extraction filter, so archive verification ran on host
Python 3.12 against the same completed bundle. CI installs all required tools
and runs the complete script. Seven-mutation restoration matched source SHA-256
`d32ffb3b8345e0c0aebfbb78072edc8e302bc024959c6c615af68cd58f0ca761`.
These results do not claim native or physical acceptance for the review fixes;
the PR check history records the matching native runs.

## Coordinated check of the development artifact

CI uploads an inner `companion-<platform>-development.tar.gz`, its `.sha256`,
`artifact.json` source/content inventory, and release smoke evidence. The tar
preserves executable permissions and framework links; packaging verifies a fresh
extraction against the complete original inventory. The smoke entrypoint uses
stdout on Linux/macOS and a task-owned result file on Windows, always requiring
exit status zero. Uploaded bundles are rebuilt with the normal `lib/main.dart`.
For an isolated local build without Git metadata, the packaging helper accepts
an explicit full `--source-revision` together with `--source-dirty`; CI obtains
provenance directly from its checkout.

On the operator's Mac, use the artifact from the passing run for the exact
revision being accepted. Verify and extract the inner tar into a fresh directory:

```sh
shasum -a 256 -c companion-macos-development.tar.gz.sha256
tar -xzf companion-macos-development.tar.gz -C /path/to/fresh-test-directory
open "/path/to/fresh-test-directory/companion_slice.app"
```

Do not replace the installed companion or disable Gatekeeper. If development
signing cannot run/reopen the key, preserve that result and coordinate recovery.

1. Confirm the Rust connection, fixture and availability; startup must not create
   a key or prompt. Explicitly create/reopen the disposable key and record its
   public fingerprint plus source revision.
2. Review request 1, check without interaction (only interactionRequired passes),
   review again and sign with a fresh touch. Immediately review/check without
   interaction again. Repeat with request 2 and a second separate touch.
3. Cancel a prompt and change selection during an attempt. Neither late result
   may increment verification; admission stays closed until the worker returns.
   Observe lock/unlock and fast-user-switch with the operator; these event
   mappings remain deferred until real-Mac evidence exists.
4. Quit/relaunch, explicitly reopen and compare the fingerprint. Repeat with a
   changed executable whose different SHA-256 is recorded to test update
   continuity. A rebuild of identical bytes does not establish update behavior.
5. Delete the exact disposable key; its fingerprint disappears and reopen
   reports missingKey. Any unsafe warning stops acceptance and persists through
   cleanup. Restarting does not erase the recorded failed observation.

Record actual separate touches and outcomes; automated counters do not prove
physical touches. Enrollment changes and lockout require separate authorization.

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

## Desktop bundle installation slice (#50)

The portable desktop artifact now includes the platform-applicable CLI/helpers,
a build-derived component/compatibility manifest and native user command
activation. See [desktop installation](desktop-installation.md) for actual roles,
prerequisites, repair, rollback, signing boundaries and isolated test instructions.
This supersedes earlier statements that bundled command inspection/repair is
absent. Development signing and missing native platform roles remain explicit;
this does not qualify native macOS provider execution or replace installed apps.
