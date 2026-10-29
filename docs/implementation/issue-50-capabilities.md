# Issue 50: capability checklist and delivery slices

Implementation baseline: remote `main` **476bf3f**, 2026-10-27.
First-slice verification evidence is recorded below; broader acceptance stays open. Parent: [issue #50](https://github.com/sixtoad/vaultwarden-cli/issues/50).
The approved first-slice specification is [the shell specification](../../_bmad-output/implementation-artifacts/spec-50-quiet-instrument-shell.md).

## Current platform capability

| Platform | Existing evidence in this checkout | Remaining dependency |
|---|---|---|
| macOS | Flutter password approvals through native pinned TLS to Linux; separate synthetic Secure Enclave signer | Production distribution, guided enrollment, notification parity; integrated provider biometric approval |
| Linux | Protected CLI/provider execution; Flutter desktop build | Flutter native transport/identity adapter and approval integration |
| Windows | Flutter desktop build | Native provider transport/identity/authentication integration |
| Android | No Android project directory or native adapter | Committed first-class approval client: project, secure transport/storage, lifecycle/authentication, notifications and enrollment |
| iOS | No iOS project directory or native adapter | Same committed native delivery, including Face ID/Touch ID and phone lifecycle qualification |

Desktop build support is not proof of requesting, approving or executing support.
Phones are approval clients, not desktop CLI installers. Web remains exploratory
and is excluded. Native macOS execution belongs to [#49](https://github.com/sixtoad/vaultwarden-cli/issues/49);
physical biometric/lifecycle evidence remains tracked in [#41](https://github.com/sixtoad/vaultwarden-cli/issues/41).

## Source-backed checklist

- [x] **Real password approval:** `companion/lib/provider/page.dart` invokes
  `controller.decide`; `src/adapters/companion.rs:31` defines the closed password
  decision protocol. `companion/lib/platform/provider.dart:38` gates native
  provider availability on macOS.
- [x] **Request-bound lifecycle and recovery:**
  `companion/lib/provider/controller.dart` tracks route eligibility, context,
  uncertain IDs and durable settlement. `companion/rust/src/provider/session.rs`
  enforces tickets, deadlines, epochs and original-request recovery. Preserve this
  behavior across tab, back, selection, lock, background and disposal transitions.
- [x] **Native synthetic Touch ID:** `companion/macos/Runner/ApprovalContract.swift`
  and `NativeTestKey.swift` implement the separate signing demonstration.
  `companion/lib/main.dart` hosts it separately. Do not remove it or represent its
  signatures as real provider approval.
- [x] **Structured review presentation, current companion schema:** Rust validates
  and escapes facts in `companion/rust/src/provider/protocol.rs`; the bridge now
  exports an optional typed review alongside retained `review_text`. Both derive
  from the same admitted review and clear together on retirement/expiry. Flutter
  displays all fields, separate indexed arguments/credentials, digests and exact
  deadline. Originating device identity remains unavailable and is labeled so.
  Reviews exceeding the existing provider limits of 32 arguments or 16 credentials
  are rejected before display or decision admission; prior review authority clears.
  Existing `create`/`ssh` extensions and unknown fields remain rejected in full;
  adding complete support requires another slice. See the
  [structured-review spec](../../_bmad-output/implementation-artifacts/spec-50-typed-request-review.md).
  This records implementation; its new verification evidence must be recorded
  separately from the first-slice results below.
- [ ] **Mutual enrollment:** `src/bin/vaultwarden-accessd.rs:64` provides offline
  console enrollment and exact-fingerprint revocation. Flutter imports an already
  provisioned CA/PKCS#12 (`companion/macos/Runner/ProviderAdapter.swift:47`). No
  nearby invitation, matching-code, QR or dual-human-authorization protocol exists
  in these surfaces. Advanced setup cannot satisfy guided enrollment acceptance.
- [x] **Trusted-device management (implementation):** provider-backed inventory/detail, explicit
  owner-granted remote administration, permanent revocation and action-bound
  reconciliation are implemented in the device-management slice; final Linux,
  native packaging and CI verification remains pending. See the
  [identity management contract](issue-50-device-agent-management.md). Enrollment
  remains separate. PR #55 requires future-access denial and provider-owned
  cleanup without terminating consumer programs.
- [ ] **Remote activity:** allowlisted durable history already exists in
  `src/access/history.rs`; `src/bin/vw-access.rs:108` exposes `history --limit`.
  Companion v1 has no history command. Slice one shows latest known status only;
  a bounded authenticated history endpoint is needed for complete activity.
- [ ] **Single installation and repair:** Flutter artifacts are development/CI
  bundles (`docs/companion-migration.md:386`). The existing DMG packaging script
  packages the Swift app, not a complete Flutter/CLI installation contract.
  `vw-access` has a version flag, but the app has no CLI inspection/repair API.
  `.github/workflows/release.yml:69` selects one binary; required bundle contents,
  version compatibility, user-level command repair and rollback need explicit work.
- [ ] **Notifications:** the Swift app has generic notifications
  (`macos/Sources/ApprovalCompanion/App.swift:155`); Flutter has no equivalent
  notification/background API. Exact-request navigation needs a native entrypoint,
  fresh loading and review; never notification-level approval.

## Screen and state mapping

| Destination | First slice | Completion dependency |
|---|---|---|
| Requests | Inbox IDs, complete validated scope, provider endpoint, password approval/denial, expiry and original-ID recovery | Typed facts and signed-admission origin (legacy origin explicitly unavailable) |
| Devices & agents | Provider-backed identities, granted roles/trust, exact-target permanent revocation and status-only recovery (management slice) | Final management verification; genuine mutual enrollment remains separate |
| Activity | Latest known redacted status with exact request ID; fresh review on reopen | Bounded authenticated durable history |
| Settings | Existing advanced setup, theme, actual capabilities, separate synthetic diagnostics | Version inspection, bundled CLI repair, native notification settings |

Desktop uses sidebar/master-detail; compact uses bottom navigation/list-to-detail,
safe areas and back. Both need keyboard/semantic labels, non-color status, visible
focus, scrolling long scopes and 200% text scaling. Phone layout tests do not prove
Android/iOS native support. Reference tokens and source are preserved under
`docs/design/issue-50/`; the first-slice spec records their application.

`ProviderOutcome.accepted` means a command reply was accepted, not that execution
completed. Closed protocol statuses are pending, approved, denied, expired,
running, completed and failed. `ProviderStatusProgress.committed` includes approved
and running: it is not terminal. Busy/submitting and reviewing are presentation
states; the current protocol has no distinct authenticating result or cancelled
request status. Cancelling a review retires its ticket, not the remote request.
Unknown outcome is recovered through the original ID only; locks/unavailability
must never become inferred denial, failure or completion.

## Proposed linked work, in order

These are local proposals linked to #50; no external issues have been created.

1. **Shell and existing flow:** the approved specification implements shared theme,
   responsive navigation and the existing real request path. Verification below;
   retain #50 as open.
2. **Typed read models:** structured review is the second slice. Bounded redacted
   remote history and actual trust/role/capability metadata remain separate API
   work, with negative-schema, exact-ID and privacy tests. Add missing origin
   identity at the authoritative producer, not in widgets. Current companion
   review does not yet admit the provider's optional `create`/`ssh` extensions.
3. **Mutual enrollment protocol:** define expiring single-use invitations, session
   identity verification, independent human authorization at both endpoints,
   cancellation, duplicates and revoked identities. Validate mismatch, replay,
   role substitution and offline failure. Then build discovery/manual/QR journeys
   for GUI-to-GUI, human CLI and phone. UI cannot invent this cryptosystem.
4. **Desktop installation:** explicit app/CLI/helper manifest, compatibility
   inspection, user-level enablement/repair, permissions, upgrades and rollback
   for macOS/Windows/Linux. Keep #49's native execution boundary explicit.
5. **Native client parity:** separate Android, iOS, Windows and Linux adapters;
   secure identity, authentication, lifecycle and generic notifications with exact
   request routing. Define mobile enrollment/review designs now; record hardware
   evidence separately. Provider biometric verification is a reviewed protocol
   dependency, not reuse of the synthetic signer as an approval button.

## Verification and handoff

The first slice implements four destinations and light/dark/System appearance,
with all review authority still owned by Rust. Navigation/back and selection
retire tickets, clear passwords and reject late review responses. In-flight
decisions retain original-ID settlement/recovery across destinations. Advanced
certificate setup and the build-gated disposable pilot remain in Settings.
No protocol, native adapter or generated bridge changes were needed.

Verification on 2026-10-27 uses a checksum-verified private Flutter 3.47.7 /
Dart 3.13.5 SDK at `/private/tmp/vaultwarden-sdk/flutter`, on macOS. Private Rust
1.88.0 passed the core checks; release/debug app builds used private Rust 1.99.1
because 1.88.0 emitted an invalid Mach-O LINKEDIT string pool with this host's
Xcode 27. No production credentials or installed app were imported/replaced.
Evidence was captured under `/private/tmp/vaultwarden-50-evidence/`; the durable
handoff copy is `/Volumes/sixto_dev/ai/vaultwarden-cli-evidence/issue-50/`.
Relative evidence paths below resolve within either copy.

- Full Flutter suite: **59 passed**, including six golden scenarios; analyzer
  clean. Disposable-pilot enabled suite: **9 passed**.
- Synthetic golden matrix: desktop and compact, both themes, plus compact at
  200% text scale, with review and action captures (12 images). All inspected.
  Images use test-only licensed Roboto for repeatability, including as a review
  monospace substitute. Production keeps system fonts. Desktop and compact
  200% reachability, keyboard navigation and selected semantics are also tested.
- Independent review fixes: dark primary/onPrimary contrast, top-of-content
  resets for review/back/navigation, and locked Activity review admission. Before
  fixes, new regressions measured 1.18:1 contrast, a retained 1846px inbox offset,
  and an enabled locked-state callback (`review-patches-red.log`). Final full
  Flutter suite, analyzer and pilot results are `review-patches-*.log`.
- Light/dark enabled foreground/background contrast is checked at >=4.5:1.
  Dark filled buttons use #456d8e with white text; other dark foregrounds remain
  light. Color tokens retain the selected reference accent separately.
- Controller/navigation mutation campaign: **12/12 detected**, including both
  tab and back retirement; exact controller/page hashes restored and the restored
  tests passed (`review-patches-controller/report.json`).
- Rust: **28 passed**; rustfmt and Clippy passed. Python artifact tests: **6 passed**;
  packaged diagnostics: **17 passed**. Companion Swift contract: **12 passed**;
  synthetic Touch ID probe: **11 passed**.
- Native fixture suites: normal **36 executed, 1 skipped, 0 failures**; pilot
  **37 executed, 1 skipped, 0 failures**. The default OpenSSL executable on this
  host was an incompatible CPU binary; the retry explicitly selected
  `/opt/homebrew/opt/openssl@3/bin/openssl` (3.6.3). A task-private Swift wrapper
  selected `--build-system native` for Xcode 27 to preserve the harness's expected
  object-file layout. Native source/fixture hashes match the baseline.
- **The full host gate is not green:** the native trust campaign caught leaf-pin
  and CA/hostname/validity mutations, but `install-save` survived while the
  CI-only production-namespace install test was skipped. Trust/settings hashes
  were restored exactly and the restored suite passed. No CI flag was forged or
  production namespace altered to bypass this prerequisite. See
  `provider-native-compatible/trust-mutations/report.json`.
- Unaffected remaining host checks ran separately: AOT release smoke passed
  (`review-patches-smoke/release-smoke.log`: `COMPANION_RELEASE_SMOKE_OK`), macOS debug bridge integration **1 passed**,
  and the normal `lib/main.dart` release was rebuilt and its development archive
  verified: `review-patches-artifact/companion-macos-development.tar.gz`
  (`artifact.json` and SHA-256 sidecar in the same directory).
  The CI-only packaged native TLS smoke was not run locally.

Windows/Linux matching-build CI and Android/iOS native adapters remain separate
requirements. Physical assistive technology, biometric/lock lifecycle and live
provider acceptance require coordinated hardware evidence. Compact goldens do
not establish native phone support. These limits keep #50 open.

Rollback is source/build reversion; no credential or persistent protocol migration
was introduced. Isolated builds must not replace the installed app or import
production credentials.
