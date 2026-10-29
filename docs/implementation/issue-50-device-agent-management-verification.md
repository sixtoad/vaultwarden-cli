# Device and agent management verification

## Scope and contract

Baseline `60fadd6251cafb08e91ef2856f82ef44dfe164f5` contains merged PR #52.
PR #55 is preserved: access removal denies future delivery and cleans up
provider-owned resources without terminating consumers or recalling secrets.
The final source revision and CI run are recorded in the draft pull request.

## Local evidence (macOS, 2026-10-29)

- Pinned Rust 1.88 core: 46 tests passed; stable Clippy and formatting passed.
- Flutter 3.47.7 / Dart 3.13.5: 81 tests passed, including real generated FFI,
  provider replacement, process-recreation recovery, paginated polling, stale completions,
  malformed origin, expiry/password clearing, themes and 200% text scaling.
- Management core mutations: 7/7 detected after successful compilation, with
  exact source restoration and a passing restored baseline.
- Existing controller mutations: 12/12 detected; source/page hashes restored,
  restored baseline passed. Initial sandbox socket denial was infrastructure,
  not a mutation kill; the complete run passed outside the enclosing sandbox.
- Native adapter tests: normal build 37 tests and opt-in build 38 tests,
  each with one explicit CI-only Keychain-installation skip and no failures.
- Existing native trust mutation `install-save` cannot be credited locally:
  its disposable-Keychain regression skips outside CI, so the full native
  script correctly refuses local success. CI must run it on a fresh runner.
- Release AOT smoke and macOS debug bridge integration passed. Xcode printed
  unrelated CoreSimulator version warnings; the macOS app built and executed.
- Artifact test suite: 6 passed. TLS fixture suite: 2 passed.
- Light/dark 200% review and confirmation screenshots were visually inspected;
  controls and wrapped text remain readable. Existing exact goldens remain
  unchanged. Screenshot evidence is external to source control.

Local logs and screenshots are under
`/private/tmp/vaultwarden-device-evidence`; complete suite logs also use the
`/private/tmp/vaultwarden-device-*.log` prefix. CI uploads portable evidence.

## Required CI evidence

The provider/adapters are Linux-gated; Mac cargo success cannot establish their
compilation or runtime behavior. The final revision must pass the repository's
Linux unit/all-feature/no-default/doc matrices, actual systemd and distinct-UID
agent transport, seven management security mutations, macOS native/TLS,
Flutter desktop packaging on all configured hosts and the disposable pilot.
The packaged management scenarios traverse AOT Dart, generated Rust bindings,
native persistence, certificate pinning and mutual TLS using synthetic backend
records. Actual provider semantics are separately checked by real TLS backend
and systemd tests. Neither is claimed to use production credentials or a live
vault. No hardware identity or physical-device attestation is inferred.

## Independent review

A separate security reviewer examined grants, commit synchronization,
lifecycle races, journal fencing, offline reconciliation and self-revocation.
Actionable findings were fixed before the final diff review. Final blind, edge-case and acceptance reviews found four additional concrete
issues: absent-journal recovery, automatic page resets, live signing-socket
cleanup evidence and invalid action-fact pairs. These were repaired with exact-
actor owner recovery, explicit page refresh, strict stopped SSH cleanup and a
closed action-pair matrix. Regression coverage accompanies each repair.
An additional runtime-availability audit replaced the unlocked-session inference
with dispatcher liveness, queue capacity and supervisor readiness.

## Integration notes

PR #54 owns Activity and PR #56 owns installation. This slice adds management
v2 commands, additive `managementRecovery` native metadata and origin reads;
it does not own their features. Merge shared controller/configuration changes
deliberately and regenerate FRB bindings with pinned tools. Preserve both
request and management pending markers, exact-provider binding, native
foreground retirement and the status-only recovery contract. Keep issue #50
open for its remaining capabilities.
