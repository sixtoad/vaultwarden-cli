# Touch ID probe preparation — 2026-10-16

Status: native build and state-model verification passed. Human hardware
acceptance is pending. No app launch, biometric prompt, Keychain creation,
production enrollment or provider authorization change was performed.

## Environment and results

- Operator-authorized Mac mini staging: `/private/tmp/vw-touch-id-probe.XryZwHXf`.
- macOS 27.0.1 (26A434), arm64, Apple Swift 6.4 (swiftlang-6.4.0.34.1).
- Debug tests and release build passed with `-Xswiftc -warnings-as-errors`.
- Ten XCTest state-model tests passed after restoring all mutations, including
  three regression tests added from independent review.
- Bundle plist lint and strict ad-hoc signature verification passed.
- Rebuilding into the existing bundle correctly failed without replacing it.
- Local shell syntax and diff whitespace checks passed. Production `src/`,
  `macos/` and `.github/` were unchanged against the approved-spec baseline.

## Focused mutations

Each mutation was compiled and run separately on the Mac, then reverted. These
are six manually selected mutations, not a whole-program mutation score or proof
of native authentication enforcement.

| Injected defect | Test | Observed result |
| --- | --- | --- |
| Invert cancellation guard | `testOneWorkerEvenAfterCancellation` | 2 assertion failures |
| Accept any active token, including stale completion | `testStaleCompletionCannotFinishNewAttempt` | 3 assertion failures |
| Remove busy admission guard | `testOneWorkerEvenAfterCancellation` | 3 assertion failures |
| Treat missing-key status as interaction-required | `testOnlyKnownInteractionErrorsPassNegative` | 2 assertion failures |
| Handle cancellation before unsafe/completed-key observations | `testCancellationCannotHideUnsafeResult` and `testCompletedKeyMutationSurvivesCancellation` | 11 assertion failures |
| Reset evidence on failed key mutation | `testFailedKeyMutationPreservesEvidence` | 4 assertion failures |

An earlier, broader token-guard inversion also failed, but caused a test
force-unwrap trap; the narrower stale-token mutation above replaced it as the
focused evidence. No mutation remains in the delivered source.

Final restored `AttemptGate.swift` SHA-256 (matched locally and on the Mac):
`39bb92b8d178160562633a7e05e485849b36ea140d40a8d11e5bd747490f3f11`.

Build/test logs remain in that staging directory: `verified-build.log`,
`final-build.log`, `mutation-cancel.log`, `mutation-stale-exact.log`,
`mutation-admission.log`, `mutation-error.log`, `overwrite-refusal.log`,
`reviewed-build.log`, `mutation-cancel-order.log`, `mutation-failed-key.log`
and the final restored `handoff-build.log`.

The bundle for the human test is
`/private/tmp/vw-touch-id-probe.XryZwHXf/handoff-build/Touch ID Probe.app`
on the Mac. Earlier build directories are intermediate artifacts, not the handoff.

## Independent review

One context-free reviewer reported five findings, all corrected: cancellation
must not conceal unsafe observations or completed key changes; failed key
mutations must preserve counters; update testing must use a changed executable
with recorded distinct hashes; on-screen instructions must include the immediate
post-sign negative check. All final native tests passed after the corrections.
No review findings were deferred. Hardware acceptance is still pending.

## Next gate

Follow [the operator runbook](touch-id-probe.md) for coordinated synthetic-key
testing: fresh touches, noninteractive rejection before/after signing,
cancellation, key continuity across reopen/rebuild, and exact-key cleanup.
Compilation cannot establish these properties. Fingerprint-set-change and
lockout testing require separate coordination; production integration remains
out of scope for this probe.
