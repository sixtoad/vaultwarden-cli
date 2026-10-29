# Activity history verification and handoff

Scope: bounded durable Activity for issue #50, based on main `93431e6` (merged
PR #52). The parent issue remains open. No installation, enrollment, native adapter
or abuse-protection changes are included.

## Local evidence (2026-10-28)

Durable evidence directory:
`/Volumes/sixto_dev/ai/vaultwarden-cli-evidence/issue-50-activity-history`.
Tools: Flutter 3.47.7 / Dart 3.13.5, flutter_rust_bridge_codegen 2.13.0,
cargo-expand 1.0.112, Rust 1.99.1 and 1.88.0. Generated bindings were regenerated.

- Companion Rust: 37 tests passed on Rust 1.88 and 1.99.1, Rustfmt and Clippy clean.
- Full Flutter suite: 79 tests passed; analyzer clean. This includes generated
  FFI/controller regressions for late responses, replacement, exact-ID reopening,
  legacy timestamps, unsupported providers and status-only uncertainty recovery.
- Authenticated Python loopback TLS fixture: 2 passed. Packaging diagnostics:
  17 passed. Packaged AOT native history scenarios are authored for final CI,
  not claimed from these portable tests.
- Provider-core security mutations: 23/23 detected, exact bytes restored and
  baseline passed. Controller mutations: 12/12 detected, exact bytes restored and
  baseline passed. The added Linux endpoint mutation gate independently changes
  post-read revocation, owner filtering and the canonical default/maximum limits.
- macOS root tests: 542 passed. The initial sandbox attempt could not bind mock
  server sockets; an unrestricted isolated-fixture rerun passed. Provider/access
  modules are Linux-gated, so this is not endpoint runtime evidence.
- macOS root all-target/all-feature Clippy is not green: unchanged platform test
  helpers have needless-return/unreachable-code/unused-argument diagnostics. The
  companion Clippy gate passed; final Linux lint remains mandatory.
- Six new macOS 27 arm64 Activity captures were individually reviewed: light/dark,
  desktop/compact and scrolled 200% event controls. Existing review/action goldens
  are unchanged. Linux, Windows and macOS 26 x64 images were individually reviewed from
  capture run `40721598625` on `55f1007` and copied exactly; exact comparisons
  are retained. The six ARM captures were reviewed and adopted on 2026-10-29
  from run `40725130148`, attempt 5, job `123371110473`.

The full local desktop script passed Flutter/pilot, packaging diagnostics, Swift
contract and normal/pilot native fixture suites, then correctly failed the
`install-save` mutation because the CI-only production-namespace test was skipped.
Native sources were restored exactly and the restored baseline passed. No CI flag
was forged. Separate remaining checks passed the Swift probe (11), release AOT
smoke and packaged debug bridge integration (1); the normal app archive passed extraction/provenance verification. It records
`55f1007` with `source_dirty: true` because captures/docs were pending; this is
local packaging evidence, not a clean final-revision release artifact. The hosted
results below close the native test gap without changing local CI prerequisites.

## Hosted evidence for `bcbadde`

[CI run 40725130148](https://github.com/sixtoad/vaultwarden-cli/actions/runs/40725130148)
tested head `bcbaddece26c6d74dddcc22308480ddf4627c727` through merge revision
`94c2d86f2962a59d4dd1971f61489d59f8b24b47`. Linux, Windows and Intel macOS full
desktop jobs passed, as did the root Rust matrix, security, coverage, builds and
Linux integration jobs. The first Intel runner lost communication; its successful
retry produced the evidence below.

- Normal/pilot native suites: 36/37 passed, no skips; Swift probe: 11 passed.
- Packaged AOT mTLS: all 20 synthetic-backend scenarios passed with exact command
  counts and cleanup, including supported, unsupported and malformed history.
  Opening a history event sent its fresh review and no decision command.
- Controlled security mutations: endpoint 4/4, core 7/7, provider 23/23,
  controller 12/12, pilot setup 3/3 and native trust 3/3 detected; restored
  pristine controls passed.
- Debug bridge, release smoke and normal-entry archive checks passed on all three
  desktop hosts. Linux and Intel macOS archives record clean source. Windows
  records `source_dirty=true`; changed paths were not saved, so clean-checkout
  provenance is unverified. The flag predates this slice, but its cause remains
  undiagnosed.

The macOS ARM pilot failed to acquire a hosted runner four times on 2026-10-28.
The 2026-10-29 retry acquired macOS 26.6.2 arm64 and produced the six Activity
captures. All were individually reviewed before byte-exact adoption; the capture
run passed 73 tests and failed only those six absent references. Existing
review/action references passed unchanged. The golden README records host and
capture provenance. Final acceptance requires CI after adoption; the PR records
that revision and outcome, without substituting earlier evidence.

## Independent review

A provider security reviewer found a test-fixture error: newly cloned pending IDs
had no application deadlines, so history correctly expired them and added events.
The fixture now uses terminal legacy records and tests owner filtering without
inventing live deadlines. Three subsequent independent blind/edge/acceptance
reviews found no concrete production/security defects. They identified the known
missing matching-host Activity goldens as pending verification work.

## Integration seams and limitations

The full wire/privacy/compatibility contract is in
[the capability checklist](issue-50-capabilities.md#activity-history-slice-issue-50).
Keep `ProviderHistoryEvent/historyState` separate from status/uncertainty fields.
Only original-ID status recovery settles a decision; history cannot. Event opening
calls the existing fresh review path with its exact ID. Generated outputs must be
regenerated together after future API changes.

History-specific selection, transport, projection and rendered rows are bounded.
The canonical JSON database still loads its whole store; this slice does not bound
that preexisting storage allocation. Physical accessibility, actual lock/biometric
hardware acceptance, live production and native phone adapters are not established
by synthetic fixtures. No CI flag is forged to satisfy native prerequisites.

Final PR revision and CI run evidence will be linked in the PR after matching-host
capture review and successful checks. This document does not substitute historical
PR #52 evidence for the current revision.

The first CI run confirmed the Linux endpoint tests and all four new endpoint
mutations, plus companion MSRV/security mutations. Missing Activity references
failed exact comparisons as expected. Because Flutter emits no actual image for
an absent reference, a reviewed test-only comparator now records actual Activity
bytes under ignored `test/failures/`, then delegates the exact comparison unchanged.
It never creates expected images or accepts differences. CI uploads those captures
for manual review and adoption.
