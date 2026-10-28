# Issue 50: structured review verification

Baseline: `3ecaab452cf9f5f5791e135a03aa1a26767e2e99` (merged PR #51).
The structured-review spec was approved on 2026-10-28. Issue #50 stays open.

## Independent review

Three reviewers inspected the implementation independently without conversation
history: a diff-only adversarial reviewer, an edge-case reviewer with source
access, and an acceptance auditor with the approved spec and both context docs.

- The blind reviewer found no actionable defect in projection completeness,
  escaping, generated codec ordering, review retirement or decision admission.
- The acceptance auditor found no source deviation; it identified outstanding
  cross-platform evidence and stale wording that still called the spec unapproved.
- The edge reviewer identified a new rendering problem: an accepted response
  below the 1 MiB limit can contain approximately 300,000 empty arguments. Eagerly
  creating a selectable widget for every argument would exhaust UI resources.
  Further investigation established that provider operations already allow at
  most 32 arguments and 16 credential references. The final correction rejects
  reviews exceeding those existing limits before projection or decision
  admission. Both crates pin accepted/rejected boundaries with literal counts.
  No new paging UI or automatic device suspension is part of this change.

## Local verification and pending hosted evidence

Evidence directory: `/Volumes/sixto_dev/.devcache/tmp/vaultwarden-typed-evidence/`.
Tooling is private: verified Flutter 3.47.7/Dart 3.13.5, Rust 1.88.0 for the
support-floor checks and Rust 1.99.1 for local macOS builds, bridge generator
2.13.0 and cargo-expand 1.0.112. Generated Rust/Dart bindings were produced together.

Before the long-list review patch: 31 Rust tests and 66 Flutter tests passed;
analysis was clean; all 15 provider and 12 controller mutations were detected,
with exact source restoration and passing restored controls. The twelve local
macOS 27 arm64 golden captures were inspected in both themes and all layouts.
Final count-bound correction: all 33 companion Rust tests passed on Rust 1.88;
all 542 root tests passed with `cargo test --all-targets --locked`; full Flutter
suite 70 passed, pilot suite 9 passed, analyzer clean. All 17 provider mutations
(including both count bounds) and 12 controller mutations were detected by test
failures. Pristine/restored controls passed and source hashes matched exactly.
The edge reviewer confirmed the final count-bound correction resolves the
allocation problem while preserving complete accepted scope. Local exact golden
comparisons still pass after removing the unnecessary pagination.

All four other renderer sets were captured in
[CI run 40693829222](https://github.com/sixtoad/vaultwarden-cli/actions/runs/40693829222)
on `f3d03b4`. Each host passed 64 non-golden Flutter tests; the six failed tests
were the intended presentation changes. Independent visual review inspected all
ten changed actuals, all ten isolated diffs and both unchanged large-text action
references per host. The forty approved PNGs were adopted byte-for-byte; no
comparison tolerance or skipped assertion was introduced.

The spec remains in review. The authoritative final verification is the latest
[PR #52 checks](https://github.com/sixtoad/vaultwarden-cli/pull/52/checks) for its
current head, including exact renderer comparisons, native installation and
packaged TLS/recovery/cleanup. The PR verification summary records the resulting
run and evidence; initial expected screenshot failures are not a passing gate.

The final local AOT smoke, debug packaged-bridge integration and normal-entry
release archive verification passed on clean commit `f3d03b4`. The archive
SHA-256 is `493911acd71b28a2b885285e661ae75c82e8b87efe870c77b83d1bce80ba1c73`;
it records `lib/main.dart`, release mode and successful extraction verification.
The separate synthetic Swift probe's 11 tests and final Clippy checks passed.

The full local desktop gate reached native checks. Normal and pilot suites
executed 36 and 37 tests respectively, each with one CI-only installation test
skipped and no failures. Leaf-pin and CA/hostname/validity mutations were caught;
`install-save` survived because its detecting test was skipped. The harness
restored exact Trust/ProviderSettings hashes and the restored suite passed, then
correctly failed the gate. No CI flag, trust check or production namespace was
changed to bypass this prerequisite. Fresh matching CI is required for this
branch; PR #51's passing evidence is historical, not proof of the new bridge.
