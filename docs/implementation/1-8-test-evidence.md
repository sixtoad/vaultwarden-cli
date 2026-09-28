# Story 1.8 — completed implementation and verification

Implementation, both workflow review rounds and their corrections are complete.
The user approved the completed implementation and evidence on 2026-09-28.
All required test and mutation jobs finished before approval. No host provider
installation was performed.

Branch: `feature/contain-protected-child-processes`. Base: updated main at
`ffd8ed4c434f585b2bcb37b0ca9a8517538be662`. Stories 1.1–1.7 are merged; no dependency
branch is needed. Story 1.2's issue remains open despite its merged implementation.

## Final results

The parent ran every full check after the final patches. The 77-file
[source manifest](1-8-evidence/review-2-parent/source.sha256), SHA-256
`599e551b774eee3edce99c47f94298211c18662bc44bae252968280fbb181230`, matched both after verification and after mutation restoration.
[Exact commands and durations](1-8-evidence/review-2-parent/verification-results.json)
and the [runner](1-8-evidence/review-2-parent/verification-runner.py) are retained.
Commands ran through `scripts/with-secure-test-tmpdir.sh`; Rust suites used
`RUST_TEST_THREADS=4`, `--offline --locked`.

| Check | Final result | Evidence |
| --- | --- | --- |
| Stable `cargo test --all-targets` | 811 passed, 0 failed, 12 accounted-for ignored; 13 benchmark smoke cases; 198.40s | [log](1-8-evidence/review-2-parent/stable-all-targets.log) |
| Rust 1.88 `cargo test --all-targets` | 811 passed, 0 failed, 12 accounted-for ignored; 13 benchmark smoke cases; 203.88s | [log](1-8-evidence/review-2-parent/rust-1.88-all-targets.log) |
| `cargo fmt --all -- --check` | Passed; 1.07s | [log](1-8-evidence/review-2-parent/formatting.log) |
| Strict Clippy, all targets/features, `-D warnings` | Passed; 11.32s | [log](1-8-evidence/review-2-parent/strict-clippy.log) |
| Static adapter/composition contracts | 4 checks passed; 0.17s | [log](1-8-evidence/review-2-parent/static-contracts.log) |
| Named Rust contract tests | 6 passed; 16.37s | [log](1-8-evidence/review-2-parent/named-contracts.log) |
| Firefox UI/accessibility | 24 axe checks, 0 violations, 0 unexpected diagnostics; 46.61s | [log](1-8-evidence/review-2-parent/browser.log) |
| Real systemd | 29 scenarios plus injected-panic cleanup; 2 tests passed, 0 failed/ignored; test 52.99s, command 60.16s | [log](1-8-evidence/review-2-parent/real-final.log) |
| Scoped mutations | 21 generated + 21 semantic caught; no unresolved survivors | [classifications](1-8-mutation-classifications.md) |
| Complete baseline diff and added files | `git diff --check` and added-file checks passed | [results](1-8-evidence/review-2-parent/whitespace-results.json) |

The 12 ignored entries are accounted for: eight isolated library fixtures run by
passing wrappers, one explicit browser fixture, one internal real-manager harness,
and two external real-manager entries. Ignored entries alone are not passes.

## Acceptance coverage

| Requirement / frozen matrix row | Named passing evidence |
| --- | --- |
| Containment precedes verified-descriptor login execution; explicit environment and silent output | Real `app-exit`, `helper-environment`, pinned-image source replacement; `exact_typed_manager_contract_and_no_secret_properties`; bridge tests |
| Fork/double-fork/setsid/SIGTERM-resistant descendants fully terminate and reap | Real `orphan`, lifecycle cases, `crash`, worker shutdown and panic cleanup; independent zombie/deleted-group/subtree regression |
| Lock, cancellation, revocation, shutdown and authority races preserve cleanup/terminal ordering | Real lifecycle cases and five `phase-*` barriers; queued-cancellation, final-release, cleanup-uncertainty and terminal-immutability regressions |
| Job acceptance, helper start, actual exec and process outcome remain distinct | Real `helper-failure`, `fault-job`, `fault-exec`, `app-nonzero`, `app-signal`; `pre_exec_sigkill_with_empty_error_pipe_reports_failure_and_confirmed_cleanup` |
| Collisions/repeated stop are scoped; unrelated units preserved | Real `collision`, crash recovery and panic cleanup; strict ownership grammar and atomic no-replace lease tests |
| Missing/incompatible/disconnected manager and setup/job/stop failure fail closed | Version rejection; five `fault-*` cases; early-unavailability admission closure and uncertain-cleanup terminal gate |
| Recovery precedes admission, retaining cleanup identity across unit unloading | Real crash/restart, populated stop-failure recovery and `failed-launch-recovery`; startup-before-validation, competing-owner, interrupted staging and previous-version migration tests |
| Credentials absent from unit properties, journal, responses, audit and persistent state | Mandatory checked journal queries and both-stream visibility markers; null streams, two simultaneous 200 KiB output writers, explicit synthetic environment, application review/state and browser assertions |

All 29 live scenarios are listed in the final real-manager log. The external crash
observer SIGKILLs the provider and proves process disappearance without provider
cleanup callbacks, before restart recovery. The actual `ExecutionWorker` is tested
for approved-ID execution, durable completion and bounded shutdown. Nonzero and
signal outcomes are asserted exactly in persisted `DirectStatus` after cleanup.
Failed-launch collection is checked before test cleanup can call `reset-failed`.

The final review fixed queued cancellation, atomic leases, helper environment
inheritance, unrelated job retention, mandatory external observations, panic cleanup,
worker/migration coverage, scan budgets, failed-unit collection and Cargo artifact
resolution. A nondefault Cargo target directory was tested with default `target`
absent: [scoped evidence](1-8-evidence/review-2/README.md). Every workflow finding has
an individual verdict in the build spec's Review Triage Log.

## Platform and remaining limits

Tested on Linux `6.18.7-76061807-generic`, x86-64, cgroup v2, systemd user manager
`255.4-1ubuntu8.15pop0~1778766128~24.04~85b5073`; Rust 1.98.1 and 1.88.0;
Firefox 151.0.2, Puppeteer 25.11.0 and axe-core 4.13.0.
Support requires Linux 6.3+ executable memfds, feature-checked systemd 255+,
cgroup v2, safe provider-owned helper installation and permitted parent/child
ptrace exec-event observation. Unsupported configurations fail closed.

- AArch64 execution and manual screen-reader use were not tested. The real syscall
  fixture explicitly rejects other architectures. No production vault was accessed.
- Reviewed operations run as trusted provider-UID code; this is not a hostile
  same-UID sandbox. Agents require separate restricted principals. Deliberate
  user-manager/cgroup manipulation by a trusted operation is outside the guarantee.
- Manager environment names are removed before helper exec; values are zeroized
  locally and never copied into properties. The same-UID manager is trusted across
  snapshot/start. Recovery does not require equality with a newer name snapshot.
- Journal markers prove visibility of earlier output on both provider streams,
  not privileged global journal disk synchronization. Request streams are null.
  Missing markers or failed reads invalidate the tests' disclosure evidence.
- A full dispatch queue deliberately closes admission and stops active work.
  Rare crash windows can leave an empty private socket entry with no process,
  credentials or executable authority until runtime-directory cleanup.

Tests used unique namespaces and exact identity-based cleanup. A final audit also
removed historical failed-unit metadata from earlier iterations after independently
verifying this worktree's exact harness command, derived namespace, relationships
and process absence: 103 request units, 103 harness units, 81 owned artifacts or
empty directories; no unrelated resources touched. [Cleanup result](1-8-evidence/review-2-parent/cleanup-result.json)

## Evidence classification

Earlier full-suite snapshots and exploratory failures remain historical. They are
not presented as final-source verification. One earlier worker mutation attempt
failed during fixture compilation; private per-invocation fixtures fixed it, and
the corrected baseline/mutant both completed. The new outcome tests initially
assumed failure was returned directly by `run_execution`; that test expectation
was corrected to assert the exact durable status while preserving the existing
redacted return contract. No infrastructure failure or outer timeout alone was
counted as a mutation kill. Evidence-only excess EOF blank lines were normalized;
source bytes and test results were unchanged.

## Approval-time checks

On 2026-09-28, all 77 source hashes still matched the final tested manifest.
The staged whitespace check passed. The staged secret scanner returned four
false positives in `tests/ui/direct-request.mjs` (lines 119, 153, 156 and 221):
three explicit synthetic browser-password fixtures and one DOM query expression.
Each flagged line was verified identical to the base commit. No real credentials
were found; no scanner rules or tested source files were changed.
