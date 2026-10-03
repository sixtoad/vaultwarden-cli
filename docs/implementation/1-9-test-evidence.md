# Story 1.9 implementation and verification evidence

Latest reviewed CI extension results are in [the native CI evidence report](1-9-native-ci.md): 839 tests on each toolchain, all final local checks complete, and hosted runs pending publication. The results below retain the original implementation snapshot and acceptance mapping.

Implemented on `feature/inspect-redacted-operation-history` in a fresh worktree
from updated main `7a0ebf352c2c8fd68d2fe73da896039e2f6a4e33`.
Stories 1.1–1.8 are all merged; no dependency branch is needed. See the
[dependency table](1-9-planning-notes.md). No commit, push, or PR is authorized
until the human approves the completed implementation and this evidence.

## Behavior and security contract

`HistoryEvent` is the explicit audit and read projection. Its only fields are
version, request ID, operation ID, requester identity, policy revision, credential
labels/use types, creation/expiry/event timestamps, ordinal, status, and a closed
outcome category. The provider emits submission and transition events through the
existing serialized atomic state writer. Current records validate snapshots,
ordinal continuity, lifecycle consistency and execution claims when loaded.

Human CLI requests require the existing kernel peer-UID boundary; browser reads
require its authenticated session and proof, with generation rechecked under the
application gate. History remains readable while locked. The agent protocol gains
no command or discovery API. `vw-access history --limit N` and the provider's
read-only UI list the newest events, default 50, valid range 1–200. Sorting is
explicitly descending `(timestamp, request ID, ordinal)`; absent legacy times sort
last. Limits count events, not requests.

Terminal history survives restart. Recovery invalidates unexecuted authority and
records recovery using the existing lifecycle events. Execution completion still
requires confirmed cleanup/reaping. Migration strips old audit approval bindings,
retains proved attribution, and uses `legacy_unknown`/absent time where older
storage did not preserve facts. It does not fabricate retrospective events.

CLI JSON escapes terminal and directional controls; browser text uses DOM text
nodes and visible control escapes. Read/write/render errors use closed static
categories. Audit data never contains approval bindings or record seals; existing
private live-request authority fields remain in their established storage section.

## Native CI extension

A subsequent approved extension adds native Linux ARM64/stable/MSRV, browser and
systemd CI coverage. Its implementation and local/hosted evidence are tracked in
[the native CI report](1-9-native-ci.md). Hosted Actions and ARM64 runtime results
remain pending publication; cross assembly is not runtime validation. The table
below records the completed history implementation checks before that extension.

## Final required checks

All post-review jobs completed successfully. No required check was blocked, skipped
without a fixture harness, or left running. Source hashes were unchanged throughout
full verification and checked again after completion.

| Check | Exact result | Seconds |
| --- | --- | --- |
| `formatting` | [passed](1-9-evidence/post-review/formatting.log) | 0.67 |
| `stable-all-targets` | [838 passed, 0 failed, 12 accounted fixture ignores; 13 benchmark smoke successes](1-9-evidence/post-review/stable-all-targets.log.gz) | 154.85 |
| `rust-1.88-all-targets` | [838 passed, 0 failed, 12 accounted fixture ignores; 13 benchmark smoke successes](1-9-evidence/post-review/rust-1.88-all-targets.log.gz) | 156.72 |
| `strict-clippy` | [all targets / all features, warnings denied: passed](1-9-evidence/post-review/strict-clippy.log) | 7.57 |
| `human-integrations` | [12 passed, 0 failed](1-9-evidence/post-review/human-integrations.log.gz) | 7.94 |
| `build-human-cli` | [passed](1-9-evidence/post-review/build-human-cli.log) | 3.53 |
| `browser` | [Firefox: all history/race/security assertions passed; axe 24 passes, 0 violations; 0 unexpected diagnostics](1-9-evidence/post-review/browser.log) | 45.08 |
| `real-systemd` | [2 tests passed; 29 scenarios plus panic cleanup; 0 failed](1-9-evidence/post-review/real-systemd.log.gz) | 55.45 |

Nine isolated verification-runner guard cases passed, including dependency overrides
and empty/unknown check selection. `git diff --check`, new authored-file whitespace
checks, and the final restored-source manifest check passed. The named matrix audit
confirms 29 relevant Rust checks executed and passed in the full suite.

The 12 ignored entries are eight isolated library subprocess fixtures exercised
by wrappers, one browser fixture exercised by Firefox, one internal systemd fixture
and two integration tests exercised by the explicit real-manager harness. The
real-systemd invocation has one internal launcher test filtered out; its fixture is
invoked by the two outer tests. These are accounted fixtures, not missing checks.

Firefox separately recorded 15 known cross-origin/blocked-favicon automation diagnostics.
Unexpected diagnostics remained zero. Exact commands/exits/durations are in
`post-review/verification-results.json`. Captured verbose logs use lossless gzip.

The exact parent orchestration was:

```sh
scripts/with-secure-test-tmpdir.sh python3 /tmp/story19-post-review.py
```

An identical copy is retained as
[post-review-runner.py](1-9-evidence/post-review-runner.py). It sequentially runs
all 28 semantic faults, all 16 selected generated transformations, the full
[verification runner](1-9-evidence/verification-runner.py), the runner guard checks,
and `git diff --check`. No mutation or full-suite jobs run concurrently.

The full verification runner sets `RUST_TEST_THREADS=4` and `CARGO_NET_OFFLINE=true`.
Browser dependencies used `/tmp/vw-story14-browser/node_modules` and
`/tmp/vw-story13-nss/extracted/usr/bin/certutil`; caller overrides are honored.
The secure temporary wrapper preserves HOME and uses private fixture ancestors.
Source manifests cover source, tests, scripts, systemd files and Cargo inputs.

## Acceptance and matrix coverage

All Rust names below are in the complete all-targets suite. Browser assertions
run in the explicit real-Firefox harness, rather than an ignored fixture alone.

| Acceptance / frozen matrix row | Named checks and observations |
| --- | --- |
| Complete permitted fields for submission, decisions, expiry, execution and invalidation | `history_submission_and_decision_have_exact_allowlisted_snapshots`; `history_every_lifecycle_projection_has_exact_fields_and_distinct_outcomes` checks 16 transition/outcome cases with exact JSON fields and one emission; `history_execution_corpus_is_absent_from_storage_responses_and_diagnostics` exercises successful and failed application execution; `history_first_read_at_request_deadline_expires_pending_and_approved_once` verifies history-triggered expiry without another read masking it. |
| Deterministic order, equal times, valid limits and empty history | `history_limits_empty_equal_timestamps_and_all_tiebreakers_are_deterministic`; `history_time_precedes_identity_and_ordinal_and_unknown_time_sorts_last`; `history_default_and_maximum_limits_count_events`; Firefox `historyEmptyAndRows`. |
| Invalid/oversized limit and stable rejection | The limit tests cover 0, 201 and maximum-u32; `history_parser_errors_and_help_are_static`, human wire schema tests, and Firefox `historyLimitsAndAuth` separately cover malformed, overflow, unknown fields, missing/wrong proof and valid input. |
| Historical policy/credential/requester attribution | `history_policy_and_credential_labels_are_event_time_snapshots`; `history_agent_snapshot_fixture_is_closed_and_stable_without_agent_authority`; exact CLI agent attribution and browser synthetic-agent rendering. No agent pairing is introduced. |
| Terminal records across restart, unexecuted work remains invalid | `history_all_current_terminal_records_and_attribution_survive_two_restarts` preserves denied/expired/completed/failed records and all 12 events; `history_terminal_restart_is_idempotent_and_pending_never_regains_authority`; `history_completed_legacy_three_approvals_reconstruct_exact_phases_and_restart_stably`; legacy migration/recovery tests; existing real-systemd recovery/cleanup scenarios. |
| Human access; anonymous, stale-session and agent denial | `history_owner_and_browser_generation_guards_work_while_locked`; `history_provider_owner_guard_is_independent_of_application_authentication`; `correctly_sealed_other_owner_record_is_not_disclosed_to_current_human`; `actual_socket_authenticates_kernel_peer_rejects_input_and_cleans_up`, `history_browser_guards_are_independent_and_current_locked_sessions_work`, existing agent credential tests and closed agent wire schema; Firefox `historyLimitsAndAuth`, `historyStaleSessionRejected`, `historyLateResponseDiscarded`, `historyQueuedMutationBlocked`, `historyRetirementClearsAndDisables`, and `historyInitialReadIndependent`. |
| Forbidden secrets, output and capabilities absent from persistence, responses and diagnostics | `history_execution_corpus_is_absent_from_storage_responses_and_diagnostics` uses 10 synthetic sentinels with positive capture assertions and success/failure paths; exact allowlist snapshots exclude private identifiers/authority; `history_cli_uses_human_socket_and_escapes_controls_without_losing_attribution`; browser checks persisted human response/UI text and diagnostics. Existing execution/systemd tests cover child output suppression and cleanup. |
| Safe HTML/terminal text; unsafe/malformed storage; atomic consistency | `history_arguments_and_terminal_json_preserve_data_without_controls`; actual CLI test; Firefox `historyAgentControlEscaping` with injected labels and zero HTML nodes; `history_durable_read_and_private_file_guards_are_independent`; `history_malformed_storage_unknown_versions_duplicates_and_state_mismatch_fail_closed`; `history_transition_failure_cannot_split_audit_and_lifecycle`; `history_wire_validation_guards_are_independently_observable`; `history_http_output_bound_has_stable_redacted_failure` and `history_frames_fail_closed_before_writing_oversized_output`. |

The application/provider authorization negatives are independent. Storage negatives
use separate fixtures for each guard. Mutation testing exposed masked/missing
negative cases; the corrected fixtures reject for the intended invariant.

## Mutation evidence

[Classifications and exact fault mapping](1-9-mutation-classifications.md): 28
semantic faults and 16 generated transformations, all caught after strengthening
four meaningful survivors. No equivalent exception or unresolved survivor.
Original failures, baseline logs, patches, retries, commands, durations, and source
hashes are retained. A browser baseline ordering assumption was corrected and
explicitly excluded from caught-mutant counts.

## Earlier verification and corrections

The first parent stable/MSRV complete runs each passed 834 tests with 12 ignored,
plus 13 benchmark smoke successes. Strict Clippy then found four lint issues
(wildcard error bindings and fixture style); these were corrected and Clippy
passed. The adapter run passed 12 integrations, Firefox, and real-systemd checks.
Two additional history tests were subsequently added for independent wire guards
and current terminal records across restart; the pre-review suite passed 836 tests.
After review, two more migration/expiry tests brought the final suite to 838.
These final results supersede earlier counts; older logs remain for provenance.

## Limitations

Verification uses synthetic credentials, deterministic clocks and private fixtures
on x86_64 Linux. Rust stable 1.98.1, Rust 1.88.0, Firefox 151.0.2, Node 26.3.1,
and user-systemd 255.4 were used. There was no production vault inspection, live
agent pairing, AArch64 run, or manual screen-reader session. Agent attribution is
verified with internal DTO fixtures and adapter responses because pairing is
outside this story. No production test-inspection endpoint was added.

Large-history latency remains unmeasured: the review recorded a deferred performance
measurement, not a verified latency defect. History storage still uses the existing
complete state file. Limits bound query results and transport rendering, not retention or total disk usage; retention
engine selection and export are deliberately deferred. Legacy records can expose
only facts actually retained by the previous schema.

All three workflow review layers completed and all 15 findings were individually
triaged. Every confirmed local fix and verification gap is resolved and covered
by post-review verification. Two claims were refuted by retained historical fields;
one unverified large-history latency concern was recorded for measurement. See
[review triage](1-9-review.md). Human approval remains pending. No commit, push or
PR has occurred.
