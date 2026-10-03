# Story 1.9 mutation classifications

All 44 distinct scoped mutations are caught on the post-review source: 28 explicit
semantic faults and 16 cargo-mutants transformations. There are no unresolved
survivors or equivalent exceptions. No process-timeout, infrastructure failure or
compile failure is counted as a catch.
This is a scoped campaign, not a repository-wide mutation score.

## Semantic campaign

Every fault was preceded by a passing unmutated run. Each source replacement is
recorded in the named `.diff`, with baseline/mutant output beside it. Rust tests
must fail with exit 101 and `test result: FAILED`; browser tests must fail with an
assertion. Sources are restored unconditionally and checked against their hashes.
The complete commands, durations, exit codes, and source hashes are in each
phase's `results.json`. The reproducible runner is
[`semantic-mutation-runner.py`](1-9-evidence/semantic-mutation-runner.py).

| Fault | Detecting test (exact Rust name or browser harness) | Final evidence |
| --- | --- | --- |
| requester-attribution | `access::history_tests::history_submission_and_decision_have_exact_allowlisted_snapshots` | [caught](1-9-evidence/review-semantic/requester-attribution-mutant.log.gz) |
| policy-projection | `access::history_tests::history_submission_and_decision_have_exact_allowlisted_snapshots` | [caught](1-9-evidence/review-semantic/policy-projection-mutant.log.gz) |
| credential-projection | `access::history_tests::history_submission_and_decision_have_exact_allowlisted_snapshots` | [caught](1-9-evidence/review-semantic/credential-projection-mutant.log.gz) |
| application-human-check | `access::history_tests::history_owner_and_browser_generation_guards_work_while_locked` | [caught](1-9-evidence/review-semantic/application-human-check-mutant.log.gz) |
| provider-human-check | `access::history_tests::history_provider_owner_guard_is_independent_of_application_authentication` | [caught](1-9-evidence/review-semantic/provider-human-check-mutant.log.gz) |
| browser-generation | `access::history_tests::history_owner_and_browser_generation_guards_work_while_locked` | [caught](1-9-evidence/review-semantic/browser-generation-mutant.log.gz) |
| minimum-limit | `access::history_tests::history_limits_empty_equal_timestamps_and_all_tiebreakers_are_deterministic` | [caught](1-9-evidence/review-semantic/minimum-limit-mutant.log.gz) |
| maximum-limit | `access::history_tests::history_limits_empty_equal_timestamps_and_all_tiebreakers_are_deterministic` | [caught](1-9-evidence/review-semantic/maximum-limit-mutant.log.gz) |
| default-limit | `access::history_tests::history_default_and_maximum_limits_count_events` | [caught](1-9-evidence/review-semantic/default-limit-mutant.log.gz) |
| timestamp-precedence | `access::history_tests::history_time_precedes_identity_and_ordinal_and_unknown_time_sorts_last` | [caught](1-9-evidence/review-semantic/timestamp-precedence-mutant.log.gz) |
| identity-tiebreak | `access::history_tests::history_time_precedes_identity_and_ordinal_and_unknown_time_sorts_last` | [caught](1-9-evidence/review-semantic/identity-tiebreak-mutant.log.gz) |
| ordinal-tiebreak | `access::history_tests::history_time_precedes_identity_and_ordinal_and_unknown_time_sorts_last` | [caught](1-9-evidence/review-semantic/ordinal-tiebreak-mutant.log.gz) |
| bounded-query | `access::history_tests::history_default_and_maximum_limits_count_events` | [caught](1-9-evidence/review-semantic/bounded-query-mutant.log.gz) |
| legacy-binding | `access::history_tests::history_malformed_storage_unknown_versions_duplicates_and_state_mismatch_fail_closed` | [caught](1-9-evidence/review-semantic/legacy-binding-mutant.log.gz) |
| final-lifecycle-consistency | `access::history_tests::history_malformed_storage_unknown_versions_duplicates_and_state_mismatch_fail_closed` | [caught](1-9-evidence/review-semantic/final-lifecycle-consistency-mutant.log.gz) |
| execution-claim-consistency | `access::history_tests::history_recorded_execution_requires_a_claim_independently_of_other_guards` | [caught](1-9-evidence/review-semantic/execution-claim-consistency-mutant.log.gz) |
| recovery-invalidation | `access::history_tests::history_terminal_restart_is_idempotent_and_pending_never_regains_authority` | [caught](1-9-evidence/review-semantic/recovery-invalidation-mutant.log.gz) |
| durable-submission | `access::history_tests::history_submission_and_decision_have_exact_allowlisted_snapshots` | [caught](1-9-evidence/review-semantic/durable-submission-mutant.log.gz) |
| transition-event | `access::history_tests::history_every_lifecycle_projection_has_exact_fields_and_distinct_outcomes` | [caught](1-9-evidence/review-semantic/transition-event-mutant.log.gz) |
| terminal-controls | `tests::history_arguments_and_terminal_json_preserve_data_without_controls` | [caught](1-9-evidence/review-semantic/terminal-controls-mutant.log.gz) |
| browser-control-escaping | `tests/ui/direct-request.mjs` | [caught](1-9-evidence/review-semantic/browser-control-escaping-mutant.log.gz) |
| browser-html-escaping | `tests/ui/direct-request.mjs` | [caught](1-9-evidence/review-semantic/browser-html-escaping-mutant.log.gz) |

## Generated campaign

cargo-mutants 27.1.0 ran in place, with independent successful baselines. The
initial selection contains 16 transformations of the new validation, outcome,
ordering and limit functions. The inventory and selected names are retained;
semantic faults cover projection, access, write, recovery and rendering behavior
that generated return-value changes do not express well.

```sh
scripts/with-secure-test-tmpdir.sh env RUST_TEST_THREADS=4 CARGO_NET_OFFLINE=true   cargo mutants --no-config --in-place --file src/access/history.rs   --re 'replace HistoryEvent::(valid|consistent_outcome|matches_record) -> bool|replace limit ->|replace newest -> Vec<HistoryEvent> with vec!\[\]|in outcome|delete match arm'   --output docs/implementation/1-9-evidence/generated-initial   --timeout 120 --build-timeout 180 -- --lib history
```

| Transformation | Initial result | Final result/evidence |
| --- | --- | --- |
| `src/access/history.rs:119:9: replace HistoryEvent::valid -> bool with true` | MissedMutant | [CaughtMutant](1-9-evidence/generated-final/mutants.out/log/src__access__history.rs_line_119_col_9.log.gz) |
| `src/access/history.rs:119:9: replace HistoryEvent::valid -> bool with false` | CaughtMutant | [CaughtMutant](1-9-evidence/generated-initial/mutants.out/log/src__access__history.rs_line_119_col_9_001.log.gz) |
| `src/access/history.rs:138:9: replace HistoryEvent::consistent_outcome -> bool with true` | MissedMutant | [CaughtMutant](1-9-evidence/generated-final/mutants.out/log/src__access__history.rs_line_138_col_9.log.gz) |
| `src/access/history.rs:138:9: replace HistoryEvent::consistent_outcome -> bool with false` | CaughtMutant | [CaughtMutant](1-9-evidence/generated-initial/mutants.out/log/src__access__history.rs_line_138_col_9_001.log.gz) |
| `src/access/history.rs:197:9: replace HistoryEvent::matches_record -> bool with true` | CaughtMutant | [CaughtMutant](1-9-evidence/generated-initial/mutants.out/log/src__access__history.rs_line_197_col_9.log.gz) |
| `src/access/history.rs:197:9: replace HistoryEvent::matches_record -> bool with false` | CaughtMutant | [CaughtMutant](1-9-evidence/generated-initial/mutants.out/log/src__access__history.rs_line_197_col_9_001.log.gz) |
| `src/access/history.rs:209:5: replace limit -> Result<usize, DirectRequestError> with Ok(0)` | CaughtMutant | [CaughtMutant](1-9-evidence/generated-initial/mutants.out/log/src__access__history.rs_line_209_col_5.log.gz) |
| `src/access/history.rs:209:5: replace limit -> Result<usize, DirectRequestError> with Ok(1)` | CaughtMutant | [CaughtMutant](1-9-evidence/generated-initial/mutants.out/log/src__access__history.rs_line_209_col_5_001.log.gz) |
| `src/access/history.rs:217:5: replace newest -> Vec<HistoryEvent> with vec![]` | CaughtMutant | [CaughtMutant](1-9-evidence/generated-initial/mutants.out/log/src__access__history.rs_line_217_col_5.log.gz) |
| `src/access/history.rs:243:52: replace match guard decision == D::Recovered with true in outcome` | CaughtMutant | [CaughtMutant](1-9-evidence/generated-initial/mutants.out/log/src__access__history.rs_line_243_col_52.log.gz) |
| `src/access/history.rs:243:52: replace match guard decision == D::Recovered with false in outcome` | CaughtMutant | [CaughtMutant](1-9-evidence/generated-initial/mutants.out/log/src__access__history.rs_line_243_col_52_001.log.gz) |
| `src/access/history.rs:243:61: replace == with != in outcome` | CaughtMutant | [CaughtMutant](1-9-evidence/generated-initial/mutants.out/log/src__access__history.rs_line_243_col_61.log.gz) |
| `src/access/history.rs:250:13: delete match arm D::ReviewUnavailable in outcome` | CaughtMutant | [CaughtMutant](1-9-evidence/generated-initial/mutants.out/log/src__access__history.rs_line_250_col_13.log.gz) |
| `src/access/history.rs:251:13: delete match arm D::ExecutionUnavailable in outcome` | CaughtMutant | [CaughtMutant](1-9-evidence/generated-initial/mutants.out/log/src__access__history.rs_line_251_col_13.log.gz) |
| `src/access/history.rs:252:13: delete match arm D::Invalidated in outcome` | CaughtMutant | [CaughtMutant](1-9-evidence/generated-initial/mutants.out/log/src__access__history.rs_line_252_col_13.log.gz) |
| `src/access/history.rs:253:13: delete match arm D::Recovered in outcome` | CaughtMutant | [CaughtMutant](1-9-evidence/generated-initial/mutants.out/log/src__access__history.rs_line_253_col_13.log.gz) |

The two generated retries use the same command with
`--re 'replace HistoryEvent::(valid|consistent_outcome) -> bool with true'` and
`--output docs/implementation/1-9-evidence/generated-final`.
The initial run was 14 caught / 2 missed; the retry was 2 caught / 0 missed.
These are 16 unique transformations, not 18 unique mutants.

## Meaningful survivors and corrections

- `legacy-binding`: the negative fixture also mismatched the final lifecycle
  status, allowing another guard to mask removal of binding validation. It now
  starts from an independently valid denied record and changes only the binding.
- `final-lifecycle-consistency`: added a record with a valid expired outer state
  and independently valid denied final audit event; only their mismatch rejects it.
- `HistoryEvent::valid => true` and `consistent_outcome => true`: added independent
  wire-level negatives for each field invariant and status/outcome agreement,
  including successful deserialization of the unchanged valid fixture first.

All four survived initially and were caught after these test corrections. No
production behavior was changed to satisfy the mutations. Original surviving
logs and final catching logs are both retained.

A browser baseline initially asserted that one particular request was globally
newest after lock. Equal timestamps permit another request to sort first by its
ID. The assertion now selects that request by ID and checks its newest event.
That failed baseline is retained in
`semantic-final/browser-control-escaping-baseline.log.gz`; no mutation was applied
and it is not counted as a caught mutant. Both browser mutations then had
passing baselines and failed assertions under their respective faults.

## Scope and limitations

The 28 semantic cases cover requester/revision/credential projections, both human
checks, browser generation, all limits and ordering tie-breaks, legacy validation,
execution claims, final lifecycle consistency, durable submission, transition
emission, recovery invalidation, and HTML/terminal/control escaping. Generated
cases add positive/negative DTO validation and explicit outcome branches.
Legacy/constant-return transformations outside this selection were not run;
there is no claim that every possible mutant was tested or is equivalent.
The final full verification manifest establishes that restored sources were
unchanged throughout final testing. No mutation job remained running at review.


## Post-review semantic rerun

All 28 semantic cases passed their unmutated baselines and caught their faults on
the patched source. This reruns the original 22 cases and adds six independent
regressions: per-record ownership, history-first expiry, multi-event legacy
reconstruction, queued mutation refresh, session-retirement clearing, and initial
review independence. Results, commands, durations and restored-source hashes are
in `1-9-evidence/review-semantic/results.json`.

The initial-review-independence fault failed the explicit `waitForFunction`
condition for a visible Pending review at `tests/ui/direct-request.mjs:57`, after
30 seconds. It exited normally with a failing browser test (exit 1), within the
240-second process budget. This is a demonstrated behavioral deadline failure,
not an infrastructure or process-timeout catch. The source was restored afterward.
All 16 generated transformations were rerun and caught in `review-generated/`,
with zero missed, timeout or unviable cases. The original campaign history above
is retained for provenance; the post-review run supersedes it. Restored source
hashes were checked against every semantic result before the final full suite.


| Additional post-review fault | Detecting check | Evidence |
| --- | --- | --- |
| history-record-owner | `access::direct_request_tests::correctly_sealed_other_owner_record_is_not_disclosed_to_current_human` | [caught](1-9-evidence/review-semantic/history-record-owner-mutant.log.gz) |
| history-first-expiry | `access::history_tests::history_first_read_at_request_deadline_expires_pending_and_approved_once` | [caught](1-9-evidence/review-semantic/history-first-expiry-mutant.log.gz) |
| legacy-execution-phase | `access::history_tests::history_completed_legacy_three_approvals_reconstruct_exact_phases_and_restart_stably` | [caught](1-9-evidence/review-semantic/legacy-execution-phase-mutant.log.gz) |
| history-pending-mutation | `tests/ui/direct-request.mjs` | [caught](1-9-evidence/review-semantic/history-pending-mutation-mutant.log.gz) |
| history-session-retirement | `tests/ui/direct-request.mjs` | [caught](1-9-evidence/review-semantic/history-session-retirement-mutant.log.gz) |
| history-review-independence | `tests/ui/direct-request.mjs` | [caught](1-9-evidence/review-semantic/history-review-independence-mutant.log.gz) |

Post-review generated outcomes: [machine results](1-9-evidence/review-generated/mutants.out/outcomes.json.gz).
All 44 faults ran again after review fixes; none relies solely on the earlier snapshot.

## Native CI extension

The extension caught three native-oracle guard mutations and twelve scoped CLI/browser mutations (three repeat cases, nine new). No survivor, equivalent, build/infrastructure failure or process timeout occurred. Four browser cases were caught by bounded assertion waits, not process timeouts. All sources were restored and the full final verification passed. See [exact classifications and snapshot limits](1-9-native-ci.md#scoped-mutation-evidence).
