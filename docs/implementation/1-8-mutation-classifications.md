# Story 1.8 mutation classifications — final

**21 generated mutants and 21 semantic mutants caught.** No unresolved survivor,
equivalent survivor, test timeout or unviable generated mutant remains. All runs
had passing unmutated baselines. Sources were restored and their hashes verified.

## Generated predicates on final source

The parent refreshed generated mutations after all final patches:

```sh
scripts/with-secure-test-tmpdir.sh timeout --signal=TERM --kill-after=15s 1800s \
  cargo mutants --in-place --file src/adapters/supervisor/manager.rs \
  --re 'owns_name|belongs|proc_empty_with_budget' --timeout 60 --build-timeout 180 \
  --output docs/implementation/1-8-evidence/review-2-parent/generated \
  --cargo-arg=--offline --cargo-arg=--locked \
  -- --lib adapters::supervisor::manager::tests
```

Result: **21 tested, 21 caught**, 0 missed, 0 unviable, 0 timeout; approximately
7 minutes. It covers ownership grammar, deleted/subtree membership, numeric PID
filtering, missing/unreadable proc entries, process identity correlation, unified
cgroup availability and both inventory budget checks. Every patch and test log is
retained with [machine outcomes](1-8-evidence/review-2-parent/generated/mutants.out/outcomes.json)
and the [summary](1-8-evidence/review-2-parent/generated-summary.log).

## Semantic cases

Every row was caught by a behavioral assertion with a passing baseline. The first
15 were verified at the prior frozen review checkpoint; their expressions remain
unchanged, and the final full suites re-ran their regressions. The final six cover
the new review corrections. Per-source hashes, patches and detailed classifications
remain in the linked evidence and runner result files.

| Mutation | Detecting test | Classification |
| --- | --- | --- |
| cleanup-lock-order | `access::application::tests::uncertain_cleanup_releases_execution_registry_before_closing_admission` | [caught](1-8-evidence/review-1/semantic/cleanup-lock-order-mutant.log) |
| zero-packet-rights | `adapters::supervisor::bridge::tests::zero_length_packet_closes_every_received_descriptor` | [caught](1-8-evidence/review-1/semantic/zero-packet-rights-mutant.log) |
| required-dependency | `adapters::supervisor::manager::tests::exact_typed_manager_contract_and_no_secret_properties` | [caught](1-8-evidence/review-1/semantic/required-dependency-mutant.log) |
| release-authority | `access::direct_request_tests::final_release_revalidates_authority_after_supervisor_setup` | [caught](1-8-evidence/review-1/semantic/release-authority-mutant.log) |
| cleanup-terminal | `access::direct_request_tests::uncertain_cleanup_closes_admission_and_never_persists_terminal` | [caught](1-8-evidence/review-1/semantic/cleanup-terminal-mutant.log) |
| revocation-lifecycle | `access::direct_request_tests::running_is_observed_before_reaping_and_lock_waits_without_holding_authority` | [caught](1-8-evidence/review-1/semantic/revocation-lifecycle-mutant.log) |
| recovery-before-validation | `access::provider::tests::startup_cleanup_precedes_registered_image_integrity_validation` | [caught](1-8-evidence/review-1/semantic/recovery-before-validation-mutant.log) |
| actual-helper-parent | `adapters::supervisor::bridge::tests::parent_death_before_and_after_prctl_uses_actual_helper_identity` | [caught](1-8-evidence/review-1/semantic/actual-helper-parent-mutant.log) |
| queued-cancellation | `access::direct_request_tests::queued_cancellation_is_owner_bound_and_prevents_later_claim` | [caught](1-8-evidence/review-1/semantic/queued-cancellation-mutant.log) |
| unavailable-closes-admission | `access::direct_request_tests::unavailable_supervisor_prevents_claim_resolution_and_launch` | [caught](1-8-evidence/review-1/semantic/unavailable-closes-admission-mutant.log) |
| lease-no-replace | `adapters::supervisor::manager::tests::lease_publication_is_atomic_collision_safe_and_recovers_interrupted_staging` | [caught](1-8-evidence/review-1/semantic/lease-no-replace-mutant.log) |
| recover-abandoned-staging | `adapters::supervisor::manager::tests::lease_publication_is_atomic_collision_safe_and_recovers_interrupted_staging` | [caught](1-8-evidence/review-1/semantic/recover-abandoned-staging-mutant.log) |
| discard-unrelated-jobs | `adapters::supervisor::manager::tests::job_observation_discards_unrelated_churn` | [caught](1-8-evidence/review-1/semantic/discard-unrelated-jobs-mutant.log) |
| helper-name-filter | `adapters::supervisor::manager::tests::helper_environment_is_name_only_complete_and_recovery_stable` | [caught](1-8-evidence/review-1/semantic/helper-name-filter-mutant.log) |
| worker-dispatch | `real:app-worker-exit` | [caught](1-8-evidence/review-1/semantic/worker-dispatch-mutant.log) |
| pre-exec trace ignored | `pre_exec_sigkill_with_empty_error_pipe_reports_failure_and_confirmed_cleanup` | [caught](1-8-evidence/review-2/preexec-mutant.log) |
| nonzero mapped to zero | `real app-nonzero exact durable failure` | [caught](1-8-evidence/review-2/nonzero-as-zero-provider.log) |
| signal mapped to zero | `real app-signal exact durable failure` | [caught](1-8-evidence/review-2/signal-as-zero-provider.log) |
| entry-scan-budget | `adapters::supervisor::manager::tests::proc_inventory_stops_at_the_entry_that_exhausts_the_remaining_budget` | [caught](1-8-evidence/review-2-parent/entry-scan-budget-mutant.log) |
| final-scan-budget | `adapters::supervisor::manager::tests::proc_inventory_stops_at_the_entry_that_exhausts_the_remaining_budget` | [caught](1-8-evidence/review-2-parent/final-scan-budget-mutant.log) |
| failed-unit-collection | `adapters::supervisor::manager::tests::exact_typed_manager_contract_and_no_secret_properties` | [caught](1-8-evidence/review-2-parent/failed-unit-collection-mutant.log) |

The nonzero/signal mutants caused the exact provider-side assertion to show
`Completed` instead of the required failure reason. Their outer observer then
failed its bounded completion barrier; the timeout alone was **not** the kill
criterion. See [status results](1-8-evidence/review-2/status-and-target-results.json).
The pre-exec mutant falsely emitted `ExecConfirmed` after an empty pipe EOF from
SIGKILL: [trace results](1-8-evidence/review-2/preexec-results.json).
The parent's three guard cases have separate [results](1-8-evidence/review-2-parent/mutation-results.json)
and a [reproducible runner](1-8-evidence/review-2-parent/mutation-runner.py).

One earlier worker mutation attempt failed before behavioral testing because a
read-only fixture path was reused. It was classified as infrastructure, fixed and
successfully rerun; it is not a survivor or a catch. No equivalent-mutant exception
was needed. All final full-suite, browser and real-manager checks passed, and the
final source manifest still matched after generated-mutation restoration:
[complete evidence](1-8-test-evidence.md).
