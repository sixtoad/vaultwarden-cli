# Story 1.8 mutation classifications

> Historical pre-review evidence below. Review-iteration-1 changed source requires fresh verification; the new run is in progress and this historical evidence does not validate it.

Generated mutation verification completed: **19 tested, 19 caught**, no survivors,
no compiler failures and no timeouts. The unmutated baseline passed. The run took
8 minutes and ran sequentially in place; the tool restored source afterward.

Command (run through `scripts/with-secure-test-tmpdir.sh`):

```sh
timeout --signal=TERM --kill-after=15s 1800s cargo mutants --in-place \
  --file src/adapters/supervisor/manager.rs --re 'owns_name|belongs|proc_empty' \
  --timeout 60 --build-timeout 180 \
  --output docs/implementation/1-8-evidence/generated \
  --cargo-arg=--offline --cargo-arg=--locked \
  -- --lib adapters::supervisor::manager::tests
```

The generated set removes or changes the strict ownership grammar and the
independent reaping predicate: full bodies, Boolean operators, deleted/subtree
membership, numeric PID filtering, missing versus unreadable proc entries,
process-start identity correlation and unified-cgroup availability. The tests
include unrelated non-PID entries, missing entries, malformed/unreadable entries,
zombies, deleted paths, subtrees and sibling-prefix lookalikes. No equivalent
survivor classification was needed.

Machine-readable outcomes, every patch and every baseline/mutant build/test log
are in [generated evidence](1-8-evidence/generated/mutants.out/outcomes.json).
The concise tool result is [generated-summary.log](1-8-evidence/generated-summary.log).

Eight explicit semantic mutations were verified sequentially by
[semantic-runner.py](1-8-evidence/semantic-runner.py). It saves each source hash,
patch, separate passing unmutated baseline and mutant log; restoration occurs in
a `finally` block. It distinguishes test kills from compiler/infrastructure
failures and timeouts. No failure is treated as a kill without a completed failing
test result. The targets are:

| Mutant | Named test |
| --- | --- |
| Retain registry lock while closing admission | `uncertain_cleanup_releases_execution_registry_before_closing_admission` |
| Reject zero-byte packet before closing received FDs | `zero_length_packet_closes_every_received_descriptor` |
| Remove BindsTo | `exact_typed_manager_contract_and_no_secret_properties` |
| Bypass final release authorization | `final_release_revalidates_authority_after_supervisor_setup` |
| Remove cleanup-uncertainty terminal gate | `uncertain_cleanup_closes_admission_and_never_persists_terminal` |
| Terminalize active requests during revocation | `running_is_observed_before_reaping_and_lock_waits_without_holding_authority` |
| Skip startup cleanup before state validation | `startup_cleanup_precedes_registered_image_integrity_validation` |
| Omit actual helper-parent identity comparison | `parent_death_before_and_after_prctl_uses_actual_helper_identity` |

Semantic result: **8 tested, 8 caught**, with eight passing unmutated baselines,
no survivors, no compiler/infrastructure failures and no timeouts. Exact results
and baseline source hashes are in [semantic/results.json](1-8-evidence/semantic/results.json).
All mutated files were restored. Final stable and Rust 1.88 all-target suites,
strict Clippy, browser and real-manager checks passed; see
[verification evidence](1-8-test-evidence.md).
