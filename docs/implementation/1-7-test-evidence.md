# Story 1.7 test evidence

All credentials are synthetic sentinels. The protected execution path is exercised with an explicit test supervisor; production supervision remains unavailable and therefore fails closed before lookup.

| Requirement | Evidence |
| --- | --- |
| Exact item, selected fields, marker and eligibility | `adapters::vaultwarden::tests::resolution_rejects_wrong_deleted_unmarked_or_ambiguous_items`; `claimed_execution_resolves_after_image_verification_once_into_only_policy_environment` |
| Explicit policy-owned environment and no persistence | `access::ports::tests::child_environment_*`; `claimed_execution_resolves_after_image_verification_once_into_only_policy_environment` |
| Approval/image ordering, non-approved rejection and prelaunch failure | `claimed_execution_failure_before_launch_is_redacted_terminal_and_never_supervises`; `execution_rejects_each_nonapproved_state_before_image_or_backend_work`; `unavailable_supervisor_prevents_claim_resolution_and_launch` |
| One-time concurrent execution | `concurrent_claimed_execution_attempts_consume_approval_once` |
| Exit and launch lifecycle | `claimed_execution_returns_only_permitted_terminal_outcomes` |
| Authority revalidation, lock race and persistence failure | `claimed_execution_rechecks_live_authority_before_terminal_persistence`; `claimed_execution_lock_intent_racing_resolution_prevents_launch`; `claimed_execution_claim_and_terminal_persistence_fail_closed` |
| Large dual-stream output discard | `adapters::execution::linux::tests::fixture_supervision_discards_large_secret_output_from_both_streams` (two concurrent writers, 128 KiB per stream; `TEST_DISCARDED_BYTES == 256 KiB` confirms both streams were drained) |

Final commands completed successfully:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features --locked --offline -- -D warnings`
- `cargo check --release --locked --offline`
- `./scripts/with-secure-test-tmpdir.sh cargo test --all-targets --locked --offline` (539 library tests plus all binary/integration targets)
- `./scripts/with-secure-test-tmpdir.sh rustup run 1.88.0 cargo test --all-targets --locked --offline`
- `git diff --check`

The Linux fixture tests use harmless sealed ELF descriptors. No real secret-bearing child can launch until Story 1.8 provides containment.
