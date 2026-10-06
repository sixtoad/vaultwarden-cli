# Story 2.3 verification

Implementation, all three workflow reviews and final patch verification are complete.
Iteration-0 evidence and review triage are retained in the archive. The implementation
is uncommitted; commit, push and pull-request publication remain unauthorized.

Base: `6081c48764208c1adad03b9d5be31550ff850895` on updated `main`.
Epic 1 and Stories 2.1–2.2 are merged; there is no unmerged dependency.
See [planning evidence](2-3-planning-notes.md), [wire and CLI contract](2-3-protocol-contract.md),
and the [detailed acceptance map](2-3-implementation-notes.md).

## Acceptance coverage

| User acceptance criterion | Executed witnesses |
|---|---|
| 1. Signed versioned snake_case status query; purpose/request/freshness bound | Protocol suite (12 tests): canonical independent vector, all signed fields, strict Ed25519, cross-purpose reuse, strict dispatcher and field schemas |
| 2. Kernel peer, signature, enabled pairing and immutable owner on every query | Signed suite (33 tests), including independent UID/group/enabled/owner negatives; actual mapped-UID Unix socket test with independently eligible other binding and wrong-group decoy |
| 3. Explicit safe lifecycle/exit/failure projection | Every supported lifecycle and five failure categories, exit bounds, injected unknown fields; raw wire and CLI output assertions |
| 4. Indistinguishable inaccessible/nonexistent rejection | Exact byte equality and EOF behavior for known non-owner, guessed ID, unpaired and revoked callers; no state/audit/replay-marker changes on rejection |
| 5. Noninteractive polling and request-and-wait | 18 CLI integration tests plus 6 virtual-time wait tests; capped 100/200/400/800/1000 ms backoff, terminal/rejection/Busy handling, timeout, disconnected acknowledgment/query, SIGINT/SIGTERM before and after receipt, full stdout/stderr pipes, shared submission/receipt/poll budget, fresh-query reconnect, exactly one submission, stdin closed and setsid |
| 6. Provider-authoritative expiry and confirmed completion | Separate provider monotonic/wall clocks; Pending/Approved × request/session deadline × before/write/final-read crossings; controlled cleanup synchronization; real systemd cleanup/recovery regression tests |
| 7. Repeated terminal observation without transferable authority | Fresh signed observations, unchanged terminal RequestRecord/audit, restart, shared nonce replay across actions, concurrency, durable write failure cases, re-pairing without old ownership, revocation intent during blocked query persistence and established-connection/active-wait revocation |

Every frozen matrix row has an executed passing witness: owner query maps to criteria
1/3/7; inaccessible ID to 2/4; invalid authority to 1/2/4; authority changes to 6/7;
interrupted waiting to 5. Existing agent-binding registry tests also passed in both
full suites; no changes to their source were needed. Query tests assert no new
requests/audits, review launch, secret resolution, backend unlock or execution.

## Exact automated results

The [machine-readable ledger](2-3-evidence-summary.json) records exact argv, exit
codes, durations and mutant failure names. All tests finished before review was
requested. Both complete suites ran on identical source bytes. The mutation copy
and restored original were checked against those source hashes.

| Check | Result | Duration |
|---|---|---|
| Final patched source: `fmt` | exit 0 | 3.53 s |
| Final patched source: `clippy` | exit 0 | 15.93 s |
| Final patched source: `all-targets` | 949 reported passed, 0 failed, 14 ignored | 306.85 s |
| Final patched source: `msrv-all-targets` | 949 reported passed, 0 failed, 14 ignored | 337.52 s |
| Final patched source: `protocol` | 12 reported passed, 0 failed, 0 ignored | 1.57 s |
| Final patched source: `signed` | 33 reported passed, 0 failed, 0 ignored | 11.01 s |
| Final patched source: `socket` | 17 reported passed, 0 failed, 0 ignored | 5.98 s |
| Final patched source: `cli-lifecycle` | 25 reported passed, 0 failed, 0 ignored | 15.98 s |
| Final patched source: `real-peer` | 1 reported passed, 0 failed, 0 ignored | 6.89 s |
| Final patched source: `systemd` | 2 reported passed, 0 failed, 0 ignored | 77.49 s |
| Final patched source: `diff-check` | exit 0 | 0.12 s |
| Restored source: `build-bins` | exit 0 | 12.26 s |
| Restored source: `protocol` | 12 reported passed, 0 failed, 0 ignored | 75.16 s |
| Restored source: `signed` | 33 reported passed, 0 failed, 0 ignored | 12.32 s |
| Restored source: `socket` | 17 reported passed, 0 failed, 0 ignored | 6.04 s |
| Restored source: `cli-lifecycle` | 25 reported passed, 0 failed, 0 ignored | 67.38 s |
| Restored source: `real-peer` | 1 reported passed, 0 failed, 0 ignored | 9.80 s |
| Restored source: `wait` | 6 reported passed, 0 failed, 0 ignored | 0.42 s |
| Restored source: `fmt` | exit 0 | 0.82 s |
| Restored source: `diff-check` | exit 0 | 0.12 s |

Both complete suites additionally passed 13 benchmark smoke checks. Of the 949
reported passes per suite, 71 live-Vaultwarden tests return early because
`VAULTWARDEN_LIVE_TEST_URL` and `VAULTWARDEN_LIVE_ADMIN_TOKEN` are absent; **878
other reported tests execute**. The 14 ignored entries comprise nine subprocess
fixtures invoked by passing parent tests, one browser fixture, one internal
systemd fixture, one namespace fixture and two real-manager tests. Namespace and
systemd harnesses were explicitly executed; systemd covered 30 real-manager
scenarios. The browser fixture was not rerun for this agent-only change.

The mapped namespace invocation uses provider UID 0, separate agent/wrong UIDs
8/10, socket-access GID 7 and binding GID 9. A second UID-8/GID-10 binding allows
preflight admission while independently testing a query's selected-binding group.
The held connection is proven admitted before revocation using consumed input,
nonblocking response peek and pipe synchronization; the active-wait revocation
phase is separate. The unit socket witness uses a first-frame-chunk hook.

The tests use `scripts/with-secure-test-tmpdir.sh`, locked offline dependencies,
`CARGO_BUILD_JOBS=2`, `RUST_TEST_THREADS=4`, and the existing target cache at
`/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/target`. Escalated local
execution allowed the repository's HOME-based secure temporary fixtures, mapped
user namespaces and user systemd; HOME was not replaced. Toolchain/kernel versions
are recorded in the ledger. Fresh original source mtimes forced rebuilding after
mutations; source content hashes remained identical.

The separate log scan checks eleven exact synthetic secret/label/output/capability
sentinels across successful unmutated verification logs. The real-peer test runs with
`--nocapture`; its captured provider stdout/stderr contains no unexpected
application diagnostics. CLI tests independently require exact redacted JSON,
empty stderr where appropriate and no reflected invalid-input sentinel.

## Scoped mutation results

**36 distinct semantic mutations: 36 caught, 0 survivors, 0 equivalent mutants,
0 unviable mutants, 0 timeouts and 0 infrastructure failures.** Ten unmodified
baseline test selections passed before mutation. A caught result requires a
compiled test binary and an actual `test result: FAILED` outcome;
compilation errors and campaign timeouts are classified separately. The two blocked-output mutants trip bounded child-exit assertions and kill/reap the child; neither stalls the campaign. The terminal-stop
mutant attempts an extra query after Completed and exhausts the finite response
fixture; all other caught results are explicit assertion failures. Review-derived mutants restore blocking stdout, unbounded stderr diagnostics, a reset deadline after acknowledgment, a release gate held over storage, missing CLI request-ID validation, a renewed response-read deadline, and duplicate-field collapse through intermediate JSON values. The campaign is a
manual semantic mutation campaign, not a generated cargo-mutants run.

| Mutation | Classification | Failing witness |
|---|---|---|
| `query-purpose-signing` | caught (exit 101) | `signed_query_canonical_vector_and_cross_purpose_separation`, `signed_query_binds_every_field_and_uses_strict_verification` |
| `query-id-signing` | caught (exit 101) | `signed_query_canonical_vector_and_cross_purpose_separation`, `signed_query_binds_every_field_and_uses_strict_verification` |
| `query-nonce-signing` | caught (exit 101) | `signed_query_canonical_vector_and_cross_purpose_separation`, `signed_query_binds_every_field_and_uses_strict_verification` |
| `query-strict-verifier` | caught (exit 101) | `signed_query_binds_every_field_and_uses_strict_verification` |
| `query-signature-auth` | caught (exit 101) | `signed_status_inaccessible_ids_and_authority_rejections_have_no_effects` |
| `query-peer-auth` | caught (exit 101) | `signed_status_stored_enabled_pairing_is_independent_of_application_token`, `signed_status_inaccessible_ids_and_authority_rejections_have_no_effects` |
| `query-uid-auth` | caught (exit 101) | `signed_status_inaccessible_ids_and_authority_rejections_have_no_effects` |
| `query-group-auth` | caught (exit 101) | `signed_status_inaccessible_ids_and_authority_rejections_have_no_effects` |
| `query-enabled-auth` | caught (exit 101) | `signed_status_stored_enabled_pairing_is_independent_of_application_token` |
| `query-stored-owner` | caught (exit 101) | `signed_status_inaccessible_ids_and_authority_rejections_have_no_effects`, `signed_status_repairing_same_label_and_principal_never_transfers_ownership`, `signed_status_shared_nonce_replay_precedes_neither_authentication_nor_ownership` |
| `query-durable-marker` | caught (exit 101) | `signed_status_concurrent_identical_queries_consume_once`, `signed_status_projects_every_validated_state_without_mutating_terminal_records`, `signed_status_failed_persistence_never_discloses_and_retains_post_rename_nonce`, `signed_status_revocation_intent_is_published_during_blocked_query_write`, `signed_status_shared_nonce_replay_precedes_neither_authentication_nor_ownership` |
| `query-replay-lookup` | caught (exit 101) | `signed_status_concurrent_identical_queries_consume_once`, `signed_status_failed_persistence_never_discloses_and_retains_post_rename_nonce`, `signed_status_shared_nonce_replay_precedes_neither_authentication_nor_ownership` |
| `query-submission-replay-lookup` | caught (exit 101) | `signed_status_shared_nonce_replay_precedes_neither_authentication_nor_ownership` |
| `submission-query-replay-lookup` | caught (exit 101) | `signed_status_shared_nonce_replay_precedes_neither_authentication_nor_ownership` |
| `query-marker-format` | caught (exit 101) | `signed_status_query_markers_are_backward_compatible_canonical_unique_and_disjoint` |
| `query-marker-uniqueness` | caught (exit 101) | `signed_status_query_markers_are_backward_compatible_canonical_unique_and_disjoint` |
| `query-revocation-token` | caught (exit 101) | `signed_status_revocation_intent_during_authentication_prevents_marker_and_disclosure`, `signed_status_revocation_intent_is_published_during_blocked_query_write` |
| `query-running-projection` | caught (exit 101) | `signed_status_projects_every_validated_state_without_mutating_terminal_records`, `signed_status_running_remains_nonterminal_until_confirmed_cleanup` |
| `query-exit-projection` | caught (exit 101) | `signed_status_projects_every_validated_state_without_mutating_terminal_records` |
| `query-failure-projection` | caught (exit 101) | `signed_status_projects_every_validated_state_without_mutating_terminal_records` |
| `query-final-request-expiry` | caught (exit 101) | `signed_status_uses_provider_deadlines_even_when_storage_crosses_expiry` |
| `query-final-session-expiry` | caught (exit 101) | `signed_status_uses_provider_deadlines_even_when_storage_crosses_expiry` |
| `query-closed-projection` | caught (exit 101) | `signed_status_projection_is_closed_and_validates_every_lifecycle` |
| `wait-terminal-stop` | caught (exit 101) | `busy_then_running_then_terminal_and_backoff_cap` |
| `wait-backoff-cap` | caught (exit 101) | `busy_then_running_then_terminal_and_backoff_cap` |
| `wait-busy-retry` | caught (exit 101) | `busy_then_running_then_terminal_and_backoff_cap` |
| `wait-expiry-control-exit` | caught (exit 101) | `every_terminal_and_rejection_stops_without_sleep_or_retry` |
| `wait-deadline-extension` | caught (exit 101) | `deadline_clips_sleep_and_inflight_exchange`, `submission_receipt_and_observation_share_one_deadline` |
| `wait-cancellation-priority` | caught (exit 101) | `interruption_and_transport_uncertainty_never_become_lifecycle` |
| `wait-blocked-stdout-runtime` | caught (exit 101) | `agent_wait_full_stdout_and_stderr_preserve_timeout_and_signal_exits` |
| `wait-blocked-diagnostic-exit` | caught (exit 101) | `agent_wait_full_stdout_and_stderr_preserve_timeout_and_signal_exits` |
| `wait-reset-budget-after-ack` | caught (exit 101) | `submission_receipt_and_observation_share_one_deadline` |
| `query-release-gate-held-during-storage` | caught (exit 101) | `signed_status_revocation_intent_is_published_during_blocked_query_write` |
| `cli-request-id-redaction-guard` | caught (exit 101) | `malformed_agent_selectors_are_usage_errors_before_key_access` |
| `exchange-response-deadline-renewed` | caught (exit 101) | `query_exchange_response_read_retains_the_original_exchange_deadline` |
| `query-response-duplicate-fields-collapsed` | caught (exit 101) | `signed_status_projection_is_closed_and_validates_every_lifecycle` |

The disposable mutation copy was restored byte-for-byte. All 95
production/test/script/manifest hashes agree between the initial suite, copied
baseline, restored copy, post-mutation suite and final worktree. All 97
files in the complete disposable copy also match the original worktree. Production
binaries were rebuilt from the original unmutated worktree before the final
focused and real-peer tests. No meaningful survivors remain to fix and no
equivalence claims are needed.

## Review resolution

Iteration 0 found blocked output and unbounded fixture failure paths; those were
re-derived and independently verified. Iteration 1 completed blind, edge-case and
verification-gap reviews. The edge reviewer returned no findings. Triaged patches
extend malformed positional-ID redaction, a single transport budget, terminal and
broken-pipe output, binding-scoped nonce reuse and duplicate nested response-field
coverage. The pipe witness now explains its dependency on observable Linux task
wchan symbols. No review layer was skipped. Per-finding verdicts and evidence are
retained in the archive and build spec.

Existing synchronous-filesystem stalls and permanent replay-storage growth remain
documented follow-ups. Nonblocking inherited stdout errors retain the closed local
failure behavior; automatic output readiness retries were not added. No change to
approved ownership, disclosure, lifecycle or replay intent was needed.

## Evidence and limitations

The [evidence archive](2-3-evidence.tar.gz) includes raw logs, runners, case
definitions, per-mutant diffs, classifications, source/restoration hashes and
historical implementation attempts. SHA-256: `3d95acdf0e0aa29b93df6bb11c2dac4c25dd01002810dee6effe29c0b139df7c`.
Earlier fixture contention failures, the sandbox-only secure-wrapper refusal and
the strict-Clippy test-hook initializer failure are retained. The initializer was
made const; the complete final campaign passed afterward.

- All configured checks, scoped mutations and workflow reviews have finished. The 71 live-backend tests could not exercise Vaultwarden without the missing test URL/admin-token configuration. Completed-implementation human approval is the next checkpoint.
- Live Vaultwarden, hosted GitHub CI, a combined live-backend/cross-UID browser
  deployment, and manual accessibility checks were not run. No such acceptance
  is inferred from these synthetic tests. No agent-facing UI was added.
- Linux blocked-pipe synchronization requires observable task `wchan` symbols in procfs; hidden symbols fail the fixture explicitly instead of skipping it.
- Every successful poll permanently adds a nonce digest and rewrites the provider
  snapshot. Storage growth and write amplification remain; no quotas, compaction
  or replay-marker eviction were added. Freshness is durable nonce uniqueness,
  matching Story 2.2, not a client wall-clock message-age claim.
- Synchronous filesystem access can still stall beyond the network deadline; this is a pre-existing documented transport limitation. Older executables reject snapshots containing query replay metadata; replay evidence must not be stripped to force a downgrade.
- A lost submission acknowledgment can leave the client without an ID. Waiting
  never discovers, resubmits or cancels work; reconnect uses a known ID with a
  fresh signature. Local timeout/interruption/transport errors remain separate
  from provider lifecycle and execution exit status.
- These mutation witnesses cover selected security/lifecycle/wait guards; they
  are not an exhaustive enumeration of every possible defect.
