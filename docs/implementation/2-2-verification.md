# Story 2.2 verification

Status: implementation, three workflow reviews, review fixes and all required
automated verification complete. Approved for commit, push and pull request.

Base: `24ad5d14aa9b72f6e3ddb8cddae34f58335c52d3` (`origin/main`). Epic 1 and
Story 2.1 implementations are merged; see [dependency evidence](2-2-planning-notes.md).
The [wire contract](2-2-protocol-contract.md) defines canonical encoding, group
semantics, replay persistence and deployment requirements.

## Acceptance mapping

| Story criterion | Executable evidence |
|---|---|
| 1. Noninteractive signed JSON Lines submission | `protocol_tests::{canonical_vector,every_signed_semantic_field_is_bound,json_order_and_escaping_do_not_change_semantics}`; `human_cli::signed_submit_without_stdin_or_tty_sends_only_signed_envelope`; real namespace CLI invocation with UID 8, stdin `/dev/null`, and `setsid` |
| 2. Peer plus enabled stored key; provider identity/ID/expiry | `signed_independent_rejections_have_zero_admission_launch_resolution_and_execution`; `signed_commit_attributes_complete_review_and_replay_is_binding_scoped`; real namespace matrix with independent UID, primary group and supplementary group cases |
| 3. Strict rejection with no admission/UI | Closed-envelope and strict-signature protocol tests; signed independent-rejection side-effect counters; adapter framing/deadline tests; real namespace negative matrix and capacity recovery; signed replay/concurrency/restart/persistence/race tests |
| 4. Complete attributed human context; redacted agent acknowledgment | `signed_commit_attributes_complete_review_and_replay_is_binding_scoped`; Firefox `signedAgentAdmission`, `signedAgentCompleteReview`, `signedAgentCapabilityIsolation`; closed-response and CLI diagnostic tests |

## Frozen matrix mapping

| Matrix row | Tests exercising the expected behavior |
|---|---|
| Valid submission | `signed_commit_attributes_complete_review_and_replay_is_binding_scoped`, real Linux namespace CLI, Firefox signed review |
| Invalid authority/input | `signed_independent_rejections_have_zero_admission_launch_resolution_and_execution`, `closed_envelope_rejects_ambiguous_missing_and_noncanonical_input`, real peer matrix |
| Replay/concurrency | `signed_concurrent_duplicate_commits_at_most_once_and_retry_is_replay`, `signed_replay_survives_lock_restart_and_terminal_transition`, `signed_restart_expires_pending_and_preserves_replay_evidence_without_prior_lock` |
| Authority race | `signed_revocation_intent_during_verification_prevents_commit_and_ui`, `signed_lock_intent_before_commit_cannot_admit_under_the_old_session`, `signed_deadlines_are_rechecked_at_guarded_snapshot_rename`, `signed_authority_loss_after_commit_retains_one_tombstone_without_stale_ui` |
| Transport failure | `frames_require_single_lf_and_eof_and_bound_total_size`, `partial_frames_work_but_slow_input_cannot_reset_deadline`, `already_expired_deadline_rejects_even_ready_complete_input`, `blocked_response_writer_has_a_five_second_deadline`, real namespace capacity saturation/recovery |

## Verification results

All required automated checks and campaigns completed on the reviewed implementation.
The [machine-readable summary](2-2-evidence-summary.json) records exact argv,
exit codes, durations and mutant failures. The [full evidence archive](2-2-evidence.tar.gz)
contains 186 files, including raw logs, source hashes, mutant diffs, classified
failures, runners, review triage and equivalent-mutant proof. Its SHA-256 is
`de5270fa03d5b91ad239e421078053d0520569a8e5a90b883bdb29dfae7060cf`. Earlier failed attempts and successful reruns remain archived.

| Check | Result | Duration |
|---|---|---|
| `cargo fmt --all -- --check` | exit 0 | 2.02 s |
| CI YAML, new job shell syntax and required dependency edges | pass; hosted CI not executed | 0.52 s |
| Secure wrapper + `cargo test --all-targets --offline --locked` | 915 reported passed, 0 failed, 14 ignored; 13 benchmark smoke successes | 255.80 s |
| Secure wrapper + `cargo +1.88.0 test --all-targets --offline --locked` | 915 reported passed, 0 failed, 14 ignored; 13 benchmark smoke successes | 315.97 s |
| `cargo clippy --all-targets --all-features --offline --locked -- -D warnings` | exit 0 | 16.63 s |
| Explicit mapped-namespace `agent_submission` harness | 1 passed; actual UID/primary/supplementary groups, capacity, stdin-closed CLI, traversal-only paths and client authentication failures | 3.68 s |
| Secure wrapper + `--test human_cli --test direct_request --test provider_session` | 16 passed, 0 failed, 0 ignored | 8.90 s |
| Secure wrapper + `node tests/ui/direct-request.mjs` | Firefox 151.0.2; trusted TLS; all signed checks true; axe 0 violations / 24 passes; 0 unexpected diagnostics | 68.78 s |
| Secure wrapper + `scripts/test-systemd-supervisor.sh` | 2 passed, 0 failed, 0 ignored; 30 real-manager scenarios | 74.98 s |
| `git diff --check` | exit 0 | 0.27 s |
| Post-mutations: Fresh unmutated `cargo build --bins --offline --locked` | exit 0; production binaries restored after mutations | 14.38 s |
| Post-mutations: Fresh unmutated protocol tests | 8 passed, 0 failed | 64.90 s |
| Post-mutations: Fresh unmutated `signed_` filter tests | 15 passed, 0 failed | 5.19 s |
| Post-mutations: Fresh unmutated Unix-socket tests | 14 passed, 0 failed | 5.28 s |
| Post-mutations: `cargo fmt --all -- --check` | exit 0 | 3.33 s |
| Post-mutations: `git diff --check` | exit 0 | 0.27 s |

The complete suite includes 8 protocol tests, 14 Unix-socket tests and 11 binding
registry tests, plus signed admission and existing revocation/approval coverage.
Both full suites ran after the final code changes. Of the 915 reported passes,
71 live-Vaultwarden tests return early without a configured backend: **844 other
reported tests execute**, plus the explicit environment harnesses above. The 14
ignored entries are 9 subprocess fixtures invoked by passing parent tests, the
Firefox fixture, the real-manager provider fixture, the namespace fixture, and
2 systemd tests. Required environment harnesses were explicitly executed.

The real peer invocation was:

```sh
VW_AGENT_NAMESPACE=1 unshare --user --map-auto --map-root-user --fork \
  cargo test --offline --locked --test agent_submission \
  real_linux_peer_matrix_and_noninteractive_cli -- --ignored --exact --nocapture
```

The harness uses mapped provider UID 0 and distinct agent/wrong UIDs 8/10, socket
access GID 7 and required binding GID 9. It independently tests primary-only and
supplementary-only required membership. Kernel UID/GID-map checks reject execution
as initial-namespace root. CI now provisions and invokes this harness in a required
Linux job. This evidence records its syntax check and local invocation; hosted CI
results are tracked separately on the pull request.

Earlier pre-review attempts retained in the archive include a browser assertion
that expected truncated status text, and a systemd invocation missing its required
TMPDIR wrapper. Both were corrected and rerun successfully before review. All
post-review checks passed on their first recorded attempts. Browser diagnostics
contain only the fixture's allowlisted cross-origin/blocked-favicon messages;
protected-input sentinels and unexpected diagnostics are checked.

## Workflow review

Three independent layers completed: blind hunter, edge-case hunter and verification
gap reviewer. All 13 findings were individually triaged before grouping. Twelve
findings were fixed (two identified the same masked size-limit test); one existing
storage-growth issue was deferred and recorded in the deferred-work ledger under this spec’s path.
The archive includes the full triage table.

Fixes cover traversal-only directory access; recoverable precommit cancellation;
linear framing scans; independent client size/owner/kernel-UID/inode tests; remote
CLI rejection/no-retry evidence; safe namespace preconditions; TLS option dependencies;
accurate socket-path/seed trust documentation; and required real-peer CI execution.
The deterministic expiry test now proves admission remains usable and the same
unconsumed nonce succeeds after renewing authority when needed. Partial-frame tests
synchronize on actual consumption rather than relying on timing sleeps.

The deferred issue is existing full-snapshot history growth: connection/task bounds
do not limit lifetime disk usage. Quotas or compaction need a separate design that
preserves audit retention and consumed-nonce tombstones. No meaningful mutation
survivor or unresolved implementation review defect remains.

## Mutation classification

The campaigns completed **39 mutation executions: 38 caught, 1 equivalent,
0 meaningful survivors, 0 unviable, 0 timeouts, 0 infrastructure failures**.
These represent 35 distinct mutations; four admission mutations were rerun after review.

- **Semantic campaign: 19/19 caught.** Omitted purpose, nonce, revision, argument
  count and signing domain; ordinary or missing signature verification; removed
  UID/group/enabled/selector checks; replay lookup/persistence removal; stale-policy
  and argument-check removal; request persistence removal; and commit epoch,
  session-deadline and request-deadline removal. Each caught classification is an
  actual failing test result, with exact failing test names in the classified ledger.
- **Generated cargo-mutants campaign: 9 tested, 8 caught, 1 equivalent.** Scope:
  `src/access/protocol.rs`, functions `SignedSubmission::{signing_bytes,verify,replay_digest}`.
  Raw cargo-mutants exit is **2**, reporting one missed mutant. That survivor changes
  `(high << 4) | low` to `(high << 4) ^ low`. `validate()` restricts revision bytes
  to lowercase hexadecimal; both decoded nibbles are 0–15, so their bits are
  disjoint. The archived `hex-equivalence.py` exhausts all **256** valid pairs,
  asserts disjointness and identical OR/XOR/hex-decoding results, and passes.
  This is an equivalent mutant, not an uncaught security defect.
- Unmodified baselines passed for every test selection. The generated baseline
  was forced to rebuild by refreshing copied source mtimes. Mutations ran
  sequentially in disposable copies; byte hashes prove source restoration and
  equality to the unchanged worktree. A fresh unmutated worktree rebuild and
  focused checks passed after the campaigns, preventing reuse of a cached mutated binary.
- Audit corrections made before campaigns: isolate session expiry from request
  expiry; independently re-sign the unknown-selector negative case; and include
  a strict-verification witness that ordinary dalek verification accepts.
  The final semantic mutations independently catch both deadline guards and the
  strict-versus-ordinary verifier change.

- **Post-review semantic campaign: 11/11 caught.** Reran commit epoch, both
  deadlines and request persistence; added client frame/inode/peer UID/socket-owner
  guard removal, traversal-only regression, fatal-expiry regression, and forgotten
  LF state. Baselines passed for signed, socket and real namespace selections.
  The owner and peer UID mutations fail the independent no-connection/no-payload
  assertions; the partial-frame mutation fails the deterministic LF test.
- All 95 copied files match the restored mutation copy and worktree byte hashes.
  Protocol implementation and protocol tests are byte-identical to the generated
  campaign's source, so its scoped classification remains applicable. Final
  production binaries were rebuilt unmutated; protocol, signed and socket checks
  then passed. Exact failure test names and restoration proofs are archived.

## Limits and checks not run

- Live Vaultwarden tests without a configured backend return early; they are not
  claimed as executed behavior. Synthetic keys, clocks and backend are deliberate.
- Hosted GitHub CI is not included in this local evidence. Its new job
  configuration parses and its namespace test command passed locally on Linux;
  hosted results are tracked separately on the pull request.
- The Firefox fixture exercises production signed core admission and the real
  human launcher/UI. The namespace integration independently exercises actual
  kernel credentials and the production socket/CLI. This is not one live-backend,
  cross-UID browser deployment. Manual screen-reader behavior was not validated.
- Filesystem or desktop stalls can outlast network deadlines and delay shutdown;
  retained permits bound outstanding jobs. History/replay storage has no pruning
  or quota. The configured socket path must be human-provisioned under ancestors
  untrusted users cannot replace; the client derives expected UID from its owner.
- A lost acknowledgment does not roll back admission; the client does not retry
  automatically. Re-running the CLI generates a new nonce and can create another
  request. Signed polling/waiting remains Story 2.3.

Every frozen matrix row has an executed passing witness. No required automated
check remains blocked or running. The implementation and evidence are approved
for publication as a pull request.
