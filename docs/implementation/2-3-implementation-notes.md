# Story 2.3 implementation and acceptance map

Implementation is local and uncommitted. All three workflow reviews, their patches,
final full verification and 36-case mutation checks have passed; see the
[exact final-source evidence](2-3-verification.md). Historical handoffs below
and in the archive retain their original scope. Completed-implementation human
approval is pending; commit, push and PR remain unauthorized.

## Changed behavior

- `protocol.rs` adds signed status queries, canonical purpose-separated signing,
  strict envelope dispatch and closed agent lifecycle/failure projections.
- Provider persistence stores validated query nonce digests separately from
  immutable requests/audits. Submission and status consult both marker sets.
- Application observation rechecks current key/OS binding and immutable ownership,
  uses guarded persistence and serializes final disclosure against revocation, and refreshes
  provider lifecycle clocks around potentially slow persistence/snapshot reads.
- The existing socket dispatches both actions through the same bounded peer-gated
  JSONL/EOF path. Query clients reject mismatched IDs and unexpected response kinds.
- `vw-access` adds `poll`, `wait`, and `submit --wait`, stable control exits, separate
  local-error JSON, changed-state emission, fresh-query Busy retry, absolute
  deadlines, prearmed signal handling and immediate receipt flushing.

## Acceptance-to-test map

| Requirement | Principal independent witnesses |
| --- | --- |
| Owner observations across all states/failures, terminal persistence and redaction | `signed_status_projects_every_validated_state_without_mutating_terminal_records`; `signed_status_projection_is_closed_and_validates_every_lifecycle`; CLI poll lifecycle matrix |
| Canonical signing, strict Ed25519 and cross-purpose separation | `signed_query_canonical_vector_and_cross_purpose_separation`; `signed_query_binds_every_field_and_uses_strict_verification`; shared dispatcher missing/duplicate/noncanonical tests |
| Inaccessible IDs, current key/peer/owner, no observable side effects | `signed_status_inaccessible_ids_and_authority_rejections_have_no_effects`; `signed_status_stored_enabled_pairing_is_independent_of_application_token`; exact raw namespace rejection comparisons with independently eligible other peer and group-decoy binding |
| Replay across actions, concurrency, restart and failed writes | `signed_status_shared_nonce_replay_precedes_neither_authentication_nor_ownership`; `signed_status_concurrent_identical_queries_consume_once`; `signed_status_failed_persistence_never_discloses_and_retains_post_rename_nonce`; strict marker schema test |
| Revocation intent, existing connection and re-pair ownership | `signed_status_revocation_intent_during_authentication_prevents_marker_and_disclosure`; `signed_query_rechecks_revocation_after_admission_and_partial_frame`; same-label/principal re-pair test; namespace active-wait and connect-before-revoke witnesses |
| Provider expiry and separate request/session clocks | `signed_status_uses_provider_deadlines_even_when_storage_crosses_expiry`, independently varying Pending/Approved, request/session deadlines, before/write/final-read crossings and wall-clock skew |
| Cleanup/reaping precedes terminal completion | `signed_status_running_remains_nonterminal_until_confirmed_cleanup` with explicit channel-controlled cleanup |
| Backoff/cap, exchange/sleep deadlines, terminal exits and Busy retry | `agent_wait` virtual-time tests; real CLI state/Busy/timeout fixtures |
| SIGINT/SIGTERM before acknowledgment and during waiting, reconnect without resubmit | `human_cli` real subprocess signal/disconnect fixtures; namespace timeout, explicit poll resume and exactly-one `submit --wait` request |
| Real kernel identities, stdin closed/no TTY and no secret resolution/extra review | Existing ignored `real_linux_peer_matrix_and_noninteractive_cli`, extended in place so its established explicit invocation still covers Story 2.3 |

The namespace held-connection fixture waits for kernel send-queue consumption of
an innocuous JSON whitespace prefix, then requires a nonblocking response peek to
return WouldBlock before signaling readiness over a pipe. Early rejection writes
its response/EOF before draining input, so this excludes the rejection-drain path. The
signed query remains withheld until revocation completes. It runs separately from
the active-wait revocation phase, so periodic waiting cannot mask an authorization
failure with legitimate Busy. The separate socket unit witness synchronizes on
actual first-chunk consumption with `FRAME_CHUNK_HOOK`. Neither infers admission
from `connect()` alone or uses scheduler sleeps to manufacture ordering.

## Historical iteration 0 focused implementation verification

Core commands used `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=4` and the existing cached
`CARGO_TARGET_DIR=/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/target`,
with `scripts/with-secure-test-tmpdir.sh`, offline locked dependencies and escalation
for the real HOME test directory. Raw historical core output remains in the worker
transcript; it was not saved as a standalone log.

- Core `--lib signed_`: 29 passed, 0 failed/ignored, 645 filtered (14.08s).
- Protocol `--lib protocol_tests`: 12 passed, 0 failed/ignored, 662 filtered (0.41s).
- Additional isolated stored-enabled query witness: 1 passed, 0 failed/ignored;
  `/tmp/2-3-integration-build.log`. That command also compiled the namespace target,
  but its filter selected zero namespace tests; that is not namespace evidence.
- Wait `--lib agent_wait`: 4 passed, 0 failed/ignored, 674 filtered;
  `/tmp/2-3-cli-agent-wait.log`.
- CLI `--test human_cli`: 15 passed, 0 failed/ignored;
  `/tmp/2-3-cli-human-cli.log`.
- Socket `--lib unix_socket`: 16 passed, 0 failed/ignored, 665 filtered (5.00s);
  `/tmp/2-3-socket-focused.log`.

An initial core signed run had 28 passes and one test-fixture failure: its reused
supervisor independently polled the authority gate, so the intended Running
observation correctly returned Busy. The fixture was replaced with deterministic
channel-controlled cleanup; the rerun passed 29/29. Production wait explicitly
retries Busy using fresh queries. An initial un-escalated CLI secure-wrapper run
exited 2 before Cargo because sandbox ancestry metadata was unsafe; the escalated
wrapper runs passed. The refusal is retained in
`/tmp/2-3-cli-wrapper-sandbox-failure.log`. No HOME override was used. The initial expanded namespace run also exposed fixture
contention: its held connection received Busy while a separate active waiter held
the authority gate. The phases were separated and admission synchronized; the next
run passed 1/1 (8.93s). The final strengthened run with nonblocking response-peek passed 1/1, zero
failed/ignored, one filtered (10.15s); raw output is
`/tmp/2-3-namespace-final.log`. Initial and intermediate output remains in
`/tmp/2-3-namespace-focused.log` and `/tmp/2-3-namespace-rerun.log`.

These focused results precede the final acceptance campaign. Mutation results,
source restoration hashes, final all-targets/MSRV/Clippy/systemd counts, ignored
and early-return scope, review findings and unavailable evidence belong to the
final verification record, not inferred from this implementation summary.

## Deliberate limitations

Every successful observation permanently adds a nonce digest and rewrites the
full provider snapshot. No quotas, eviction or compaction are implemented. Lost
submission acknowledgments can leave no known ID; no discovery or automatic retry
is provided. Client deadlines and interruptions do not cancel or change provider
work. Synthetic fixtures do not imply live Vaultwarden/browser/manual accessibility
acceptance or hosted CI. Human command behavior remains under its existing tests.


## Iteration 1 corrections and regression witnesses

- Output is asynchronous at the waiter boundary. Dedicated descriptor-owning OS
  threads avoid blocking the current-thread runtime, global stdout lock, or runtime
  shutdown. Awaited receipt flushing still precedes the first query. Best-effort
  stderr delivery waits at most 50 ms before detaching its worker.
- `observe` is the production submission/receipt/observation composition boundary.
  `submission_receipt_and_observation_share_one_deadline` delays acknowledgment by
  700 ms under virtual time and independently stalls receipt or the first query;
  both expire at the original one-second deadline and preserve the accepted ID.
- `agent_wait_full_stdout_and_stderr_preserve_timeout_and_signal_exits` fills real
  pipes and waits for the kernel's pipe-write wait state before signaling. It covers
  receipt and state output, timeout/SIGINT/SIGTERM, normal and blocked stderr,
  retained ID and no subsequent query/submission. No scheduler delay establishes
  this ordering. The process must exit within two seconds of the established block.
- `signed_status_revocation_intent_is_published_during_blocked_query_write` blocks
  persistence before and after rename, requires independently published revocation
  intent before releasing the write, and checks withheld disclosure and durable
  replay evidence. Post-rename uncertainty preserves existing fail-closed behavior.
- Canonical binding selectors are rejected before key access with usage exit 2.
  Documentation explicitly excludes old-reader/new-snapshot downgrade compatibility
  and records the existing synchronous-filesystem deadline limitation.
- Shared CLI fixture helpers bound accepts, pipe reads, worker joins and process
  completion. Owned-child Drop kills and reaps on failure. Missing connections or
  omitted observations fail within a finite fixture budget rather than blocking the
  suite. Namespace pipe reads and child waits use the same helpers.

Focused iteration 1 results are recorded by the implementation handoff. Initial
secure-wrapper invocation without escalation refused unsafe sandbox ancestry before
Cargo; the escalated real-HOME wrapper was used without a HOME override. The first
CLI run caught two fixture defects (a noncanonical supposed-valid selector and the
kernel's `anon_pipe_write` spelling); both were corrected before the passing rerun.

### Iteration 1 focused handoff results

All Cargo commands used the shared target cache, two build jobs, four test threads,
`--offline --locked`, and the escalated secure temporary-directory wrapper.

- `cargo test --lib agent_wait`: 6 passed, 0 failed/ignored, 678 filtered.
- `cargo test --test human_cli --test agent_submission`: CLI 17 passed, 0 failed/
  ignored; namespace target guard 1 passed, 1 explicitly ignored. The explicit
  multi-UID harness is reserved for the parent verification campaign.
- `cargo test --lib signed_status`: 13 passed, 0 failed/ignored, 671 filtered.
- `cargo fmt --all -- --check` and `git diff --check`: passed at handoff.

The parent subsequently completed all-targets/MSRV/Clippy, explicit namespace/
systemd and the 33-case mutation campaign on this source. All checks passed; see
[the verification ledger](2-3-verification.md). No commit, push or PR was made.


### Review coverage additions

The output fixture now covers Completed output under full-pipe timeout, SIGINT and
SIGTERM, plus a stdout reader closed after a flushed accepted receipt for both
Running and Completed observations. Positional poll/wait request selectors are
corrupted independently of binding selectors, with an absent key proving usage
validation precedes key access. Protocol rejection cases include duplicate nested
status, exit-code and failure-category fields. Replay coverage permits two enabled
bindings to use the same nonce when each observes its own request. A virtual-time
caller-level query exchange witness consumes four seconds before response reading
and requires expiration at the original five-second exchange deadline.

The Linux blocked-pipe synchronization witness requires readable task `wchan`
symbols through `/proc/<pid>/task/<tid>/wchan`, including `pipe_write` or
`anon_pipe_write`. Kernels or procfs policies that hide these symbols (for example,
returning `0`) cannot establish this fixture's required ordering. Such environments
fail with an explicit dependency diagnostic; an unobserved blocked write is never
skipped or reported as passing coverage.


Review-fix focused verification used the existing target cache, secure real-HOME
wrapper with escalation, offline locked dependencies, two build jobs and four test
threads: `--lib signed_status` passed 13/13 (672 filtered), `--lib unix_socket`
passed 17/17 (668 filtered), and `--test human_cli` passed 18/18. No failures or
ignored tests occurred in these selections. Full verification remains with the
parent orchestrator.

The explicit `--lib protocol_tests` selection also passed 12/12 (673 filtered),
including the nested duplicate-field cases. After adding an independent fixture
failure bound to the exchange witness, its exact-name rerun passed 1/1 (684
filtered). Formatting and diff whitespace checks passed.


### Final parent verification

All review patches are verified. Both stable and Rust 1.88 all-targets runs report
949 passed, zero failed and 14 ignored (71 live-backend early returns; 878 other
tests executed). Strict Clippy, formatting, focused suites, real peer credentials,
30 real-manager scenarios, and all post-mutation restoration checks passed.
All 36 semantic mutants were caught; no survivor or equivalence claim remains.
See the final verification ledger for exact commands, durations and limitations.
