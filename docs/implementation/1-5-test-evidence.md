# Story 1.5 decision verification

Implementation baseline: `041c10837c12a9a8d2b92b36eae5c634856bc9cc` on
`feature/decide-request-exactly-once`. No commit, push, PR, production account or
protected execution is part of this evidence. Verification is complete; the source remains uncommitted for review.

## Behavior and acceptance mapping

| Acceptance condition | Independent executable evidence |
|---|---|
| Fresh authenticated approval, exact durable binding, tokenless status, one audit | `access::direct_request_tests::decision_approval_binds_exactly_and_audits_once_without_client_authority`; expected ID/UID/digests/expiry/epoch/seal are constructed independently of the binding helper |
| Denial without password and immutable history | `decision_denial_is_immutable_without_password_and_restart_preserves_history` |
| Missing, empty, wrong, failed, cancelled and oversized authentication | `decision_missing_empty_wrong_failed_and_cancelled_authentication_grant_nothing`; `decision_generation_and_password_bounds_are_independent_of_other_guards` includes an otherwise-permissive authenticator |
| Approve/approve, approve/deny, expiry, active revision replacement, deletion, lock, lock/unlock, shutdown during authentication | `decision_authentication_releases_authority_and_rechecks_each_intervention`; channel entry/release ensures the competing operation completes before authentication resumes |
| Exact deadline equality and wall-clock rollback | `decision_deadline_equality_wall_changes_and_prepared_binding_changes_are_isolated` tests 309/310/311 with a deadline of 310 |
| Identity, normalized arguments, expiry, record and policy binding changes | Same test recomputes unrelated record seals before attempting stale commit |
| Eligibility becomes false/errors, or slow eligibility crosses request/session deadlines or shutdown | `decision_rechecks_credential_eligibility_and_deadline_after_backend_work` |
| Password verification does not unlock or renew the provider | `decision_does_not_unlock_or_renew_the_existing_provider_session`; `adapters::session::tests::silent_derivation_and_setup_require_supported_authenticated_keys` also verifies immutable setup identity |
| Persistence fails before rename or after rename; deadline crosses each stage | `decision_persistence_failures_and_slow_commit_never_publish_authority`; private `cfg(test)` hooks are not production APIs |
| Session expiry and shutdown during persistence while the request is still live | `decision_session_and_shutdown_during_persistence_are_independent_of_request_expiry`, 3600-second request versus 900-second session, before and after rename |
| 65 lock/unlock generations do not exhaust browser slots; authenticated terminal history survives | `decision_browser_rotation_reuses_a_slot_and_preserves_terminal_review` |
| Current approvals require exact bindings; legacy terminal history remains readable | `decision_current_approved_records_require_an_exact_binding`; `decision_legacy_explanations_preserve_terminal_history_and_never_restore_approval` |
| Restart invalidates Pending/Approved exactly once | `decision_restart_invalidates_pending_and_approved_with_single_expiry_event` |
| All forbidden lifecycle transitions and terminal replays | `decision_transition_matrix_rejects_every_illegal_edge_including_terminal_replays` |
| Missing/wrong cookie, missing/wrong CSRF, Host, Origin, content type, method, cross-session proof, stale cookie/proof/pair | `adapters::loopback_ui::tests::decision_browser_guards_are_isolated_against_eligible_requests`; each negative keeps an eligible request and then proves a valid positive control |
| Post-auth browser guards independent of provider invalidation | `decision_browser_authentication_allows_lock_and_denial_to_finish` rotates cookie, CSRF or browser generation while provider/request remain eligible, in addition to lock/deny races |
| Missing/invalid password wire input and replay never reauthenticates | `decision_browser_authentication_input_is_closed_and_replay_does_not_authenticate` |
| Actual requester IPC and trusted HTTPS decision/status boundaries | `tests/direct_request.rs::human_submission_https_review_expiry_and_independent_negative_cases` approves and denies separate requests through HTTPS and reads tokenless status through real Unix IPC |
| Keyboard approve/deny/cancel, immediate field clearing, truthful confirmation, disabled terminal controls, labels, focus, axe | `tests/ui/direct-request.mjs`, real Firefox with trusted synthetic CA |

## Ordinary checks

Final frozen-source checks passed:

- `cargo fmt --all -- --check`.
- `cargo test --all-targets`: 451 library tests passed, three intentionally ignored;
  all binary/integration/benchmark targets completed successfully. Across 15 suites,
  the harness reported 707 passes: 636 executed non-live tests and 71 live tests
  that returned early without configured account credentials. Thirteen benchmark
  smoke checks succeeded. Full log:
  `1-5-evidence/ordinary/all-targets.log`.
- `cargo clippy --all-targets --all-features -- -D warnings`:
  `1-5-evidence/ordinary/clippy.log`.
- `VW_UI_DEPS=/tmp/vw-story14-browser/node_modules LD_LIBRARY_PATH=/tmp/vw-story13-nss/extracted/usr/lib/x86_64-linux-gnu node tests/ui/direct-request.mjs`:
  `1-5-evidence/ordinary/browser.log`, Firefox 151.0.2, trusted TLS, zero axe
  violations, keyboard approve/deny/cancel, cleared password, rejected replay,
  and terminal inspection after lock. The harness builds its application target.

The initial sandboxed library attempt could not bind synthetic Unix/TCP sockets;
its socket/keyring-lock follow-on failures are environment failures, not security
evidence. The same tests were rerun with local socket permission. Two outdated
Story 1.4 assertions and a policy-test fixture change that did not alter its digest
were corrected before the successful complete run.

## Mutation provenance and scope

The generated inventory is `/tmp/story15-mutation-campaign/inventory.json` with
230 mutants. Selection expands every changed production function to its complete
body, includes changed constants, and adds unchanged admission, owner and browser
session guards used by the new flow. Functions without generated mutations are
covered by explicit manual substitutions or ordinary tests. The campaign separates
229 library mutants from one daemon wiring mutant, with exact argv recorded in
JSON and source/test SHA-256 manifests alongside the results.

Two preliminary runs were interrupted before counting any mutant outcomes: one
to strengthen the independent binding oracle and one to correct build invocation
scope. They are retained as setup history, not kills. The corrected command uses
`--cargo-arg=--lib`, `--cap-lints=false`, four disposable workers and bounded
build/test timeouts. Library filters exclude unrelated API/CLI/config/crypto/model/
TOTP modules but retain the access and adapter suites. Binary wiring uses its
applicable real-process integration suite.

Manual counterfactuals run in `/tmp/story15-manual-workspace`, never the live
worktree. Each retains a patch, exact test command and log. The cases cover password
authentication bypass, each exact binding field, omitted persistence, deleted legal
transition enforcement, deleted post-auth browser enforcement, cross-session proof,
and browser-level CSRF/password clearing changes. All 16 initial manual cases were
caught by test assertions, including the two real-Firefox cases; no compiler or
infrastructure failure is counted as a kill. Final results, patches and logs are
in `/tmp/story15-mutation-campaign/final-manual/` and
`closed-audit-manual/`. The additional cases substitute Denied/Expired audit
outcomes and fail the independently constructed complete-event assertions.

The first completed generated outcomes used an earlier snapshot. A final rescope
retains 59 caught cases only where the entire production function is byte-identical
and at least one actual failing test body is byte-identical; 12 unchanged-function
compiler rejections are retained separately. Every other case (159) is rerun against
the final snapshot. `final-scope-map.json` records full-function SHA-256, relative
mutation identity, original outcome/log, and individual failed-test comparisons.
The binary wiring case additionally records the unchanged complete integration
file hash. Seven earlier build-phase timeouts are infrastructure results and are
rerun with a 600-second build budget, never counted as caught. The reconciled final inventory is **230 generated cases: 204 caught, 25
compiler-rejected, and one reviewed equivalent survivor**. There are no unresolved
survivors, timeout results, or infrastructure failures in the final accounting.
`1-5-evidence/final-results.json` maps every case to its original/fresh result,
whole-function fingerprint, relative identity, exact log/patch, and failing tests.
Every fresh caught result has named failed tests; all 25 compiler rejections retain
a concrete compiler diagnostic in `compiler-rejection-audit.json`.

The sole equivalent case changes deadline-map cleanup from `<` to `<=` in
`ProviderApplication::expire_requests`. Durable expiry runs first and marks the
request Expired with no approval authority. At exact equality the mutation retains
only a terminal request's monotonic deadline entry until a later tick; it cannot
restore Pending/Approved state or any binding. Exact-deadline and session-expiry
assertions still pass. This is recorded separately from caught mutations.

Two audit timestamp constant survivors led to an appended test asserting persisted
lock/restart/failed-launch event timestamps between independent SystemTime reads.
Both were then caught. A second appended test asserts exact denial and provider-clock
expiry events, independent bindings, redaction and immutability. All preexisting test
and production bytes remain unchanged (the previous test file is an exact prefix),
recorded in `test-addition-provenance.json`. `verified-input-sha256.json` and
`verified-source.tar.gz` describe these final test additions.

All 14 serving-loop mutations additionally ran through real HTTPS `direct_request`
and `provider_session` integration tests: 12 caught, two compiler-rejected, no
survivors/timeouts. The library pruning test alone can be masked by launch-artifact
cleanup when an unserved UI is dropped, so no serving-only library survivor is
classified equivalent. Exact argv, test failures and compiler diagnostics are retained.

The final authenticator `||` → `&&` survivor exposed a masked size-bound test:
wrong-key decryption had rejected the oversized input even with the bound removed.
A separately appended test constructs valid encrypted keys for empty, 4096-byte and
4097-byte passwords, first proves derivation succeeds, then checks only the approval
input bound. All five authenticator mutants were rerun and caught by this fixture.
Production and all prior test bytes remain unchanged.

Immutable evidence is retained in `1-5-evidence/`: final inventory/results and
fingerprints are directly readable; `mutation-evidence.tar.gz` contains exact commands,
all original/final outcomes, patches, logs, source snapshots, manual assertion audits,
and setup history. `SHA256SUMS` verifies these artifacts. Earlier interrupted runs,
argument setup mistakes and build timeouts are historical evidence only, never kills.

The explicit request-body `zeroize()` reduces password lifetime by clearing the
raw body before potentially slow authentication. Installed zeroize's Vec
implementation also clears the full allocation capacity at final Zeroizing drop
(via `spare_capacity_mut()`); this change does not claim that drop previously
left the old capacity uncleared.

## Independent review and final refresh

All three workflow review layers completed: blind review, edge-case review and
verification-gap review. The accepted findings were fixed: pre-decision and
in-flight polling cannot restore stale Pending controls; decision feedback persists
separately from lifecycle status; retired tabs explain how to relaunch; cancellation
describes only the local form; externally completed requests restore keyboard focus.
The current provider paths already pair valid transitions with their correct audit
outcome; speculative extra audit-history validation and rare unresolved-fetch
hardening were rejected with reasons in the build spec's per-finding triage log.

The expanded Firefox harness holds two distinct Pending responses across approval,
checks immediate clearing and disabled controls through a Pending poll, scans active
and in-flight forms with axe, discards an actual delivered approval response, and
asserts exactly one outgoing approval. It also exercises persistent rejection and
retired-session guidance, cancellation after external denial, and focus recovery.
Final Firefox output reports zero axe violations and zero unexpected diagnostics;
13 recognized automation/cross-origin/favicon diagnostics were classified separately.

After the patches, formatting, all-targets (707 reported passes: 636 exercised,
71 gated early returns; three subprocess fixtures ignored), strict Clippy, Firefox
and whitespace checks all passed. Source fingerprints match the tested files.
All 32 generated mutations in the changed handler were rerun: 30 caught and two
compiler-rejected, with no survivors. The other 198 cases retain identical complete
production-function bodies, mapped in `post-review-evidence.tar.gz`.

The final total remains **230 generated cases: 204 caught, 25 compiler-rejected,
one equivalent**. There are now **24 distinct manual cases, all caught**: the 16
initial cases plus eight new browser counterfactuals. Two original browser cases
were also rerun and are not double-counted. The new cases remove immediate clearing,
submission-time disabling, Pending-poll disabling, submission invalidation,
completion-time forced refresh, stale-response checks and external focus restoration,
or introduce an automatic approval retry. Every failure was inspected. Two cases
fail the harness's bounded wait assertions for deliberately prevented progress
(lines 166 and 174 of the browser harness); these are expected test failures, not
process/build timeouts. The automatic-retry mutant sends two approvals versus the
required one, and the stale-response mutant renders Pending after Approved.

`post-review-results.json` and `post-review-evidence.tar.gz` retain the refreshed
commands, patches, results, assertions, fingerprints and source snapshot. A missing
benchmark source in the disposable browser workspace initially prevented the clean
baseline from starting; that setup failure is preserved and excluded from results.
The corrected baseline passed before any browser mutation was counted.

## Boundaries and limitations

The request lifetime remains configurable and defaults to five minutes. Execution,
executable verification, paired-agent fingerprints and platform authenticators are
later stories. Direct identity is the kernel-authenticated human UID; no fabricated
agent fingerprint is stored. Historical failed handoffs and other safe legacy
records remain readable; new failed handoffs use Expired plus a closed audit reason.

Synthetic password/session/keyring and TLS fixtures are exercised. Environment-gated
live tests return early when `VAULTWARDEN_LIVE_TEST_URL` and required credentials
are absent; their harness success is not evidence of a live Vaultwarden account.
The ignored synthetic browser fixture is explicitly exercised by the Firefox harness.
Automated axe and keyboard checks are not a manual screen-reader session. Firefox
reported only the already-classified automation cross-origin property warnings and
blocked favicon; unexpected page errors were zero.
