# Story 2.1 verification

Status: implementation, all three workflow reviews and post-review verification complete.
The user approved publication by requesting a PR on 2026-10-05.

## Scope and decisions

The worktree is `vaultwarden-pair-revoke-agent`, branch
`feature/pair-and-revoke-restricted-agent-identity`, based on updated main
`0ea6c996c2b1c3e5cef9e280667f884e0753e53b`. All Epic 1 implementation PRs
are merged; [planning evidence](2-1-planning-notes.md) records their ancestry.

“Fingerprint/metadata only” excludes agent private keys. Private provider storage
retains the validated Ed25519 public verification material needed by Story 2.2.
Fingerprints are derived from those bytes. Views and administrative audit contain
identity metadata only. Every used key remains reserved; reusing a revoked label
requires a fresh key and immutable binding ID. Revocation retries target that ID.

Signed request transport, kernel peer admission enforcement and agent polling
transport remain Stories 2.2/2.3. This story supplies internal production checks;
synthetic admission exists only under `cfg(test)`. Tests do not create host accounts
or inspect production Vaultwarden data.

## Acceptance and edge-case coverage

`A::` below means `access::agent_binding_tests::`; `D::` means
`access::direct_request_tests::`. Every named test ran and passed in the final all-targets output.

| Acceptance / matrix row | Executed-test obligations |
|---|---|
| Valid explicit pairing; safe listing/audit | `A::bindings_have_random_ids_derived_fingerprints_and_closed_safe_views`; `D::agent_administration_checks_human_authority_even_while_locked_and_retains_tombstones`; socket and CLI tests below |
| Malformed/weak/noncanonical keys | `A::key_codec_rejects_encoding_length_invalid_points_weak_and_noncanonical_points` |
| Label/UID/GID validation; same provider UID | `A::pairing_rejects_each_invalid_label_and_os_identity_independently`; CLI parser test |
| Duplicate labels, keys and immutable IDs | `A::registry_enforces_unique_ids_keys_enabled_labels_and_immutable_audit`; `A::duplicate_binding_id_is_rejected_independently_of_key_label_and_audit_checks`; `A::stored_binding_ids_require_canonical_32_byte_values`; `A::revoked_label_needs_fresh_key_and_id_and_retains_both_audit_events` |
| No defaults, restart and narrow legacy migration | `A::store_round_trips_revoked_tombstones_and_audit_on_repeated_restart`; `A::schema_migration_is_narrow_closed_and_repeatable`; locked socket test |
| Human-only administration, independently rechecked | `D::agent_provider_administration_revalidates_human_independently_of_application`; `D::agent_administration_checks_human_authority_even_while_locked_and_retains_tombstones`; existing socket peer-credential guards |
| Enabled/revoked, exact UID and required group | `A::os_match_requires_enabled_exact_uid_and_required_membership`; `D::agent_provider_rechecks_revocation_without_application_tokens`; `D::agent_os_lookup_and_exact_poll_ownership_reject_each_independent_mismatch` |
| Unsafe storage after warm lookup and corruption after restart | `D::agent_warmed_authority_revalidates_actual_unsafe_storage_for_each_entrypoint`; `A::durable_binding_registry_corruption_rejects_warmed_reads_and_restart_independently`; existing store owner/mode/type tests |
| Pre/post-rename persistence failure and uncertain reads | `D::agent_pair_and_revoke_persistence_failures_close_admission_and_preserve_denial`; `D::agent_durable_read_failure_closes_otherwise_valid_poll_authority` |
| Only revoked agent's unexecuted work invalidated | `D::agent_revoke_invalidates_only_unclaimed_owned_work_and_preserves_attribution`; `D::agent_revoke_targets_requested_id_when_another_binding_precedes_it` |
| Running work and repeated revoke wait for confirmed cleanup | `D::agent_running_revoke_and_retry_wait_for_confirmed_scoped_cleanup`; real-systemd `app-agent-revoke` scenario |
| Supervisor uncertainty cannot report termination | `D::agent_running_revoke_rejects_uncertain_and_impossible_not_started_cleanup`; `D::agent_cleanup_timeout_keeps_running_nonterminal_until_confirmed_reaping` |
| Concurrent admission and durable transaction | `D::agent_revocation_during_admission_denies_before_persistence_without_harming_other_agent`; `D::agent_persistence_racing_revoke_serializes_admission_then_expires_exact_binding` |
| Concurrent claimed preparation and final launch | `D::agent_request_preparation_rejects_published_intent_before_durable_revoke`; `D::agent_revocation_intent_fences_backend_continuation_before_gate_is_available`; `D::agent_revoke_before_final_release_never_starts_and_waits_for_unstarted_claim_cleanup` |
| Re-pair and restart never revive old authority | `D::agent_revocation_persists_across_restart_without_rewriting_old_owners`; `D::agent_same_label_and_os_replacement_retains_running_work_during_old_id_retry` |
| Immutable request seals/history and clear human review | `D::agent_request_seals_and_legacy_migration_cannot_rewrite_attribution`; `D::agent_review_distinguishes_a_label_that_matches_human_presentation` |

Transport tests are
`adapters::human_socket::tests::locked_socket_agent_administration_is_closed_redacted_and_durable`,
`tests/human_cli.rs::agent_commands_send_exact_identity_fields_and_print_only_safe_views`,
and `tests/human_cli.rs::agent_parser_failures_are_redacted_and_help_describes_identity_not_authority`.

The shared agent helper deliberately gives different bindings the same UID/GID,
so OS identity cannot mask missing binding-ID ownership. Storage failures use
independent fresh fixtures for each shape and entry point. Corrupt-registry tests
preserve otherwise matching audit metadata and omit requests when testing registry
validation, preventing another failure from masking the guard under test.

## Execution record

Evidence is under [2-1-evidence](2-1-evidence/). Each verification phase records
commands, exit codes, durations and source hashes. Mutation runs retain patches,
logs, classifications and restoration evidence.

- Initial core verification passed before the parent strengthened the tests.
- `systemd-first`: the new real scenario failed before its observation marker.
  Its synthetic service journal identified a rejected request submission. The
  harness prepared its second request while the first supervisor was running;
  admission uses an intentional nonblocking authority check. The corrected harness
  prepares both requests before launching either one.
- `systemd-second`: compilation reached the 360-second budget before running tests;
  exit 124 is an infrastructure timeout, not a test failure or mutation detection.
- `systemd-third`: all 30 focused agent tests passed, and the isolated real-systemd
  selective-revocation scenario passed. The independent integration process saw
  the revoked agent's empty cgroup and the unaffected agent's active populated
  cgroup before permitting cleanup of the second workload.

All three workflow review layers completed. The parent triaged every finding
before grouping; the original implementation agent applied the accepted local
patches. See [individual review triage and limitations](2-1-review.md).
The gate/I/O latency finding is pre-existing and recorded as deferred work.

## Scoped mutation results

The campaigns tested 105 distinct mutations: **103 caught, 2 unviable, 0 surviving
viable mutants, 0 equivalent exclusions, 0 mutation timeouts**. The generated
campaign reran its five initial survivors after strengthening tests; these reruns
are not counted as five additional distinct mutations.

- 26 initial semantic mutations, 5 additional semantic mutations and 6 review regression mutations were caught.
  Each exact test first passed unmodified. Every mutant exited 101 with a failing
  test, and source restoration was checked. The running-scope mutation failed the
  bounded completion watchdog because revoking A incorrectly waited for B's held
  workload; this is a liveness assertion, not a cargo-mutants timeout.
- 68 generated mutants: initially 61 caught, 5 missed, 2 unviable. All five missed
  mutants were then caught by added tests. The final classification is 66 caught
  and 2 unviable. See [per-mutant classifications](2-1-evidence/generated-classifications.json),
  [initial semantic results](2-1-evidence/semantic/results.json), and
  [additional semantic results](2-1-evidence/semantic-followup/results.json).
- The two unviable generated replacements use `Ok(Default::default())` for
  `Provider::agent_binding_for_peer` and `Provider::agent_status`. Their build logs
  report E0277: `AgentOwner` and `DirectStatus`, respectively, do not implement
  `Default`. These are excluded from detected-mutation counts, not treated as
  equivalent or caught.

| Initially surviving mutation | Added independent oracle; follow-up result |
|---|---|
| Stored binding ID length/canonical guard `\|\|` → `&&` | Canonical 31- and 33-byte IDs are rejected; caught |
| Cleanup postcondition `\|\|` → `&&` | Hold cleanup through the actual 20-second wait; require error, closed admission and nonterminal Running until Reaped; caught |
| `request_agent_live` → `Ok(())` | Hold revocation after intent publication but before durable invalidation; approval preparation must reject A and admit B; caught |
| `agent_current` → `true` | Claimed Approved request retains its status after direct provider revocation, but execution and admission checks reject it; caught |
| `agent_current` exact-owner/enabled `&&` → `\|\|` | Same direct provider check, independent of application tokens and status invalidation; caught |

Scope covers key/OS/label/ID validation, registry uniqueness and immutable audit,
legacy schema, durable reads and writes, independent human authority, binding and
poll ownership, retained historical owners, revocation publication, exact target
selection, selective invalidation/cancellation, persistence failure closure,
cleanup waiting and Running-to-terminal evidence. The mutation runners record
commands and hashes; patches and compressed logs are retained alongside results.
An earlier generated campaign was intentionally interrupted because it rebuilt all test targets per mutant.
One duplicate mutant completed as caught before interruption. Its baseline and
partial output are retained under `generated/`; the interrupted campaign contributes
no additional distinct mutation result.

After mutation testing, strict Clippy required naming intentionally discarded
`map_err` parameters and replacing forbidden `unreachable!` macros in test fixtures
with explicit fixture panics. The three production-file changes were reconstructed
from the pre-lint diff and verified identical after parameter-name and whitespace
normalization; see [source equivalence](2-1-evidence/lint-source-equivalence.json).
No authorization, persistence or cleanup decision changed. Strict all-target,
all-feature Clippy subsequently passed with `-D warnings` (33.65 seconds).

The opt-in live Vaultwarden suite has no configured service URL or admin token.
Its environment-gated tests return early and are not evidence of live Vaultwarden
integration. Story 2.1 uses synthetic provider identities and the real local
Linux/systemd supervisor. The final Firefox harness is an automated browser check,
not a manual screen-reader exercise. No production account or vault was inspected.

The first final Firefox run exposed a valid base64url request ID beginning with
`-` being parsed as a CLI option. The same issue affected new agent binding IDs
and public-key values. The CLI now explicitly permits leading hyphens for these
three argument paths. The real-process wire test deterministically covers all
three; the administration integration suite and strict Clippy passed afterward.
The browser and complete all-targets reruns are recorded separately below.


## Pre-review verification results

All commands below exited 0 and completed before workflow review. Tests used the
secure temporary-directory wrapper outside the ownership-remapping sandbox, with
`RUST_TEST_THREADS=4`, `CARGO_BUILD_JOBS=2` and offline locked Cargo dependencies.

| Check | Exact result | Duration |
|---|---|---|
| Formatting, final source | `cargo fmt --all -- --check`, passed | 3.18 s |
| Complete suite, final source | `cargo test --all-targets --offline --locked`: 874 reported passed, 0 failed, 13 ignored; 13 benchmark smoke successes | 245.48 s |
| Strict lint, final source | `cargo clippy --all-targets --all-features --offline --locked -- -D warnings`, passed | 2.32 s |
| Agent authorization/lifecycle | `cargo test --offline --locked --lib agent_`: 35 passed | 21.50 s |
| Persistence | `cargo test --offline --locked --lib provider_store::`: 13 passed | 1.17 s |
| Human administration integrations, final source | `cargo test --offline --locked --test human_cli --test direct_request --test provider_session`: 14 passed | 11.71 s |
| Real Linux/systemd | `scripts/test-systemd-supervisor.sh`: 2 integration tests passed, covering all 30 manager scenarios and panic cleanup | 87.61 s |
| Firefox | `node tests/ui/direct-request.mjs`: Firefox 151.0.2, trusted TLS; 0 axe violations, 24 axe passes; 0 unexpected diagnostics | 71.55 s |
| Whitespace | `git diff --check`, passed; untracked text has no trailing whitespace | 0.22 s |

The 874 Cargo-reported passes include 71 environment-gated live Vaultwarden tests
that returned early: 803 other tests executed successfully. The 13 default ignores
are specialized harness entry points: nine are invoked by passing isolated parent
tests, and the remaining browser/systemd entry points were run explicitly above.
The Rust 1.88 MSRV check is defined in the verification runner but was not run;
MSRV compatibility remains **unverified**. The executed all-targets evidence uses
stable Rust 1.98. Live Vaultwarden, cross-platform execution and manual
screen-reader testing are not claimed.

The final [matrix audit](2-1-evidence/final-cli/matrix-audit.json) confirms 36 named
covering-test entries passed. Exact commands, exits, timings and source manifests
are in [final suite results](2-1-evidence/final-cli/results.json),
[focused/systemd results](2-1-evidence/final/results.json), and
[CLI/browser results](2-1-evidence/cli-fix/results.json). The earlier browser failure
is retained rather than overwritten. Only the CLI parser and its subprocess test
changed after the real-systemd run; [retained supervisor evidence](2-1-evidence/retained-supervisor-proof.json)
confirms provider, storage, authorization and supervisor source hashes are unchanged.


## Review regression evidence

The four new Rust tests passed in focused checks and are included in the complete
post-review rerun:

- `access::application::tests::pair_agent_rechecks_closed_admission_after_waiting_for_gate`
- `access::application::tests::pair_agent_rechecks_closed_admission_before_token_publication`
- `access::application::tests::agent_status_refreshes_request_and_session_expiry_at_exact_deadlines`
- `adapters::human_socket::tests::agent_revoke_exchange_waits_beyond_the_ordinary_response_timeout`

The CLI wire test now uses a leading-hyphen label as well as a leading-hyphen key
and ID. Pairing closure tests use deterministic gate/write barriers; expiry tests
check Pending and Approved work at exact request and session deadlines. The socket
test returns a valid revoked binding after 11 seconds, beyond the former 10-second
response budget.

All six new mutation probes were caught: each pairing closure guard, each polling
expiry refresh, label parsing, and the revoke response budget. Every selected test
passed before mutation, every mutant failed its test with exit 101, and restoration
was hash-checked. See [review mutations](2-1-evidence/review-mutations/results.json).
The earlier 99 mutation decisions are unchanged: whole-file hashes match for key,
binding, provider, request ownership and storage code; the previously mutated
application methods match their reviewed source exactly. See
[retention and restoration proof](2-1-evidence/review-mutation-retention.json).

`python3 docs/implementation/2-1-evidence/runner-tests.py -v` passed 2 tests
(6.396 seconds). They verify whole-group timeout termination, immediate-child
reaping, source restoration, preserved outcome classifications and nonzero campaign
exit for each unresolved classification. Review-focused Rust checks are retained
in [focused results](2-1-evidence/review-fixes-focused/results.json).


## Final post-review verification

All required checks finished; all commands exited 0. The source manifest remained
unchanged throughout the complete sequence. Exact commands and durations are in
[post-review results](2-1-evidence/post-review/results.json).

| Check | Final result | Duration |
|---|---|---|
| `cargo fmt --all -- --check` | Passed | 0.92 s |
| `cargo test --all-targets --offline --locked` | 878 reported passes, 0 failed, 13 intentional harness ignores; 13 benchmark successes | 272.06 s |
| All-target/all-feature Clippy, `-D warnings` | Passed | 17.59 s |
| Agent authorization and lifecycle | 39 passed | 21.96 s |
| Provider persistence | 13 passed | 1.17 s |
| Human CLI/request/session integration | 14 passed | 8.85 s |
| Real Linux/systemd supervisor | 2 integration tests passed; all 30 scenarios and panic cleanup | 86.46 s |
| `cargo build --offline --locked --bin vw-access` | Passed | 2.83 s |
| Firefox 151.0.2 | Trusted TLS; 0 axe violations, 24 passes; 0 unexpected diagnostics | 70.49 s |
| `git diff --check` | Passed | 0.27 s |

The complete-suite count includes 71 live-service tests that returned early because
no Vaultwarden URL/admin token is configured: **807 tests executed successfully**.
The 13 default ignores are specialized harness entry points, covered by isolated
parent tests or the explicit systemd/browser runs. The final
[matrix audit](2-1-evidence/post-review/matrix-audit.json) confirms 40 named
covering-test entries passed. The suite and all focused checks have finished;
there are no active verification jobs and no required Story 2.1 check remains unrun.

All acceptance areas are covered: validated explicit human pairing; safe durable
storage and no defaults; redacted listing/audit and historical ownership; exact
OS/binding admission and polling checks; selective invalidation and confirmed
running-work cleanup; concurrency, retries, restart, fresh-key re-pairing and
fail-closed storage/supervisor failures. Public verification material is retained;
agent private keys are never requested or stored.

Final scoped mutation total: **105 distinct, 103 caught, 2 unviable, 0 viable
survivors, 0 equivalent exclusions, 0 mutation timeouts**. The two unviable results
are the documented E0277 replacements; every additional review mutation was caught.

Known limits: stable Rust 1.98 was tested, not Rust 1.88; live Vaultwarden,
cross-platform and manual screen-reader checks are not claimed. Listing is capped
by the existing 2 MiB response frame and has no pagination. Tombstones and runtime
ownership metadata are retained. The existing synchronous lifecycle gate/storage
wait can exceed the client timeout before the 20-second cleanup budget begins;
revocation denial is already published, and cleanup success is never invented.
That shared latency issue is deferred, with all review dispositions in
[the review report](2-1-review.md).

The user approved publication of the completed implementation and evidence on
2026-10-05 by requesting a PR. The recorded test-source manifest is unchanged.

Publication check: `scripts/scan-staged-secrets.sh` exited 1 for three verified
false positives in application.rs (lines 518, 614 and 1174). Each match calls
`agent_token`, returning an in-memory `Option<Arc<AtomicBool>>` revocation flag;
none contains a credential literal. The tested source was preserved unchanged.
See [scan disposition](2-1-evidence/publication-scan.json).
