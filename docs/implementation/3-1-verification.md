# Story 3.1 implementation verification

Status: implementation, independent reviews and required local verification complete. The user approved publication by requesting a pull request on 2026-10-06.

## Base and scope

Branch `feature/bind-ssh-key-fixed-operation` starts from updated main at `0c5c1d9a2780132db0c4b313934dbe66716e0851`. All twelve prerequisite implementation PRs in Epics 1–2 are merged ancestors; no dependency branch is required. [Planning evidence](3-1-planning-evidence.md) records the merge hashes, issue discussion and planning-document locations. Issues #6, #12 and #16 remain open despite their merged implementation PRs.

The [policy contract](3-1-policy-contract.md) describes the synthetic JSON shape and its constraints. SSH requires one immutable UUID-bound actual SSH-key item, explicit `ssh` use, a registered verified executable, fixed absolute working directory and a structured host/port/user/resource destination with a pinned SHA256 fingerprint. Generic targets, argument schemas and login credentials must be empty; requests accept no argument values. Unknown members and ambiguous authority are rejected.

Existing login serialization and version-2 digests are preserved. SSH uses a version-3 projection covering the operation ID, complete resolved executable, credential identity/use, directory and every destination/trust field. Labels and descriptions remain display-only under the existing convention. DNS/IP and padded fingerprint forms normalize before persistence and hashing.

The backend defaults to denial and uses a private metadata decoder requiring exact identity, actual numeric type 5, undeleted status and all required SSH field shapes. It consumes encrypted values without retaining/decrypting them; no marker convention is introduced. Approval rechecks eligibility. Both execution entry points reject SSH before preparation, key resolution or launch. The review explanation and approved status explicitly say that SSH execution is unavailable.

## Acceptance and matrix coverage

| Acceptance criterion / matrix row | Executed evidence |
|---|---|
| AC1: valid immutable binding, registered image, fixed directory/target/trust; normalized activation and persistence | `policy::tests::ssh_normalization_revision_review_and_persistence`; `direct_request_tests::ssh_approval_review_history_and_execution_are_secret_free_and_unavailable`; policy/store suites |
| AC1: missing/mutable identity, wrong actual item type, missing/malformed SSH body | `vaultwarden::tests::ssh_metadata_checks_identity_actual_type_body_and_duplicates_without_decryption`; `ssh_backend_fetches_only_exact_metadata_without_key_decryption`; activation eligibility test |
| AC1: missing/malformed directory, destination or trust; independent prefix, encoding and size failures | `policy::tests::ssh_rejects_each_invalid_authority_and_selector_independently` |
| AC2: every prohibited selector category at activation and direct/signed admission; generic argument bypasses | Policy negative matrix; `ssh_caller_selector_wire_members_and_values_are_independently_rejected`; `ssh_signed_admission_rejects_arguments_and_stale_revision_before_review`; real human/agent transport integrations |
| AC3: fixed target and non-secret label/use; no private key or reusable capability | Explicit policy review projection; `ssh_approval_review_history_and_execution_are_secret_free_and_unavailable`; actual Firefox review/history, keyboard-denial and redaction assertions |
| AC4: no generic protected SSH CLI, key export or signing socket | Existing closed CLI/protocol regressions; common execution-authority guard; preparer/resolver/supervisor counters remain zero for approved SSH |
| Equivalent normalized policies hash equally; every authority field is covered | Normalization test, independent `ssh_revision_projection_matches_explicit_v3_contract` golden digest, each individual digest-field mutant |
| Changed credential, destination, directory, executable or trust invalidates requests and approvals | `ssh_each_authority_change_rejects_stale_requests_and_approvals`, with a fresh otherwise-valid fixture for each change |
| Unsupported backend/verifier and ineligible item fail before publication/approval | `unsupported_session_backend_denies_ssh_metadata_without_resolving`; `ssh_verifier_default_denies_eligibility`; `ssh_activation_and_approval_recheck_eligibility_without_publication_or_secrets` |
| Persistence, responses, UI, history/audit and diagnostics omit synthetic secrets/capabilities | Module/transport/browser assertions and [60 successful-log scans](3-1-evidence/log-redaction.json), with no matches for ten sentinels |
| Existing login policy compatibility | Unchanged login golden revision plus complete all-targets, focused integrations and browser login regressions |
| Approved SSH execution attempt remains unavailable | Both preparation and execution guard assertions, terminal `execution_unavailable` history, zero resolution/preparation/launch calls |

Post-review tests additionally cover IPv6 policy persistence and bracketed review, session/request/closing/revocation changes during SSH eligibility, and negative production-backend HTTP responses (including oversized and truncated bodies).

No production inspection API was added for tests. The real backend adapter tests use local synthetic HTTP fixtures with deliberately non-decryptable key-field sentinels; no live vault was inspected.

## Completed final checks

All twenty commands completed against the same source manifest. [Exact commands, durations and suite results](3-1-evidence/post-review-clean/results.json), [source hashes](3-1-evidence/post-review-clean/source-hashes.json) and compressed logs are retained. The runner checks source hashes before and after every command.

| Check | Final result |
|---|---|
| Formatting; strict workspace/all-targets Clippy; `git diff --check` | Passed |
| Default all-targets | 966 reported passed, 0 failed, 14 ignored; 13 benchmark smoke checks passed |
| Rust 1.88.0 all-targets | 966 reported passed, 0 failed, 14 ignored; 13 benchmark smoke checks passed |
| All-features all-targets | 966 reported passed, 0 failed, 14 ignored; 13 benchmark smoke checks passed |
| No-default-features all-targets | 966 reported passed, 0 failed, 14 ignored; 13 benchmark smoke checks passed |
| SSH-focused | 21 passed |
| Policy | 19 passed, 1 ignored subprocess fixture (exercised by its parent test) |
| Provider persistence | 13 passed |
| Vaultwarden backend | 16 passed |
| Human request / session / agent / CLI integrations | 27 passed, 1 ignored mapped-UID fixture |
| Explicit mapped-UID transport | 1 passed; includes SSH admission and rejection |
| CLI build | Passed |
| Firefox 151.0.2 | Passed in 89.50 seconds; SSH review/history, exact label/use, redaction, keyboard denial/approval, unavailable-execution explanations and axe assertions |
| Real systemd supervisor | 2 passed, 0 ignored; real manager crash/fault/recovery and cleanup scenarios |
| Native fixture verification | Passed x86-64 and AArch64 assembly/relocation comparisons and C compilation |
| Documentation, default/all/no-default feature modes | All passed; 0 documentation tests in each mode |

The final post-review run includes five additional Rust tests. Each all-targets count includes 71 live-backend tests that return early without credentials: 895 other reported tests execute. Counts across repeated feature/compiler runs are not distinct-test totals. The 14 ignored entries comprise eleven library fixtures, one mapped-UID fixture and two systemd tests. The relevant browser, mapped-UID and systemd fixtures were explicitly run; isolated child fixtures are also exercised by their parent tests.

No required local Story 3.1 check remains unrun. Runtime verification was Linux x86-64; remote CI, other-OS/ARM runtime jobs and manual screen-reader testing were not run locally. Firefox reports 26 known cross-origin/CSP automation diagnostics and zero unexpected diagnostics, with zero axe violations.

## Mutation evidence

[The scoped mutation report](3-1-evidence/mutations/README.md) records 52 independently executed mutants: 43 killed initially and nine killed after test-only improvements. Final classification: **52 killed, 0 survivors, 0 equivalent claims, 0 unviable, 0 timeouts, 0 infrastructure failures within the campaign**. Every case retains its patch, command, log, result and candidate/restoration hashes.

[Three additional post-review mutants](3-1-evidence/review-mutations/README.md) were killed by the exact production-backend wrong-ID assertion, pending-review explanation assertion, and approved-status browser assertion. This follow-up used separate source and Cargo target directories and hash-verified restoration. Combined final result: **55 killed, 0 unresolved survivors, 0 equivalent claims, 0 unviable, 0 campaign timeouts, 0 infrastructure failures within the campaigns**. The approved-status mutant hit its intended browser assertion deadline; it did not exceed the campaign timeout.

The measured gaps were exact duplicate metadata spelling, verifier default denial, independently malformed fingerprint prefix/base64, constant use/profile fields in the revision format, helper-derived review expectations, and a history substring assertion masked by the operation name. Tests now isolate those conditions. The constant-field omissions were treated as meaningful revision-format regressions and caught with an independent golden projection, not labeled equivalent.

## Verification corrections retained as evidence

The initial strict Clippy attempt found four style violations; all were corrected. Post-review Clippy also caught one forbidden `unreachable!` macro in a new test; it was replaced with the existing test-failure style before the successful full rerun. Historical results remain in [the check ledger](3-1-evidence/checks-summary.json.gz).

The first parent browser attempt found the last UI mutant retained in the shared Cargo test executable even though source restoration hashes were correct. [Diagnostic hashes](3-1-evidence/cache-contamination.json) prove the mismatch. Package-only cache cleanup and a complete rebuild produced [a verified clean executable](3-1-evidence/clean-test-executables.json). Future mutation reproduction must isolate its target directory or clean package artifacts before changing worktrees.

Two subsequent browser runs stopped before SSH assertions when existing login submissions exhausted the fixture's exact-unavailable retry. The ignored fixture was calling `app.status()` every 25 ms without a synthetic clock change, repeatedly validating persisted state while holding admission's mutex. Maintenance now runs only when the clock changes. Production behavior and the original ten-attempt/50 ms retry remain unchanged. Two consecutive Firefox runs then passed (140.09 s and 139.43 s), followed by the passing final full sequence. [Fixture verification](3-1-evidence/fixture-clock-browser/results.json.gz) and all failed development attempts are retained; none is substituted for final acceptance evidence.

## Story 3.2 dependency

SSH resolution, provider-local ephemeral key material, connection-time enforcement of the pinned host trust, contained launch and cleanup remain Story 3.2 work. Story 3.1 establishes, persists and reviews policy authority only. An approved SSH request cannot execute in this version and terminates with the existing redacted execution-unavailable outcome when dispatched.

## Workflow reviews

Three independent context-free reviewers completed: blind hunter, edge-case hunter and verification-gap reviewer. [The triage record](3-1-review.md) assesses all eleven findings individually: six addressed in five small patch groups, five rejected with evidence, none deferred. The edge-case hunter reported no findings. All twenty required final commands were rerun after the patches and passed against unchanged source.

The BMAD implementation spec is marked done. Vaultwarden Story 3.1 is absent from the shared Oriel sprint file, so that unrelated tracking file remains unchanged. The implementation was held uncommitted until the user approved publication by requesting a pull request on 2026-10-06. The reviewed source manifest remains unchanged.
