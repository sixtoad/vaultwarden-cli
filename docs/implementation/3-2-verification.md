# Story 3.2 verification

Baseline: `fcc1bf3bb2977457572383d6da879e8c23a660ee` (merged Story 3.1 PR #31). Branch: `feature/ssh-ephemeral-provider-material`. Verification date: 2026-10-07. All credentials, pins and disclosure sentinels are synthetic. Verification completed before publication. On 2026-10-07, the user requested opening a PR, authorizing the local commit and branch push required for it; merge and deployment remain outside that authorization.

The implementation uses provider-owned request directories, pinned trust and fixed image/arguments, then explicit cleanup after independent process-reap evidence. See [execution contract](3-2-execution-contract.md) and [planning/provenance](3-2-planning-evidence.md). All 20 post-review normal checks passed against unchanged source. [Workflow review](3-2-review.md) findings were triaged and accepted patches were completed before this run.

## Final post-review normal matrix

The runner captures each exact argv, exit status, duration, test-summary counts, timeout flag, source-integrity result and log hash. It stops on any failure or changed source. The completed records and logs are in `3-2-evidence/verification-post-review.tar.gz`; reproduction scripts and check/mutation plans are in `3-2-evidence/reproduction.tar.gz` and `3-2-evidence/reproduction-post-review.tar.gz`. Normal builds use `/tmp/vw-ssh-builder-target`; mutations use a separate target and isolated source copies. These directories never exchange binaries.

Counts below are reported passes / failures / ignored, not distinct tests across repeated configurations.

| Check | Exit | Result | Seconds |
|---|---:|---|---:|
| `fmt` | 0 | command passed | 10.27 |
| `clippy` | 0 | command passed | 7.71 |
| `native-fixtures` | 0 | command passed | 6.63 |
| `ssh` | 0 | 41 / 0 / 1 | 56.42 |
| `systemd` | 0 | 3 / 0 / 0; 39 scenarios | 196.6 |
| `build-cli` | 0 | command passed | 4.41 |
| `browser` | 0 | command passed | 129.78 |
| `all-targets` | 0 | 986 / 0 / 15 | 427.96 |
| `policy` | 0 | 19 / 0 / 1 | 25.3 |
| `store` | 0 | 13 / 0 / 0 | 0.87 |
| `backend` | 0 | 19 / 0 / 0 | 12.23 |
| `integration` | 0 | 27 / 0 / 1 | 17.05 |
| `diff-check` | 0 | command passed | 0.29 |
| `real-peer` | 0 | 1 / 0 / 0 | 9.35 |
| `doc` | 0 | 0 / 0 / 0 | 3.92 |
| `msrv-all-targets` | 0 | 986 / 0 / 15 | 401.18 |
| `all-features` | 0 | 986 / 0 / 15 | 292.54 |
| `doc-all-features` | 0 | 0 / 0 / 0 | 4.66 |
| `no-default-features` | 0 | 986 / 0 / 15 | 218.41 |
| `doc-no-default-features` | 0 | 0 / 0 / 0 | 1.44 |

Each all-target configuration includes **71 live-backend tests that return early** because both live URL/admin-token gates are absent. Their reported passes are not live-backend acceptance evidence. Thus 986 reported passes comprise 915 other reported tests plus those 71 early returns. Repeated compiler/feature runs are not additive test totals. Each all-target run also executes 13 benchmark smoke checks. Documentation checks contain zero doctests.

The 15 ignored cases are nine internal subprocess fixtures exercised by their parent tests, one Firefox fixture exercised by the browser script, one material-principal fixture exercised explicitly by the systemd script, one provider harness exercised inside real transient units, one signed-agent mapped-principal test exercised with `unshare`, and two systemd integration tests exercised explicitly. Exact names and output remain in the logs. No ignored fixture is counted as a direct pass in its default suite.

Real supervision: two external integration tests exercise 39 scenarios, including the original login/authentication cases and SSH natural/nonzero/signaled exits, cancellation, authority loss, provider death, failed reap and cleanup interlocks. The separate material test creates real provider-owned files and confirms EACCES from two subordinate agent UIDs; its inherited-descriptor oracle rejects otherwise valid foreign-owned material. Signed-agent transport and ownership are independently exercised under mapped UIDs. Native fixture compilation covers x86_64 and AArch64; runtime verification is x86_64 Linux. Firefox and axe exercise the browser approval flow.

The completed pre-review 20-command matrix (981 reported passes/15 ignored in each compiler/feature configuration) remains in `verification-complete.tar.gz`. Review patches add five tests. Focused review-fix checks passed 67 tests; their one opt-in material fixture was separately executed under the new timeout. Exact commands and the initial Clippy naming failure/corrected pass are in `review-fixes.tar.gz`.

## Acceptance matrix audit

All named module tests below execute in the final all-target suite; explicit process/principal cases execute through the final systemd and real-peer commands.

| Approved matrix row | Executed coverage |
|---|---|
| Current approval | `material_is_private_pinned_and_only_explicitly_removed_after_reap`; `ssh_application_supervises_before_finalization_and_persists_redacted_failures`; real `ssh-exit` checks fixed argv, cwd, baseline environment and descendant reads |
| Bad credential/pin/authority | `ssh_resolution_uses_personal_item_organization_and_organization_item_keys`; `ssh_resolution_rejects_invalid_utf8_with_redacted_error`; `wrong_pin_missing_key_and_destination_fail_before_request_files`; `ssh_resolution_rechecks_response_and_decrypts_only_selected_private_key`; `ssh_lock_intent_during_key_resolution_cleans_material_without_launch`; existing SSH authority/approval/signed-selector regressions |
| Exit/cancel/authority loss | Real `ssh-exit`, `ssh-cancel`, `app-ssh-nonzero`, `app-ssh-signal`, `app-ssh-lock`, `app-ssh-cancel`; application finalization ordering and existing release/revocation race tests |
| Partial setup/deletion failure | `ssh_post_mkdir_failures_report_uncertain_and_interlock_until_recovery`; `ssh_partial_writes_and_create_sync_failures_are_cleaned_or_interlocked`; `ssh_cleanup_failure_after_unlink_or_directory_removal_recovers_safely`; `partial_setup_is_cleaned_and_unlink_failure_survives_restart_until_recovery`; application redacted failure/closed-admission assertions; real `ssh-cleanup-failure` |
| Uncertain reap/restart | `drop_preserves_residual_until_ordered_recovery`; real `ssh-crash`, `ssh-uncertain` retain both files during failed startup recovery while the cgroup remains populated, then clean after recovery |
| Unsafe path/link/owner/collision | `directory_walk_rejects_symlinks_dot_components_and_shared_ancestry`; `unknown_objects_and_links_poison_cleanup_and_are_never_removed`; `ssh_creation_modes_are_private_with_permissive_umask`; `ssh_exclusive_install_preserves_existing_key_and_replacement_inodes`; explicit distinct-principal test |

Disclosure coverage includes zeroizing/redacted private-key resolution, exact authenticated descriptor transfer, absence of ambient sockets/overrides, persistent/public sentinel scans and independent native stdout/stderr descriptor assertions. Existing signed requests, owner-only status/cancel, exact human approval and login execution remain in the regression and real-manager suites.

## Scoped semantic mutations

Final post-review campaign: **31 unique mutations, 31 killed, 0 survived, 0 timed out, 0 unviable, 0 unclassified**, all source restorations verified. This reruns the complete prior 28-case scope and adds denial of organization-key resolution, denial of item-key resolution, and weakening the post-mkdir error category. Each new mutant was killed by its named covering test after a passing baseline. Exact patches, commands, source hashes and named failing assertions are in `mutations-post-review.tar.gz`. Earlier campaigns below are historical evidence and are not added to this unique count.

Initial 24 module mutations: **19 killed, 5 survived**. Initial three real-process mutations: **1 killed, 2 survived**. No timeout, unviable mutant or unclassified result occurred in those completed campaigns. All seven initial survivors were retained and addressed by stronger test oracles; expectations and production security checks were not weakened.

The hardened campaign executes **28 unique mutations: 28 killed, 0 survived, 0 timed out, 0 unviable, 0 unclassified**. It adds the post-key-resolution authority-loss mutation. Every case requires a passing nonzero baseline, package recompilation, a named executed failing test with a failed summary, and restored source hashes. Compilation failures and unavailable tests cannot count as kills. See `mutations-hardened.tar.gz` for exact patches, commands, source hashes and assertions.

After the final unsigned-index and disposable-cwd fixture corrections, the three affected real-process mutations were reconfirmed: **3 killed, 0 survivors, 0 timeouts, 0 unviable, 0 unclassified**, with passing rebuilt baselines. See `mutations-final-confirmed.tar.gz`. The other 25 unit mutations retain their hardened-campaign results; their production and assertion files are unchanged. These are reconfirmations, not three additional unique mutations. Source manifests identify the two changed fixture files.

The seven initial survivors and their corrections:

| Survivor | Added evidence |
|---|---|
| File creation mode | Direct 0600 metadata assertion in an isolated process with umask 0 |
| Request directory mode | Direct 0700 metadata assertion under the same permissive umask |
| Exclusive create | Second install fails and preserves original key bytes |
| Provider owner | Actual foreign-owned descriptor with valid mode/link count is rejected after mapped UID change |
| Inode identity | The `same` helper rejects replacement file inodes; finalization rejects replacement request directories and preserves originals/unrelated content. Files at reserved names are validated afresh during cleanup |
| Startup cleanup before reap | Keep stop failure active across fresh provider startup; live cgroup and both retained files are asserted |
| Raw child output | Native child independently checks fd 1 and fd 2 resolve to `/dev/null`; outer test detects its explicit unsafe-output marker |

Other mutations cover no-follow open, exact mode, hard links, host fingerprint/destination/port, strict trust, signing agents, ambient config/environment, uncertain reap, omitted/premature cleanup, residual admission interlock, unknown objects, ignored cleanup errors, poisoning, no-launch cleanup, backend response identity, authority recheck and checked working-directory handoff.

A real disclosure negative control established that synthetic stdout/stderr reached the journal **without unit attribution** after both output-discard defenses were disabled. The old unit-filtered journal oracle missed it. The raw attribution record is retained; missing metadata's cause is not established. The final descriptor oracle kills this mutation directly. This is a test gap discovered and fixed by mutation testing, not evidence that the unmutated implementation leaked output.

## Failed attempts and infrastructure

All failed phases are retained alongside successful reruns in [evidence archives](3-2-evidence/README.md):

- Sandbox secure-ancestry preflight rejected unmapped root ownership. Host execution preserved the production checks and enabled user systemd/subordinate mappings.
- Initial Firefox run failed a stale “execution unavailable” copy assertion; corrected to the implemented protected-execution text.
- Initial permissive-umask test incorrectly created its fixture root after clearing umask; secure ancestry correctly rejected that root. The fixture now creates its private root first.
- A diff-whitespace check rejected raw logs with blank EOF lines; byte-preserving compressed evidence resolves this without altering recorded output.
- Cross-architecture strict compilation caught signedness in the new native descriptor loop; an unsigned index corrected it.
- The cwd-bypass negative control wrote three synthetic marker files in the provider home. Exact content/metadata/creation provenance was checked before removing only those three files. The harness now assigns a private disposable ambient working directory, confining that mutation's markers. Cleanup provenance is retained in reproduction evidence.
- First final real-mutation reconfirmation stopped on an invalid baseline caused by a stale helper artifact: source copies preserved old mtimes in a reused mutation-only cache. No kill was claimed. The runner now copies with fresh timestamps and preserves executable modes. An intermediate copy-mode mistake also stopped before testing and is retained. Normal build artifacts were separate and unaffected.

No live Vaultwarden credentials or actual remote SSH server were used. The tests prove the native execution, trust-argument and material-lifetime boundary with reviewed synthetic static images; they do not prove interoperability of a particular production SSH implementation. No macOS execution or companion-worktree changes were performed. Host infrastructure required for Linux checks is available; unavailable live integration is explicitly excluded rather than passed.

## Publication checks

After the user requested a PR on 2026-10-07, all 97 source hashes in the final verification manifest and all 20 evidence archive hashes still matched. Fetched `origin/main` remained at the baseline above; no implementation rebase or code change was needed.

The additional `bash scripts/scan-staged-secrets.sh` check returned failure, not a pass. All 11 reported matches were inspected: five `self.agent_token(...)` expressions in `src/access/application.rs` (lines 522, 610, 711, 873, 1489); four browser-test lines containing the synthetic password or a DOM expression in `tests/ui/direct-request.mjs` (198, 232, 235, 319); an OpenSSH format string in the synthetic key fixture (`src/adapters/ssh_material.rs:519`); and the native fixture's expected format marker (`tests/fixtures/protected-tree.c:90`). None is a live credential. This is documented manual false-positive triage; the scanner was not changed and its failure is not represented as a passing automated check.
