# Story 1.6 verification evidence

Status: implementation, required verification and all three workflow review layers
complete. The user accepted the completed implementation and evidence by requesting
publication of the pull request on 2026-09-25.

## Baseline and environment

- Baseline: `fd6b7eb3dea18d686c844189772fb9e5673ec050` (updated main).
- Branch: `feature/verify-exact-protected-executable`.
- Stories 1.1–1.5 are merged through PRs #19–#23. See
  [planning notes](1-6-planning-notes.md) for exact dependency commits and sources.
- Host observed: Linux 6.18.7 x86_64; default rustc 1.98.1;
  cargo-mutants 27.1.0; cc and ld available.
- Rust 1.88.0 and Cargo 1.88.0 were installed in isolated
  `/tmp/vw-story16-rustup`; compiler reports
  `rustc 1.88.0 (6b00bc388 2025-06-23)`.
- Baseline `cargo metadata --locked --offline --format-version 1` returned
  324 packages; none declares a minimum Rust version above 1.88. This metadata
  inspection is not a successful compiler/build/test result.

## Test filesystem boundary

The ordinary filesystem sandbox remaps `/` and `/home` ownership to uid65534.
The workspace also has group-writable ancestors. Both are incompatible with the
approved strict execution ancestry policy. Production checks must not be weakened
to accommodate these conditions.

Outside that sandbox, `/` and `/home` are root-owned0755 and
`/home/sixtocantolla` is provider-owned0750. A dedicated private temporary fixture
parent was created at `/home/sixtocantolla/.vw-story16-tests.LGlAXW`; setting
`TMPDIR` to this directory allows real positive preparation tests through the
production absolute-path traversal. Shared directory permissions were not changed.
Mutation scratch copies must also use safe ancestry so metadata rejection cannot
masquerade as a caught security mutation.

The checked-in `scripts/with-secure-test-tmpdir.sh` now provisions and cleans a
private temporary directory beneath verified safe provider-owned HOME ancestry
on Linux, preserving command arguments and exit status. CI and the just
`test`, `check`, `pre-commit` and `coverage` entry points invoke it. The final
ordinary runs below used this wrapper, which supplies its own fresh TMPDIR;
the preexisting TMPDIR in their recorded environment was not the fixture root
used by the wrapped command. A reproducible command from the project root is:

```bash
./scripts/with-secure-test-tmpdir.sh cargo test --all-targets --locked --offline
```

The separate Linux wrapper probe observed mode 0700, cleanup, argument preservation
(including empty arguments, spaces and metacharacters), exit 0/37 preservation,
and unsafe/symlink/shared-ancestry rejection. Non-Linux passthrough was simulated
and preserved TMPDIR/exit 23; this is not a native macOS run.

## Final ordinary verification after review amendments

The current source passed all required ordinary checks after the final review
regression test and documentation corrections. The stable and Rust 1.88 before/after manifests each
contain 68 inputs, agree with each other, and match the current code, tests,
fixture, scripts and configuration. Both all-targets runs include real Linux
execveat, owned-descriptor cleanup, closed/zero descriptors, and seccomp failures.

Every command below was prefixed with `./scripts/with-secure-test-tmpdir.sh`.
The stable run used `CARGO_TARGET_DIR=/tmp/vw-story16-refinement-target`; Rust 1.88
used `RUSTUP_HOME=/tmp/vw-story16-rustup` and the worktree's `target/msrv188`.
`CARGO_TERM_COLOR=never` and locked offline dependencies were used throughout.

| Wrapped command | Exit | Elapsed | Final log |
|---|---|---|---|
| `cargo fmt --all -- --check` | 0 | 2.736 s | `stable-0.log` |
| `cargo test --all-targets --locked --offline` | 0 | 197.186 s | `stable-1.log` |
| `cargo clippy --all-targets --all-features --locked --offline -- -D warnings` | 0 | 5.680 s | `stable-2.log` |
| `rustup run 1.88.0 cargo test --all-targets --locked --offline` | 0 | 111.804 s | `msrv-0.log` |

Logs, exact argv/environment/exit records, source manifests and the matrix audit
are packaged under `review2-ordinary/` in the raw archive (also available at
`/tmp/vw-story16-review2-final-verification/`). The current command records are
[ordinary-results.json](1-6-evidence/ordinary-results.json). Older archive labels
`ordinary-initial` and `ordinary-final` are historical pre-review runs.

Each toolchain reports **774 passes across 15 suites**, **zero failures** and
**nine ignored library entries**. Of the reported passes, **703 non-live tests
executed** and **71 live-account tests returned early**. All **13 benchmark smoke
checks** separately reported `Success`.

| Suite | Reported passes on each toolchain |
|---|---:|
| Library (`src/lib.rs`) | 518 |
| Provider daemon (`src/bin/vaultwarden-accessd.rs`) | 9 |
| Main CLI (`src/main.rs`) | 34 |
| Human CLI (`src/bin/vw-access.rs`) | 3 |
| `tests/api_client.rs` | 21 |
| `tests/cli.rs` | 10 |
| `tests/command_basic.rs` | 31 |
| `tests/config_edge.rs` | 21 |
| `tests/direct_request.rs` | 1 |
| `tests/human_cli.rs` | 3 |
| `tests/integration_tests.rs` | 22 |
| `tests/live_tests.rs` | 71 early returns |
| `tests/msrv_docs.rs` | 1 |
| `tests/provider_session.rs` | 6 |
| `tests/safety_checks.rs` | 23 |

`tests/live/env.rs:118–119` returns `None` without either
`VAULTWARDEN_LIVE_TEST_URL` or `VAULTWARDEN_LIVE_ADMIN_TOKEN`; all 71 live tests
return when that fixture is unavailable. Neither variable was configured.
Their suite took 0.01s on stable and 0.01s on Rust 1.88. These are not verified live
account interactions or Rust `#[ignore]` skips. The new real-backend credential
contract test uses local Wiremock HTTP fixtures and executes in the library suite.

Eight of the nine ignored entries are isolated fixtures explicitly invoked by
passing parents: five execution fixtures (`execution_child`, `cleanup_child`,
`syscall_failure_child`, `descriptor_zero_child`, `required_syscall_flag_child`),
`preliminary_open_flags_child`, `isolated_system_launcher_child`, and
`isolated_descriptor_fixture`. Their child assertions and exit statuses are
checked by the parents; they are not added again to the 774 reported passes.
`direct_request_browser_fixture` is the remaining ignored entry and was not run.
No live-account or browser verification is claimed.

The first final Rust 1.88 attempt failed (exit 101, 159.115 s) in the existing
`fixed_system_launcher_uses_only_an_isolated_desktop_association` test: its child
returned `ReviewUnavailable` at the production two-second deadline while both
toolchain suites ran concurrently. The entire Rust 1.88 suite was rerun alone and
passed without source changes. Load-related timeout is an inference, not a proven
cause. The failed attempt is preserved under `review2-msrv-first-attempt/` and is
not counted as successful verification.

## Historical pre-review ordinary verification

The pre-review source passed these ordinary checks. These counts and timings
are retained as history and do not describe the amended current source. Its source
SHA-256 manifests taken before and after each toolchain run agreed. All commands
used the secure `TMPDIR` described above, locked offline dependencies, and distinct target
directories. Both all-targets runs include the real Linux execveat, descriptor
cleanup, closed/zero descriptor, and seccomp failure subprocess tests.

| Command | Exit | Elapsed |
|---|---|---|
| `cargo fmt --all -- --check` | 0 | 3.110 s |
| `cargo test --all-targets --locked --offline` | 0 | 522.199 s |
| `cargo clippy --all-targets --all-features --locked --offline -- -D warnings` | 0 | 154.295 s |
| `rustup run 1.88.0 cargo test --all-targets --locked --offline` | 0 | 477.524 s |

Each suite reported **763 passes across 15 targets/suites**: **692 non-live tests
executed**, while **71 live-account tests returned early** without configured
credentials. All **13 benchmark smoke checks** passed. The library reported
507 passes and nine ignored entries. Eight of those entries are isolated fixtures
explicitly invoked by passing parents (six execution/policy fixtures and two
existing launcher/socket fixtures); the remaining browser fixture was not run.
No live Vaultwarden account or browser verification is claimed.

## Initial ordinary verification

The initial implementation passed both full runs; before/after SHA-256 manifests agree.
Mutation-driven test refinements were added afterward. The completed final verification above supersedes these initial counts.
All commands ran in the worktree with `TMPDIR` set to the private fixture parent
and `CARGO_TERM_COLOR=never`.

| Command | Result | Elapsed |
|---|---|---|
| `cargo fmt --all -- --check` | Pass | 0.460 s |
| `cargo test --all-targets --locked --offline` | Pass | 148.794 s |
| `cargo clippy --all-targets --all-features --locked --offline -- -D warnings` | Pass | 18.556 s |
| `rustup run 1.88.0 cargo test --all-targets --locked --offline` | Pass | 144.149 s |

The Rust 1.88 run additionally used `RUSTUP_HOME=/tmp/vw-story16-rustup` and its
own `target/msrv188` directory. Each all-targets run reported **743 passes across
15 suites**, including **71 environment-gated live-account tests that returned
early**. Thus 672 non-live tests executed, plus 13 benchmark smoke checks. The
library reported 487 passes and six ignored entries. Three ignored entries are
new isolated execution fixtures, each explicitly invoked by a passing parent;
two existing isolated descriptor/launcher fixtures also have parent harnesses.
The existing browser fixture was not independently run in this backend-only story.
No live Vaultwarden account or browser verification is claimed here.

An earlier all-targets run found one outdated daemon test binding lacking the new
root/profile fields. Its fixture was updated to a pinned static image and the
complete stable and Rust 1.88 suites were rerun. That earlier failure is setup
history, never counted as a successful run or mutation kill.

## Acceptance and edge-case matrix

The current 19-row matrix names 66 distinct tests. Every named test appears as
`ok` in both final all-targets logs, and its source is covered by the matching
68-input manifests. The independent audit found no missing test or false pass
flag in `/tmp/vw-story16-review2-final-verification/matrix-audit.json`. Adapter
names live under `adapters::execution::linux::tests`; request names under
`access::direct_request_tests` unless otherwise indicated.

| Required behavior | Executed evidence |
|---|---|
| Approved preparation retains owned bytes, leaves approval untouched, resolves no secrets or child | `execution_preparation_retains_capability_without_consuming_approval_or_resolving` uses a platform-neutral owned capability and asserts argv/call/drop counts; `execution_application_integrates_real_owned_linux_preparation` separately retains the real Linux executable resource |
| Exact descriptor execution, explicit argv and empty environment | `descriptor_execution_subprocess` invokes `execution_child`, replaces/unlinks the source after preparing, and expects exit 42 from assembly fixture checking argc, argv and envp |
| Every invalid status, target/arguments, policy/effect/credential binding | `execution_rejects_each_nonapproved_state_before_image_or_backend_work`; `execution_rejects_independently_resealed_semantic_changes_before_preparation` rebuilds unrelated seals |
| Approval binding, owner, epoch, locked/shutdown/reunlock, expiry equality, restart and stale active policy | `execution_rejects_binding_epoch_lock_shutdown_restart_and_deadline_equality`; `execution_preparation_rejects_actual_restart_and_changed_active_policy`; `execution_validity_at_last_second_and_failed_preparation_are_independent` |
| Authority invalidated by preparation, durable read or backend work | `execution_revalidates_authority_and_exact_binding_after_slow_preparation`; `execution_rechecks_compatibility_and_each_credential_without_resolution`; `access::application::tests::execution_post_read_deadlines_precede_the_first_preparation_call`; `execution_failed_durable_reads_still_clear_invalidated_authority`; `execution_failed_request_expiry_write_still_clears_invalidated_authority`; `execution_final_durable_validation_rejects_edits_during_backend_work` independently alters binding, authority-bearing policy and state |
| Concurrency and prepared-resource release | `execution_preparation_releases_owned_bytes_when_admission_closes_on_another_thread` uses channel synchronization and asserts one owned-capability drop |
| Final/root/descendant/ancestor symlinks | `symlinks_at_leaf_root_descendant_and_ancestor_are_rejected`, including an independently valid target beneath the ancestor link |
| Regular file, owner and individual write/special/read/execute bits | `invalid_paths_and_special_sources_fail_without_blocking`; `source_owner_check_is_independent_of_path_and_other_metadata`; `independent_source_mode_guards`; `independent_root_and_descendant_mode_guards`; `each_private_directory_permission_bit_is_rejected_independently`; `directory_ownership_and_ancestor_permissions_are_independent`; `full_preparer_rejects_each_unsafe_execution_root_ancestor_permission` uses a safe positive then independently adds each unsafe intermediate-ancestor permission bit |
| Hash, digest syntax, malformed/unsupported closure, size and argv | `wrong_digest_and_invalid_digest_are_distinct_closed_failures`; `each_unsupported_or_malformed_elf_is_rejected_with_matching_hash`; `dependency_and_executable_stack_headers_are_rejected_beside_a_valid_load`; `malformed_section_contents_and_overlapping_loads_are_rejected`; `load_mapping_validation_uses_the_host_page_size`; `truncated_and_oversized_sources_fail`; `arguments_are_bounded_and_nul_free` |
| Invalid, closed, unavailable/unsealable descriptors and cleanup | `invalid_and_unsealable_descriptors_fail_closed`; `descriptor_cleanup_subprocess` invokes `cleanup_child`; `unavailable_memfd_and_sealing_syscalls_close_resources` invokes `syscall_failure_child` with process-local seccomp denials of memfd, sealing and execveat, asserting stable descriptor counts |
| In-place modification and pathname replacement around copy/seal/hash/execution | `source_changes_during_copy_reject_before_capability`; `pathname_replacement_and_source_write_after_copy_do_not_replace_verified_bytes`; `channel_coordinated_writer_cannot_change_the_retained_object`; real `descriptor_execution_subprocess` |
| Immutable bytes, mode and redacted diagnostics | `valid_image_has_all_seals_and_redacted_debug`, failed pwrite/truncate/grow/chmod; closed error enums contain no paths, argv, errno or backend values |
| Exact protocol boundaries and descriptor0 | `literal_protocol_limits_are_independent_of_implementation_constants`; `snapshot_contract_accepts_literal_64_mib_pinned_image`; `access::policy::tests::preliminary_image_limit_uses_independent_literal_boundaries`; `descriptor_zero_is_valid_for_open_and_snapshot_subprocess` |
| Independent seals, syscall flags, and error categories | `descriptor_execution_rejects_each_independently_missing_seal_before_syscall`; `literal_seal_set_and_descriptor_flags_are_required`; `seal_readback_failure_closes_resources_before_capability`; `preparation_explicitly_requests_executable_memfd_and_no_controlling_terminal`; `execution_error_labels_are_stable_and_redacted`; `access::policy::tests::preliminary_open_flags_are_required_by_the_syscall_contract` |
| ELF header/table/section/load/entry boundaries | `elf_boundaries_reject_every_truncated_header_without_panicking`; `elf_boundaries_program_table_count_and_extent`; `elf_boundaries_section_table_metadata_and_extent`; `elf_boundaries_second_section_fields_and_nobits_semantics`; `elf_boundaries_entry_and_independent_second_load`; `elf_userspace_profiles_have_independent_literal_bounds_and_rounding`; `elf_userspace_high_load_is_rejected_with_matching_hash_and_valid_entry`; `elf_userspace_end_and_entry_boundaries_have_matching_hashes`; `elf_userspace_boundaries_account_for_supported_page_rounding` |
| Failure ordering and conservative source-change rejection | `execution_failed_io_still_revokes_expired_or_closed_authority_before_returning`; `execution_legacy_approval_has_a_stable_closed_rejection_category`; `sealing_precedes_both_digest_and_format_rejection`; `snapshot_contract_rejects_same_byte_rewrite_with_changed_timestamp` |
| Policy revision and legacy persistence | `access::policy::tests::root_and_profile_are_mandatory_and_part_of_the_execution_binding`; `execution_root_must_be_canonical_and_contain_the_image`; `access::provider_store::tests::legacy_populated_bindings_require_reprovisioning_without_rewriting_state`; `registry_root_changes_do_not_match_a_previously_bound_operation` |
| Exact policy-bound credential identity, required fields and operation marker | `adapters::vaultwarden::tests::preparation_rechecks_each_policy_credential_with_the_real_backend` uses two real backend-selected Wiremock items, keeps the first eligible, independently revokes second-item identity/marker/username/custom-field eligibility, and asserts zero resolution/launch and owned-resource release |
| Durable validation independent of credential count | `execution_durable_validation_work_is_independent_of_credential_count` pins a 2 MiB image and compares one/eight distinct credentials: three durable reads, 15 image-lengths actually hashed, complete per-item eligibility, zero resolution/launch. Existing deserialization/rebuilding hashes five image copies per durable read; the bound does not depend on timing |

## Mutation verification

All required campaigns have finished. The effective inventory contains **506 generated
and 79 manual distinct mutations**. Generated scope covers complete production
functions and relevant existing admission/ownership/expiry guards: 371 adapter,
96 policy, 22 application, 16 provider and 1 redacted-error formatter cases.
Manual cases cover guard omissions, individual flags/mode bits, credential wiring,
resource leaks, digest/path bypasses, syscall ordering and protocol constants.

| Scope | Caught by named failing tests | Documented equivalent/redundant | Compiler rejected | Unresolved |
|---|---:|---:|---:|---:|
| Generated: 506 | 443 | 40 | 23 | 0 |
| Manual: 79 | 77 | 2 | 0 | 0 |
| Total: 585 | 520 | 42 | 23 | 0 |

These are distinct mutations, not summed attempts or a claimed 100% mutation score.
Compiler rejection and timeout are never credited as tests catching a bypass.
The [survivor classifications](1-6-mutation-classifications.md) explain every
remaining survivor, distinguishing exact equivalence from preparation/race-contract
redundancy and observable timing or conservative-rejection differences.

After review amendments, all six changed function scopes were freshly mutated:
`prepare_execution`, `execution_authority`, `execution_live`,
`executable_identity_matches`, `validate_elf_for_page_size` and
`checked_userspace_mapping_end`. This 257-case generated run completed with
230 named-test catches, 19 initial survivors, 5 compiler rejections and
3 build timeouts (2796.576 seconds; tool exit 3). Its unmutated baseline
passed 150 tests, with six subprocess fixtures invoked through passing parents.

All three build timeouts occurred while separate dependency caches warmed under
parallel load. Separate completed reruns in an idle isolated workspace resolved
them as two named-test failures and one compiler rejection. Six size-boundary
survivors were separately caught using the literal 64 MiB positive control and
correctly hashed oversized images. No final timeout or unclassified case remains.

The 25 refreshed manual cases produced 23 named-test failures and two adjacent
live-check redundancies. They cover failed-I/O authority cleanup, final durable
policy/binding changes during backend calls, every particular credential item,
username/custom-field requirements and operation marker through the real backend,
both architecture address-bit constants, capability cleanup and aggregate
preliminary size/execute guards. The former final-authority-check survivor is
now caught; its old equivalence classification was retired.

The refreshed broad generated run omits the two expensive 64 MiB tests, the
credential-count performance oracle and the FIFO test. The six relevant new
boundary mutants ran against the size oracle separately; unchanged size/flag
mutations retain the earlier completed boundary and syscall-contract evidence.
The FIFO omission prevents a deliberately removed O_NONBLOCK flag from hanging a
mutation worker. Missing flags are tested by bounded syscall-contract fixtures.
The performance oracle and all omitted tests passed in both complete ordinary
suites. The separate manual baseline also ran the performance and size oracles.

Results retained from prior completed campaigns are explicitly identified:
**249 generated and 53 manual cases** concern unchanged production code. Exact
whole-function/constant hashes and manual patch anchors were checked, and their
**109 original named failure oracles pass in both final toolchain suites**
(subprocess fixtures via their passing parents). Current source ranges are mapped
in [provenance](1-6-evidence/retained-result-provenance.json). The current inventory
has 44 scoped function/constant ranges: 38 retained and six freshly mutated.
Retained results are not described as rerun after every test change.

The final review added one full-preparer ancestor permission test and documentation
corrections; production code was unchanged. The new manual mutation removes the
entire metadata guard inside execution-root ancestry traversal while leaving the
separate root/descendant guard intact. It compiled (exit 0, 15.585 s) and the new
test failed (exit 101, 1.689 s) because unsafe preparation returned a capability.
The safe positive and all five independent unsafe permission cases pass unmutated.
This adds one catch to the prior 584 distinct results. Those results were retained,
not rerun: all 44 production ranges match their recorded hashes, and all their
named failure oracles pass in both final ordinary suites. The proof and consolidated
585-case inventory are archived under `review2-classification/`.

Historical raw evidence includes the original 496-case generated campaign,
91-case refinement, 11 size reruns, 63-case manual run and supplemental cases.
Their initial 16 test timeouts were all rerun as named failures before retention.
The 69 prior manual cases were superseded by the retained/refreshed 78-case
inventory, followed by the final ancestor-guard case (79 total); they are not added
again. All meaningful earlier survivors were addressed by independent
permission, descriptor-zero, seal, error-label, source-race and ELF-boundary oracles.

Excluded attempts are preserved but contribute no outcomes: the earlier interrupted
manual timeout-harness run, a manual run with a concurrent build-target collision,
and the first review-refresh generated attempt that redundantly ran the costly
performance oracle for each mutant. The latter was explicitly stopped and the
entire 257-case campaign restarted. Completed campaigns used isolated workspaces
and targets; reuse of the idle manual target for the three infrastructure and six
boundary reruns was sequential and checked against current source before reuse.

Channels/hooks determine race ordering. No production inspection API was added
for tests. Raw commands, mutation diffs, compiler errors, named assertions and
attempt exclusions are retained in the archive.

## Evidence files

- [Ordinary command results and counts](1-6-evidence/ordinary-results.json)
- [Acceptance matrix audit](1-6-evidence/matrix-audit.json): 19 rows and 66 distinct passing tests on both toolchains
- [Mutation totals](1-6-evidence/mutation-summary.json) and [compiler rejection audit](1-6-evidence/compiler-rejections.json)
- [Verified source hashes](1-6-evidence/verified-input-sha256.json) and [production-function provenance](1-6-evidence/mutation-source-provenance.json)
- [Raw verification archive](1-6-evidence/verification-raw.tar.gz): commands, logs, patches, full inventories, per-mutant classifications, runners, source manifests and fixture assembly evidence
- [SHA-256 checksums](1-6-evidence/SHA256SUMS)

## Platform and scope limitations

The real descriptor execution and seccomp integration were exercised on Linux
6.18.7 x86_64. Linux 6.3+ executable memfds and all required seals are mandatory;
policy or syscall denial fails closed. Both x86_64 lower 47-bit-minus-final-page
and AArch64 lower 36-bit address bounds are directly tested using independent
literals and 4/16/64 KiB page-rounding cases on this x86_64 host. Matching-digest
ELF cases test high loads, crossing ends and entry boundaries. Native AArch64
execution has not been run. The minimum
Linux 6.3 kernel was verified against authoritative API documentation, not an
actual 6.3 host; only Linux 6.18.7 was available. Tests ran as a non-root provider UID. The x86_64
fixture is independently assembled from `tests/fixtures/protected-exit.S` and its
61-byte machine-code payload matches the embedded test bytes.

Platform-neutral authority tests use a small owned test capability; Linux-only
integration separately covers the real prepared descriptor. Non-Linux adapter
`Unavailable` tests exist under the non-Linux cfg, but no native macOS build or
test run was available. Simulated shell-wrapper passthrough does not validate
those Rust cfg branches. Kernel allocation, security policy or syscall denial
may still prevent execution of a structurally accepted image.

Only reviewed self-contained native ELF64 ET_EXEC artifacts are supported.
The provider declaration is a trust assumption: hashing and ELF inspection do not
prove absence of runtime code loading or helper execution in an arbitrary program.
Scripts, dynamic/interpreter-backed images and static PIE are rejected. A pinned
interpreter does not certify its interpreted code. Preparation is internal and
confers no dispatch authority; production secret injection, login-backed execution,
approval consumption and process supervision remain Stories 1.7/1.8.

Current final formatting, all-targets, Linux primitive, Rust 1.88 and strict
Clippy checks passed. Scoped mutation verification and tracked/untracked
`git diff --check` are complete; no required check is blocked. Live-account, browser, native macOS, native AArch64 and an actual
Linux 6.3-host run are not claimed.

## Workflow review outcome

All three context-free review layers completed. The edge-case review returned no
findings. The accepted documentation precision and full-preparer ancestor coverage
findings were patched and verified. Individual verdicts and carried/rejected
findings are recorded in the build spec's review triage log.

One medium pre-existing performance item was deferred: durable snapshot validation
rehashes image bindings repeatedly. Preparation now performs three durable reads
independent of credential count, but a single-operation example still hashes fifteen
image-lengths. Large registries can delay callers including Lock while the authority
gate is held. This is documented in `docs/access-mvp.md` and the shared deferred-work
log; this change does not claim to solve per-snapshot duplication or policy-count
scaling. ELF checks cover selected execution structures, not all auxiliary ABI
metadata; unused null-section/name-table semantics are not certified.

The user authorized committing, pushing and opening the pull request on 2026-09-25.
