# Story 1.8 verification evidence

> Historical pre-review evidence below. Review-iteration-1 changed source requires fresh verification; the new run is in progress and this historical evidence does not validate it.

Implementation verification completed. Workflow review and human acceptance are
still pending; no commit, push, deployment or PR has been performed.

Baseline: `ffd8ed4c434f585b2bcb37b0ca9a8517538be662`, branch
`feature/contain-protected-child-processes`. The exact final source manifest and
fingerprint are [source.sha256](1-8-evidence/source.sha256) and
[source-fingerprint.json](1-8-evidence/source-fingerprint.json). All semantic
mutation source hashes were checked against the restored files.

## Platform and boundaries

Tested on Linux `6.18.7-76061807-generic`, x86-64, unified cgroup v2,
systemd user manager `255.4-1ubuntu8.15pop0~1778766128~24.04~85b5073`, Yama scope 1.
Rust versions: `1.98.1 (48a229cea 2026-09-01)` and
`1.88.0 (6b00bc388 2025-06-23)`. Browser: Firefox 151.0.2, Puppeteer 25.11.0,
axe-core 4.13.0 (matching the locked browser dependencies).

Support requires Linux 6.3+ executable memfds, cgroup v2, feature-checked systemd
255+, safe provider-owned helper installation and permitted parent/child ptrace
exec-event observation. Unsupported configurations fail closed. AArch64 was not
executed on this x86-64 host. The supplied user provider unit was not installed or
changed on the host; real tests used unique provider/request harness namespaces.
All selected credentials and output sentinels were synthetic.

## Completed commands

Every row completed with exit 0. Host commands used
`scripts/with-secure-test-tmpdir.sh`; test/build timeouts and full argv are retained
in [verification-results.json](1-8-evidence/verification-results.json) and logs.
Rust suites ran sequentially with `RUST_TEST_THREADS=4`.

| Verification | Result | Log |
| --- | --- | --- |
| Stable `cargo test --all-targets --offline --locked` | 804 passed, 0 failed, 11 ignored; 13 benchmark smoke cases; 243.01s | [stable](1-8-evidence/stable-all-targets.log) |
| `rustup run 1.88.0 cargo test --all-targets --offline --locked` | 804 passed, 0 failed, 11 ignored; 13 benchmark smoke cases; 294.98s | [MSRV](1-8-evidence/rust-1.88-all-targets.log) |
| `cargo clippy --all-targets --all-features --offline --locked -- -D warnings` | Strict pass, 21.12s | [Clippy](1-8-evidence/strict-clippy.log) |
| `cargo test --offline --locked --lib contract -- --test-threads=4` | 6 passed, 0 failed, 0 ignored | [named contracts](1-8-evidence/named-contracts.log) |
| Explicit static composition checks | 4 checks passed | [checks](1-8-evidence/static-contracts.py), [log](1-8-evidence/static-contracts.log) |
| Daemon startup regression | 1 passed, 0 failed | [startup](1-8-evidence/startup-regression.log) |
| `node tests/ui/direct-request.mjs` | Passed; 24 axe checks, 0 violations, 0 unexpected diagnostics; 56.3s | [browser](1-8-evidence/browser.log) |
| `scripts/test-systemd-supervisor.sh` | 1 integration test, 23 scenarios, 0 failures/ignored; test 45.68s, command 53.84s | [real manager](1-8-evidence/real-final.log) |
| `cargo fmt --all -- --check`; `git diff --check` | Passed; 135 added files also passed whitespace checks | [format](1-8-evidence/formatting.log), [diff](1-8-evidence/diff-check.log) |

Each Rust library run includes 548 passing tests and 10 ignored isolated fixtures.
Eight isolated fixtures are invoked by their passing wrapper tests. The ignored
browser fixture was exercised by the explicit Firefox run, and the internal
provider harness plus ignored integration entry were exercised by the real-manager
script. Ignored entries alone are not credited as passes. Manual screen-reader
verification was not performed.

The concurrent-output C fixture and one browser text assertion were strengthened
after the final Rust snapshot. Neither is compiled or executed by the default
Rust suite; both were exercised by their subsequent explicit harness runs. The
final manifest records those two test-only updates. Rust source remained unchanged
throughout the final stable/MSRV/Clippy passes.

## Named requirement coverage

| Requirement | Passing evidence |
| --- | --- |
| Typed manager properties, dependencies, finite bounds and no secret properties | `exact_typed_manager_contract_and_no_secret_properties`; live property assertions; static composition checks |
| Unique ownership, collision refusal, repeated stop, preserving lookalikes | `strict_ownership_namespace_and_random_names`; real `collision` and `crash`/restart recovery |
| Existing approval, pinned descriptor, selected credentials and explicit environment | Real `app-*` cases; direct real source-path replacement; strict fixture environment checks; provider environment unchanged assertion |
| Fork/double-fork/setsid/SIGTERM resistance and independent zombie-aware reaping | Real `orphan`, lifecycle and crash cases; `independent_reaping_observes_zombies_deleted_groups_and_subtrees` |
| Responsive lock/cancel/revoke/shutdown/deadlines; actual Running; cleanup before terminal | `running_is_observed_before_reaping_and_lock_waits_without_holding_authority`; `every_authority_loss_hook_withholds_terminal_until_observed_cleanup`; seven real `app-*` cases |
| Launch/natural-exit revocation and immutable result | Five real `phase-*` barriers; `final_release_revalidates_authority_after_supervisor_setup`; existing terminal immutability tests |
| Manager/helper/exec/stop/monitor failures and admission closure | Version rejection unit test; real `helper-failure` and five `fault-*` cases; `uncertain_cleanup_closes_admission_and_never_persists_terminal` |
| Recovery before admission/state validation, including corrupt state and competing writer | Real crash/restart and populated-tree stop-failure recovery; `startup_cleanup_precedes_registered_image_integrity_validation`; daemon startup cleanup/competing-owner tests |
| Private bridge authentication, truncation, FD counts/seals, release order and parent-death races | Eight `bridge::tests`, including zero-byte SCM_RIGHTS closure and actual helper-parent checks before/after prctl |
| Output and credential disclosure boundaries | Two concurrent fixture processes each write and verify 200 KiB to stdout/stderr; null streams; unit properties, request/provider journals, review/status and durable-state sentinel assertions |
| UI composition | `approval_dispatches_only_committed_ids_and_closes_on_queue_failure`; real Firefox authentication, approval/deny/cancel, replay, focus and accessibility suite |
| Cleanup/cancellation lock ordering | `uncertain_cleanup_releases_execution_registry_before_closing_admission` with explicit synchronization |

The real matrix names are `exit`, `orphan`, `cancel`, `crash`, `collision`,
`helper-failure`, `app-exit`, `app-lock`, `app-cancel`, `app-revoke`, `app-shutdown`,
`app-deadline`, `app-persistence`, `phase-job`, `phase-helper`, `phase-transfer`,
`phase-release`, `phase-exit`, `fault-missing`, `fault-job`, `fault-exec`,
`fault-monitor` and `fault-stop`.

`crash` kills only the isolated provider MainPID and verifies disappearance from
an external process, without provider callbacks, then restarts recovery while
preserving an unrelated namespace lookalike. `fault-stop` proves a resistant tree
is still populated when cleanup uncertainty is reported, retains its lease,
closes admission and then explicitly recovers/reaps it. `fault-exec` uses a
manager-applied test-only seccomp filter to deny execveat after helper launch;
Running must never appear. Missing/job/monitor/stop failures use test-only adapter
injection rather than disrupting the shared user manager. Each scenario has a
40s observer deadline; the real suite has a 900s outer timeout, finite manager and
helper waits, and manager runtime limits. Parent-death tests use pipe barriers,
isolated subreaper state and kernel alarms.

## Mutations and corrective evidence

[Mutation classifications](1-8-mutation-classifications.md) record 19 generated
and 8 semantic mutants, all caught, with passing baselines and no survivors,
compiler/infrastructure failures or timeouts. Patches and individual logs remain
in the evidence directory.

Exploratory failures were not counted as passing evidence. The full suite caught
supervisor initialization occurring before writer-locked provider layout; startup
construction is now inside that cleanup callback. Deterministic red/green tests
caught and fixed zero-byte SCM_RIGHTS descriptor leakage and cleanup/cancellation
lock inversion. Strict lint caught two test-only disallowed macros. Firefox
caught the old approval-copy assertion; it now checks the queued-execution copy.
The interrupted first Rust 1.88 build was stopped to correct the FD leak, not
reported as a pass. Relevant failed logs are retained beside the final results.
