# Story 1.7 planning evidence

Date: 2026-09-25. Planning, implementation, verification, and workflow-directed review are complete.

## Repository and dependencies

Fresh worktree: `/home/sixtocantolla/sessions/day-to-day/vaultwarden-login-backed-child`.
Branch: `feature/run-login-backed-child`.
Fetched `origin/main` and verified GitHub main: `fc226624a722e82997f4a280776399971a96c7b4`.
All six dependency merge commits are ancestors of this base; no dependency branch is required.

| Story | Implementation | Merged PR | Merge commit |
| --- | --- | --- | --- |
| 1.1 | `b5de6d6aa2a6039899ae92909703a9f5e84cadbd` | https://github.com/sixtoad/vaultwarden-cli/pull/19 | `b71af8c31fd31a1ebb2b515210a0582b1bd8bf22` |
| 1.2 | `339d7ffb5ec15c8c34767626d614abd7f37e131c` | https://github.com/sixtoad/vaultwarden-cli/pull/20 | `91a6a662cdfb6b27edba2ca93cd3735b630a1931` |
| 1.3 | `77d6617c1da8bfda3d484e0a8ee9c6d19c8cb2fd` | https://github.com/sixtoad/vaultwarden-cli/pull/21 | `5e5941bc3ce19c9437532900e2b530d093eff7e8` |
| 1.4 | `b4e8d579b458adabd5c6e9ccd39b959c1d4cd8ea` | https://github.com/sixtoad/vaultwarden-cli/pull/22 | `041c10837c12a9a8d2b92b36eae5c634856bc9cc` |
| 1.5 | `599a6c8b4de58531a9cfc42e6ef454d4846c7a4f` | https://github.com/sixtoad/vaultwarden-cli/pull/23 | `fd6b7eb3dea18d686c844189772fb9e5673ec050` |
| 1.6 | `a66afaefbdeaba69493014e5f684434522700bef` | https://github.com/sixtoad/vaultwarden-cli/pull/24 | `fc226624a722e82997f4a280776399971a96c7b4` |

Story 1.6 additionally includes CI/platform/rustls fix `ee3283ae024053e757e6bf5cd61308ea69453fa3`.
Story 1.2 issue #6 remains open despite merged implementation; issues #5 and #7–#10 are closed.
Story 1.7 issue https://github.com/sixtoad/vaultwarden-cli/issues/11 is open and has no comments.
Story 1.8 issue #12 is open; no supervisor implementation exists in the base.

## Sources and workflow state

The renderer belongs to the parent project `/home/sixtocantolla/sessions/day-to-day`.
Successful workflow snapshot: `_bmad/render/bmad-build/day-to-day-d00ae63d9eda/1fb18c5ba28adad60cd9/workflow.md` under that project.
The original repository worktree has untracked planning documents; it was left unchanged.
The fresh worktree was clean before this planning artifact was written.
Planning documents absent from the fresh worktree were read at:

- `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/docs/stories/1-7-run-login-backed-child-without-disclosure.md`
- `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/docs/epics.md`
- `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/docs/architecture/architecture-vaultwarden-access-2026-09-01/ARCHITECTURE-SPINE.md`
- `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/docs/specs/spec-vaultwarden-access/SPEC.md`

Loaded the existing Vaultwarden Epic 1 context and completed Story 1.6 build spec from the parent implementation-artifacts directory. Preserve Story 1.6's descriptor verification, sealed snapshots, isolated rejection oracles, safe fixture ancestry, and bounded durable validation work.
The parent's current sprint-status.yaml belongs to **Oriel**, not Vaultwarden; its similarly numbered Story 1.7 must not be updated. Vaultwarden story_key remains unset.

Three read-only subagents investigated dependencies, backend selection, and execution; the dependency agent also investigated lifecycle persistence. Implementation and workflow-directed review agents follow after plan approval.

## Design decisions for implementation

1. Reuse `VaultwardenBackend::selected` and `SecretBackend::resolve`. They already fetch an immutable item, verify its ID/type/deletion state and exact marker, handle personal/organization/item keys, and return only selected `SensitiveString` values. Strengthen isolated tests instead of introducing broad decrypted models or CLI presentation APIs. Malformed unselected value ciphertext must not prevent otherwise valid selected-field resolution. Field names/marker metadata may be decrypted to identify eligible selections; unselected credential values must not be decrypted.
2. Extend the crate-private policy binding view to preserve field-to-environment mappings. Build an explicit environment with fixed `LANG=C` and `LC_ALL=C`, plus only policy credential mappings. Reserve baseline names, existing dangerous loader/shell names, and `VAULTWARDEN_`/`BITWARDEN_` prefixes. Reject duplicates, resolver cardinality mismatch, NUL bytes, and excessive encoded size. Use a conservative 32 KiB total encoded environment limit and test exact boundaries; empty selected values are valid when the field exists. Never inspect or mutate inherited process environment in the implementation.
3. Store environment strings and exec-ready NUL-terminated entries in zeroizing owners with redacted Debug and no Serialize. Prebuild pointer arrays before any fork boundary; do not allocate, lock, format errors, or run Rust destructors in a forked multithreaded child. Extend the existing sealed-descriptor execveat path; no path reopening or shell runner.
4. Add a private durable `execution_claimed` flag, defaulting false for old records, and an internal noncloneable claim. Under provider serialization, guard claim persistence against current binding and live authority. Reject already claimed approvals. Keep status Approved during preparation; publish Running only after launch confirmation. Revalidation of a held claim must differ from admission of a new attempt.
5. Publish a monotonic atomic lock/revocation epoch before waiting for the provider gate. Compare it after blocking image/backend/setup/persistence work and at the launch boundary, together with shutdown, session/request deadlines and exact durable binding. Ordinary lock must remain reversible through human unlock; do not reuse permanent shutdown as its normal mechanism.
6. Permit claimed Approved-to-Failed for prelaunch failures; retain immutable terminal states. Burn claims on preparation, resolution, setup, supervisor and launch errors. Any uncertain claim/start/result persistence closes admission and attempts both backend clearing and state invalidation; a successfully launched fixture must also be killed/reaped on subsequent start-persistence failure. Restart invalidation applies to claimed approvals.
7. Introduce the architecture's crate-private `ProcessSupervisor` port and an unavailable production implementation. Require supervisor availability before resolving real secrets. Controlled `cfg(test)` supervisors exercise harmless fixture launches through the same descriptor/environment/output code. No production direct-child fallback. Story 1.8 must supply manager-bound transient units, descendant cancellation/reaping, provider-death handling and startup cleanup before enabling secret-bearing execution.
8. Drain stdout and stderr concurrently into fixed-size zeroizing buffers; discard continuously, retry interrupted reads and map other failures to closed categories. Avoid unbounded buffering, output decoding, log/IPC relay and retained pipe deadlocks. Join drainers and reap fixture children on every exit path; bound test subprocesses and cleanup hung mutation cases.
9. Success reports Completed with exit 0. Nonzero exit and signal termination report distinct stable failure categories; do not synthesize negative exit codes. Failure to persist a terminal result cannot be reported as successful completion. Connect approval dispatch through provider-owned execution orchestration; adjust existing approval copy/status handling only as needed. No history UI work.

## Verification obligations

Acceptance evidence must map all four story criteria and the user's expanded requirements to named tests. Use synthetic credentials only, deterministic channels/barriers, and independently valid negative fixtures. Observe sentinels through real child output while asserting absence from serialized client/status/review responses, UI, logs, audit and on-disk state. Include large simultaneous stdout/stderr, success, nonzero exit, signal, launch/setup/backend/persistence failures, and cleanup.

Run formatting, complete all-targets suites, relevant Linux native executable fixtures, strict Clippy and Rust 1.88 verification. Use `scripts/with-secure-test-tmpdir.sh`; its safe HOME ancestry and fixture ownership may require sandbox escalation. Do not weaken owner/mode verification or count infrastructure rejection as security-test success.

Run scoped cargo-mutants plus manual semantic mutations for exact field/item selection, environment construction, approval/claim/revalidation, output capture/discard, and failure cleanup. Save baseline/mutant logs, exact patches, source fingerprints, named test results and classifications. Fix meaningful survivors; equivalent/redundant classifications require specific evidence. Compiler failures and infrastructure failures are separate categories; timeouts require investigation and are not automatically catches.

Run `git diff --check`, including added-file whitespace inspection. Wait for every required job before review. Report exact counts, skipped/live-account early returns, architecture/OS limitations, any blocked required checks, and the remaining Story 1.8 integration dependency. Finish workflow-directed reviews and human implementation acceptance before any commit, push or PR.
