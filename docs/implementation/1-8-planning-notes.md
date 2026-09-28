# Story 1.8 planning evidence

Date: 2026-09-27. Status: planning checkpoint pending; implementation and verification have not started.

## Repository and dependency evidence

Fresh worktree: `/home/sixtocantolla/sessions/day-to-day/vaultwarden-contain-protected-child-processes`.
Branch: `feature/contain-protected-child-processes`.
Fetched origin and created the worktree from updated `origin/main` at `ffd8ed4c434f585b2bcb37b0ca9a8517538be662`. The fresh worktree was clean. No unmerged dependency branch is required.

| Story | Merged PR | Canonical merge commit | Issue |
| --- | --- | --- | --- |
| 1.1 | #19 | b71af8c31fd31a1ebb2b515210a0582b1bd8bf22 | #5 closed |
| 1.2 | #20 | 91a6a662cdfb6b27edba2ca93cd3735b630a1931 | #6 remains open despite merge |
| 1.3 | #21 | 5e5941bc3ce19c9437532900e2b530d093eff7e8 | #7 closed |
| 1.4 | #22 | 041c10837c12a9a8d2b92b36eae5c634856bc9cc | #8 closed |
| 1.5 | #23 | fd6b7eb3dea18d686c844189772fb9e5673ec050 | #9 closed |
| 1.6 | #24 | fc226624a722e82997f4a280776399971a96c7b4 | #10 closed |
| 1.7 | #25 | ffd8ed4c434f585b2bcb37b0ca9a8517538be662 | #11 closed |

GitHub PR metadata and the local first-parent history agree. Provider foundation, constrained policy, sessions, direct requests, one-time decisions, sealed descriptor preparation and login-backed orchestration are present in the base. Story 1.7 deliberately leaves production execution unavailable pending this story.

Read [issue #12](https://github.com/sixtoad/vaultwarden-cli/issues/12) and discussion: open, no comments. It requires systemd-bound descendant cleanup, stale recovery and the provider-only secret boundary.

The original worktree contains untracked planning documents and was left unchanged. Read these absent planning files there:

- `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/docs/stories/1-8-contain-and-reap-protected-child-processes.md`
- `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/docs/epics.md`
- `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/docs/architecture/architecture-vaultwarden-access-2026-09-01/ARCHITECTURE-SPINE.md`
- `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/docs/specs/spec-vaultwarden-access/SPEC.md`

Loaded cached Vaultwarden Epic 1 context and the completed Story 1.7 build spec, plus its checked-in planning/evidence documents. The parent sprint tracker belongs to Oriel; its similarly numbered entries must not change. Vaultwarden story_key is unset.

Workflow renderer was invoked exactly once from the parent project and succeeded. Snapshot: `/home/sixtocantolla/sessions/day-to-day/_bmad/render/bmad-build/day-to-day-d00ae63d9eda/1fb18c5ba28adad60cd9/workflow.md`. Step 2 requires explicit plan approval before implementation. Two read-only subagents investigated lifecycle/composition and descriptor/containment design. Implementation and workflow-directed review agents follow approval.

## Platform probe, not integration-test evidence

- Kernel: `6.18.7-76061807-generic`; unified cgroup v2.
- User manager: `255.4-1ubuntu8.15pop0~1778766128~24.04~85b5073`, reports `running` outside the sandbox. Sandbox bus access returns Operation not permitted.
- Rust stable and 1.88.0 installed; cargo-mutants 27.1.0 installed.
- Real-manager tests appear feasible using host access. None has run yet; this is not review-readiness evidence.
- Proposed support floor: Linux 6.3+, systemd 255+, cgroup v2, existing native x86-64/AArch64 ELF profile, Rust 1.88. Validate actual required manager capabilities/properties rather than trusting only its version string. Report tested versions separately from supported assumptions.

## Implementation design

### Supervisor and authority

Extend the existing ProcessSupervisor port rather than introducing a second execution route. Separate manager job acceptance, helper start, workload exec, outcome, stopping and reaped completion. A returned generic error cannot imply cleanup. Introduce explicit cleanup uncertainty that poisons admission without terminal persistence. No production direct-child fallback.

`application::run_execution` currently holds Authority across synchronous supervision. Register execution and independent cancellation before releasing the short state/backend gate. Preserve durable one-use claims, current policy/arguments, session/request deadlines and published revocation epoch; revalidate after asynchronous preparation and at the helper's final execution-release boundary. Serialize release against cancellation intent; a late loss stops the cgroup. Never hold a provider-state lock while waiting for manager cleanup or output drains.

Add provider-owned request cancellation and requester-revocation lifecycle hooks and exercise them directly. Pairing administration and signed agent transports remain Epic 2 work; this story supplies the containment hook they must call. Do not confuse the existing browser Cancel authentication control with cancellation of running work. Wire successful one-time approval into a bounded provider execution worker and correct approval/status copy. Keep authentication/session/CSRF checks and client redaction intact.

`provider::finish_execution` currently synthesizes Running only after supervision ends. Add a real exec-confirmed Running transition and claim/execution-bound cleanup-confirmed terminal transition. Authority to record cleanup must not require permission to launch still being live. `provider_store::invalidate_unexecuted` currently terminalizes Running and claimed Approved without evidence; prevent this for active/uncertain execution. Resolve epoch/state-validation interactions explicitly. Persistence faults invalidate launch authority, trigger cleanup, and cannot report success.

### Private launch bridge proposed for approval

No existing architecture or Story 1.7 document specifies a concrete descriptor-transfer protocol. Approval of this plan adopts the following provider-private mechanism:

1. Start a trusted provider-owned helper binary inside each systemd transient request service. Its public arguments contain only a private socket path and non-secret identifiers. Validate helper installation ownership and safe ancestry. Never launch the protected executable by its original pathname.
2. Use a checked provider-owned 0700 runtime directory and mode-0600 Unix SOCK_SEQPACKET endpoint. Authenticate both peers with kernel credentials. Match the helper against manager-observed MainPID, invocation identity and cgroup, and validate the provider service/instance identity. Socket paths are not approval capabilities.
3. Observe the start job, helper exec, expected unit relationships/properties and current authority before transferring any credentials. Helper blocks until this handshake completes. Verify provider is the intended active service, not an arbitrary process launched from a shell.
4. Transfer the already verified sealed executable FD with SCM_RIGHTS, receiving with MSG_CMSG_CLOEXEC. Reject truncation, extra/missing FDs, malformed ancillary data, wrong protocol, oversize fields and unexpected seals; close all received resources on rejection. Transfer argv and explicit environment only over this channel in bounded zeroizing buffers. No manager Environment/EnvironmentFile/SetEnvironment, descriptor-store credential values or secret-bearing ExecStart properties.
5. Helper acts as a subreaper. Prepare argv/envp and pipes before fork. Child sets PR_SET_PDEATHSIG(SIGKILL), verifies getppid against the captured helper PID, and uses execveat(AT_EMPTY_PATH) on the transferred descriptor. The actual parent is the helper, not the provider. Keep the forking helper thread alive. No unsafe allocation/locking/destructors after multithreaded fork; prefer a single-threaded helper through fork.
6. A CLOEXEC error pipe distinguishes protected-image exec success from helper launch; its payload is a closed failure category. Capture/discard both streams concurrently with bounded zeroizing storage. Helper standard streams are null, core dumps disabled, and no secret payload receives Debug/Serialize/log treatment.
7. On main workload exit, stop remaining descendants through the manager. Helper continues draining and waitpid-reaping adopted descendants while handling termination until ECHILD. It reports only redacted process outcome/reaping evidence. Manager retains final SIGKILL authority even if helper/provider dies.

### Typed systemd contract

Add a direct Linux dependency on the already locked dbus 0.9.12 stack if suitable for the typed client. Do not shell out to systemd-run for production behavior or construct untyped command strings. Build/assert exact a(sv) property shapes, including ExecStart a(sasb), string-array dependencies, booleans and microsecond u64 timeouts.

Required request properties include BindsTo/PartOf/After targeting `vaultwarden-accessd.service`, KillMode=control-group, SendSIGKILL=true, Restart=no, explicit service type/exit semantics, finite stop/start/runtime limits, null helper streams and no secret environment. Use Type=exec to observe helper execution, with separate workload exec acknowledgment. Select ExitType consistently with helper supervision; do not mistake either choice for reap evidence. Bound the service runtime to authority as defense against monitor failure.

Subscribe before creating jobs; correlate JobRemoved with the returned job and inspect actual unit/service states. Handle instant exit, job rejection, dependency failure, collisions, repeated stop, disconnected monitoring and unit garbage collection. Use unique random names and mode fail; never replace an existing service on collision. A failed stop/job or inaccessible monitoring cannot manufacture terminal evidence. On disconnection, close admission and release no launch capability, attempt scoped cleanup/reconnection, and fail the provider service if necessary so manager dependency cleanup applies independently.

### Recovery and reaping proof

Use a strict request-name grammar with stable provider identity namespace plus per-execution randomness. Validate ownership through namespace, exact provider dependencies, expected helper ExecStart and transient-unit identity; a loose prefix is insufficient. Test unrelated prefix lookalikes and mismatched relationships. Never reset/stop arbitrary units or use global manager cleanup.

Run recovery under the existing exclusive writer lock via Provider::start_with_cleanup, before durable startup invalidation, UI/socket binding or work admission. Stop owned stale units and confirm termination/reaping before reconciling their records. Preserve cleanup-before-state-validation and competing-provider exclusion. Account for request After ordering so recovery never waits on starting new request units before provider activation.

Empty cgroup.procs/populated=0 or removed unit alone is insufficient. Use helper waitpid/ECHILD evidence normally plus manager exit/stop observation and bounded independent /proc cgroup scans including zombies and the kernel's ` (deleted)` suffix. Forced cleanup/provider crash/recovery must independently establish no process remains in the exact owned cgroup/subtree, correlating process identity to avoid PID reuse. Scan after containment is closed and no live process can fork; pre-kill snapshots alone miss forks. Unreadable or incomplete evidence fails closed. Preserve owned identities until observation finishes, even if the manager unloads the unit.

## Authoritative sources checked during planning

- [systemd v255 manager D-Bus interface](https://raw.githubusercontent.com/systemd/systemd/v255/man/org.freedesktop.systemd1.xml): typed StartTransientUnit, job objects, Subscribe, JobRemoved, unit/process observation. Method acceptance is distinct from job completion; Type=exec is still only helper execution.
- [systemd v255 unit relationships](https://raw.githubusercontent.com/systemd/systemd/v255/man/systemd.unit.xml): combine BindsTo with After for the stronger active-provider requirement; PartOf propagates stop/restart one way.
- [systemd v255 kill behavior](https://raw.githubusercontent.com/systemd/systemd/v255/man/systemd.kill.xml): control-group stops remaining descendants and escalates after the stop timeout when SendSIGKILL is enabled.
- [systemd v255 service semantics](https://raw.githubusercontent.com/systemd/systemd/v255/man/systemd.service.xml) and [transient settings](https://raw.githubusercontent.com/systemd/systemd/v255/docs/TRANSIENT-SETTINGS.md): helper type, main/cgroup lifetime and transient execution settings. Check implementation-specific property signatures against installed introspection and versioned manager source when coding.
- [Linux cgroup v2 process semantics](https://docs.kernel.org/admin-guide/cgroup-v2.html): fork inherits cgroup; zombies retain association until reaped but do not appear in cgroup.procs; removed cgroup paths carry a deleted suffix in proc. This is why separate reaping evidence is required.
- [Linux parent-death signal](https://www.man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html): applies to the creating thread, does not retroactively signal an already-dead parent, and requires explicit race handling. [Unix sockets](https://man7.org/linux/man-pages/man7/unix.7.html) documents SCM_RIGHTS and peer credentials; validate message/control handling against that API during implementation.

## Required verification matrix

All fixtures use synthetic credentials and deterministic barriers/acknowledgments with deadlines. Tests own unique unit namespaces and clean up only resources they create. Never install/replace/stop the operator's real provider service for tests: use uniquely named provider harness units and test-only adapter composition.

1. Exact D-Bus signatures/properties/dependencies, no manager-visible secrets, random names/collision refusal, actual job versus helper versus exec outcomes.
2. Existing approval/descriptor/login path through the real adapter, synthetic selected credentials, path replacement after verification, inherited environment exclusion, parent environment unchanged, large simultaneous discarded streams.
3. Descendants outliving the immediate parent, double fork, setsid, ignoring SIGTERM; all disappear including zombies. Main exit alone withholds terminal state.
4. Lock, request cancellation, requester revocation, shutdown, deadlines and abrupt provider SIGKILL; independent external observer verifies crash cleanup with no provider callbacks executed.
5. Authority loss at job acceptance, helper connection, credential transfer, final release and natural exit; repeated stop; state-persistence failure after launch; terminal immutability.
6. Startup recovery stops stale owned services before admission, preserves unrelated and namespace-lookalike services, handles manager unloading and state corruption safely.
7. Missing/incompatible manager, rejected job, failed helper/exec, stop failure, monitor disconnect and unreadable reaping evidence all fail closed with stable redacted categories.
8. Credential sentinels absent from unit properties/description/ExecStart/environment, journal, client/status/UI responses, audit and persistent state. Assert output is discarded without retaining decoded secrets.
9. Parent death before/after prctl, actual helper-parent identity, exec-error pipe, peer/FD/protocol validation and cleanup of partial setup.

Before workflow review: formatting; full all-targets tests; Rust 1.88 all-targets; explicit static contract tests; strict Clippy; real manager descendants/crash/recovery suite. Opt-in skips are not passes. Record exact commands, exit codes, totals, skips and platform. Real integration tests must finish successfully or story remains out of review-ready status.

Scoped mutation testing covers changed launch guards, lifecycle transitions, cleanup, recovery, and terminal persistence. Preserve baseline and mutant logs, patches, source revision/diff fingerprint and named test evidence. Fix meaningful survivors; justify equivalent mutants with specific evidence. Compile and infrastructure failures are distinct from kills; investigate timeouts. Re-run affected verification after fixes and complete git diff --check, including added files, before reviews. Then perform workflow-directed independent reviews and human implementation/evidence acceptance. No commit, push or PR until authorized.
