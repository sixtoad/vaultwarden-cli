# Native containment feasibility: no-go for the current port

**Historical decision, superseded by the operator's 2026-10-28 boundary.**
[The CLI controls secret access; consumer execution is outside its scope](../../secret-access-boundary.md).
The no-go below applies to a rejected CLI responsibility. Even the intermediate
optional CLI stop feature has been withdrawn. Preserve this investigation as
history; do not use it to block the native secret-access port or require a VM
or restricted in-process-only product. Original investigation follows.

Decision date: 2026-10-27. Investigation complete. **Do not proceed with the
general native protected-command implementation under the current requirements.**
None of the examined mechanisms establishes the required combination of complete
descendant ownership, termination, independent reap evidence and crash recovery.
This is an engineering no-go on the available evidence, not a proof that macOS
can never support the feature.

The user authorized this bounded feasibility investigation after the native
probe and regression runs. This decision does not change issue 49, approve a
reduced operation model, or authorize privileged setup. The earlier
[contract audit](containment-decision-2026-10-27.md) remains supporting evidence.

## Decision criteria

An eligible design must satisfy all five conditions before a security prototype
can meaningfully qualify it:

1. **Ownership:** every protected descendant belongs to a durable job identity,
   including after double fork, `setsid`, reparenting and supervisor death.
2. **Closure:** cancellation can stop further protected process creation or
   otherwise account for concurrent creation while terminating the complete job.
3. **Termination and reap:** independent evidence accounts for both running and
   exited processes; signal delivery or a helper acknowledgement is insufficient.
4. **Recovery:** provider/controller failure revokes launch authority and has a
   defined cleanup path that does not depend on that failed process running code.
   Restart cannot lose ownership, recycle a live identity or replay approval.
5. **Supported deployment:** the guarantee uses a supportable macOS interface
   without weakened platform security or reliance on an undocumented behavior.

These conditions map to `ProcessSupervisor`, `ExecutionControl` and
`CleanupEvidence` in `src/access/ports.rs`. The existing Linux implementation
only reports `Reaped` after manager cleanup succeeds; it reports uncertainty and
closes admission when cleanup fails. Its cgroup ownership and reap evidence
cannot be replaced by a list of recently observed macOS PIDs.

## Candidate disposition

| Candidate | Useful property | Missing requirement / disposition |
| --- | --- | --- |
| launchd job and process group | Service lifecycle and group signalling | A daemonized descendant can leave the group. Fails ownership/closure for the accepted workload class. |
| PID-tree enumeration and kqueue | Observation of known process identities | Recursive tracking is unsupported; enumeration and registration do not close concurrent forks. Cannot establish complete ownership after reparenting or controller loss. |
| Dedicated UID per job plus repeated signalling | Potential durable attribution and separation from unrelated jobs | Does not itself prevent forks or provide an atomic kill-and-reap operation. Recovery, complete enumeration and zombie accounting remain unproved. Not selected. |
| Endpoint Security | Rich authenticated process events and selected authorization events | Fork is a notification; notifications may be dropped. There is no demonstrated complete membership/cleanup contract across observer loss. Not selected. |
| Coalition interfaces | Kernel accounting and membership concepts | Published termination semantics still permit member forks; inspected public SDK lacks the relevant controls. No supported deployment/closure contract established. |
| App-bundled XPC service | Documented service lifetime tied to its client | That promise describes the service process, not arbitrary external descendants launched by it. A connection invalidation is not independent reap evidence. Potential building block only for a changed worker model. |
| App Sandbox / custom Seatbelt profile | Restricts resource access; children can inherit restrictions | App Sandbox permits spawning. Custom deny-fork restrictions lack a qualified supported contract here; the native SDK marks `sandbox_init` unsupported. Not selected for the current port. |
| Resource limits or cooperative parent monitoring | Limits process count or lets participating code self-terminate | A process cap does not close the job dynamically; cooperative monitoring does not cover arbitrary descendants. Preventing all spawning would change supported operations. |

The first, second, fourth and fifth rows are supported by the previous
[native manual/SDK audit](evidence/macos-arm64-2026-10-27-api-audit/native-api-inventory-expanded.json).
The remaining routes were investigated in this continuation, as detailed below.

## Dedicated UID: why a broadcast is insufficient

Apple's archived [`kill(2)` contract](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/kill.2.html)
describes signalling eligible processes, not joining their termination. Published
XNU revision `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` corroborates that distinction:
[`killpg1`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_sig.c#L1548)
counts eligible zombies as found and broadcasts through `proc_iterate`.
[`proc_iterate`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_proc.c#L3827)
collects a PID list under the process-list lock, skips processes in construction,
then releases the lock before applying callbacks. This published revision is
not claimed to be the exact source of the test host's kernel.

The inferred failure schedule is concrete: the list contains parent A; after
list collection, A creates child B before A receives its signal; signalling
the collected list does not include B. Repeating the scan may eventually catch
B but does not establish bounded convergence while processes continue creating
children. This is source-level reasoning, not a native reproduction. A stop-
then-kill loop also needs proof that every process is stopped and no in-flight
creation can escape; the inspected interfaces supplied no such contract.

An empty scan must additionally account for incomplete enumeration, permissions,
processes being created, identity changes and non-child zombies. The archived
[`waitpid` contract](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/waitpid.2.html)
waits for children; sharing a UID does not make an orphan the supervisor's child.
An alternative independent reap proof could be acceptable, but none was
established. No broadcast signal was run on the operator account and no account
was created for this investigation.

## XPC, sandboxing and process limits

Apple's current [XPC overview](https://developer.apple.com/documentation/XPC)
documents a bundled service process tied to its client's lifetime. It also
describes service configurations for work that outlives a client; the exact
service type matters. The archived [service guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
documents abrupt service termination and connection interruption/restart.
Neither cited contract extends that promise to every subprocess an external
command might launch. Inference: wrapping that command in XPC does not discharge
the descendant requirement. A service doing only reviewed in-process work is
a different candidate, still needing cancellation and independent death tests.

Apple DTS explicitly confirms that macOS [App Sandbox allows child processes](https://developer.apple.com/forums/thread/747499).
The inspected SDK's `sandbox.h` marks `sandbox_init` unsupported and reserves
flag values other than named profiles. The host's `sandbox-exec` manual also
marks the tool deprecated. These observations do not assert that custom
profiles cease to enforce restrictions; they do rule out treating an unqualified
custom profile as a supported production contract for this port.

Apple's archived [`setrlimit` documentation](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setrlimit.2.html)
defines `RLIMIT_NPROC` as a simultaneous-process limit for a user ID. A finite
limit allows process turnover and does not supply job ownership or reap. A hard
limit intended to disallow all children could be investigated for a restricted
worker, but is not a qualified solution for operations that need descendants.

## Evidence and prototype gate

The new [native inventory](evidence/macos-arm64-2026-10-27-feasibility/containment-feasibility-inventory.json)
records exact hashes and line references for `libproc.h`, `sandbox.h` and the
host's `sandbox-exec` manual on macOS 27.0.1 build 26A434 with SDK 27.0. The
requested host paths for `kill(2)` and `setrlimit(2)` manuals were absent; those
claims use the explicitly archived Apple references above, not invented native
manual evidence. All host actions in this investigation were read-only apart
from writing the report in the previously authorized private test directory.

**No candidate passed the contract gate, so no new supervisor prototype or
runtime security test was run.** Passing a bounded simulation could not fill
the missing lifetime contract. Existing evidence remains nine passing primitive
observations, 16 passing Linux harness tests, 15 passing Mac harness tests with
one platform-specific skip, and one passing native unsupported-platform test.
Those results are unchanged and do not become production qualification.

## Disposition and concrete next choices

Close this feasibility investigation with no-go; keep the larger qualification
specification in progress and macOS protected execution disabled. Reopen the
general native design only when a supported mechanism addresses the specific
missing guarantees, with an identified API/version and failure semantics. More
successful runs of the current cooperative fixtures are not reopening evidence.

My recommended next proposal is a **restricted native first release**, if the
operator accepts its compatibility cost. It would keep the human/agent approval
flow but accept only fixed first-party operation types whose worker does its
work in-process. Arbitrary executable paths, shell commands, plugins, external
OpenSSH and subprocess-producing adapters would be rejected before secret
resolution. Worker lifetime, dependency behavior and absence of indirect work
delegation would still require qualification; source review alone is not enough.
This is a proposed scope change, not an approved or already-safe implementation.

If preserving external-command compatibility matters more, the alternative is
a local VM boundary with the provider and complete workload tree inside it.
That preserves local operation without a separate Linux host but changes the
native-execution requirement and may require Linux-compatible workloads. VM
lifecycle, storage, secrets and controller-death behavior also require a new
design and tests. Neither alternative is implemented by this decision.
