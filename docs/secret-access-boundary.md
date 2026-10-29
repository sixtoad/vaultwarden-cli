# Secret access is not execution authority

Accepted product boundary, 2026-10-28. This document governs new design and
changes to the protected CLI/provider, including issue 49. It supersedes earlier
requirements that made program termination or descendant containment a condition
of secret access. The Linux delivery implementation follows this boundary; macOS protected delivery
has a native Apple Silicon source candidate; installed deployment qualification
remains separate. See the [native implementation record](implementation/issue-49-native-provider.md).

## Who controls what

Vaultwarden CLI answers: **may this recipient receive this secret for this
approved request?** It authenticates requests, obtains the required approval,
enforces the approved scope, prevents replay and delivers through the approved
channel. It protects its credentials, state and temporary resources.

Deciding what a consumer program may run and when it should stop is outside
this project’s responsibility. Receiving a secret does not transfer execution
authority to Vaultwarden CLI. No particular caller, sandbox or external
orchestrator integration is required by this boundary.

| Responsibility | Owner |
| --- | --- |
| Authenticate the request and approved recipient; approve and deliver a secret | CLI/provider |
| Reject a denied, expired, replayed or otherwise unauthorized request | CLI/provider |
| Prevent new delivery after vault lock or removal of an app's access | CLI/provider |
| Launch, sandbox, supervise, pause, cancel or terminate an agent and its helpers | Caller or separately authorized execution owner |
| Decide what cancelling a sandbox does when work uses several secrets | Execution owner, under its user's policy |
| Protect and clean up the CLI's own resources without damaging live consumers | CLI/provider, with an explicit resource handoff contract |

This is a standalone project boundary, not a requirement to integrate with an
external execution-management system.

## Approval and cancellation mean specific things

One approval authorizes one request, bound to its recipient and scope. A second
request cannot reuse that consumed approval. There is no implicit reusable grant
because a program is running, was paired or received a password previously.

- **Cancel request:** prevent a pending, not-yet-delivered request from delivering
  its secret. Serialize cancellation against final delivery; do not report that
  an already-delivered secret was taken back.
- **Lock vault:** prevent further delivery through the locked provider session.
- **Remove app access:** reject future requests using the removed authorization.
- **Cancel an agent/program:** a separate action by its user or execution owner,
  outside the scope of the above CLI actions.

Cancellation, lock, expiry and access removal must not signal consumer programs,
kill descendants, ask a service manager to stop workloads or instruct an external
runner to terminate them. A blocked new request must not implicitly become a
termination command. The runner may independently choose cancellation under its
own explicit policy, including when an agent regains secret access.

Do not add an optional “stop programs holding this password” feature to the CLI.
That intermediate proposal was withdrawn when the operator clarified ownership.
Any future transfer of execution responsibility needs a new explicit product
decision, not an inference from administrator privileges or existing code.

## A delivered password cannot be recalled

An approved recipient may save, forward or use a password to establish a remote
session. Stopping the recipient cannot erase copies or undo those actions.
Approval therefore trusts the specified recipient with the disclosed value;
termination is not a password-revocation mechanism.

A program that received two secrets may keep using both values. Removing future
access to one does not remove that value from memory and does not give the CLI
authority to stop work using the other. The execution owner can choose to stop
the whole agent/sandbox under its own policy. Password rotation or remote-session
revocation belongs to the relevant service and is not implied by local CLI access
removal. Avoid the ambiguous label “revoke password.”

## Pipes do not bypass approval

Secret delivery must bind the approved request to the intended recipient and
delivery channel. A request, pipe, process name or caller-supplied PID alone
does not establish that identity. The CLI must reject unauthorized delivery and
must not leak values into logs, diagnostics, audit records or unrelated channels.
Any supported delivery channel needs specification and tests; this decision does
not introduce an unrestricted secret-export endpoint or require a new integration.

The execution owner may use redacted request results to make its own decisions.
The CLI does not prescribe a termination policy or require proof that an agent
has stopped as a prerequisite to denying a new secret request.

## Resource cleanup is a separate obligation

The CLI may close its own delivery handles, clear its own sensitive buffers,
cancel its own resolver and manage its own service. That does not extend to
programs consuming secrets. Provider shutdown must not intentionally take down
consumer workloads through inherited service dependencies or parent-death hooks.

Private temporary files or shared resources need explicit ownership and lifetime
rules. Prefer an explicit handoff or a delivery mechanism that does not leave
provider-owned files needed by consumers. Do not delete resources still in use,
recycle a live identity, assume a whole process tree is gone or invent cleanup
evidence. If a particular delivery mode cannot safely manage its resources,
disable that mode and explain the limitation; do not turn it into a requirement
to supervise all consumer programs or block the whole macOS port.

## Implications for issue 49 and existing code

Native macOS support needs authenticated approval/delivery, recipient identity,
safe storage and resource handling, replay protection and private transport.
It does not need a macOS equivalent of Linux process-tree containment simply to
deliver an approved secret. The earlier containment no-go is historical evidence
about a responsibility this product no longer claims. It does not require a VM,
a restricted in-process-only product or a new CLI supervisor.

The Linux implementation separates final delivery from subsequent observation:

- Cancellation, lock and access removal invalidate authorization. The delivery
  worker closes its observation channel without terminating released consumers.
- A confirmed main-process result can be recorded while descendants continue.
  `observation_lost` means the provider cannot establish the result; it does not
  mean the program stopped or its password was recalled.
- New transient services have no provider stop dependencies or access-derived
  runtime limit. Consumer execution has no parent-death or tracer-exit kill hook.
  Recovery observes retained services without stopping them.
- Protected SSH uses a provider-managed agent for each approved request. The
  private key stays in provider memory; the SSH client receives a signature,
  never a private-key file. Identity and signing requests are tied to the approved
  process, selected key, pinned server and remote user. One approval permits one
  authentication signature, not an open-ended agent session.
- Lock, cancellation, expiry and access removal prevent subsequent signing once
  they win the final delivery check. Closing the provider's agent ends its key
  service without terminating the SSH client or an established connection. A
  signature already delivered cannot be recalled. A new authentication requires
  a separately approved request; ordinary traffic on an established connection
  does not require another signature.
- Agent sockets and public host-key files contain no private key. They have their
  own cleanup rules, independent of consumer termination. Legacy private-key files
  that may still be in use remain untouched; they do not block requests through
  the new agent path.
- Producer output is not submitted to the vault after cancellation wins the
  final authorization race. A vault write already admitted at that boundary may
  finish; cancellation waits for the bounded write call and cannot recall an
  already-issued remote effect.

This change applies to newly launched workloads. Already-running workloads from
an older version retain their original systemd dependencies and helper behavior.
Installing a new binary cannot retroactively remove those hooks. Let legacy work
finish before stopping or upgrading its provider; this change does not terminate
it for the operator. Update provider and clients together because older versions
may reject the new `observation_lost` result in responses or saved history. Never
delete consumed approvals to make an older binary accept the state. No installed
services are modified by these source changes.

## Required regression checks for the migration

- Cancellation or lock wins before release: no value is delivered. Release wins:
  report delivery accurately, without claiming recall or terminating consumers.
- Repeating a consumed request cannot deliver again; later independent requests
  undergo their own authorization checks.
- Lock, expiry, access removal, disconnect and provider shutdown do not directly
  or indirectly request termination of a consumer or its descendants.
- A run using multiple secrets continues independently of future-access changes;
  the execution owner's separate cancellation remains its responsibility.
- Authenticated secret delivery reaches only the approved destination;
  errors and audit/status records contain no secret values.
- A platform without descendant containment can still qualify secret delivery.
  Unsafe delivery modes remain unavailable without broadening CLI authority.

Tests that expect automatic consumer termination must be migrated, not treated
as immutable product intent. Historical evidence should remain labelled with the
old contract; do not rewrite it as proof of the new behavior.
