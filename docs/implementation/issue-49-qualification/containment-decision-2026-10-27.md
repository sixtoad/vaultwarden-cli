# Containment contract audit

Superseded product requirement, 2026-10-28: [the CLI controls secret access;
consumer execution is outside its scope](../../secret-access-boundary.md). Consumer
termination, including an optional CLI stop action, is out of scope. The original
audit below is historical evidence, not a current Mac qualification gate.

Status: no supported all-descendant containment mechanism selected. This is a
specific gap in the examined candidates, not proof that native macOS protected
execution is impossible. Installing a privileged service would not resolve it.

The subsequent [bounded feasibility investigation](containment-feasibility-2026-10-27.md)
is complete: no-go for implementing the current general native port, with
explicit reasons and scope alternatives. This earlier audit remains evidence.

Issue 49 requires termination and accounting for protected descendants after
cancellation, lock, expiry, revocation and provider failure, including children
that daemonize. The existing nine native observations exercise bounded fixtures
that register their own descendants before release. They do not establish that
an arbitrary reviewed operation's descendants can all be discovered or stopped.

## Evidence checked

On 2026-10-27, read-only inspection of the M1 host's macOS 27.0.1 manual and
Xcode macOS 27.0 SDK produced a [hashed inventory with line references](evidence/macos-arm64-2026-10-27-api-audit/native-api-inventory-expanded.json).
No service, account, entitlement or system setting was changed. This inventory
describes the inspected files; it is not runtime testing of these candidates.

| Candidate | Evidence | Consequence for this design |
| --- | --- | --- |
| launchd job cleanup | The host's `launchd.plist(5)`, lines 609–613, specifies cleanup of remaining members of the job's process group. Apple's [published manual](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.plist.5) describes the same boundary. | A descendant leaving that group is outside the stated cleanup guarantee. Do not select this as the all-descendant supervisor. |
| kqueue recursive tracking | SDK `sys/event.h`, lines 356–362, marks `NOTE_TRACK`, `NOTE_TRACKERR` and `NOTE_CHILD` unsupported since macOS 10.5. Lines 252–255 say the child PID is not delivered in the fork kevent. Apple's [published header](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/event.h) has the same limitations. | `NOTE_EXIT` remains useful for independently observing an already identified fixture; automatic discovery of every descendant is not established. |
| Endpoint Security event tracking | SDK `ESTypes.h` lists fork notification, while `ESMessage.h`, lines 2711–2719 and 2732–2739, documents dropped-event detection. Apple's [fork notification documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_fork) identifies it as a notification. | Inference: tracking notifications alone cannot prevent a fork, guarantee complete membership after an event gap, or guarantee cleanup after the observer dies. No Endpoint Security client was installed or tested. |
| Coalition termination | Apple's [XNU implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/sys_coalition.c) states that existing members can still fork after a termination request; its syscall checks privileged coalition membership. Coalition headers were absent from the inspected public SDK paths; neither inspected spawn header exposed coalition controls. | Inference: this is not evidence of an available, supported atomic kill-and-reap contract. The published source is not claimed to match the host kernel build. No private syscall was invoked. |

## Separate image-verification candidate

Apple documents kernel-enforced [launch and library constraints](https://developer.apple.com/documentation/security/applying-launch-environment-and-library-constraints)
and a [`cdhash` constraint](https://developer.apple.com/documentation/security/defining-launch-environment-and-library-constraints).
These are worth qualifying for binding a launch to approved signed code. They
do not establish descendant lifetime management. A future image proposal must
verify the supported API/version, signing provenance, full executable/dependency
policy, replacement attacks and the exact release point for synthetic secrets.
This audit does not select that proposal or change the proposed OS baseline.

## What would unblock implementation

A native supervisor proposal needs a supported membership/lifetime contract,
an independent way to establish termination and reap, and recovery after the
supervisor dies. Its tests must cover fork/exit races, double fork, `setsid`,
ignored termination, provider death and restart without relying on cooperative
fixture registration. Resource retention on uncertainty is necessary but does
not satisfy the requirement to stop running protected work.

A restricted operation model that prevents descendant creation, or a virtual
machine boundary, would be a different product proposal. Neither is silently
substituted for the approved native goal. Until a contract is established or the
user explicitly changes that goal, keep production rejection and the existing
qualification status. Cross-account authentication, exact-image launch and
service Keychain evidence remain additional gates after containment is resolved.
