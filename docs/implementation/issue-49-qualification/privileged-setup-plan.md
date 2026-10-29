# Prepared privileged setup proposal — NOT executed

Policy update, 2026-10-28: [consumer execution is outside CLI scope; the CLI controls secret access](../../secret-access-boundary.md). The proposal must be revised for that
model before execution. Consumer containment/termination is not a CLI capability
to install. Safe CLI-owned resources and authenticated delivery remain mandatory. No privileged setup is authorized here.

The user authorized repository fixtures/reports and subsequently the unprivileged
M1 native run and its continuation. Those runs are recorded in the native run
report. Account creation, service registration, privileged ownership changes,
installation, production signing/notarization or system modification still require
explicit authorization of concrete host-specific changes. This file proposes
that review surface. The runner neither uses sudo nor runs installation tools.
An authorized unprivileged native fixture run includes disposable local ad-hoc
signing of its generated probes. That signing uses no production identity,
Keychain credential, notarization service or privileged installation and does
not require a second production-signing authorization.

## Proposed disposable resources

| Resource | Proposed boundary | Pre-authorization evidence still needed |
| --- | --- | --- |
| Disposable Apple Silicon Mac | Native arm64; SIP and Gatekeeper unchanged; record exact macOS build | Host identifier, owner authorization, restore/recovery plan and actual OS matrix |
| `_vw49provider` | Dedicated non-login service UID, no admin/sudo; private state | Account collision check, reserved UID, home/shell/group plan and ownership diff |
| `_vw49agent_a`, `_vw49agent_b` | Different restricted UIDs, no operator/provider/admin/session/service authority | Exact account/group membership, safe UID allocation, independent key enrollment |
| Operator identity | Existing authorized human, separate from both agents and provider | Enrolled UID and signed companion identity; forbid agent UID substitution |
| `/Library/Application Support/VaultwardenQualification/<run-id>/` | Provider-private state and no-writer image staging; manifest-owned resources only | Exact modes/ACLs/owners, ancestry checks, signed version manifest and source hashes |
| `dev.vaultwarden.qualification.<run-id>` service | Narrow controller, fixed signed helper and typed endpoints | **No service definition yet:** provider lifecycle and authenticated delivery contract unresolved; review full plist/binary/entitlements before any registration |
| Service Keychain test item | Synthetic bootstrap credential only, signed access requirement, no plaintext fallback | Exact service access group/ACL and reboot/login/lock/delete plan |

These names and destinations are proposals, not permission to overwrite existing
resources. UID allocation must happen only after checking the authorized host.
No agent should receive provider credentials, human approval authority, debug
entitlements or generic privileged execution. No registration plan can rely on
launchd process-group cleanup as an all-descendant containment guarantee.

## Review packet and rollback

Before asking to execute setup, prepare the actual account/group diff, fixed
file destinations with modes/ACLs and signatures, service definition and caller
authentication requirement, resource ownership manifest, collision checks,
commands and expected results. Include the exact-image and resource-lifetime
contracts and the authenticated handoff to the execution owner. Do not install
a consumer process supervisor as part of this secret-access service. Do not install a service
to hide a missing mandatory boundary. No runnable privileged script is provided
while these inputs are absent.

The teardown must first close admission and independently account for owned
work across crash/restart. Delete only manifest-owned files/accounts/items after
proven cleanup and confirmation that no unrelated resources use them. Retain
private material and prevent identity reuse when ownership or reap is uncertain.
Preserve redacted evidence. Do not disable SIP, Gatekeeper, signature checking,
library validation or OS diagnostics globally to make a probe pass.

Native unprivileged observations can be authorized separately from this setup.
Their success does not authorize privileged actions or qualify production use.
