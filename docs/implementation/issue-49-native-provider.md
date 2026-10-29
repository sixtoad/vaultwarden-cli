# Native Apple Silicon provider implementation

Source implementation candidate, 2026-10-29. Governed by
[the accepted secret-access boundary](../secret-access-boundary.md).
This is source qualification, not an installed-production support claim.
No accounts, installed services, real vault data, SIP/Gatekeeper settings or
production Keychain records are changed by the tests or templates.

## Implemented contract

The protected application, signed request protocol, password approval, consumed
request persistence, redacted status/history, companion mTLS and final release
lock are shared with Linux. Native composition uses the same `run_execution`
and `ExecutionControl::release`; approval does not reserve later delivery.

| Boundary | Native implementation |
| --- | --- |
| Platform | Only `aarch64-apple-darwin` exposes protected provider/client code. Intel binaries, including Rosetta processes, retain early rejection; native availability also rejects translated processes. |
| Identities | Root-owned `/Library/VaultwardenAccess/native-identities.json` enrolls distinct nonroot provider/operator UIDs and their account UUIDs. Existing account lookup and UUID matching prevent silent UID reuse. Agent bindings persist their own account UUID; admission and final release check the current account while revoked history survives account removal. |
| Administrative authority | Operator UID is distinct from filesystem owner. Durable human/audit authority uses the enrolled operator; files remain provider-owned. A paired agent cannot acquire either identity. |
| Human transport | Separate provider-owned 0750 directory, configured human GID and 0660 socket. Kernel peer UID must equal enrolled operator. Client requires configured provider ownership and matching kernel server UID. |
| Agent transport | Provider-owned 0750 directory and 0660 socket, configured agent GID. `getpeereid` authenticates UID/effective GID before parsing. Native enrollment requires this effective GID; it does not pretend to provide Linux supplementary-group evidence. Signed requests remain mandatory. |
| Paths and ACLs | Component-by-component `openat` with no-follow; owner/mode checks and rejection of ACL allow entries. Deny-only ACLs are accepted. `F_GETPATH` is a pathname used only with retained inode evidence and a chain without untrusted writers, never a `/proc` replacement capability. |
| Expiry | `mach_continuous_time` includes sleep. Clock failure/backward observation permanently expires authority. |
| Image | Separately versioned `reviewed_native_macho_arm64_v1`; complete artifact SHA-256, root-owned regular executable, one hard link, no group/other writer or set-ID bits, safe ancestry, no ACL grants. Provider/workload accounts cannot rewrite the image. |
| Loader | Validate thin ARM64 or every ARM64 slice in bounded FAT/FAT64 images; explicit ARM64 spawn preference. Require the system dyld and dependencies present in the signed OS shared cache. Reject rpaths, loader environment commands, scripts, unknown loader commands and non-system dependencies. Behavioral review still excludes interpreters/plugins/helper loading. |
| Signing | Security.framework strict Apple/Developer-ID trust, hardened runtime and no debug/library-validation/DYLD/JIT/unsigned-memory exceptions, separately checked for each native slice. Exact cdhash alternatives contain only those reviewed native slices. |
| Delivery | Explicit bounded environment with no inherited variables, Darwin loader-variable rejection, closed inherited descriptors and discarded standard I/O. Final authorization serializes `posix_spawn` of the verified no-writer path. |
| Observation | Only the direct child is observed/reaped. Withdrawal detaches observation and closes provider authority; one bounded reaper waits for natural exits without signals. Its 64 slots are reserved before secret resolution; initialization failure or full capacity rejects new execution. No parent-death hook or process-tree containment condition. |
| SSH | Existing bounded agent protocol, pinned host/user/session, one verified signature, no client private-key file. Kernel `LOCAL_PEERTOKEN` binds the connection to the unreaped direct-child PID; Security.framework dynamic validation binds its audit token to exact reviewed cdhashes, including another exec under the same PID. The check repeats inside final signature release. |
| Restart/cleanup | Restart stays locked and retains consumed requests. Public sockets/host pins have independent inode-checked cleanup; unknown or historical resources are preserved. No recovered consumer is signalled. Offline management reconcile cleans SSH runtime and Keychain session only while kernel process listing shows no other `vaultwarden-accessd` under the enrolled provider UID, checked before, between and after cleanup; launchd text output is not relied on. |
| Storage | Existing native Keychain backend and explicit password approval. No plaintext credential fallback. Non-login service-account Keychain behavior remains an installed qualification requirement. |

Native SSH exposed an actual architecture-selection difference on the M1 test
host: the default static Security object selected one arm64e signature while
spawn selected arm64e.x1. A single default cdhash rejected the legitimate client.
The implementation now uses `SecStaticCodeCreateWithPathAndAttributes` with
`kSecCodeAttributeUniversalFileOffset` for every validated native slice, verifies
its runtime/entitlements/signature and permits only those exact hashes. Actual
OpenSSH signature release was then verified; it does not fall back to a team,
publisher, pathname or bare PID. The whole reviewed artifact is still SHA-256
pinned. Apple documents the slice-offset attribute in its
[Security.framework header](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/SecStaticCode.h).

## Source verification and limits

The implementation's native tests use synthetic backend/password ports and
explicit `cfg(test)` identity injection. Production code has no environment or
argument override for installed identity checks. Native test keyring setup is
mocked; no test is permission to access real provider Keychain records.

Native checks cover approved shared-application launch, one-time consumption,
signed-request replay, wrong UID/group/key, operator audit followed by new
operation provisioning, revocation, account reuse/removal with preserved history,
denial, cancellation, expiry, locked restart,
unsafe/copied/replaced image selection, ACL grants, actual Unix peer credentials,
endpoint ownership and consumers continuing after observation withdrawal.
Shared SSH tests verify signatures, host/session scope, forwarding rejection,
one-use behavior and final release withdrawal. Native tests observe the mapped
synthetic password and excluded inherited environment/descriptors in an actual
spawned child. They also exercise forbidden loader/signature policy, file ACLs,
bounded reaping, expiry during recipient validation, and a real same-PID exec
transition after the SSH connection was accepted. The explicit real OpenSSH test
uses a private temporary loopback sshd and memory-only client keys for Ed25519,
ECDSA P-256/P-384/P-521 and RSA-SHA2-256/512. Its synthetic **server host key** is
an sshd fixture file; no client private key is written.

Run `scripts/test-native-protected-macos.sh /absolute/evidence-directory` on a
native Apple Silicon Mac. It copies the exact source into a private temporary
workspace, uses umask 077 and safe temporary ancestry, records source/environment
and system SSH identity, runs strict native Clippy, the library suite and explicit
real SSH test. It does not install anything. The evidence directory must be
outside the source repository. CI adds this qualification on `macos-26`; a job
configuration is not proof that that OS has passed. Actual run results and exact
source evidence are in the [2026-10-29 verification record](issue-49-qualification/native-provider-run-2026-10-29.md).

Linux retains its ELF/memfd/systemd implementation and historical regression
fixtures. ELF-specific fixtures remain Linux-only; native authority tests exercise
the shared application using actual native images. Portable signature/session/
request tests run on both platforms. Windows and Intel/Rosetta rejection remain
separate from successful native delivery evidence.

Still unavailable or unqualified:

- Native producer/create-secret output uses the port's default denial before
  secret resolution. Login-environment delivery and SSH do not depend on this
  separate output protocol. Native producer parity is not claimed.
- Installed distinct-account end-to-end request/companion approval/Keychain
  rehearsal, launchd stop/reboot/upgrade survival and service-account credential
  ACLs have not been established by same-user synthetic fixtures.
- Developer-ID release signing/notarization and a combined Flutter/provider
  installation package are not furnished by a successful source build. The
  supplied service/configuration templates are review material.
- No broad minimum-version promise follows from one host. Record the exact OS
  build and architecture actually tested. Earlier macOS containment observations
  retain their historical meaning and do not qualify this delivery path.

## Concrete installation approval surface

Review these templates before any installed action:

- [`com.cantolla.vaultwarden-accessd.plist.in`](../../packaging/macos/native/com.cantolla.vaultwarden-accessd.plist.in)
- [`native-identities.json.in`](../../packaging/macos/native/native-identities.json.in)

Neither template is installable until placeholders are resolved. UUIDs are
lowercase hexadecimal without separators; UID/GID placeholders must become JSON
integers. Obtain the actual account GeneratedUID values and confirm they agree
with native membership lookup. Do not reuse an existing unrelated account or
assume a free UID remains unallocated.

The final host-specific packet must identify the operator and newly provisioned
non-login provider/restricted agent accounts, exact UIDs/GIDs/UUIDs, group members,
binary version/SHA-256/Developer-ID identity, companion certificate fingerprints,
service label/listen address and every file's destination/owner/mode. The provider
belongs to the narrowly scoped human/agent socket groups; restricted agents must
not belong to the human group, provider group or administrator groups. Each agent
uses its own UID and the enrolled effective agent GID. Companion mTLS enrollment
and password approval use existing trust; synthetic Touch ID is not production
approval.

| Destination | Ownership and mode |
| --- | --- |
| `/Library/VaultwardenAccess` and `versions/<version>` | root, no group/other writers or ACL grants; version directories immutable to provider and consumers |
| `versions/<version>/{vaultwarden-accessd,vw-access}` | root-owned reviewed signed executables, 0555 or 0755; never overwrite a version in place |
| `native-identities.json` | root-owned, 0644 without ACL grants, one link; no secrets |
| `state` | provider-owned 0700 without ACL grants |
| `state/{backend.json,provider-cert.pem,provider-key.pem,companion-ca.pem}` | provider-owned 0600, one link; provision through approved private credential/trust procedure |
| `run` | root-owned 0755 without ACL grants |
| `run/human` | provider owner, dedicated human group, 0750; runtime socket 0660 |
| `run/agent` | provider owner, dedicated agent group, 0750; runtime socket 0660 |
| `run/ssh` | provider-owned 0700; only request-local sockets and public pins |
| `/Library/LaunchDaemons/com.cantolla.vaultwarden-accessd.plist` | root:wheel, 0644, resolved version/account/GID placeholders |

The LaunchDaemon must retain **`AbandonProcessGroup=true`**. Without it, launchd
can kill remaining consumer processes when the provider exits, violating the
boundary even though the Rust adapter sends no signals. Core limits are zero,
standard streams are discarded, and no credentials appear in plist arguments or
environment. The daemon runs as the provider account, never root. Use the
companion endpoint for local password approval; `vw-access --state-root
/Library/VaultwardenAccess/run/human` addresses the separate administrative socket.
Restricted clients use `run/agent/agent.sock` and their own 0600 signing seed.

After approval of that exact packet, installed qualification must prove both
endpoint and recipient isolation with real distinct UIDs, fresh password approval,
Keychain access after reboot/login/lock, policy replacement rejection, consumed
request recovery, withdrawal racing signature release, and **launchd provider
stop/restart leaving already released consumers alive**. Also inspect arguments,
environment access, logs, memory/crash artifacts and temporary files from the
restricted identities. Record denied/unavailable checks separately. Do not disable
SIP/Gatekeeper or broaden ACLs/groups to make a failing setup run.

## Upgrade, rollback and removal

Verify a complete new signed version before closing admission. Never overwrite
an active version or delete resources whose ownership/lifetime is uncertain.
Notify the execution owner of active work; this provider does not cancel it.
Stop the provider with the qualified abandon-process-group service definition,
retain state, public-resource ownership and Keychain, switch the versioned plist,
and restart locked. Require fresh unlock and one new approval per new request.

Rollback only to a version that understands the current native profile, account
UUIDs and durable consumed-request schema. Never erase tombstones, restore an old
state backup as live authority or reactivate an approval to make rollback work.
A legacy Linux-only binary is not a native rollback target. Failed verification
leaves the current installed version intact; an unqualified service definition
must not be activated.

Uninstall first closes admission and records outstanding consumers/resources.
After separately approved service removal, remove only manifest-owned files whose
safe lifetime is established. Preserve audit/state and Keychain by default;
credential deletion and account removal require their own explicit inventory and
approval. Retain uncertain resources and report incomplete removal. Reusing an
account UID must never revive old enrollment.
