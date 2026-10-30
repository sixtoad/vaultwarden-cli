# Native protected execution on macOS — issue 49

Plan and source qualification status, updated 2026-10-29. Source: [issue 49](https://github.com/sixtoad/vaultwarden-cli/issues/49), with the operator's subsequent [secret-access responsibility boundary](secret-access-boundary.md). Historical plan baseline: `476bf3f506aad6f52628ad32a6ef34e31172d1ba`.

The authorized native source candidate and its selected delivery contract are described below. Source qualification does not establish installed production support; separate service-account and installation qualification remains required. The shared Linux lifecycle now follows the accepted responsibility boundary; see the [migration record](implementation/issue-49-future-access-only-linux.md).

The CLI/provider owns secret authorization and delivery. Consumer execution and sandbox management are outside this project’s scope. Neither automatic nor optional consumer termination belongs to this CLI. Missing process-tree containment does not block the Mac secret-access port. The remaining delivery boundaries still need qualification, and the Linux migration establishes the same future-access-only contract.

## Native source candidate (2026-10-29)

The subsequent authorized implementation now provides native Apple Silicon
composition, reviewed Mach-O preparation, explicit operator/provider identities,
Unix authentication, sleep-aware authority and memory-only SSH signing. See the
[implementation and installation packet](implementation/issue-49-native-provider.md)
for the selected contract, tests, service templates and remaining qualification.
Source tests do not establish an installed deployment. Native producer output
(create-secret) now uses a bounded provider-drained pipe as fd 3 and is covered by
source tests only; distinct-account/service-Keychain/launchd lifecycle, installed
producer qualification and release signing require the concrete separately
approved setup described there.

The earlier stages and observations below are preserved as design history; their
statements about the source being Linux-only describe the baseline, not the new
candidate. No production OS-version support is implied.

## Historical baseline evidence (2026-10-28)

`src/lib.rs` compiles the protected access/application and adapter modules only on Linux. The provider and protected client reject macOS before reading state. Linux execution verifies a sealed executable memfd, executes that object with `execveat`, and uses systemd/cgroup supervision, subreaping and independent process observations to establish cleanup. None of those guarantees follows from building an equivalent Mach-O binary.

The useful seams already exist in `src/access/ports.rs`: `ImageVerifier`, `ProtectedExecution`, `ProcessSupervisor`, `ExecutionControl`, `CleanupEvidence`, `ProducerOutput` and `SshMaterial`. Policy, signatures, approvals, audit and Vaultwarden logic should be shared after platform dependencies are isolated. `ExecutionWorker::start` and human image registration currently select Linux implementations directly.

Flutter already supports password approval, separate provider unlock, denial and status-only recovery after an uncertain decision. Its native `NativeTestKey`/`ApprovalContract` path signs the synthetic domain `dev.vaultwarden.companion.synthetic.v1`; it is not production Touch ID approval. The current Flutter archive is development signed and contains no native provider installer. The older Swift companion DMG is a different product and still needs a Linux provider.

## Proposed support and trust model

- Initial protected execution target: native Apple Silicon, including M1. Intel and Rosetta execution fail closed. Existing legacy CLI and remote-approval architecture support is unaffected.
- macOS 13 is the proposed minimum API baseline for modern service management. It is not yet a tested support claim. Qualification must test the chosen oldest supported version and the operator's actual version; if that evidence is unavailable, narrow the published matrix explicitly before release. Do not advertise all versions above a minimum based on one CI host.
- Agents run in separate restricted OS accounts without administrator, sudo, human-session, provider-account or service-management authority. A paired public key alone cannot isolate an agent running as the operator. An agent with the operator's UID is rejected even if its key is valid. Each independent agent identity uses a distinct UID; agents sharing an OS account cannot be isolated from each other's private keys.
- Trusted components are the administrator/operator, OS security services, the provider, narrowly scoped service controller, and reviewed operation code. Administrator/root compromise and malicious protected operation code are outside this threat model. Already-authorized work may continue after ordinary access revocation. Safe CLI-owned resource lifetimes remain required. Consumer execution and sandbox policy belong to the execution owner; possession of a secret conveys no process-control authority to the CLI.
- Proposed service identities: a dedicated non-login provider account and distinct restricted agent accounts. Bind the human administrative endpoint to an enrolled operator UID and authenticated companion identity, rather than equating human UID with provider UID. Protect that enrollment against agents and accidental UID reuse.

These are design proposals to qualify. Dedicated identities are mandatory for this candidate; a user LaunchAgent under the agent's identity does not satisfy the boundary.

## Service lifecycle and local authentication

Evaluate a system LaunchDaemon, managed through the installed app, for provider lifetime. Keep privileged account/install/lifecycle operations in a narrow controller; the network-facing provider should not run as root. Consumer workload privileges and sandbox configuration belong to the execution owner. Define typed requests, authenticate their caller from OS evidence and expose no generic root command execution. Account provisioning, file ownership and service registration need an administrator-approved install plan.

Apple documents [SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice?language=objc) for bundled helpers on macOS 13 and later. Its [registration contract](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) requires admin approval before a LaunchDaemon is bootstrapped. This is a lifecycle API, not proof of workload isolation or cleanup. Compare app-managed registration with a signed installer owning fixed daemon files; choose only after service identity, app relocation, upgrade and recovery tests.

Use separate administrative and agent endpoints. A candidate Unix socket transport must validate server identity on the client and caller identity on the server before accepting values. Apple's archived [getpeereid documentation](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getpeereid.3.html) establishes effective UID/GID evidence; it does not establish the existing Linux supplementary-group contract or signed application identity. Verify current SDK behavior natively. Do not replace kernel evidence with request fields, environment variables, or a PID lookup vulnerable to reuse. Use authenticated Mach/XPC identity where required for the privileged controller, proving the connection-to-signature binding.

Keep agent Ed25519 signatures, enrollment, revocation, replay markers, policy binding and receipt ownership. CLI submission/status remain noninteractive and receive only the existing redacted schema. No endpoint grants agents review, unlock, enrollment, history administration or signing authority.

Normal UI close, provider lock, access expiry, pending-request cancellation and access revocation must not request termination of work that already received its secrets. They block future delivery in their scope, including late resolution and refresh. Serialize revocation against final secret release; spawning a process or approving a request does not reserve future access. Provider/controller failure closes new delivery; restart begins locked, restores resource ownership and invalidates stale approvals/session authority. Execution limits and consumer program cancellation are outside the CLI’s responsibility. The CLI must not turn delivery failure, lock or expiry into a termination request. Sleep counts toward deadlines; [mach_continuous_time](https://developer.apple.com/documentation/kernel/1646199-mach_continuous_time?changes=la) is a candidate clock because Apple specifies that it includes sleep.

## Executable and secret boundary

Introduce a separately versioned Mach-O execution profile only after qualification. Initially reject scripts, interpreters, arbitrary plugins, writable dependencies, unsupported architectures and unreviewed loader behavior. Pin exact executable bytes and an explicit signing requirement; team identity alone does not pin a version. Validate runtime/entitlements and the dependency closure, permitting only explicitly justified system dependencies. Do not silently convert ELF registrations or reuse old policy approvals.

For any retained provider launch mode, a candidate design stages verified code under protected ownership in a versioned location inaccessible to agents and unwritable by workloads. Its resource lifetime must not require the provider to control the whole consumer process tree. For an orchestrator-owned launch, specify an authenticated recipient/channel binding instead of blindly porting the provider-launch architecture. It must withstand rename, symlink, hard-link, in-place mutation and concurrent upgrade attempts. A hash followed by path-based spawn is not sufficient without a demonstrated no-writer lifetime and binding to the executed image. Launch confirmation must distinguish actual protected exec from helper startup or death before exec.

Apple's [dynamic code validation API](https://developer.apple.com/documentation/security/seccodecheckvalidity%28_%3A_%3A_%3A%29) supports code requirements and protects its validation against filesystem-source changes. That statement does not prove our entire check-to-launch sequence. Validate the complete sequence and dependency boundary separately. Apply hardened runtime without debug/injection exceptions to trusted secret-bearing components; Apple's [notarization guidance](https://developer.apple.com/documentation/security/resolving-common-notarization-issues) explains why `get-task-allow` and disabled library validation need particular scrutiny. Development ad-hoc signing is not evidence for a production installation trust chain.

Resolve secrets inside the provider. Deliver them only over an authenticated private execution channel to the trusted workload, with explicit bounded environment and closed inherited descriptors. Never place values in launchd plists/properties, CLI arguments, agent files, diagnostic errors or raw output buffers. Discard workload stdout/stderr unless the operation explicitly uses the private bounded producer protocol. Disable secret-bearing core/crash artifacts where supported and verify agent visibility of process arguments, environment, memory, files and logs under the actual deployment identities.

Provider bootstrap credentials need Keychain access appropriate to the non-login service identity. Do not assume the operator's login Keychain works for a daemon; qualify item ACLs, signed access requirements, reboot/login/lock behavior and denial. Prefer no persisted active vault session if service-identity storage cannot meet the contract; restart must require fresh unlock. Failure must never fall back to plaintext storage. Companion signing keys stay in its native Keychain boundary.

SSH delivery should use a provider-managed agent with keys held in memory, following the Linux request-scoped authorization contract. Native implementation still needs authenticated recipient identity, pinned host/session binding, bounded signing and withdrawal serialized against signature delivery. Closing this credential service must not stop consumers or established SSH connections. Socket/public host-key cleanup is separate from workload lifetime; legacy private-key files must not be treated as a reason to acquire process-control authority. Linux pidfds are platform-specific evidence, not a macOS requirement. Ordinary system OpenSSH is not automatically an approved secret recipient, and Linux agent tests do not qualify a native macOS implementation.

## Execution ownership and resource handoff

The [accepted boundary](secret-access-boundary.md) places sandboxing and consumer
cancellation outside this project’s scope. The CLI must not implement a stop-programs feature,
control unrelated processes, or require a runner to prove full process-tree
termination before rejecting a new secret request. Approval is for one request;
secret delivery is not permission to supervise its recipient afterward.

Persist enough nonsecret authorization and delivery metadata to prevent replay
and recover safely. A failed or cancelled delivery must not be reported as a
successful password recall. Distinguish the CLI's own resource cleanup from
consumer process lifetime; retain resources when safe ownership is unresolved
and leave only the affected delivery mode unavailable.

The [2026-10-27 containment investigation](implementation/issue-49-qualification/containment-feasibility-2026-10-27.md)
answered an earlier, rejected product requirement. Preserve its findings as
history, not a gate or implementation plan for issue 49. Neither a VM nor an
in-process-only product is required solely because the CLI lacks containment.

## Production approval and single installation

Reuse Flutter's typed review and durable status recovery. Add a distinct production biometric contract bound to provider identity, request, policy revision, decision, freshness and one-time consumption. Enroll/revoke that signing identity through the authenticated human path. Keep synthetic and production key namespaces and transcript domains separate. Touch ID cancellation or unavailability never silently approves or automatically submits a password. Offer explicit password approval, independent of provider unlock. Test biometric enrollment changes, replay, stale reviews, device revocation and app relaunch. An M1 Mac mini without suitable Touch ID hardware must still work with password approval; hardware-specific biometric evidence remains separate from simulated tests and issue 41's key-continuity work.

Status (2026-10-30): PR A implements the provider side: the v2 approval and
enrollment transcripts, online own-device enrollment (fresh password, management
ticket, proof of possession) and key revocation, the `ring` verifier behind the
`BiometricApprovalVerifier` port, retired key ids, cascade on device revocation,
the `require_password` policy field, history attribution and a golden vector
(`tests/fixtures/approval-v2-golden.json`). The wire contract is in
[companion-protocol.md](companion-protocol.md#production-touch-id-approval-v2-issue-49);
owner decisions are recorded in
[issue-49-native-provider.md](implementation/issue-49-native-provider.md#production-touch-id-approval-owner-decisions-2026-10-30).
Companion bridge (PR B), Secure Enclave signer (PR C) and UI (PR D) are pending;
no hardware biometric evidence exists yet.

One installation must deliver the Flutter app, `vw-access`, provider, execution components and required service definitions with a common version manifest. The existing archive/Swift DMG cannot serve as proof. A signed installation plan must disclose account creation, file destinations and service registration. Use stable signing identities for release; obtain Developer ID/notarization capability before claiming normal distribution support. Never disable Gatekeeper or SIP to install.

Upgrade sequence: verify the new payload before activation, close admission, coordinate resource release with the execution owner or defer activation, preserve configuration/Keychain, migrate only supported state schemas, atomically switch a complete version and restart locked. Retain the old resources or defer activation when their safe lifetime cannot be established. Failed verification leaves the current version intact. Rollback must not reactivate consumed approvals or incompatible state. Do not replace unrelated binaries, accounts or settings.

Uninstall sequence: revoke admission, disclose active work, coordinate resource release with the execution owner or report pending removal, then stop/unregister owned services and remove only manifest-owned files and safe-to-remove owned accounts. Preserve audit/configuration by default; offer separate explicit removal of product-owned credentials/state. If resource lifetime cannot be established, report incomplete removal and retain the protected resources needed for recovery. Account/UID reuse must not revive old enrollment.

## Dependency-ordered delivery and evidence

| Stage | Concrete repository changes | Exit condition |
|---|---|---|
| 0. Qualify | New `tests/fixtures/macos-boundary/`, `scripts/test-macos-boundary.sh`, `docs/implementation/issue-49-qualification/` | Native identity/image/inspection, authorized delivery, future-access denial and resource lifetimes qualified; execution ownership stays external; production remains disabled until then |
| 1. Separate responsibilities and platform code | `src/lib.rs`, `src/access/{application,ports}.rs`, `src/adapters/{mod,session,supervisor,human_socket}.rs`, new `src/adapters/platform/` | Access authority separated from legacy consumer supervision; Linux authorization/delivery guarantees retained with migration tests |
| 2. Native provider | Native recipient verification, authenticated handoff/transport/storage adapters, `src/access/policy.rs`, protected binaries | Qualified recipient/channel binding, one-time delivery and fail-closed access recovery; no consumer execution control |
| 3. Local approval | Flutter controller/page, native provider settings/adapter, new production approval signer and transcript | Local enrollment, explicit password and supported Touch ID, noninteractive agent, one-time execution and status recovery |
| 4. Single install | New `packaging/macos/`, installer/build scripts, Flutter build configuration, explicit release payload | Authorized disposable install/upgrade/failure/removal rehearsal; signatures and component versions agree |
| 5. Acceptance | New `tests/macos_protected_execution.rs`, native fixtures/mutations, `.github/workflows/ci.yml`, `docs/access-mvp.md`, companion docs | Complete synthetic M1 flow, all security cases, declared support matrix and Linux regressions |

Stages 1–5 are a roadmap, not ready-for-development stories. Specify their exact APIs, file changes and tests after stage 0 determines the mechanism. No stage can waive an earlier security gate.

Before changing shared runtime behavior, specify the access/termination split across application control, transports, CLI and companion UI. Linux now separates lock/revocation from consumer lifetime; retain its delivery-race, multi-secret and consumer-survival tests in the native port. It must not be implemented as a Mac-only exception or by removing cleanup checks.

Every evidence record must name source revision/hash, OS build, architecture, signature/entitlements, identities and resource ownership, test outcome and cleanup outcome. Report pass/fail/skipped/unavailable distinctly. Preserve exact mutant patches and failing assertions for targeted identity, image, release-race, cleanup, replay and redaction mutations. Current Mac CI primarily proves remote approval and packaging; it does not prove these boundaries.

Final acceptance maps to the corrected issue 49: install/enroll/request/approve/deliver/poll with synthetic credentials and no Linux provider; authenticated delivery to the approved recipient; inability to self-approve, impersonate or widen access; denial/expiry/cancellation/access-removal/lock/restart/replay; recipient replacement and unsafe permissions; no secret leakage outside the approved channel; safe CLI-owned resource lifetime; no implicit consumer termination; native Apple Silicon rehearsal and explicit Intel exclusion; Linux authorization/delivery regression and mutation evidence. Signing, privileged setup, real Touch ID hardware and the supported OS matrix are prerequisites to record honestly, not implied passes.

## Investigation record

The initial draft was based on read-only repository inspection and Apple documentation. Existing code paths and file references were checked against the baseline above. The stage-0 qualification specification was subsequently approved on 2026-10-27; privileged actions remain separately gated by issue 49's explicit authorization requirement.

### Stage-0 implementation: qualification remains blocked

Disposable fixtures and a bounded runner now live in `tests/fixtures/macos-boundary/` and `scripts/test-macos-boundary.sh`. Their [qualification record](implementation/issue-49-qualification/README.md) describes source/signature manifests, the attack matrix, independent process observations, material retention, and the [prepared privileged setup proposal](implementation/issue-49-qualification/privileged-setup-plan.md). The user subsequently authorized the unprivileged native arm64 Mac run recorded below. No installation, account creation or service modification occurred.

The runnable observations cover kernel peer UID checks, deliberate pathname replacement and invalid signatures, private-pipe synthetic-value inspection, double-fork/`setsid` and crashes. The descendant configures SIGTERM to be ignored, but no SIGTERM is sent: ignored-signal behavior remains untested. Those observations are not a security design. The historical matrix records the previous requirements; cross-account authentication, dependency closure, resource lifetime, service Keychain, future-delivery revocation and restart invalidation still need qualification under the revised policy. Consumer containment is not a CLI responsibility; individual delivery modes still need safe resource lifetimes. A writable pathname launch is rejected as a candidate; process groups are not selected as containment.

The subsequent authorized [M1 run](implementation/issue-49-qualification/native-run-2026-10-27.md) completed all nine native primitive observations on macOS 27.0.1 after a Python 3.9 compatibility/reporting correction. All sixteen portable tests passed on Linux; fifteen passed on the Mac with one Linux-only test skipped. Eight recorded fixture identities exited and were absent at follow-up. The Cargo platform regression subsequently passed after locked dependencies were fetched into a private temporary cache; its earlier offline attempt remains recorded as unavailable. The [containment audit](implementation/issue-49-qualification/containment-decision-2026-10-27.md) records specific limitations in launchd, kqueue, event tracking and coalition candidates. No macOS version is certified and no production mechanism is selected. The initial qualification run changed no production Rust or Flutter code. Subsequent Linux lifecycle work is separate; issue 49 remains open and stages 1–5 require a subsequent specification.
