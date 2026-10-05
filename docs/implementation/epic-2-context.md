# Epic 2 Context: Operator Delegates One Approved Operation to a Paired Agent

<!-- Compiled from planning artifacts. Edit freely. Regenerate with compile-epic-context if planning docs change. -->

## Goal

Enable one human operator to pair, inspect, and revoke multiple restricted agents, then delegate an existing protected operation through a non-interactive request and signed status polling. Every request remains attributable to its paired identity and requires one human approval. The provider retains custody of Vaultwarden material and reports only redacted lifecycle outcomes to the agent.

## Stories

- Story 2.1: Pair and Revoke a Restricted Agent Identity
- Story 2.2: Submit a Signed Request Without a TTY
- Story 2.3: Poll Delegated Work and Preserve Request Ownership

## Requirements & Constraints

- Pairing is an explicit human action associating a unique readable label and Ed25519 public identity with an allowed Linux UID and required group. Fresh configuration contains no pairings. Humans can inspect fingerprint, OS identity, and enabled or revoked status without private-key or vault data.
- Provider and agent require distinct OS security principals. The provider runs in the human session; each agent runs under a restricted account or container. Same-UID deployment cannot provide the required secret boundary.
- Key possession alone grants no authority. Both the configured OS identity and the enabled cryptographic identity must match. Unknown or revoked bindings, incorrect UID/group, malformed envelopes, invalid signatures, replay, unsupported protocol versions, and stale policy revisions fail closed before creating a request or opening an approval surface.
- Revocation prevents subsequent submission and polling, invalidates the agent's unexecuted requests, and terminates its contained running execution. Historical attribution remains available to the human. Provider lock, restart, crash, and lost execution authority also invalidate stale work.
- An agent may request only a known operation with permitted non-secret arguments and its expected policy revision. It cannot supply executable commands, vault references, fields, environment names, or output destinations.
- Status is available only to the authenticated request owner. Knowledge of a request ID does not grant access or disclose another request's existence. Returned data is limited to redacted lifecycle state, permitted exit status, and stable failure category.
- Agent commands work without a TTY and never handle human passwords, browser launch capabilities, approval URLs, authentication assertions, raw vault values, protected child output, or reusable approval authority.

## Technical Decisions

- Use a hexagonal provider core: domain models and application handlers depend on ports; socket, loopback UI, persistence, backend, and systemd integrations are adapters. Only the provider core invokes the secret backend and protected execution ports.
- Agent transport is versioned newline-delimited JSON over a Unix socket. The adapter checks Linux peer credentials and passes trusted peer identity to the core; the core verifies the signature against the enabled binding. Bindings associate the key identity with a specific UID and group, preventing another allowed group member from impersonating that label.
- Pairings are provider-owned, versioned, validated before activation, and permission-checked on every load. State directories use `0700` and files use `0600`; storage lies outside agent-writable workspaces. The provider serializes pairing, policy, request, and audit writes, and transition or storage failures fail closed.
- Signature verification requires the public verification material; a fingerprint is an identity display and comparison value, not a replacement for the verification key. Persist no agent private key. Public identity digests follow the lowercase SHA-256 convention.
- Request authority binds request ID, requester identity, current policy revision, normalized argument digest, and provider-calculated expiry. The provider is the only writer. Pending work can become approved, denied, or expired; approved work becomes running and then completed or failed. Terminal states are immutable. Restart and lock invalidate unexecuted authority.
- Every submission, poll, and approval transition uses the provider clock for expiry. Polls are signed request-ID queries whose verified binding must equal the stored owner. Request IDs are cryptographically random 256-bit base64url values; wire fields use snake_case and timestamps use Unix seconds.
- Human administration and approval stay behind the authenticated human boundary. The loopback UI exchanges a desktop-delivered one-time launch capability for an HttpOnly, SameSite session. Mutations require session-bound CSRF protection and human authentication; these capabilities never enter agent IPC.
- Running work is owned by `ProcessSupervisor` in systemd transient request units bound to the provider with `BindsTo`, `PartOf`, and `KillMode=control-group`. Loss of authority kills and reaps the entire descendant cgroup. Startup cleans surviving prior execution before accepting new work.
- Audit records preserve IDs, labels, fingerprints or other digests, timestamps, decisions, and redacted outcomes. They never contain raw environment, private keys, master passwords, browser capabilities, vault values, or child output.

## UX & Interaction Patterns

Human approval distinguishes the paired agent label and fingerprint from a local human terminal. It shows the operation's friendly effect, target, permitted arguments, non-secret credential labels/use, policy and executable identity, expiry, request ID, and one-time meaning. Actions are explicit denial or authentication and approval once; no persistent approval exists. Controls support keyboards, visible focus, meaningful screen-reader labels, and non-visual confirmation. Agent output reports a request ID, waiting/running state, and a safe terminal outcome without exposing human approval capabilities.

## Cross-Story Dependencies

Epic 1 establishes provider-owned safe storage, authenticated administration and approval, operation policy, requester ownership, one-time request lifecycle, redacted audit, protected execution, and supervisor containment. Epic 2 must preserve these guarantees while adding delegated identity. Pairing and revocation supply enabled-binding and ownership checks consumed by signed submission and signed polling; their transport implementations belong to the subsequent stories. Running-work revocation depends on completed descendant cleanup, and historical identity must remain meaningful after revocation or any later pairing. Epic 3 adds SSH material handling to this same authority and containment boundary.
