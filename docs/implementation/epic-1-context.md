# Epic 1 Context: Human Runs Protected Vaultwarden Operations

<!-- Compiled from planning artifacts. Edit freely. Regenerate with compile-epic-context if planning docs change. -->

## Goal

Enable one human operator to define and run named, login-backed protected operations through human authentication and one-time approval. The provider retains custody of Vaultwarden material and supplies it only to a verified, contained protected process. Requests, lifecycle outcomes, and audit records remain redacted, and loss of authority prevents execution.

## Stories

- Story 1.1: Start a Fail-Closed Provider
- Story 1.2: Define a Constrained Protected Operation
- Story 1.3: Unlock and Lock the Provider Vaultwarden Session
- Story 1.4: Submit a One-Time Human Direct Request
- Story 1.5: Decide a Request Exactly Once
- Story 1.6: Verify the Exact Protected Executable
- Story 1.7: Run a Login-Backed Child Without Secret Disclosure
- Story 1.8: Contain and Reap Protected Child Processes
- Story 1.9: Inspect Redacted Operation History

## Requirements & Constraints

- The operator owns configuration, approvals, the Vaultwarden account, and audit. Deploy on Linux with the provider in the human session and agents under separate restricted OS principals. Same-UID deployment does not provide the claimed secret boundary.
- Start locked, with no enabled operations or pairings. Provider state must be outside agent-writable workspaces, provider-owned, permission-checked, and restricted to `0700` directories and `0600` files. Missing, malformed, or unsafe authority-bearing state fails closed.
- Named operations bind a fixed executable identity, target constraints, permitted non-secret arguments, immutable credential IDs, selected field mappings, and non-secret labels. Callers cannot choose commands, secret references, secret fields, environment names, or output paths. Changed authority produces a new revision and requires a new request and approval.
- Login credentials may include username, password, and explicitly selected custom fields. Eligibility combines immutable policy binding with a deliberate item marker; the proposed convention is `vw-access=<operation-id>`, whose client usability still needs validation.
- Human credentials and reusable backend sessions never reach client arguments, agent IPC, logs, URLs, status, or audit. Reusable Vaultwarden authority remains in provider-owned backend/keyring facilities. Unsupported or unverifiable Vaultwarden compatibility fails closed before item resolution; the supported range must be documented.
- Denial, expiry, changed policy, locked provider, unavailable backend, invalid credential eligibility, or failed execution setup prevents execution. Lock, restart, and crash invalidate unexecuted work and old approval capabilities. Status reaches an observable terminal outcome within request expiry.
- Audit contains only identifiers, requester identity, labels, digests, timestamps, decisions, and redacted outcomes. Never persist values, raw environment, passwords, private keys, browser capabilities, or protected-process output. Terminal history remains inspectable after restart.
- Generic vault reads, enumeration, secret export, arbitrary commands, persistent approvals, interpreted protected scripts, and multiple human approvers are outside MVP scope. Request-expiry defaults and audit-retention defaults remain undecided.

## Technical Decisions

- Use a hexagonal provider application: domain and core depend on ports; adapters own configuration, keyring, browser/HTTP, sockets, persistence, and execution. Core interfaces live in `access::ports`; core must not import infrastructure libraries. `vaultwarden-accessd` composes the provider; `vw-access` submits human or agent requests; the existing direct human vault CLI remains separate.
- Only provider application core calls `SecretBackend` or `ProtectedExecution`. The Vaultwarden adapter reuses extracted backend/session/keyring capabilities, never CLI presentation APIs. Backend-neutral bindings and scoped secret material cross ports; raw vault item shapes never cross the core boundary. Use existing zeroization facilities where practical.
- Password authentication stays in the loopback UI/provider-session path. `ApprovalAuthenticator` supports future platform authentication as an adapter; passkeys and biometrics are deferred.
- Provider command handlers are the exclusive state writer. Serialize persistence and lifecycle transitions: pending becomes approved, denied, or expired; approved becomes running or expired; running becomes completed or failed. Terminal states are immutable. Approval binds request, requester, policy revision, normalized arguments, and provider-calculated expiry exactly once.
- Before resolving secrets, revalidate policy and execution preconditions. Accept only provider-owned regular executable images within a no-symlink execution root; verify the opened descriptor, owner, mode, and declared SHA-256, then execute that exact descriptor with `execveat`/`fexecve` semantics.
- Inject only approved login fields into the protected child's environment. Exclude inherited `VAULTWARDEN_` and `BITWARDEN_` variables. Capture and discard stdout/stderr; return only structured lifecycle, exit status, and stable redacted failure categories.
- Run the provider as a systemd user service with `KillMode=control-group`. Protected children belong to transient request units bound through `BindsTo` and `PartOf`, also with control-group termination. Authority loss kills and reaps descendants; startup stops surviving prior request units before admitting new work.
- Conventions: kebab-case operation IDs, 256-bit random base64url request IDs and browser launch capabilities, lowercase SHA-256 digests, snake_case protocol fields, and provider-authoritative Unix timestamps. Future agent transport uses versioned JSON Lines, Unix peer admission, Ed25519 signatures, and owner-authenticated polling.

## UX & Interaction Patterns

- Human direct requests follow the same pending, review, authentication, and one-time decision model as later agent requests. The approval view distinguishes local human terminal from paired agent identity.
- Show request ID, requester, friendly operation effect, target, permitted arguments, credential labels/use types, policy and executable digests, expiry, and one-time meaning. Never show credential values.
- Provide explicit denial and authenticated approval once; no always-allow action. Keep keyboard access, visible focus, screen-reader labels, and nonvisual confirmation.
- Deliver the browser launch capability only through the human desktop-launch path, exchange it once for an HttpOnly SameSite session, and require session-bound CSRF protection plus human authentication for mutations. Request clients receive no approval URL, capability, or credential prompt.
- Completion and failures expose clear redacted status without retry authority or raw child output. Dedicated UX documents currently contain metadata only; interaction requirements above come from the available product and architecture contracts.

## Cross-Story Dependencies

- Secure startup and provider-owned state underpin policy and session authority. Policy plus an unlocked compatible backend enable requests; request creation enables one-time decisions; policy/executable verification precedes secret resolution and contained execution. Redacted history spans the complete lifecycle.
- Session lock, expiry, restart, approval transitions, and execution must share consistent authority invalidation. Process containment completes the authority-loss guarantee once children can run.
- Epic 2 adds paired-agent identity, signed admission, and owner-bound polling to this lifecycle. Epic 3 adds fixed SSH execution and provider-local temporary key handling behind the same backend and execution boundaries; neither justifies secret export or broader execution authority.
