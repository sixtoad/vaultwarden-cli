# Story 1.3 planning provenance and decisions

## Workspace and workflow

- Worktree: `/home/sixtocantolla/sessions/day-to-day/vaultwarden-provider-session`.
- Branch: `feature/provider-vaultwarden-session`.
- Base: `origin/main`, `91a6a66`, fetched 2026-09-23. Story 1.1 PR #19 and Story 1.2 PR #20 are both merged. No dependent PR is needed; no PR is authorized yet.
- Explicitly requested quick-dev was absent from the active skill catalog. Located and read `/home/sixtocantolla/sessions/day-to-day/skills/.agents/skills/bmad-quick-dev/SKILL.md`, its customization defaults and sequential planning steps. Use that workflow, including checkpoint 1 before implementation, subsequent review and human checkpoints.
- Project has no `_bmad/scripts/resolve_customization.py`, configuration, or overrides. Resolver failed because the file is absent; applied documented manual fallback. Defaults contain only the project-context glob, with no matches. English, user Sixto; project name vaultwarden-cli; planning sources below; implementation artifacts here. Do not inherit unrelated homelab project settings.
- No applicable AGENTS.md, CLAUDE.md, sprint status, or previous completed quick-dev spec was found in this project. Merged Story 1.1/1.2 code supplies continuity.
- Subagents compiled Epic 1 context and separately investigated backend/session extraction and lifecycle races. At the original planning checkpoint, implementation and tests had not started. Subsequent progress is recorded below and in the verification evidence.

## Required sources read

These documents are absent from merged main but exist in the earlier local worktree. Read the originals in full; do not substitute the older `docs/access-mvp.md` for the canonical contract:

- `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/docs/stories/1-3-unlock-and-lock-provider-session.md`
- `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/docs/architecture/architecture-vaultwarden-access-2026-09-01/ARCHITECTURE-SPINE.md`
- `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/docs/specs/spec-vaultwarden-access/SPEC.md`
- Epic context derived from that worktree's `docs/epics.md` and associated planning documents.
- Tracking: https://github.com/sixtoad/vaultwarden-cli/issues/7

## Backend and compatibility decisions

Existing login uses API client credentials; master-password unlock locally derives and decrypts vault keys. Do not introduce a password OAuth grant. Require human-provisioned provider-owned account metadata and encrypted key/KDF configuration, using the existing Config schema without automatically loading reusable CLI sessions. Provider API bootstrap credentials belong in the provider-specific OS keyring namespace, provisioned by the human through their keyring manager; document exact service/account names implemented. Never accept credentials as daemon arguments or environment variables. Account setup is a prerequisite, not a new agent or CLI password interface.

Provider session persistence uses a separate `vaultwarden-accessd` keyring service and explicit account identifiers. Distinguish provisioned account bootstrap credentials from revocable derived keys/access/refresh session tokens. On lock, expiry and restart clear the latter; retained setup cannot enable secret resolution without a fresh human password. Keyring unavailable means fail closed, even if CLI insecure-fallback environment flags are set. Never consume or clear the CLI namespace inadvertently.

The repository's live-test image is `vaultwarden/server:1.36.0`. Initial compatibility accepts exactly server version `1.36.0`, config API version `2025.12.0`, server name `Vaultwarden`, and config object `config`; every other version/shape is unsupported until deliberately validated. This is a provider support policy, not a claim that other upstream versions are broken. Upstream tagged source confirms `/api/version` reports the Vaultwarden version, while `/api/config` reports a distinct compatibility version: [Vaultwarden 1.36.0 metadata implementation](https://raw.githubusercontent.com/dani-garcia/vaultwarden/1.36.0/src/api/core/mod.rs).

Probe only those metadata endpoints, never `/sync` or cipher endpoints. Use strict URL validation, HTTPS in production, no redirects that forward authority, time/body limits, and fixed errors without raw upstream body/URL chains. Mock HTTP may explicitly permit test loopback. Unsupported KDF/cipher forms likewise fail closed. Reuse `MasterKey` and `CryptoKeys`; extract selective decryption without invoking printing `commands::*` APIs or passing `CipherOutput` through ports.

## Lifecycle and human UI decisions

Keep all backend authority inside the provider instance. Replace production caller-supplied eligibility verifiers with the owned gated backend, preserving registry/policy validation ordering. The gate spans session checks and secret consumption/disposal. Lock waits for an admitted resolution scope to finish; once lock completes, no old result is usable. Revoke state before fallible keyring or store cleanup; failure poisons admission until cleanup succeeds. Test both lock-first and resolution-first orderings and delayed unlock completion.

Use a 15-minute maximum unlocked session, bounded further by backend token expiry. Fresh human unlock renews only session authority, never invalidated work. Inject a clock for exact boundaries; use monotonic runtime deadlines so wall-clock rollback cannot extend a session. Browser capability/session lifecycle must also reject stale restart credentials. A fresh desktop launch can establish a browser session while the vault remains locked.

Launch capabilities are 256-bit, one-use, delivered through a human-owned desktop launch artifact/path, never agent IPC or stdout. Passwords use bounded POST bodies only. Validate literal loopback bind, exact Host/Origin, session cookie and CSRF before invoking authentication. Use no-store/referrer/CSP protections and avoid third-party resources or request-body logging. Denial and lock cannot require a currently usable vault session. The concrete desktop handoff must preserve the architecture's browser capability boundary without storing it in access state or audit.

Later request approval, execution and SSH operations remain outside this story. Private backend resolution tests must not add a public secret-returning test API. Ports may express neutral credential types for future adapters, but no additional operation becomes agent-accessible.

## Evidence requirements

`cargo-mutants 27.1.0` is installed. Scope must include every changed core/session/backend extraction file and the UI security boundary. Use deterministic fake backends, clock and keyring, plus mock HTTP, without real vault credentials. Include sentinel tests for password, tokens, keys and resolved fields across Debug/Display, UI responses/headers, URL handling, process output, status and persisted state/audit. Test actual keyring record deletion and namespace isolation, not only a locked flag.

Retain exact commands, result totals, full mutation outcome artifacts, and an individual rationale for each survivor. Failure to complete a required run is incomplete evidence, not success. Do not begin review before the four requested verification steps finish; after review fixes update the evidence before human presentation. User approval is still required before any commit, push or PR.

## Review-driven iteration 2

The human approved the original planning checkpoint with `A`. All four required
verification steps completed before three independent reviewers ran. Their
findings required a `bad_spec` loopback outside frozen intent: see
`1-3-review-results.md`. Positive preservation instructions were extracted, the
implementation was archived and reverted, and a new sequential implementation
pass began against the amended spec. No sprint-status file exists to synchronize.

The amended loopback design uses provisioned, browser-trusted HTTPS plus an
independent one-time launch-issued browser proof. The provider does not install
trust, bypass certificate validation, or add a native/WebAuthn authentication
path. The human's TLS identity and bootstrap/account setup are deployment
prerequisites. Actual Firefox verification uses only a disposable profile and
synthetic CA/backend, documented in `1-3-browser-evidence.md`.


## Review-driven iteration 3

The three fresh independent reviewers became available on retry. Acceptance
reported no actionable findings; blind and edge reviewers identified additional
lifecycle/browser/crypto cases. The mandatory bad-spec loopback preserves frozen
intent and archives iteration-2 evidence. See review results and the spec change log.

Use Linux CLOCK_BOOTTIME for suspend-aware elapsed lifetime: CLOCK_MONOTONIC
excludes suspend while CLOCK_BOOTTIME includes it without relying on settable
wall time ([Linux clock_gettime documentation](https://man7.org/linux/man-pages/man2/clock_gettime.2.html)).
Support optional individual cipher keys returned by the pinned server, decrypting
that key with the account/org key before field decryption inside the adapter
([Vaultwarden 1.36.0 cipher representation](https://github.com/dani-garcia/vaultwarden/blob/1.36.0/src/db/models/cipher.rs#L321)).
