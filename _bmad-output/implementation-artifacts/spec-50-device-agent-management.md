---
title: Authoritative device and agent management
type: feature
created: 2026-10-29
status: in-review
baseline_commit: 60fadd6251cafb08e91ef2856f82ef44dfe164f5
context: [docs/secret-access-boundary.md, AGENTS.md]
---

## Intent

Implement the user's issue #50 device/agent management slice across the actual
authenticated provider, generated Rust/Dart bridge and Flutter companion. The
user explicitly confirmed preservation of PR #55 on 2026-10-29: prevent future
delivery and clean up provider-owned resources, never terminate consumers.

## Security contract

Approval-client certificates, requester-agent bindings and execution providers
are separate identity types. Current administrator authority is the kernel-
authenticated provider owner UID. Enrollment grants no management authority.
Introduce an explicit trusted-console grant for an exact enrolled certificate,
default denied. Management reads and mutations require that grant; mutations
add fresh owner-password authentication and a consumed single-use ticket bound
to exact identity type/ID, action, caller certificate, generation and deadline.
Recheck authorization after authentication. Never unlock to refresh inventory.

Keep v1 responses closed and unchanged. Add deliberately versioned management
and origin commands. Bound responses and deterministic ordering; fail closed
on unsupported versions, unknown fields, duplicate IDs or malformed values.
Return only identifiers, labels, roles, trust, freshness and explicit runtime
availability. Labels never establish identity. No keys, tokens, credentials or
unfiltered diagnostics enter projections or audit.

Agent revocation must reuse ProviderApplication::revoke_agent, including token
denial before durable transaction, pending/approved invalidation, delivery
cancellation, cleanup wait and fail-closed behavior. Certificate revocation
needs durable tombstones and audit, explicit online synchronization and loss
of approval/admin access; offline deletion alone is insufficient. Re-enrollment
must not reactivate a revoked identity or reuse its name as authority.

Lost replies remain unknown. Persist the action and original typed target before
send in native configuration-bound recovery storage. Reconcile using status
reads only, never replay revocation. Durable revocation and cleanup completion
are distinct facts. Self-revocation can prevent remote reconciliation and must
retain an honest unknown/lost-access state with trusted-console recovery.

Request origin comes from the immutable signed-admission AgentOwner snapshot,
not labels or current inventory. Legacy/unsupported origin is unavailable.
An authenticated key binding is not proof of a physical device. Preserve
strict review compatibility and bind any new review envelope to the same ID.

## Code map and execution

- [x] `src/adapters/companion_identity.rs`, `src/bin/vaultwarden-accessd.rs`:
  explicit owner-provisioned administrator grants, permanent revocation records,
  private atomic persistence and redacted audit.
- [x] `src/adapters/companion.rs` and a dedicated management module: bounded
  authenticated inventory/detail/prepare/revoke/status protocol, exact-target
  tickets, authentication rechecks and authoritative reconciliation.
- [x] `src/access/application.rs`, `provider.rs`, `direct_request.rs`: reuse
  actual agent lifecycle, expose safe cleanup status and immutable provenance.
- [x] `companion/rust/src/provider/` and `api/`: closed validated models and
  generation-scoped management state, separate from request approval authority.
- [x] `companion/lib/provider/`: real inventory, details, explicit consequences,
  fresh-password confirmation, status-only recovery and provenance presentation.
- [x] `companion/macos/Runner/ProviderSettings.swift`, `ProviderAdapter.swift`,
  `companion/lib/platform/provider.dart`: durable original-action recovery with
  exact configuration binding, relaunch and setup isolation.
- [x] Regenerate bindings using FRB 2.13.0 and cargo-expand 1.0.112; never edit
  generated files. Preserve the current shared controller/Activity boundaries.
- [x] Update capabilities and migration documentation with new protocol,
  authority, consequences, compatibility and verified platform limitations.

## Acceptance

- Given an enrolled non-admin certificate, when management is attempted, then
  the provider rejects it without revealing another owner's inventory or making
  changes. A valid explicitly granted admin receives bounded provider records.
- Given duplicate labels or forged claimed IDs, when selecting and revoking,
  then only the ticket's authenticated exact identity can be affected.
- Given stale authentication, navigation, lock, background, disposal or provider
  replacement, when a completion arrives, then it cannot restore authority or
  affect the newly selected identity.
- Given pending/approved/running provider work, when access is revoked, then
  existing delivery-race and cleanup contracts hold; consumers are not killed.
- Given persistence or cleanup failure, when the UI reconciles, then durable
  revocation is distinguished from completed cleanup and no success is invented.
- Given a lost response or relaunch, when recovering, then only the original
  action's status is queried; privileged commands are never blindly replayed.
- Given a signed admitted request, when reviewing it later, then its original
  binding snapshot is shown. Legacy requests explicitly report origin unavailable.
- Given unavailable, unauthorized, empty, loading, stale or revoked inventory,
  then UI names that state and never uses local configuration as remote trust.
- Given either theme and 200% text scaling, when navigating by keyboard, then
  stable IDs, consequences and controls remain readable and reachable.

## Verification and delivery

Run complete affected Rust and Flutter tests, analyzer, format/Clippy, native
and packaging scripts. Exercise real generated FFI and authenticated TLS, not
only widget mocks. Add targeted security mutation checks for grants, target
binding, expiry, stale completions and recovery/no-replay. Review changed images
before adopting matching-host goldens. Keep hardware/CI limitations explicit.
Obtain independent code/security review, fix actionable findings, integrate
current main, regenerate bindings, and require green final-revision CI. Push a
draft PR related to #50 without closing the issue or merging other work.

## Investigation evidence

PR #52's 93431e6460f5a73c1d0f2e8d8fd087bade4e2f54 is an ancestor of baseline.
Open PR #54 owns Activity history. Independent security investigation confirmed
that remote enrollment must not be mapped to owner administration, the agent
registry has no small cardinality cap, certificate deletion has no tombstone,
and revoked inventory alone cannot prove cleanup completion. These findings
drive the contract above. No installed identity, service or application changes
are authorized by this source implementation.
