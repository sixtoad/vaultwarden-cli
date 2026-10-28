---
title: Bounded durable companion Activity
type: feature
created: 2026-10-28
status: in-review
baseline_commit: 93431e6460f5a73c1d0f2e8d8fd087bade4e2f54
context: []
---

## Intent and authorization

The user explicitly requests implementation, full verification, independent review,
a pushed branch and draft PR for the Activity slice of issue #50. This specification
records implementation decisions under that authorization; it does not close the
parent issue or authorize deployment, credential import or installed-app replacement.

Activity currently displays one remembered status. Replace it with a bounded view
of the provider's canonical durable history through authenticated transport, closed
Rust validation, generated bridge records, controller scheduling and Flutter UI.

## Boundaries

Preserve owner isolation, exact enrolled certificate checks, revocation, lifecycle
admission, strict schemas, ticket retirement and status-only uncertainty recovery.
No caller-supplied UID becomes an authenticated identity. Do not change Settings,
enrollment, device administration, native adapters or abuse protection (#53).
Never expose passwords, tokens, tickets, child output or sensitive diagnostics.
History has no authority, and cannot settle uncertainty, replay work or revive a
review. Opening an event always loads a fresh review for that exact request ID.

## Wire and display decisions

Add the closed v1 command `history` with optional integer `limit`, using canonical
50 default and 200 maximum. Keep existing session/list/review response contracts
unchanged for old clients. A response contains exactly `version:1`,
`history_version:1` and `events`. Each event contains exactly `request_id`,
`operation`, `at_unix_seconds` (required nullable), `ordinal` and `outcome`.
The outcome enum copies the canonical history enum, not arbitrary server text.
Requester identities/labels, credential metadata, policy revisions, status payloads,
create/SSH details and write receipts are deliberately omitted. Request IDs are
needed to reopen; operation names identify the action; time/ordinal/outcome describe
the event. These are display data only.

Preserve canonical descending (nullable timestamp, ID, ordinal) order, with absent
legacy timestamps last. Do not synthesize dates. Reject unknown fields, versions,
outcomes, malformed IDs/operations, oversized replies, excess rows, duplicates and
noncanonical ordering. Keep the existing 16 KiB request and 1 MiB response limits.
The provider returns the complete bounded selection or a closed unavailable error
on response overflow; it never silently truncates an event or emits partial JSON.
All history-specific allocations and projected/rendered rows remain bounded. The
canonical persistent store still loads its existing database; this preexisting
store architecture must be reported separately from wire bounds.

An old provider's closed `invalid_request` reply to History means history is
unavailable. Unknown or malformed replies remain invalid; no permissive fallback.
The companion requests the default 50 events and identifies that scope in the UI.
It requires current unlocked authority before loading Activity. The provider keeps
canonical locked-history semantics; the UI clears history on lock/background.

## Code map and execution

- [x] `src/access/application.rs`, `src/access/provider.rs`: add a crate-private
  companion history path through the existing lifecycle gate and owner filtering;
  avoid unnecessary unbounded history-specific copies.
- [x] `src/adapters/companion.rs`: add authenticated command, explicit display
  projection and response bounds; recheck enrollment before releasing history.
- [x] `companion/rust/src/provider/protocol.rs`: closed history wire structs,
  outcome validation, bounds, canonical order and display projection.
- [x] `companion/rust/src/provider/session.rs`, `api/provider.rs`: separate history
  state, loading and unavailable outcomes, epoch retirement and immutable display
  snapshot. Preserve existing uncertainty admission and settlement fields.
- [x] `companion/lib/provider/controller.dart`: fetch on Activity navigation and
  foreground refresh with context checks; clear on retirement or metadata failure.
- [x] `companion/lib/provider/support_views.dart`, `page.dart`: render loading,
  empty, available, unavailable, disconnected and locked states; exact-ID links,
  canonical ordering, accessible controls and scalable layouts in existing theme.
- [x] Regenerate Rust and Dart outputs with pinned codegen 2.13.0 and expand
  1.0.112. Never edit generated source manually.
- [x] Extend provider real mTLS tests, Rust validation/lifecycle tests and Flutter
  generated-bridge/controller/widget tests; add targeted security mutations.
- [x] Update capability and migration documentation with the wire contract,
  limits, verification, compatibility and remaining platform limitations.

## Acceptance scenarios

- Given an enrolled authenticated companion, when history is requested, then only
  the provider owner's canonical ordered redacted events are returned within limits.
- Given missing, revoked or other-owner identity, when history is requested, then
  unauthorized data is never returned, including after an enrollment change.
- Given malformed, excessive, unsupported or unknown wire data, when validation
  runs, then no partial history or decision authority is admitted.
- Given legacy history without time, when rendered, then time is explicitly unknown
  and the provider's order is preserved.
- Given an in-flight history read, when navigation, provider replacement, lock,
  background or disposal retires context, then late data cannot restore it.
- Given an uncertain decision, when Activity is visited or a completed event exists,
  then only original-ID status recovery can settle the marker; history cannot.
- Given an event row, when opened, then the exact ID enters normal fresh review;
  no stored history result authorizes execution.
- Given compact/desktop, light/dark and 200% text, when Activity is used, then text
  and controls remain reachable, labeled and scrollable without overflow.

## Verification and delivery

Run full affected root Rust tests on Linux (provider modules are Linux-gated),
companion Rust tests/MSRV/fmt/Clippy, Flutter full suite/analyzer/pilot tests, actual
FFI and desktop integration, packaging diagnostics/artifact checks and affected
security mutations. Review any changed visual captures before adopting matching
host golden bytes. Run complete host gate and record genuine hardware/CI limits.
Integrate current main before final verification, regenerate if necessary, obtain
independent code/security review, push and create a draft PR related to #50, require
final-revision CI and fix failures. Do not merge or close #50.
