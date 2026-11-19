---
title: 'Guided enrollment desktop UI (issue 59, phase 2)'
type: 'feature'
created: '2026-11-10'
status: 'in-review'
baseline_commit: 'b3390b0'
context: [docs/guided-enrollment.md, docs/secret-access-boundary.md, companion/README.md]
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Phase 1 (PR #72) ships the enrollment protocol and `vw-access enroll`, but the
desktop companion still says guided enrollment is unavailable. A human cannot add a device
or agent from the GUI, at either end.

**Approach:** Two companion journeys over the existing pinned mTLS transport. *Owner*: an
administrator companion invites (companion or agent), lists sessions, approves by typing
the joiner's code (with a fresh provider password) and cancels, through new admin-only
provider commands. *Joiner*: a companion with a CA-valid leaf joins with a `vwe1.` code,
shows the comparison code large, and confirms or declines. The joiner protocol runs in
`companion_core` (Rust), pinned to the provider implementation by a shared vector.

## Boundaries & Constraints

**Always:** the provider never sends the comparison code and the owner UI never shows
one; only an administrator companion may invite/list/approve/cancel; approve needs the
provider password; an enrolled companion is never an administrator; the invitation secret
lives in Rust memory only and is wiped on dismiss/invalidate; Linux/Windows keep compiling
(transport unavailable there, as today); match existing widgets (`AccessPanel`,
`AccessHeading`, `StatusLabel`, `FactRow`, `AccessActions`).

**Ask First:** none (owner delegated decisions; log them in the PR body).

**Never:** Intel Mac work; the #50 redesign; QR/phone (phase 3); discovery; persisting
sessions or invitation codes; crypto in Dart; reactivating revoked identities.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Joiner happy path | valid code, provider joined reply | code `1234-5678` shown large; confirm → waiting → enrolled | N/A |
| Joiner mismatch | human taps "Codes differ" | cancel `code_mismatch` sent; final "not enrolled" | session secret wiped |
| Owner mismatch | owner types wrong code | provider `code_mismatch`; joiner later sees aborted | final, nothing enrolled |
| Expiry | state `expired` / rejection `expired` | final "invitation expired, ask for a new one" | no retry of a burned code |
| Revoked/known identity | rejection or failure `identity_refused` | "already known or revoked; never reactivated" | final |
| Forged provider | bad `provider_mac` | "provider did not prove the invitation"; nothing shown | final, no code shown |
| Not admin | `unauthorized` on admin command | manual fallback (`vw-access enroll …`) shown | no retry loop |

</frozen-after-approval>

## Code Map

- `src/adapters/companion.rs`, `src/adapters/companion/enrollment.rs` -- mTLS commands; add admin enroll commands.
- `src/access/application/enrollment_service.rs` -- owner use cases reused via `app.human_owner()`.
- `src/access/enrollment/tests.rs` -- add shared-vector test.
- `companion/rust/src/provider/enrollment*.rs`, `companion/rust/src/api/enrollment.rs` -- new joiner/admin cores + bridge.
- `companion/lib/provider/enrollment_view.dart`, `controller.dart`, `devices_view.dart`, `support_views.dart` -- UI.
- `companion/test/enrollment_test.dart`, `companion/test/goldens/` -- widget + golden tests.

## Tasks & Acceptance

**Execution:**
- [x] `companion/fixtures/enrollment-v1.json` + both crates' tests -- shared vector (join/provider/control MACs, code).
- [x] `src/adapters/companion*.rs` -- `enroll_invite|enroll_list|enroll_approve|enroll_cancel` v1, administrator-only, approve password-checked and rate-limited.
- [x] `companion/rust` -- joiner + admin sessions, frb bindings regenerated.
- [x] `companion/lib` -- Add-device panel (owner) in Devices & agents; Join-a-provider panel; manual fallback and collapsed details.
- [x] tests: Rust (both crates), widget tests, macOS 27 arm64 goldens; docs updated.

**Acceptance Criteria:**
- Given an administrator companion, when it invites a companion, then the `vwe1.` code is shown once and the list never contains a comparison code.
- Given a non-administrator companion, when it opens Add device, then it sees the manual CLI fallback and no admin action is enabled.
- Given a joined session, when the owner approves with the right code and the joiner confirms, then the joiner reaches "enrolled" without the administrator role.

## Design Notes

Decisions (D1–D6) are recorded in the PR body: reimplementation + shared vector instead of
a shared crate (keeps `companion_core` slim and pinned, as the approval transcript already
does); admin approval runs under the provider owner's authority as identity revocation does;
password required for approve only; goldens for macOS 27 arm64 only, other hosts adopted
from CI captures after retargeting to main.

## Verification

**Commands:**
- `cargo fmt --check && cargo clippy --all-targets -j 4 -- -D warnings` (root and `companion/rust`) -- clean
- `cargo test -j 4 --lib enrollment` and `cargo test -j 4 --manifest-path companion/rust/Cargo.toml` -- pass
- `flutter analyze && flutter test test/enrollment_test.dart` -- pass
