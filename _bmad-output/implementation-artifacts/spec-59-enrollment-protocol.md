---
title: Guided mutual enrollment protocol (phase 1)
type: feature
created: 2026-11-09
status: done
baseline_commit: 7bc3753
context: [docs/guided-enrollment.md, docs/secret-access-boundary.md, AGENTS.md]
---

## Intent

Implement issue #59 phase 1: a provider-side Rust protocol plus `vw-access`
commands. It adds an agent or a companion device without hand-copying keys or
certificates. Expiring single-use invitations come from the provider owner.
A comparison code is bound to the session and shown only on the joining
endpoint; the provider owner types it at the provider, which never displays
it. A human approves at both ends before the commit. There is no UI.

## Security contract

- **Primitives.** Only HKDF-SHA256, HMAC-SHA256, SHA-256 and Ed25519 from
  the existing dependency tree. There is no PAKE: channels already
  authenticate their peers (kernel credentials, mTLS), and the 256-bit
  secret travels out of band.
- **Provider side.** Only the provider owner, on the human socket, can
  invite, approve or cancel. Approval requires typing the joiner's code; a
  mismatch aborts the session.
- **Joiners.** A joiner can only join, confirm, read status or cancel.
- **What enrollment grants.**
  - An agent becomes a requester binding through `pair_agent`.
  - A companion becomes an approval client and is never an administrator.
- **Known identities.** A known identity, enabled or revoked, is refused
  before any code is shown. A matching label never reactivates anything.
- **Failure handling.** Replay, mismatch, expiry, cancellation, duplicates
  and an offline peer each end in a closed, final state. Sessions live in
  memory only.

## Acceptance (Given/When/Then)

- **Both approvals required.** Given an agent invitation, when only the
  joiner confirms, then nothing is paired. When the owner then approves with
  the joiner's code and the joiner re-confirms, then a binding is created
  through `pair_agent`.
- **Typed code mismatch.** Given a joined session, when the owner types a
  different code, then the session is aborted and no approval can follow.
- **Revoked key.** Given a revoked agent key, when it joins a new invitation
  with the same label, then it is refused with `identity_refused`.
- **Revoked companion.** Given a revoked companion fingerprint, when it
  joins, then it is refused and stays revoked.
- **Wrong peer.** Given another UID, or another mTLS leaf, then it cannot
  reach or act on the session.
- **No new authority.** Given the joiner channel, it can neither approve nor
  submit work, and an enrolled companion is not an administrator.

## Tasks (done)

- `src/access/enrollment/{transcript,book,wire,joiner,tests}.rs`: the
  protocol and the state machine.
- `src/access/application/enrollment_service.rs`: the use cases and the agent
  commit through `pair_agent`.
- Transports:
  - `human_socket` (`enroll_*` commands);
  - `unix_socket` (invitation-scoped admission, `enrollment_exchange`);
  - `companion` (`enroll` command, `companion/enrollment.rs`,
    `companion_identity::enroll_online`).
- Agent driver: `adapters/enrollment_client.rs`.
- CLI: `vw-access enroll invite-agent|invite-companion|list|approve|cancel|join`.
- Documentation: `docs/guided-enrollment.md`.
