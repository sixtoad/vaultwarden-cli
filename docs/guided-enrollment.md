# Guided mutual enrollment (issue 59, phase 1)

Phase 1 is the provider/Rust protocol and a terminal client. It has no
graphical UI. Phase 2 (desktop UI) and phase 3 (phone with QR) build on it.

Today a device or agent is added in one of two manual ways:

- **Agents.** `vw-access agent pair` with a public key someone copied by hand.
- **Companions.** Offline `vaultwarden-accessd --companion-enroll-cert` with
  the daemon stopped.

Guided enrollment replaces that happy path. An already authorized human
issues a short-lived, single-use invitation. Both endpoints show the same
comparison code, and a human approves at **each** end. Only then is the
endpoint enrolled.

The manual paths stay available for diagnostics and recovery.

## Roles and authority

| Actor | Can | Cannot |
|---|---|---|
| Provider owner (kernel-authenticated `human.sock`) | invite, list, approve (typing the code), cancel | — |
| Joining agent (agent socket, invited UID/GID only) | join, confirm, read status, cancel its own session | invite, approve, submit work before enrollment completes |
| Joining companion (mTLS, CA-valid leaf, not enrolled) | join, confirm, read status, cancel its own session | inventory, review, decisions, management |

What each enrollment produces:

- **Agent.** An ordinary requester binding. It is created through the same
  `pair_agent` path as `vw-access agent pair`, so it gets the same
  validation, uniqueness rules and audit entry. A requester binding never
  approves anything.
- **Companion.** An approval client. It is **never** an administrator.
  Granting administrator stays the separate, explicit offline
  `--companion-grant-admin` step.

Pairing does not unlock the vault and does not authorize any operation.

## Cryptographic design (no new cryptosystem)

The design uses only primitives already in the dependency tree, in standard
constructions:

- **HKDF-SHA256** (`hkdf`, RFC 5869). It derives a separate key for each
  invitation and each purpose from the 256-bit invitation secret:

  ```
  key(purpose) = HKDF(salt = invitation_id, ikm = secret, info = domain || purpose)
  ```

  The purposes are `join`, `provider` and `control`.
- **HMAC-SHA256** (`hmac`). It proves knowledge of the secret. Tags are
  checked with the constant-time `verify_slice`.
- **SHA-256.** It hashes a transcript of length-prefixed fields with domain
  separation (`vaultwarden-access/enroll/v1\0`).
- **Ed25519** (`ed25519-dalek`, `verify_strict`). An agent uses it to prove
  possession of the key it enrolls.

**Why no PAKE or key agreement.** Every channel the protocol runs on already
authenticates both peers:

- **Agent socket.** Kernel peer credentials, and the socket owner is checked
  by the client.
- **Companion endpoint.** mTLS, with the client pinned to the provider
  certificate.

So the protocol needs no confidentiality and no key exchange. It only has to
bind two humans' intent to one specific pair of identities. The invitation
secret has 256 bits and is delivered out of band (shown once to the
inviting human). Online guessing is therefore infeasible, so a PAKE would
add complexity without closing any threat.

### Transcript

```
T_join = domain, channel, invitation_id, joiner_identity, joiner_nonce, provider_identity
T_full = T_join, role (agent: label, uid, gid | companion: label), provider_nonce
```

- **`channel`** is `agent-socket` or `companion-mtls`.
- **`joiner_identity`** is the 32-byte agent public key, or the SHA-256 of
  the companion's mTLS leaf certificate.
- **`provider_identity`** is empty on the agent socket, where kernel
  credentials authenticate the provider. On the companion endpoint it is the
  SHA-256 of the provider's TLS certificate (the joiner's pin).

### Messages

1. **Join (joiner).** `HMAC(key(join), T_join)`, plus the agent public key
   on the agent channel.
2. **Joined (provider).**
   - The role, `provider_nonce` and `HMAC(key(provider), T_full)`.
   - The joiner verifies this tag before showing anything, so a provider
     without the secret is detected (`ProviderNotAuthenticated`).
3. **Comparison code (both ends).**
   - The code is `HKDF(salt = SHA-256(T_full), ikm = secret, info = domain || "comparison-code" || id)`,
     truncated to 64 bits and reduced to 8 decimal digits, shown as
     `1234-5678`.
   - The modulo bias is below 2^-37.
   - Any substituted key, nonce, role, channel or provider certificate
     changes the code.
4. **Confirm, status and cancel (joiner).**
   - Each carries `HMAC(key(control), domain || action || SHA-256(T_full))`.
   - An agent's confirm also carries an Ed25519 signature by the new key
     over the `possession` control message.

The code is not a secret. It lets two humans check that both screens belong
to the same session. Because the code is derived with the secret, a passive
observer cannot precompute it.

## Message flow

```
Provider owner (human.sock)          Provider                      Joiner (agent socket / mTLS)
  enroll invite-agent|companion ──▶  new session (Open)
  ◀── id + vwe1.<id>.<secret>  ─ ─ ─ ─ out of band (said aloud, typed, later QR) ─ ─ ▶
                                     ◀── EnrollJoin {nonce, mac}                    (agent: + public key)
                                     verify mac, refuse known/revoked identity
                                     ──▶ Joined {role, provider_nonce, provider_mac}
  enroll list → code 1234-5678                                        shows role + code 1234-5678
  enroll approve <id> --code <typed from joiner>                     human answers "yes"
                                     ◀── EnrollConfirm {mac, signature}  (re-sent until final)
                                     both approvals present → commit → Enrolled
                                     ──▶ State {enrolled: binding id | fingerprint}
```

**Ordering.** The two approvals may arrive in either order.

- The commit always happens on the joiner's channel: the joiner re-sends its
  confirmation until a final state arrives.
- So the companion registry is written only by the companion endpoint,
  under its own identity-commit lock.
- The provider owner's approval is the authorizing decision. The joiner's
  confirmation is the joining human's consent.

## State machine

```
AwaitingJoin ──join──▶ AwaitingApprovals{provider_approved, joiner_confirmed} ──both──▶ Enrolled
     │                         │
     ├─ cancel (owner) ────────┼─▶ Cancelled{by: provider|joiner}
     ├─ expiry ────────────────┼─▶ Expired
     ├─ 3 bad proofs ──────────┼─▶ Aborted{too_many_failures}
     └─ known identity ────────┘─▶ Failed{identity_refused}
                               ├─ wrong typed code ─▶ Aborted{code_mismatch}
                               ├─ joiner says no ───▶ Aborted{joiner_reported_mismatch}
                               ├─ second join ──────▶ Aborted{duplicate_join}
                               └─ store refuses ────▶ Failed{identity_refused|unavailable}
```

- **Final states.** Every final state is terminal. There is no retry of a
  burned invitation: issue a new one.
- **Retention.** Final sessions stay listable for 10 minutes, then are
  forgotten.
- **Memory only.** Sessions are never persisted. A provider restart
  forgets every invitation, and joiners then see `invalid_invitation`
  (fail closed).

### Limits

| Limit | Value |
|---|---|
| Invitation lifetime | 60–1800 s, default 600 s |
| Live invitations at once | 8 |
| Sessions retained | 32 |
| Labels | 1–128 bytes; agents: printable ASCII, as with `agent pair` |

## Failure cases

Each case has a test in `src/access/enrollment/tests.rs` (pure protocol) or
in the provider and transport tests listed below.

| Case | Behaviour |
|---|---|
| Replay of a join | **Byte-identical retransmission:** the identical reply, so a lost reply is recoverable. **After completion:** `already_used`. **Against another invitation:** the MAC fails. |
| Replay of a confirm, status or cancel | The MAC is bound to the transcript hash, so it is accepted only for its own session. It is idempotent there; a commit never repeats. |
| Duplicate join (the secret leaked) | A second, different join aborts the session (`duplicate_join`). The legitimate human sees the failure. |
| Wrong secret or unknown id | Both are indistinguishable (`invalid_invitation`). Three bad proofs burn a live invitation. |
| Mismatch at the provider | The owner types a code different from the provider's: `code_mismatch`, final, nothing enrolled. A malformed code (wrong length) is an input error and does not burn the session. |
| Mismatch at the joiner | The joining human answers anything but `yes`: cancel with `code_mismatch`, final. |
| Timeout or expiry | Any action after the deadline finds `expired`. An approved but unconfirmed session expires without enrolling. |
| Cancellation | The owner (`enroll cancel`) or the joiner can cancel any live session, including after both approvals but before the commit. |
| Offline peer | **Owner approves before the join:** `awaiting_peer`, no state change. **Joiner cannot reach the provider:** the join is retried identically up to three times. The confirm is re-sent until the client deadline. A client timeout keeps the key file, because the outcome is unknown. |
| Duplicate invitation | A second live invitation for the same role and label, or for an enabled agent label, is refused (`duplicate`). |
| Revoked identity | **Never reactivated.** A known agent key (enabled or revoked) is refused at join, before any code is shown. A known companion fingerprint (enabled or revoked) is refused the same way. A matching label only ever creates a **new** binding; the revoked one stays revoked. The store refuses again at commit. |
| Wrong OS identity | Only the UID/GID an agent invitation names passes kernel admission to the enrollment messages. Everyone else is refused before parsing. An invited agent still cannot submit work. |
| Another companion | Post-join messages must come from the same mTLS leaf that joined. |
| Owner account as agent | Refused at invite. The same OS-identity rules as `agent pair` apply (on macOS the agent group, and not the provider or operator UID). |
| Shutdown | Closed admission refuses every enrollment action. |

## Terminal usage

On the provider host, as the operator:

```sh
vw-access enroll invite-agent ci-runner --uid 42001 --gid 42003      # prints id + vwe1.… code
vw-access enroll invite-companion "Studio Mac"
vw-access enroll list                                                  # state, comparison code
vw-access enroll approve <id> --code 1234-5678                        # type the joiner's code
vw-access enroll cancel <id>
```

In the invited agent account:

```sh
vw-access enroll join --socket /run/vaultwarden-access/agent.sock --key-file ~/.config/vw/agent.key
```

`join` does the following:

- **Invitation code.** It reads the code from the terminal with echo off.
  The secret is never in argv.
- **Key file.** It creates a new 32-byte seed file, `0600`, and never
  replaces an existing one. This is the `vw-access submit --key-file`
  format.
- **Confirmation.** It shows the role and the comparison code, and requires
  the person at that terminal to type `yes`. Without a terminal it refuses.
- **Result.** It prints the binding id for `vw-access submit --binding-id`.
- **Key cleanup.** The key file is deleted after a definitive failure. It is
  kept when the outcome is unknown (client timeout).

The companion side of the protocol is `access::enrollment::joiner`, using
`JoinAttempt::companion`. It is sent as the mTLS command
`{"command":"enroll","version":1,"message":{…}}`. In phase 2 the Flutter
companion calls it through the Rust bridge.

## Integration points and phase 2 needs

**#71 (`vw-access setup`), not merged.** The protocol is independent of it.

- `enroll join` creates the agent key itself (`enrollment_client::create_agent_key`).
  Once #71 lands, `setup agent-key` and this function should share one
  implementation.
- Companion certificate issuance stays with #71's `setup tls`. Phase 1
  enrolls a CA-valid leaf; it does not issue certificates.

**Desktop UI (phase 2).** It needs:

- a companion-side command to create, approve and cancel invitations from
  an administrator companion (today only the owner's `human.sock`);
- Rust-bridge bindings for `JoinAttempt` and `JoinedSession`;
- screens for the states above, with the code shown large and typed (or
  compared) at the provider end;
- a manual connection fallback;
- diagnostics kept off the happy path.

**Phone (phase 3).** It needs:

- a QR encoding of the `vwe1.` code plus the provider certificate pin, with
  a typed alternative;
- mobile mTLS identities (#60).

**Discovery.** Nearby discovery may only pre-fill the address. It is never
identity; the code and the pins are.

**Audit.** Agent enrollments write the existing `paired` audit entry.
Companion enrollments are not yet audited in the identity registry: adding
an action needs a registry format version bump. This is tracked as a
phase 2 item.

## Threat model summary

**Defended against:**

- another local account or device guessing or replaying its way in;
- a stolen invitation used after it expired, or after the legitimate join
  (the duplicate aborts it);
- a wrong-provider or man-in-the-middle substitution of the key, role or
  certificate (the code differs and the provider MAC fails);
- a joiner trying to approve itself or gain approval rights;
- reactivation of revoked identities.

**Not defended against:**

- a human who approves without comparing;
- a compromised provider owner account;
- a leaked secret combined with a human who ignores a mismatch.

The joiner-end confirmation is enforced by the client software, because the
agent process is the joiner. It protects the joining human from enrolling
into the wrong provider. The provider-end approval is the authority.
