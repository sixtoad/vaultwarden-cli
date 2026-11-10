# Guided mutual enrollment (issue 59, phase 1)

Phase 1 is the provider/Rust protocol and a terminal client. It has no
graphical UI. Phase 2 (desktop UI) and phase 3 (phone with QR) build on it.

Today a device or agent is added in one of two manual ways:

- **Agents.** `vw-access agent pair` with a public key someone copied by hand.
- **Companions.** Offline `vaultwarden-accessd --companion-enroll-cert` with
  the daemon stopped.

Guided enrollment replaces that happy path. An already authorized human
issues a short-lived, single-use invitation. The joining endpoint shows a
comparison code, the provider owner types it at the provider, and a human
approves at **each** end. Only then is the endpoint enrolled.

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
3. **Comparison code (both ends derive it; only the joiner shows it).**
   - The code is `HKDF(salt = SHA-256(T_full), ikm = secret, info = domain || "comparison-code" || id)`,
     truncated to 64 bits and reduced to 8 decimal digits, shown as
     `1234-5678`.
   - The modulo bias is below 2^-37.
   - Any substituted key, nonce, role, channel or provider certificate
     changes the code.
   - The provider **never displays** it: not in `enroll list`, not in any
     `human.sock` reply, not after approval. The owner reads it on the
     joining endpoint and types it into `enroll approve`, which compares it
     with the provider's own derivation without early exit. If the provider
     showed the code, the owner could copy it from the provider's own output
     into `approve` without looking at the joiner, and the comparison would
     prove nothing.
4. **Confirm, status and cancel (joiner).**
   - Each carries `HMAC(key(control), domain || action || SHA-256(T_full))`.
   - A cancel's action names its reason (`cancel/cancelled` or
     `cancel/code_mismatch`), so the reason is authenticated too.
   - An agent's confirm also carries an Ed25519 signature by the new key
     over the `possession` control message.

The code is not a secret once shown. Typing it at the provider proves that
the joiner's screen and the provider belong to the same session. Because
the code is derived with the secret, a passive observer cannot precompute
it.

## Message flow

```
Provider owner (human.sock)          Provider                      Joiner (agent socket / mTLS)
  enroll invite-agent|companion ──▶  new session (Open)
  ◀── id + vwe1.<id>.<secret>  ─ ─ ─ ─ out of band (said aloud, typed, later QR) ─ ─ ▶
                                     ◀── EnrollJoin {nonce, mac}                    (agent: + public key)
                                     verify mac, refuse known/revoked identity
                                     ──▶ Joined {role, provider_nonce, provider_mac}
  enroll list → awaiting_approvals (no code)                         shows role + code 1234-5678
  enroll approve <id> --code <read on the joiner, typed here>        human answers "yes"
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
  forgotten. When the 32 retained sessions are full, the oldest finished
  session is evicted, an `enrolled` one last (its joiner may still need a
  lost final reply).
- **Memory only.** Sessions are never persisted. A provider restart
  forgets every invitation, and joiners then see `invalid_invitation`
  (fail closed).
- **Agent-socket admission.** An unpaired OS identity reaches the
  enrollment messages only while a live session names it, or while a
  final session it **joined** is retained. The joiner then learns the real
  end: `enrolled` (a lost final reply is recoverable), but also
  `code_mismatch` or `duplicate_join` (a relay or a leaked secret),
  `cancelled` or `expired`. A final session nobody joined admits nobody:
  the frame is refused before parsing, and the joiner reports
  `invalid_invitation`. Admission is no authority; every message still
  needs the session's MAC. Momentary contention on the sessions is
  `busy` and a poisoned session lock `unavailable`, never "not invited",
  also for an already paired agent resending its confirmation.

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
| Replay of a join | **Byte-identical retransmission:** the identical reply, so a lost reply is recoverable. **After completion:** `already_used` (on the agent socket too, while the joined session is retained; afterwards the UID is refused before parsing, `invalid_invitation`). **Against another invitation:** the MAC fails. |
| Replay of a confirm, status or cancel | The MAC is bound to the transcript hash, so it is accepted only for its own session. It is idempotent there; a commit never repeats. |
| Duplicate join (the secret leaked) | A second, different join aborts the session (`duplicate_join`) and is itself answered `already_used`. The legitimate joiner's next message gets the state `aborted: duplicate_join`; on the agent socket its UID stays admitted while the session is retained. |
| Wrong secret or unknown id | Both are indistinguishable (`invalid_invitation`). Three bad proofs burn a live invitation. If nobody had joined it, the agent socket then no longer admits the invited UID, which the joiner also reports as `invalid_invitation`; a joined session's joiner sees `aborted: too_many_failures`. |
| Mismatch at the provider | The owner types a code different from the provider's own derivation: `code_mismatch`, final, nothing enrolled. The joiner's next message gets `aborted: code_mismatch` (a sign of a relay between the endpoints). A malformed code (wrong length) is an input error and does not burn the session. The provider never prints the code, so it cannot be copied from the provider side. |
| Mismatch at the joiner | The joining human answers anything but `yes`: cancel with `code_mismatch`, final. |
| Timeout or expiry | An approved but unconfirmed session expires without enrolling. **Companion:** an action after the deadline finds `expired` (while the session is retained). **Agent socket:** a joined session's joiner finds `expired` while it is retained; an expired session nobody joined admits nobody, so the frame is refused before parsing (`invalid_invitation`). **Owner:** `approve`/`cancel` answer `expired`. `enroll join` waits until the session's own expiry (plus 5 s), or less with `--timeout-seconds`. |
| Cancellation | The owner (`enroll cancel`) or the joiner can cancel any live session, including after both approvals but before the commit. Afterwards the joiner's next message finds `cancelled` (an agent joiner too, while the session is retained). Cancelled before the join, the agent socket refuses the invited UID before parsing (`invalid_invitation`). |
| Offline peer | **Owner approves before the join:** `awaiting_peer`, no state change. **Joiner cannot reach the provider:** the join is retried identically up to three times, after 250 ms and 500 ms. The confirm is re-sent (250 ms doubling to 2 s after a lost reply, every second while waiting) until the deadline. A client timeout keeps the key file, because the outcome is unknown. |
| Busy provider | Momentary contention on the sessions is answered `busy` on the agent socket (before parsing, never "not invited"), and a busy provider gate does not refuse an invited joiner's enrollment message. The joiner resends the identical message after 250 ms doubling to 2 s, until the deadline; `busy` is never a definitive failure. If it is still busy at the deadline, `join` reports that nothing was enrolled. An already paired agent resending its confirmation (lost final reply) under contention also gets `busy`. |
| Provider restart | Every session is forgotten. The joiner's next message is refused (agent socket: before parsing) as `invalid_invitation`; `join` explains the possible causes (mistyped, cancelled, expired or ended and forgotten, or a restart) and deletes the key file, **unless** a confirmation's reply had been lost and no non-final state was seen since: that confirmation may have committed, so the outcome is unknown and the key file is kept (check `vw-access agent list`). |
| Storage fault at join | If the identity store cannot say whether the joining key or device is known, the join is answered `unavailable` and the invitation stays open; only a definite "known" refuses it (`identity_refused`). `join` resends the identical join up to three times in all (with the busy backoff) before reporting `unavailable`; the invitation can be joined again later. |
| Storage fault at commit | `failed: unavailable`. A store fault while committing is ambiguous (the binding may be durable while a later step failed), so `join` reports an unknown outcome and keeps the key file (check `vw-access agent list`). `failed: identity_refused` is definite and deletes it. |
| First companion | With no companion enrolled yet (no registry file), the companion endpoint still starts. Zero identities authorize no command; only `enroll` with a live invitation is processed. The first guided commit creates the registry (`0600`, atomic rename, in the private provider directory). A present but invalid registry still stops the endpoint. The provider logs a startup warning while the registry is absent: a lost registry also loses its revoked list, so restore it from backup. |
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
vw-access enroll list                                                  # state (never the code)
vw-access enroll approve <id> --code 1234-5678                        # type the code the joiner shows
vw-access enroll cancel <id>
```

In the invited agent account:

```sh
vw-access enroll join --socket /run/vaultwarden-access/agent.sock --key-file ~/.config/vw/agent.key
```

`join` does the following:

- **Invitation code.** It reads the code from the terminal with echo off.
  The secret is never in argv, and the program's copy of the typed text
  is wiped right after parsing (copies made inside the terminal library
  are outside its control).
- **Key file.** It creates a new 32-byte seed file, `0600`, and never
  replaces an existing one. This is the `vw-access submit --key-file`
  format. The directory must be a real directory (not a symlink), owned
  by the agent account and not group- or world-writable (the file may
  later be removed by path); each refusal (file exists, directory refused,
  directory missing) has its own message. The creation and any removal
  are made durable with a directory `fsync`.
- **Waiting.** It waits until the invitation expires (plus 5 s), or for
  `--timeout-seconds` if that is shorter.
- **Confirmation.** It shows the role and the comparison code, asks the
  person at that terminal to read the code to the provider owner (who types
  it into `enroll approve`), and requires them to type `yes`. Without a
  terminal it refuses.
- **Result.** It prints the binding id for `vw-access submit --binding-id`.
- **Key cleanup.** The key file is deleted after a definitive failure. It is
  kept when the outcome is unknown: a client timeout, a provider that no
  longer knows the session after a confirmation's reply was lost (and no
  waiting state since), or `failed: unavailable` at commit.

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
- screens for the states above, with the code shown large on the joining
  device and typed (never displayed) at the provider end;
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

- a human who approves without comparing (mitigated: the owner must type
  the code, and the provider never shows it, so it has to come from the
  joiner's screen);
- a compromised provider owner account;
- a leaked secret combined with a human who ignores a mismatch.

The joiner-end confirmation is enforced by the client software, because the
agent process is the joiner. It protects the joining human from enrolling
into the wrong provider. The provider-end approval is the authority.
