# Approved technical contract

Derived from the recorded conversation and baseline code; scope approved on
2026-10-16. These choices remain subject to the native feasibility gate and are
not previously shipped capabilities.

## Existing integration points

Baseline: `1f97bcfb623f81e95ec104a6c3a12cf3338eec7c` on the fork's merged main.

| Area | Baseline integration point | Required change |
| --- | --- | --- |
| Companion wire/tickets | `src/adapters/companion.rs` | Add versioned biometric review/decision variants; preserve v1 and ticket limits. |
| Device enrollment | `src/adapters/companion_identity.rs`, `src/bin/vaultwarden-accessd.rs` | Bind/revoke a separate public key using provider-owned local administration. |
| Proof and commit | `src/access/direct_request.rs`, `src/access/application.rs` | Add a narrowly validated alternate authentication proof; retain prepared binding and final serialized checks. |
| Mac protocol/state | `macos/Sources/CompanionCore/Protocol.swift`, `DecisionController.swift` | Typed biometric exchange, immutable review binding, cancellation and uncertain-result handling. |
| Native trust/key use | `macos/Sources/CompanionCore/Trust.swift` plus a focused signer component | Keep mTLS identity separate; use a biometric-protected approval key. |
| Mac UX | `macos/Sources/ApprovalCompanion/App.swift` | Enrollment status, explicit Touch ID/password choices and operation-bound authentication. |

Currently `PreparedApproval.authenticate` accepts only a fresh password and the
`AuthenticatedApproval` constructor is private. Do not add a generic constructor,
test-only production bypass or fake password authenticator. The new verifier
must validate a complete biometric proof before producing equivalent internal
approval authority. Preserve existing history persistence, single-dispatch and
execution containment; a signature alone never calls the dispatcher directly.

## Trust and key lifecycle

The Mac, its human OS account, approved app and trusted local provider
administration are trusted components. Restricted agents cannot enroll devices
or keys. This design does not protect against a compromised human/provider OS
or a malicious approval key deliberately enrolled by its administrator.

The provider checks a signature against its registered public key, not Apple's
biometric matcher. No remote attestation is provided. Never describe a public
key or client assertion as proof of its hardware origin, nor a successful
signature as identifying one particular finger/person.

Approved key implementation: Secure Enclave P-256 signing, with device-only,
unlocked-device access, `privateKeyUsage` and `biometryCurrentSet`. Keep persisted
opaque key material/reference in appropriately protected local Keychain storage;
do not export raw private-key bytes or substitute a software key. The mTLS
identity remains independent so background reads do not trigger fingerprint
prompts. Apple documents [access-controlled Secure Enclave signing](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey)
and [key protection](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave).

Before provider authorization work, a small native spike must establish actual
key creation, persistence/reopening, per-use biometric enforcement and app
signing/access behavior on the M1. The current bundle is ad-hoc signed. A build
or signature check alone does not prove usable Keychain access after an update.
If a different signing/provisioning setup is necessary, stop for that decision;
do not relax the key ACL or silently recreate keys.

Each attempt has a new `LAContext`, zero Touch ID reuse duration and no retained
authorization context after signing/cancel/failure. Apple's [reuse-duration contract](https://developer.apple.com/documentation/localauthentication/lacontext/touchidauthenticationallowablereuseduration)
describes zero as disabling reuse of device unlock. Native acceptance must also
prove no application-context caching authorizes a later request. The intended
[current-biometric-set gate](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset)
must invalidate use after fingerprint enrollment changes; validate on hardware.

Enrollment/recovery:

1. After explicit opt-in, the Mac creates the separate key and displays/exports only its public key and fingerprint for the intended provider/companion binding.
2. The trusted operator verifies that binding out of band. Local provider administration registers it while the daemon is stopped, using existing ownership and safe-file rules. A fresh enrollment test challenge demonstrates possession before enabling real approvals; possession is not hardware attestation.
3. Permit one active key per companion/provider binding. Replacement/removal must be explicit; no network registration or automatic re-enrollment. Retain password-only compatibility for existing registry records, with a bounded, documented schema migration and fail-closed downgrade behavior.
4. Restart retires old connections/tickets. Revoking a companion retires its approval key; replacing/revoking only the approval key leaves explicitly permitted password approval available. Certificate renewal requires explicit key rebinding rather than inheriting authority automatically.
5. Lost keys, changed biometric enrollment and replaced Macs require a new key and trusted enrollment. Do not claim deleting a local key alone revokes the provider record.

Linux cannot directly observe fingerprint-set changes. Local key use must fail
after such a change; existing issued proofs remain subject to their ordinary
consumption, expiry and explicit revocation. Do not promise instant remote
revocation based on an event the provider cannot observe.

## Wire and authorization contract

Use additive version 2 commands on the existing companion mTLS endpoint.
Do not add fields to closed v1 response objects: old clients reject unknown
fields. Retain unchanged v1 password review/decision/unlock behavior. A typed,
explicit unsupported-version response may expose password-only compatibility;
TLS, trust or generic network failures never trigger silent downgrade.

Freeze exact command shapes, transcript encoding and signature format in shared
Rust/Swift golden vectors before production handlers. The transcript must be
domain-separated and unambiguously bind:

- protocol version and approval action;
- pinned provider identity, enrolled client certificate identity and approval key ID;
- request ID and full canonical review, including operation/effect, target, arguments, credential selection, executable/policy/argument digests and request expiry;
- provider authority generation and an unpredictable single-use nonce/ticket.

Do not hash language-dependent JSON object ordering, accept arbitrary bytes from
the app for signing, or sign a digest disconnected from the review displayed to
the human. Specify every field's encoding, ordering and bounds; test byte-for-byte
equivalence and rejection of alternative/ambiguous encodings. Select and document
the Rust signature verifier during this freeze; maintain Rust 1.88 compatibility
and dependency/license checks. The provider owns the full challenge state and
compares it with current authoritative request state.

Challenges expire after at most 60 monotonic seconds and never outlive the
request or vault session. Keep the existing conservative 55-second client
review cutoff; the server clock is authoritative. Waiting for a fingerprint
does not refresh a ticket. Consume a valid device-owned ticket atomically before
authentication, including invalid signatures. Unknown/wrong-device tickets must
not consume another device's ticket. Password and biometric reviews share
per-device/request supersession so explicit fallback cannot leave both valid.

Before final commit, revalidate enrolled device/key, authority generation,
deadline, unchanged complete review/policy and live agent binding. Serialize
with lock/expiry/revocation and retain the existing at-most-once transition.
Audit storage failure must not grant execution. Retain bounded connection/ticket
counts, closed schemas, body limits, authentication serialization/rate limits
and bounded key/signature verification costs. No cache of successful biometric
approval confers authority on another request.

## Operator interaction

The existing menu-bar companion receives pending work. Notification clicks
only open review. Display the complete existing review before offering
**Approve with Touch ID**, **Use password instead**, and **Deny**.

Snapshot the review and freeze the attempt before launching native authentication.
Allow only one in-flight attempt. Changing request, provider setup, session,
connection or sleep state cancels/invalidates it; discard late callbacks and
signatures. Recheck the current UI epoch and ticket freshness before any send.

Cancellation sends no approval and discards local authority. Denial keeps its
existing unauthenticated-decision semantics on the authenticated channel. A
password choice obtains a fresh review and asks for the provider password;
never automatically send it after biometric failure. OS password recovery may
be needed to re-enable Touch ID, but it is not a successful fingerprint approval.

After a possibly sent decision, disable competing approval paths and query
authoritative status. Never resend the signature or fall back to password
automatically. Pending/unknown status remains uncertain until resolved through
the existing explicit review/recovery flow.

History records the authentication method and a non-secret key reference, not
biometric data, challenge, signature or full wire payload. Keep all existing
redaction guarantees. No biometric data leaves macOS; biometric approval carries
no vault/master password. Existing password approval/unlock still sends its fresh
password only through the current authenticated encrypted channel.

## Bounded delivery order

1. Native feasibility/signing-profile gate and cross-language wire-vector freeze.
2. Trusted local key enrollment plus provider verifier/final-commit integration, with negative and compatibility tests.
3. Companion key use, explicit UI, cancellation and password fallback; native/controller tests.
4. Synthetic end-to-end restricted-agent acceptance on the M1, operator documentation, mutations and existing CI.

These are internal milestones for the approved feature, not additional epics.
Start with the native feasibility gate; provider authorization work waits for
that gate to pass. Recheck current main before implementation and coordinate
overlapping companion changes without absorbing unrelated branches. Native
testing and host setup require coordinated operator readiness and approval.
