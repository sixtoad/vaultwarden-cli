# Companion protocol v1

Frozen implementation contract, 2026-10-06. This opt-in LAN/VPN service expands
human authority to enrolled Macs. It never exports browser launch/session
capabilities, vault values, agent signing keys or execution capabilities.
The Linux provider remains the only password verifier and execution authority.
No public-internet deployment or SSH transport is supported in v1.

## Trust and framing

HTTPS HTTP/1.1 only, mutually authenticated TLS 1.2 or newer. The operator
provisions a private CA and server certificate with its actual DNS/IP SAN.
Clients validate that CA, hostname, certificate validity, and SHA256 of the
exact server leaf DER certificate pinned through a trusted console channel.
Client certificates chain to the configured client CA and their exact DER
SHA256 must appear in a separate private enrollment store. Enrollment is a
trusted local console operation; it is never available over this API. Revocation
requires stopping the daemon before changing the enrollment store, then restarting;
this retires all connections and tickets before enrollment changes take effect.
Never disable TLS validation. Mac client private identity is held in Keychain.

One POST request per TLS connection, path `/v1/companion`, Content-Type
`application/json`, Content-Length required; no transfer encoding, compression,
redirects, cookies, query, pipelining or HTTP upgrade. UTF-8 JSON input max 16384
bytes, headers max 8192 bytes, response max 1048576 bytes. All input objects reject
unknown fields. Password max 4096 UTF-8 bytes, nonempty. TLS/read/write deadline
5 seconds, bounded concurrent connections (at most 8), serialized authentication,
at most 5 password attempts per enrolled identity per rolling 60 seconds.

Every command includes `version:1`. Read commands are idempotent. Error replies
are closed `{ "version":1,"error":"invalid_request|unauthorized|unavailable|stale|authentication_failed|rate_limited" }`.
HTTP 200 holds a success object. Error status mappings are: `invalid_request` 400,
`unauthorized` 403, `stale` 409, `authentication_failed` 422, `rate_limited` 429,
and `unavailable` 503. Wrong unlock and approval passwords use 422 because
URLSession can interpret 403 on mutual TLS as client-certificate rejection and
hide the application error body. Enrollment rejection remains 403. This transport
correction does not change password verification, ticket consumption or retry rules.
Errors contain no backend detail. Bodies/passwords are never logged. Client never automatically
retries unlock or decision POSTs; reconnection retries only reads.

## API

* `{"version":1,"command":"session"}` =>
  `{"version":1,"state":"locked|unlocked","generation":N}`.
* `{"version":1,"command":"list"}` =>
  `{"version":1,"requests":["43-character-base64url-id",...]}` (max 256).
  Authoritative pending IDs, refreshed on reconnect; notification hints never
  authorize an operation. Generic notifications contain no request detail.
* `{"version":1,"command":"review","request_id":"..."}` =>
  `{"version":1,"review":DirectReview,"ticket":"64-lowercase-hex","generation":N}`.
  DirectReview is the existing complete canonical object (see fixture). Tickets
  are unpredictable, single-use, expire after 60 monotonic seconds, and bind the
  authenticated certificate fingerprint, exact review, and authority generation.
  Terminal reviews have `ticket:null`. At most 256 tickets; review can replace
  the previous ticket for the same device/request without consuming another slot.
* `{"version":1,"command":"decision","request_id":"...","ticket":"...","decision":"approve|deny","password":"..."}` =>
  `{"version":1,"status":DirectStatus}`. Deny omits password. Approve requires a
  fresh password. Consume ticket before verification, including wrong passwords.
  Recheck enrollment, review binding, monotonic expiry, authority generation,
  request deadline and agent binding before commit. Commit uses existing prepared
  approval authentication and execution dispatch. No notification action approves.
* `{"version":1,"command":"unlock","password":"..."}` => session response.
  Unlock is separate and invalidates old authority. Locked agent submissions
  create no pending request; the agent must submit a fresh request after unlock.
* `{"version":1,"command":"status","request_id":"..."}` =>
  `{"version":1,"status":DirectStatus}`. After a lost decision response, fetch
  status, never resend the decision. Pending after ambiguous response is still
  uncertain; obtain an explicit new review/human decision. Unknown after provider
  restart is unavailable, never proof of execution or rejection.

DirectStatus is `{ "status":"pending|approved|denied|expired|running" }`,
`{"status":"completed","exit_code":0..255}` or
`{"status":"failed","reason":DirectFailure}`. See Rust canonical enums.

## Delivery and routing

The launcher returns immediately without network I/O under the authority lock.
The app polls the authoritative pending list every 5 seconds while connected,
with capped reconnect backoff. Sleep, disconnection and quit confer no authority
and requests expire normally. Routing configuration is distinct from pinned
provider identity; a future managed tunnel must retain identical mTLS and pin
checks and require no terminal. No tunnelling is implemented in this release.

## Production Touch ID approval v2 (issue 49)

Additive, provider side (issue 49 PR A). Version 1 messages above are
byte-identical; an older companion that never sends version 2 keeps working with
password approval. The provider stays the only verifier: the companion supplies
only a key id and a signature, never a value the provider trusts.

### Encodings

* SHA-256 identifiers on the wire are 64 lowercase hex characters; inside a
  transcript they are the 32 raw bytes. Tickets are the same: the 64-hex ticket
  is 32 raw bytes in a transcript.
* Public keys: unpadded base64url of the 65-byte uncompressed SEC1 P-256 point
  (`0x04 || X || Y`). Compressed or other encodings are refused.
* Signatures: unpadded base64url, ASN.1 DER ECDSA P-256 with SHA-256, 8 to 72
  bytes; verified with `ring` `ECDSA_P256_SHA256_ASN1`. Non-canonical base64url
  (padding, other alphabets) is refused.
* Key id: SHA-256 of the 65-byte public key. One key per (provider, approval
  client); keys are never shared between devices.
* Transcript framing: each field is a 4-byte big-endian length followed by its
  bytes. Integers are unsigned 64-bit big-endian. Strings are UTF-8.

Approval transcript, in order:

| # | Field | Bytes |
| --- | --- | --- |
| 1 | domain | `dev.vaultwarden.provider.approval.v2` |
| 2 | action | `approve` (deny is never signed) |
| 3 | provider identity | SHA-256 of the provider TLS leaf certificate DER (the companion's pin); rotating the provider certificate changes it |
| 4 | approval client | SHA-256 of the client mTLS leaf DER (the registry fingerprint) |
| 5 | key id | 32 raw bytes |
| 6 | request id | UTF-8 (43-character base64url) |
| 7 | record digest | 32 raw bytes |
| 8 | policy digest | 32 raw bytes (policy revision) |
| 9 | arguments digest | 32 raw bytes |
| 10 | request expiry | u64, Unix seconds |
| 11 | provider generation | u64 |
| 12 | ticket | 32 raw bytes |
| 13 | ticket deadline | u64, Unix milliseconds, provider wall clock |
| 14 | review digest | SHA-256 of the canonical review JSON |

Review digest: SHA-256 over the `review` object exactly as received in the
Review response, canonicalized as JSON with object members sorted bytewise by
key (every key is ASCII), no insignificant whitespace, strings escaped as
`serde_json` does: only `"` (`\"`), `\` (`\\`) and U+0000 to U+001F are
escaped (`\b`, `\f`, `\n`, `\r`, `\t`, the rest as lowercase `\u00xx`);
every other character, including DEL (U+007F), the C1 controls (U+0080 to
U+009F), `/` and non-ASCII, is written as literal UTF-8; integers in shortest
decimal form. This equals RFC 8785 for this schema (no
floats; a float fails closed). Hash the received JSON value, not a
re-serialization of a typed struct that may drop or reorder members.

Enrollment proof-of-possession transcript: domain
`dev.vaultwarden.provider.approval-enroll.v2`, provider identity (32), approval
client (32), public key (65), management ticket (32), action id (UTF-8).

The synthetic contract (`dev.vaultwarden.companion.synthetic.v1`) never verifies
on the provider; the three domains are mutually exclusive. A committed golden
vector with the inputs, canonical review JSON, transcripts and signatures is in
`tests/fixtures/approval-v2-golden.json` (no private key; verify, never re-sign).

### Review and decision (version 2)

* `{"version":2,"command":"review","request_id":"..."}` =>
  `{"version":2,"review":DirectReview,"ticket":T|null,"generation":N,"approval_binding":B|null}`.
  `B` is present with a ticket:
  `{"version":2,"domain","action","provider_identity","approval_client","key_id":hex|null,"biometric_allowed":bool,"request_id","record_digest","policy_digest","arguments_digest","expires_at_unix_seconds","generation","ticket","ticket_deadline_unix_ms","review_digest"}`.
  `biometric_allowed` is false when this device has no key or the policy sets
  `require_password`. It reports eligibility only, never lock state, exactly as
  the password path does: the provider lock is signalled by `session`
  (`state:"locked"`); locking ends every pending request (a later review is
  terminal, with no ticket and no binding), and any decision on a ticket
  issued before the lock, password or proof, is `stale`. `B` is null when the
  binding is unavailable, including when the provider wall clock cannot be
  read (the ticket then never accepts a proof); password approval still works
  then. The companion should recompute `review_digest` and refuse to sign on
  mismatch.
* `ticket_deadline_unix_ms` is the provider's wall clock and is a signed
  transcript value only. The companion must not enforce it against its own
  clock (clocks may be skewed); the provider enforces the ticket's 60 second
  lifetime on its monotonic clock and answers `stale` when it has passed.
* `{"version":2,"command":"decision",...,"decision":"approve","proof":{"key_id":"hex","signature":"b64url"}}`
  or the same with `"password"`. Approve takes exactly one of `password` or
  `proof`; both or neither is `invalid_request`. Deny takes neither. Version 1
  never accepts `proof`. Reply `{"version":2,"status":DirectStatus}`.
  The proof path consumes the ticket first, rechecks the review/generation
  (`stale` on change), shares the 5-per-minute per-device attempt budget with
  passwords (`rate_limited`), requires `key_id` to be the device's current
  enrolled key, rebuilds the transcript from provider state only and verifies it
  (`authentication_failed` on any mismatch, retired key, other device's key,
  wrong domain, or `require_password`). Under the identity commit gate it
  rechecks enrollment, ticket expiry and that the key is still current, then
  commits through the same approval path as passwords. History records
  `"approval":{"method":"biometric","key_id":"hex"}` on the approved event;
  absence means password. Signatures and passwords are never logged or stored.

### Key management (version 2 management commands)

Any enabled approval client may manage its own key; no administrator is needed.
An administrator may also revoke (never enroll) another device's key.

* `{"version":2,"command":"biometric_prepare","operation":"enroll|revoke","target":{"kind":"approval_client","id":fp}}`
  => `{"version":2,"operation","target","action_id","ticket","generation","valid_for_seconds":55,"provider_identity","biometric_key_id":hex|null}`.
  Tickets are single use, purpose-bound (an `identity_prepare` ticket never
  authorizes key management and vice versa), and bound to actor, target, action,
  generation and lock epoch. Key-management tickets live apart from the
  administrators' `identity_prepare` tickets, so no device can exhaust the
  table an administrator needs to revoke it, and each device holds at most one
  outstanding ticket per operation: a new `biometric_prepare` for the same
  operation replaces (invalidates) the device's previous one.
* `{"version":2,"command":"biometric_enroll","action_id","ticket","password","public_key","enroll_signature"}`
  (own device only) => `{"version":2,"operation":"enroll","target","action_id","biometric_key_id"}`.
  Requires a fresh password and a valid enrollment proof by the new key.
  Re-enrollment atomically replaces the key and retires the old key id;
  a retired or another device's key is `invalid_request`. The retired list
  holds 256 ids; when it is full every new enrollment is `unavailable` (no id
  is forgotten to make room), while a revocation is never refused for it and
  forgets the oldest id instead. Forgetting is safe: enrollment stays refused
  while the list is full, and any enrollment needs the device certificate, a
  fresh password and proof of possession, which a fresh key needs anyway.
* `{"version":2,"command":"biometric_revoke","target","action_id","ticket","password"}`
  => `{"version":2,"operation":"revoke","target","action_id","revoked_key_id":hex|null}`.
  Disables Touch ID and retires the key; the device stays enrolled and keeps
  password approval.
* `identity_list` / `identity_detail` with `version:3` add
  `biometric_key_id` (hex or null) to every row (null for agents). Version 2
  rows are unchanged because the companion parses them as closed objects.

Device revocation (online `identity_revoke` and offline `companion revoke`)
removes the device's key and retires its id in the same registry write. Key
enrollment and key revocation append `biometric_enrolled` / `biometric_revoked`
audit records (`fingerprint` = the device acted on, `actor` = the acting
device, `key_id`) in the same write; the newest 64 are kept. Older audit
records (no `key_id`) stay readable. The registry is never written above its
64 KiB read limit: an enrollment that would exceed it is `unavailable`, and a
revocation first forgets the oldest Touch ID audit records, then the oldest
retired ids.

Registry versions and rollback: `companion-identities.json` is written as the
lowest version that represents its content. Without any Touch ID key, retired
key id or Touch ID audit record it is version 2, byte-compatible with the
previous release (empty Touch ID members are omitted), so offline `companion
enroll`, administrator grants and device revocations never lock out an older
binary. Once Touch ID has been used it is version 3 (with `biometric` and
`retired_biometric_keys`), and an older provider binary refuses it (fail
closed); it stays version 3 after the last key is revoked, because the retired
ids must not be lost. Version 1 and 2 files load with no keys. Provider history:
the approved event carries an `approval` member only after a biometric
approval; history written before any biometric approval is unchanged. An older binary
rejects an event carrying it (its event parser refuses unknown members), so
after the first biometric approval a rollback fails closed on reading that
history, exactly as it does on a version 3 registry.
