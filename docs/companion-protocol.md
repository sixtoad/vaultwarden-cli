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
