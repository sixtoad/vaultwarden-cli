# Human-approved Vaultwarden Access

`vaultwarden-accessd` runs in the human's desktop OS account. Agents must run
under distinct restricted OS principals. A same-UID agent can read the human's
memory and keyring and is not a supported secret boundary. The existing direct
`vaultwarden-cli` remains a separate human-only vault client.

Stories 1.1–1.3 provide private state, constrained operation policy and a locked
provider with a protected password UI. Request approval, agent transport,
protected execution and platform/WebAuthn authentication are later stories.
The provider has no agent-facing item lookup, secret export or password command.

## Human setup and launch

1. Choose a provider-owned state directory outside agent workspaces. Its parent
   must be owned by the human and mode `0700`. The provider creates its own
   directory/state with `0700`/`0600` and checks ownership, links and permissions.
2. Create a separate human-owned `0600` backend setup JSON. Use the existing
   Config schema's `server`, `client_id`, `email`, `encrypted_key` and explicit
   `kdf_iterations` fields from the account setup. `server` must be an HTTPS
   origin with no userinfo, path prefix, query or fragment. The supported KDF is
   PBKDF2 (`kdf: 0`, when specified), with 1–2,000,000 iterations; the production
   account's configured count must be preserved. The encrypted account key must
   be authenticated type 2. Organization bindings also need the account's
   `encrypted_private_key` and `org_keys` setup. Unsupported or stale crypto
   metadata fails closed; there is no sync/enumeration fallback.
3. Through the human desktop's OS-keyring manager, provision the account API
   client secret as service **`vaultwarden-accessd`**, account
   **`bootstrap-client-secret`**. Do not put it, the master password, access or
   refresh tokens, or derived keys in setup, command arguments or environment.
   This is separate from the direct CLI's `vaultwarden-cli` keyring namespace.
4. Provision a dedicated loopback HTTPS identity. Have a CA trusted by the human's
   browser issue a server certificate whose **subjectAltName contains IP address
   `127.0.0.1`**, with server-auth usage and valid dates. A dedicated local CA may
   be installed manually in that browser's trust store; the daemon never installs
   trust or changes the system/browser trust configuration. Store the PEM leaf
   certificate followed by any intermediate certificates, and its matching
   unencrypted PKCS#8/RSA/EC PEM private key, outside agent workspaces in the
   human's private directory. Both files must be current-user-owned, regular,
   non-symlink, single-link, mode `0600`, at most 64 KiB. Protect the CA signing
   key separately. Repository `tests/fixtures/provider-tls` identities are public
   synthetic test fixtures and must never be used or trusted for real accounts.
5. Run `vaultwarden-accessd --state-root <private-directory> --backend-config
   <private-setup.json> --ui-tls-cert <private-server-chain.pem> --ui-tls-key
   <private-server-key.pem>`. Arguments contain only paths, never passwords or
   tokens. Absent/invalid identity fails closed. Without `--backend-config`, the
   daemon remains locked with no UI, but it still requires a functioning keyring
   to clear any prior provider session before startup.
6. In the human desktop browser, open **`open-vaultwarden-access.html`** inside
   the provider state directory and follow its **HTTPS** link. Do not bypass a
   certificate warning: fix the certificate/trust provisioning before entering
   a password. No plaintext HTTP password interface exists. The file contains a
   one-use 256-bit capability, never printed to stdout or returned over agent
   IPC. The browser removes the fragment before exchanging it for a Secure,
   HttpOnly, SameSite=Strict cookie and an independent launch-only proof stored
   in that origin's `sessionStorage`. Keep this browser tab; a new tab cannot
   recover proof from the cookie. Restart creates a fresh launch file and
   invalidates old capability/cookie/proof credentials. If the launch tab is lost,
   restart the daemon and use its new launch file.
7. Enter the master password only in that authenticated loopback page. Unlock
   derives keys locally and uses separately provisioned API client credentials
   for OAuth; it does not send the master password to Vaultwarden. The page
   clears its password input before awaiting network I/O. Use **Lock** to revoke
   provider authority. Actions are sent in click order. The displayed message is
   the **last action result**, not a continuously refreshed session status.

The initial adapter supports exactly **Vaultwarden 1.36.0**, `/api/config`
version **2025.12.0**, object `config`, and server name `Vaultwarden`. This
allowlist reflects the repository's integration image, not a claim that other
versions are broken. `/api/version` and `/api/config` are the only compatibility
probe endpoints. Unknown/malformed versions, redirects, oversized responses and
transport failures fail closed before cipher resolution, with a fixed redacted
category. Compatibility is checked at unlock and again before item access.
Personal and organization login items may use an individual encrypted item key;
the adapter authenticates and unwraps it with the account or organization key,
then uses it for the selected fields and eligibility marker. Malformed,
unsupported or unauthenticated item keys fail closed.

## Authority lifetime and redaction

Sessions last at most 15 minutes and never longer than the backend token lifetime.
The deadline uses Linux suspend-aware monotonic boot time, so sleep counts toward
the session lifetime and wall-clock changes cannot extend it. Clock failure or
backward movement expires authority. Checks run at each credential admission,
after successful or failed backend work, before policy persistence, and by the
daemon timer.
The OS-keyring account **`revocable-session`** under service
**`vaultwarden-accessd`** holds only the provider's revocable access token and
vault keys; it is never restored automatically. Startup (even without setup), lock and expiry clear
it and usable memory authority. Startup clears the session and stale launch file
after acquiring exclusive writer ownership, before decoding or validating state;
a competing writer never clears the active provider's session. No refresh token is retained. Bootstrap setup
remains provisioned but cannot decrypt vault values without a fresh password.
Keyring unavailability fails closed; CLI insecure-file fallback flags do not
apply. Run a single provider per human keyring namespace.

Lock, expiry and startup invalidate unexecuted durable work and advance the
lifecycle epoch. Unlock never resurrects invalidated work. One authority mutex
serializes session changes, admission and scoped secret consumption. Lock waits
for an already admitted scope to dispose of its values; after lock returns no
old scope can release a value or restore a session. Expiry during resolution
discards the result. Cleanup failures leave authority revoked and poison
re-unlock until cleanup succeeds.

The loopback listener binds literal `127.0.0.1` on an ephemeral port. It requires
TLS server authentication, exact Host and Origin, a session cookie and the
independent launch proof for mutations,
and bounded HTTP headers/body with no transfer encoding or duplicate headers.
TLS handshake/request parsing has a two-second total deadline per connection.
Up to eight independent parser workers prevent a slow unauthenticated connection
from blocking Lock. Exhausting capacity irreversibly closes admission and clears
authority; restart is required. Cookie-only page loads never reveal mutation
proof. Only encrypted POST bodies carry passwords. Responses disable caching/referrers/framing;
no request-body or upstream-body logging exists. Status/errors and durable
state contain no password, session, raw item, resolved field or browser capability.
Only provider core holds the backend port; raw `Cipher`/`CipherOutput` never
cross that port. Future execution must consume values inside the private core
scope, and must not expose them to clients.

SIGINT/SIGTERM remains responsive while backend or status work is delayed. In
configured mode it irreversibly closes admission before waiting, joins every accepted UI
worker, clears authority again after joining even on worker failure, and removes
the launch artifact. Delayed unlock cannot recreate authority after shutdown. Process-manager crash containment for protected children is
implemented with the later execution/supervisor stories; this story starts no
protected processes.

## One-time human requests (Story 1.4)

With a provisioned operation and an unlocked provider, use the human terminal
under the same desktop UID as the provider:

```sh
export VAULTWARDEN_ACCESS_STATE_ROOT=/path/to/private-provider-directory
vw-access request deploy -- staging safe 3
vw-access request deploy --revision <policy-sha256> --no-wait -- staging safe 3
vw-access status <request-id>
```

Values are positional, in the operation's Target/Choice/Integer order. Integers
are normalized to decimal before the provider hashes and stores them. Omitting
`--revision` binds the current policy; an explicit stale revision rejects before
creation or desktop handoff. Clients cannot select requester identity, ID,
creation time, expiry, launch URL, credential binding, or executable.

The request command prints a provider receipt containing only its ID, policy
revision, normalized argument digest, expiry and status. It then waits and prints
state changes until terminal. `--no-wait` returns after the receipt. Disconnecting
does not resubmit or grant approval; use `status` with the printed ID. Parser and
transport errors use fixed categories and do not echo rejected values. A failed
desktop handoff is a durable `failed/review_unavailable` receipt; the request is
never executed.

The private `human.sock` uses mode `0600` inside the provider's checked `0700`
directory. Linux kernel peer credentials authenticate the human before parsing;
the client verifies socket ownership, permissions and the server's kernel UID
before sending values. Agents must remain in separate restricted UIDs. Each
connection carries a version-1 JSON request, terminated by closing its write
half. Inputs are limited to 2 MiB and a two-second parsing deadline; the client
allows ten seconds for validation, persistence and the bounded desktop handoff.
At most sixteen human request workers are admitted. This is not agent transport.

The provider defaults to a five-minute request lifetime. Configure
`--request-lifetime-seconds` or
`VAULTWARDEN_ACCESS_REQUEST_LIFETIME_SECONDS` (1–86400 seconds) at provider startup.
The provider's suspend-aware monotonic clock enforces the deadline independently
of displayed Unix time. Session expiry, Lock, restart and shutdown can invalidate
a request earlier. Expiry runs during polling and on the daemon timer even when
no terminal is connected. Unlock never revives an expired request. Terminal
status remains available while locked; no history pruning is introduced.

Each accepted request opens a private `review-<id>.html` desktop artifact through
the fixed, root-owned `/usr/bin/xdg-open`, with only the artifact path in process
arguments and null standard streams. The artifact navigates automatically to
the trusted HTTPS loopback page. The 256-bit capability is exchanged once and
removed from the browser address bar. Capabilities are request-scoped and become
unusable on expiry or lifecycle invalidation; consumed, stale and failed-launch
artifacts are removed. Successful launcher exit confirms handoff, not viewing.

The review displays requester, operation/effect, target, normalized arguments,
credential labels/use types, executable and policy digests, argument digest,
expiry, one-time meaning and live textual status. It never includes immutable
item IDs, field/environment mappings, secrets, backend sessions or process output.
Review reads require both a browser cookie and independent session-bound proof;
a cookie-only page never reveals review data or recovers proof. Valid new request
launches preserve existing browser sessions. Capabilities and browser sessions
are each bounded to 64; restart refreshes these in-memory browser sessions.

Use Tab/Shift+Tab and Enter for session controls and **Refresh request status**.
Focus is visibly outlined, controls have names, and status uses an atomic live
region. Approval and denial are explicitly unavailable in Story 1.4, and no
operation runs. The closed status protocol already represents pending, approved,
denied, expired, running, completed (exit code 0–255), and failed (closed reason);
future outcomes are tested through fixtures without adding decision handlers.
Legacy schema-v1 `{id,status}` records remain readable by the store but carry no
human ownership and cannot be queried or reviewed as direct requests.
