# Human-approved Vaultwarden Access

`vaultwarden-accessd` runs in the human's desktop OS account. Agents must run
under distinct restricted OS principals. A same-UID agent can read the human's
memory and keyring and is not a supported secret boundary. The existing direct
`vaultwarden-cli` remains a separate human-only vault client.

Stories 1.1–1.9 provide private state, constrained operation policy, a protected
provider session, authenticated one-time browser decisions and immutable executable
preparation, login-backed execution, descendant containment and redacted history.
Story 2.1 adds durable restricted-agent pairing and selective revocation. Story 2.2
adds signed noninteractive agent submission over a bounded Unix socket. Story 2.3
adds owner-authenticated polling and interruptible noninteractive waiting.
Platform/WebAuthn authentication remains a later story.
The provider has no agent-facing item lookup, secret export or password command.

## Supported platform

The provider and human terminal client (`vaultwarden-accessd` and `vw-access`)
require Linux. Their access and adapter library modules are compiled only on Linux.
On other platforms both binaries exit unsuccessfully with a fixed unsupported-platform
message, before parsing arguments or accessing provider state, keyrings or transports.
The general `vaultwarden-cli` retains its existing cross-platform support. Native
macOS and Windows provider transports require future platform-specific adapters;
there is no fallback that relaxes Linux ownership, socket or execution checks.
Protected executable preparation has additional kernel and image requirements
specified below.

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
5. Configure the supplied `vaultwarden-accessd.service` user unit to run
   `vaultwarden-accessd --state-root <private-directory> --backend-config
   <private-setup.json> --ui-tls-cert <private-server-chain.pem> --ui-tls-key
   <private-server-key.pem>`, then start that user service. Install its companion
   helper as described below; arbitrary shell launches are rejected. Arguments
   contain only paths, never passwords or
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

## Human operator provisioning

The human owner can register reviewed executables and create operations through
`vw-access` and `human.sock`, starting with empty provider state. Unlock through
the existing desktop UI first. These writes use the owner's existing local
administration authority; they do not prompt for a second approval or accept a
password. Every later execution still requires its own approval. Agents use
different OS identities and cannot provision through the agent protocol. There
is no same-UID isolation: the provider owner remains trusted to administer policy.

Keep the reviewed, self-contained native ELF64 artifact in a private execution
root with safe ancestry, owned by root or the provider as required below. The
file must be non-writable, executable, and not a symlink. Ordinary dynamically
linked executables, scripts and general-purpose interpreters are unsupported.
The command verifies using production execution preparation, without launching
the image or resolving credentials. A matching digest does not establish that
the program's behavior was reviewed; specifying the profile declares that review.

```sh
export VAULTWARDEN_ACCESS_STATE_ROOT=/path/to/private-provider-directory
vw-access image register --id backup-image \
  --execution-root /path/to/private-executables \
  --path /path/to/private-executables/reviewed-backup \
  --sha256 <64-lowercase-hex-digest> \
  --profile reviewed_self_contained_elf64_v1
vw-access image list
vw-access image show backup-image
vw-access operation create --file backup-policy.json
vw-access operation list
vw-access operation show backup
```

`operation create` reads an `OperationPolicyDraft`, not persisted provider JSON.
Files are regular, non-symlink JSON files at most 128 KiB. Unknown fields and
invalid input produce redacted errors. Responses are JSON containing metadata;
inspection is available while locked, and results above the inspection bound
(1 MiB) produce an explicit error instead of a truncated listing. Lists take no ID.

This Login-backed secret example maps a pre-existing Login item's password field:

```json
{
  "id": "backup",
  "description": "Back up the reviewed staging resource",
  "image_id": "backup-image",
  "targets": ["staging"],
  "arguments": [{"type": "target"}],
  "credentials": [{
    "item_id": "11111111-1111-1111-1111-111111111111",
    "label": "Backup service token",
    "use_type": "login",
    "field_mappings": [{"field": "password", "environment": "BACKUP_TOKEN"}]
  }]
}
```

For a username/password Login, use the same credential binding with
`field_mappings` containing both `{"field":"username","environment":"BACKUP_USER"}`
and `{"field":"password","environment":"BACKUP_PASSWORD"}`. The exact Login item
must contain the requested fields and exactly one custom field named `vw-access`
whose value is `backup` (the marker `vw-access=backup`);
markers are specific to each operation ID. Only immutable item IDs and policy
metadata belong in these files, never passwords, tokens or private-key values.
Credential onboarding remains a separate human task.

An SSH-key operation uses a pre-existing SSH-key item, fixed destination and
pinned host fingerprint. Replace these synthetic identifiers and fingerprint
with reviewed metadata before creating a real policy:

```json
{
  "id": "ssh-backup",
  "description": "Back up the fixed resource",
  "image_id": "backup-image",
  "targets": [], "arguments": [], "credentials": [],
  "ssh": {
    "credential": {
      "item_id": "22222222-2222-2222-2222-222222222222",
      "label": "Backup SSH key", "use_type": "ssh"
    },
    "working_directory": "/var/empty",
    "destination": {
      "host": "backup.example.test", "port": 2222, "user": "backup",
      "resource_path": "/srv/archive",
      "host_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    }
  }
}
```

SSH eligibility checks the SSH-key item type/body; it does not substitute a Login
or apply Login markers to SSH-key items. Provisioning does not install an SSH
client or make ordinary OpenSSH compatible with the self-contained image profile.
The operator must supply and review a compatible artifact; destination controls,
private key material handling and execution containment restrictions still apply.

Registration and creation are atomic and create-only. Every existing ID conflicts,
including an identical retry; there is no replace/delete command. On a timeout or
disconnect, the write may already have committed. Reconcile with `image show ID`
or `operation show ID`, compare digest/revision and metadata, and only retry if the
record is absent. An `Unavailable` persistence failure can poison the store and
prevent inspection in that process. Restart the provider before reconciling;
owner-only inspection works while the restarted provider is locked. Inspect
before unlocking and retrying: a post-rename failure may have committed the record,
and an identical retry must then conflict. Retain each registered artifact at its
pinned path/root with identical bytes and permissions: all state reads validate
registered artifacts, and execution
revalidates using production preparation. Moving or deleting even an unused
artifact can make the store unavailable. Back up metadata and artifacts together;
do not hand-edit state to recover or treat a lost response as rollback.

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
launches preserve current browser sessions; after lock/unlock, a new launch rotates
the cookie and proof before granting decision authority. Rotation reuses that
browser’s existing slot. A current authenticated pair can inspect terminal history;
a retired proof cannot decide new work. Capabilities and browser sessions
are each bounded to 64; restart refreshes these in-memory browser sessions.

Use Tab/Shift+Tab and Enter for session controls and **Refresh request status**.
Focus is visibly outlined, controls have names, and status uses an atomic live
region. **Deny request** records an immutable denial. **Authenticate and approve
once** opens a labeled password form. **Cancel authentication** clears that form
and leaves the request Pending before submission. Submitting disables cancellation:
a lost response may still mean a decision was committed, so the page polls status
and never automatically retries approval. Password inputs clear immediately.

Approval verifies the master password against the same immutable setup snapshot
used by the live backend, without unlocking, renewing its lifetime, changing the
keyring, resolving values, or executing anything. Password verification releases
both UI and provider locks, so another browser can deny or lock while it runs.
Commit rechecks the exact request, authenticated local UID, active policy revision,
normalized arguments digest, lifecycle generation, credential eligibility and
provider deadline. Status, the internal approval binding, and a redacted audit event
are persisted atomically; replays cannot create a second decision. Any uncertain
persistence closes provider authority until restart.

Approved means **approved once; execution has not started**. Only Running will
announce execution in a later story. Pending and unexecuted Approved requests expire
at their monotonic deadline (five minutes by default), on lock or restart. Denied
and Expired never regain authority. Failed desktop handoffs now become Expired,
with a redacted review-unavailable audit outcome; historical Failed records remain
readable and unchanged. Audit contains allowlisted request/operation identifiers, requester snapshots, policy
revision, credential labels/use types, timestamps and closed outcomes. Reusable
approval bindings stay outside audit. History never includes passwords, browser
proof, backend values, argument values or raw errors. The public status remains tokenless.
Legacy schema-v1 `{id,status}` records remain readable by the store but carry no
human ownership and cannot be queried or reviewed as direct requests.

## Restricted agent identities (Story 2.1)

Run these commands from the provider's human OS account, using the same
`--state-root` or `VAULTWARDEN_ACCESS_STATE_ROOT` as other human commands:

```sh
vw-access agent pair builder --public-key <base64url-public-key> --uid 42001 --gid 42003
vw-access agent list
vw-access agent revoke <binding-id>
```

All three commands use the private, kernel-authenticated `human.sock` and work
while the vault is locked. Pairing does not unlock the vault or approve work.
The public key must be canonical unpadded base64url encoding of a valid,
non-weak 32-byte Ed25519 verification key. Never supply a private key. Labels
are bounded printable ASCII (1–128 bytes). Numeric UID/GID values exclude zero
and `4294967295`; the UID must differ from the provider's UID. No OS account
lookup or account creation occurs. Agent admission requires the exact
UID and membership in the configured primary or supplementary GID, together
with verified signed transport proof; a key alone grants no access.

Pair/list/revoke responses expose only immutable binding ID, label, SHA-256
public-key fingerprint, UID, GID and enabled/revoked status. Public verification
bytes remain in private durable storage; views and administrative audit omit
keys. Pairing and revocation record the human actor and identity metadata in a
separate closed audit record. There are no default agents. Enabled labels are
unique, and every previously paired key stays reserved after revocation. To
reuse a revoked label, pair a fresh key; this creates a fresh immutable ID.

Revoke uses that ID rather than the label. Retrying an old ID cannot revoke a
replacement with the same label. Revocation denies further authority, expires
the binding's unclaimed work and cancels its claimed/running executions. A
successful response waits for confirmed affected-process cleanup; repeats also
wait for outstanding cleanup. Other agents and human work retain authority
after a successful scoped revoke. Uncertain persistence or containment closes
admission and returns a failure rather than claiming cleanup succeeded. The
client allows 30 seconds for a revocation response; transport failure is not
proof of success, so retry the same immutable ID. Bindings and tombstones
survive restart, and historical requester snapshots retain their original
identity. Signed submission and owner-authenticated polling are described below.

## Signed noninteractive agent submission (Story 2.2)

Provision a separate provider-owned directory with mode `0750` and the chosen
access group. Its parents must be traversable by the restricted agents; do not
place it inside the private `0700` provider state directory or an inaccessible
human runtime directory. No path component may be a symlink. The provider account
must be permitted to assign the socket to that group. Enable the optional listener
alongside the existing backend and HTTPS configuration with both flags:

```sh
vaultwarden-accessd --state-root <private-state> --backend-config <private-setup.json> \
  --ui-tls-cert <private-server-chain.pem> --ui-tls-key <private-server-key.pem> \
  --agent-socket-dir <shared-socket-directory> --agent-socket-gid 42003
```

The daemon validates the preprovisioned directory, creates `agent.sock` with mode
`0660` and the configured group, and refuses unsafe or active socket paths. It
removes only a verified stale socket and unlinks only its own socket inode on
shutdown. Directory descriptors pin path resolution and cleanup. Omitting both
agent flags preserves human-only operation. The existing service supervision and
execution containment requirements still apply; these flags do not create an OS
account, change group memberships or grant access to provider state.

Pair the agent's public key through the human interface described above. Provision
its corresponding raw 32-byte Ed25519 seed separately, in an agent-owned regular
file with mode `0600`; PEM, JSON, base64 text, symbolic links, trailing bytes and permissive
modes are rejected. No key generation or password prompt is added. As that
restricted UID, submit without a TTY, stdin, human state access or browser access:

```sh
vw-access submit deploy --socket <shared-socket-directory>/agent.sock \
  --key-file <agent-private-seed> --binding-id <paired-binding-id> \
  --revision <current-operation-sha256> -- staging safe 3
```

The current operation revision is mandatory and supplied through human-managed
configuration. The client generates a fresh random 32-byte nonce, signs the input,
checks socket ownership and the server's kernel UID, writes one JSON line, closes
its write half and reads one closed response. The expected provider UID comes
from the human-provisioned socket directory owner; the client has no separately
pinned provider UID. Trust the configured pathname and ensure its ancestors are
owned and permissioned so an agent or other untrusted user cannot replace that
directory. Descriptor pinning prevents races after opening a directory; it does
not establish trust in a malicious directory selected beforehand. Without `--wait`,
submission returns after acknowledgment. The agent client never reads passwords,
resolves credentials, launches a browser or falls back to human authentication. Seed buffers are bounded and zeroized. Successful stdout is
only the pending commit acknowledgment:

```json
{"status":"pending","protocol_version":1,"request_id":"<opaque-provider-generated-id>"}
```

Rejections contain `status: "rejected"`, `protocol_version: 1` and one closed
`category`: `unauthorized`, `malformed`, `unsupported_version`, `replay`,
`stale_revision`, `invalid_arguments`, `locked`, `busy` or `unavailable`. No
caller input, label, policy detail, approval URL/capability, secret or child output
is reflected. The client also exits unsuccessfully on rejection. Transport
failure or a lost acknowledgment can occur after commit. The client never retries;
re-running the command creates a new nonce and can create another request. Ask the
human to inspect retained history when delivery is uncertain. Replaying the exact
original signed message never grants another admission.

Before parsing any payload, the provider obtains `SO_PEERCRED` and `SO_PEERGROUPS`
from the connected Linux socket. The non-provider UID must match a current enabled
binding and the required GID must occur in the union of primary and supplementary
groups. Account database or PID lookups are not used. After parsing, the selected
binding independently must match the same kernel evidence and its current stored
key must pass strict Ed25519 verification. A key alone is insufficient. Policy
revision and ordered values are checked through the existing normalization rules;
identity, ID, creation time and expiry are exclusively provider-derived.

The listener admits at most 32 connection tasks and configures backlog 32. A
request frame is at most 64 KiB including its final LF; one LF-terminated JSON
object must be followed by write-half EOF, with no extra frame or trailing data.
Responses are at most 1 KiB. Input has a five-second total deadline starting at
accept; response writes have a five-second deadline. Supplementary-group storage
is capped at 65,536 entries. Overload closes connections or returns `busy`.
Synchronous authority and storage work runs in bounded blocking jobs, retaining
capacity until those jobs finish. Filesystem and desktop stalls can outlast socket
deadlines and delay shutdown; the daemon joins admitted work instead of detaching
unbounded authority jobs. Kernel credential failures fail closed.

Admission atomically stores the request, submitted audit and binding-scoped nonce
digest in one guarded snapshot replacement. Lock/revoke intent, session epoch and
request/session deadlines are rechecked at commit and before human launch. If
admission wins, later authority loss invalidates that retained request. The
acknowledgment describes the pending commit snapshot, even if review launch fails
or later lifecycle changes expire it. The human receives the existing complete
review with the immutable agent label and key fingerprint. All browser authority
stays in the private human interface.

Replay markers remain through approval, denial, completion, expiry, revocation,
lock and restart; there is no TTL or pruning. Startup expires old unexecuted work,
and unlocking never restores its nonce. A failed pre-rename write consumes neither
request nor nonce; post-rename uncertainty closes admission while preserving durable
evidence. Pre-rename authority expiry returns `locked` without poisoning admission;
actual storage failures remain fatal. Renew the session when necessary before
retrying an unconsumed nonce. Future history pruning must retain replay tombstones. Legacy human and
Story 2.1 records without markers retain their existing integrity checks. See the
[wire and persistence contract](implementation/2-2-protocol-contract.md) for exact
signed bytes and the frozen test vector.

## Polling delegated work (Story 2.3)

Use the same socket, private seed and immutable binding ID for each command:

```sh
vw-access poll <request-id> --socket <shared-directory>/agent.sock \
  --key-file <agent-private-seed> --binding-id <paired-binding-id>
vw-access wait <request-id> --timeout-seconds 300 \
  --socket <shared-directory>/agent.sock --key-file <agent-private-seed> \
  --binding-id <paired-binding-id>
vw-access submit deploy --wait --timeout-seconds 300 \
  --socket <shared-directory>/agent.sock --key-file <agent-private-seed> \
  --binding-id <paired-binding-id> --revision <current-operation-sha256> \
  -- staging safe 3
```

`poll` observes once. `wait` resumes an existing request; `submit --wait` prints
and flushes the accepted request ID before observing it. Waiting immediately
queries, then delays 100, 200, 400, 800 and at most 1000 milliseconds between
queries. Each exchange uses a fresh random nonce and signature. Temporary `busy`
admission responses retry under the same deadline; other rejections end waiting.
Only changed provider states print to stdout. The default monotonic client deadline
is 300 seconds, including submission acknowledgment, flushed receipt and changed
state output, exchanges and sleeps. Full stdout pipes remain interruptible by the
same deadline and SIGINT/SIGTERM handlers. Stderr diagnostics are best effort with
a bounded 50 ms delivery allowance; an unread pipe cannot prevent process exit.
A cancelled output may be partial or absent, while the diagnostic retains any
known accepted ID. Synchronous filesystem checks retain the existing limitation:
a filesystem stall can exceed the network/wait deadline.
`--timeout-seconds` accepts positive whole seconds that fit the local monotonic
clock; on `submit` it requires `--wait`. Options and canonical request/binding
selectors are checked before key loading and submission; malformed selectors
receive the redacted usage error (exit 2).

```json
{"status":"status","protocol_version":1,"request_id":"<opaque-id>","state":{"status":"running"}}
{"status":"status","protocol_version":1,"request_id":"<opaque-id>","state":{"status":"completed","exit_code":0}}
```

The closed states are `pending`, `approved`, `running`, `denied`, `expired`,
`completed` (exit code 0–255), and `failed` with one category:
`review_unavailable`, `execution_unavailable`, `execution_rejected`,
`execution_nonzero`, or `execution_signaled`. Responses contain no operation,
arguments, labels, timestamps, secret/output data, history, URLs or capabilities.
Provider clocks determine expiry. Running work remains nonterminal until existing
cleanup and reaping requirements are confirmed. Terminal request/audit content is
immutable, and enabled owners can observe terminal work after lock/restart.

Each query rechecks kernel UID/group evidence, the enabled stored key, strict
signature, immutable request ownership and revocation. Unknown, other-owner,
unpaired and revoked requests all receive the identical `unauthorized` rejection.
Re-pairing a label or OS principal does not transfer ownership. Query nonce digests
are persisted before disclosure, separately from request/audit records. Submission
and querying reject nonce reuse across either action; signatures bind their distinct
purposes. Markers have no TTL or eviction. Every successful poll rewrites a full
provider snapshot and permanently grows replay metadata; quotas and compaction
are outside this story. The new reader accepts older snapshots without query
metadata, but older executables reject snapshots containing `query_replay_markers`.
Downgrade compatibility is not provided. Preserve replay evidence; stripping these
markers or restoring stale snapshots would invalidate the authority/replay contract.

CLI exit codes are 0 for acknowledgment, nonterminal observation or completion;
1 for unsuccessful terminal states, rejection or local failure; 2 for usage;
3 for transport uncertainty; 4 for wait timeout; 130 for SIGINT; and 143 for SIGTERM.
The protected operation's exit code stays in JSON and is separate from these codes.
Client failures print a separate stderr JSON diagnostic, for example:

```json
{"event":"client_error","category":"wait_timeout","request_id":"<known-id>"}
```

Other local categories are `local_failure`, `transport_uncertain`, `interrupted`
and `terminated`. A lost acknowledgment can leave `request_id: null`. Timeout,
interruption and disconnect do not expire, complete or cancel provider work.
Retain the known ID and resume with `wait` or `poll`. The client never retries
submission, prompts, cancels, discovers requests or falls back to human access.
See the [wire contract](implementation/2-3-protocol-contract.md).

## Redacted operation history (Story 1.9)

Run `vw-access history` or `vw-access history --limit 200` from the human desktop
account. The JSON response contains `result: "history"` and an `events` array.
In the authenticated desktop page, use **Operation history**, choose **Number of
events**, then **Refresh history**. Both views default to 50 events and accept
1–200; the limit counts lifecycle events, not requests. Empty storage returns an
empty list. Invalid limits and malformed requests fail with fixed redacted errors.
Responses and terminal output are bounded to 2 MiB; oversized results fail without
partial output. Use a smaller limit if needed.

Each event exposes only its format version, request ID, operation ID, event-time
requester kind/identity/label, original policy revision, original credential
labels/use types, creation/expiry/event times, per-request ordinal, lifecycle
status and stable outcome. Submission, approval, denial, expiry, execution start,
success, nonzero exit, signal, rejected/unavailable execution, invalidation and
recovery have distinct outcomes. Confirmed cleanup and reaping still precede
terminal execution records. Historical labels never join the current policy.
No argument values, targets, environment mappings, backend item IDs, secrets,
process streams, sessions, browser/launch capabilities or reusable approval
material enter history. Agent work records immutable requester label/fingerprint
snapshots; revocation and re-pairing cannot rewrite earlier attribution. No
agent-facing history or discovery endpoint is provided.

Events sort newest first by event timestamp, then request ID, then per-request
ordinal, all descending. Supported legacy records migrate atomically into the
versioned format at startup. Where old storage cannot prove an event time or
phase, `legacy_unknown` and null fields preserve that uncertainty; the UI shows
**Unknown (legacy record)**. Unknown-time events sort after known-time events.
Terminal history survives restart. Unexecuted work expires during recovery and
cannot gain authority from a read. No retention, export or pruning is introduced.

CLI reads require kernel-authenticated provider-owner UID. Browser reads require
the cookie, independent session proof and current provider generation, checked
inside the serialized query. Reads work while the vault is locked when the proof
is current. Lock/unlock retires the earlier generation for history; use a fresh
provider/request launch to authenticate, or use the CLI while locked. The existing
request review may still show a terminal status with older proof. The public page
contains no historical data. History text uses DOM text nodes; invisible controls
and directional formatting are visibly escaped. Terminal JSON additionally
escapes DEL/C1 and directional controls while preserving its parsed values.

## Exact executable preparation (Story 1.6)

Approved operations can now be prepared internally as an owned immutable executable
image. Preparation rechecks the current Approved record, exact approval binding,
authenticated owner, lifecycle epoch, active policy, canonical arguments and target,
monotonic deadlines, unlocked session, compatibility and every credential's
eligibility. It repeats those checks after filesystem and backend work. Preparation
resolves no credentials and starts no protected child. The retained image conveys
no approval authority; later dispatch must atomically consume the one-time decision
and revalidate authority before resolving credentials.

Preparation performs three normal durable state reads, independent of credential
count. Each state snapshot still incurs the pre-existing image rehashing during
deserialization and validation while holding the authority gate. That repeated
work scales with registry image bytes and policy bindings; large registries can
therefore delay a Lock waiting for the gate even with the bounded read count.

The supported execution profile is **Linux 6.3+**, with executable memfds and
WRITE/GROW/SHRINK/EXEC/SEAL support, and native little-endian ELF64 **ET_EXEC**
(x86-64 or AArch64). Each private image binding requires an explicit
`execution_root` and `profile: "reviewed_self_contained_elf64_v1"`, as well as its
absolute path and SHA-256 digest. The profile is the provider operator's declaration
that the pinned artifact was reviewed as self-contained: it uses no interpreter,
helper, plugin, runtime-loaded code or mutable executable dependency. ELF structure
and hashing cannot establish arbitrary program behavior; a statically linked
interpreter does not satisfy this declaration. Scripts, dynamic executables,
static PIE, unsupported profiles, writable executable segments and executable
stack declarations are rejected. The parser checks ELF identification, native
machine/type/version and header sizes; program/section-table bounds and selected
section extents/alignment; load file/memory sizes, alignment, ordering and
page-rounded nonoverlap; and an entry in file-backed executable-load bytes.
Images violating those checks are rejected. This is not complete ELF ABI metadata
validation: unused section-name and null-section semantics are not certified,
and unused section names are not consulted for loading.

This version also restricts every load mapping, including its page-rounded end,
to the lower 47-bit userspace minus the final native page on x86-64, and the lower
36-bit userspace on AArch64. The end is exclusive; the entry must lie in file-backed
bytes of an executable load. These conservative profile limits follow Linux 6.3's
[ELF load checks and page rounding](https://github.com/torvalds/linux/blob/v6.3/fs/binfmt_elf.c),
[x86-64 TASK_SIZE and DEFAULT_MAP_WINDOW](https://github.com/torvalds/linux/blob/v6.3/arch/x86/include/asm/page_64_types.h),
and AArch64's [TASK_SIZE definition](https://github.com/torvalds/linux/blob/v6.3/arch/arm64/include/asm/processor.h)
and [36-bit configuration for 16 KiB pages](https://github.com/torvalds/linux/blob/v6.3/arch/arm64/Kconfig).
Kernels with larger address spaces do not widen this profile. Passing structural
validation does not guarantee execution: address allocation and kernel security
policy can still refuse the image.

Every execution-root ancestor is traversed through a checked directory descriptor.
Ancestors must be root- or provider-owned with no group/other write or special
permission bits; sticky-directory exceptions are not supported. The execution root
and descendants must be provider-owned mode `0700`. Sources must be regular,
provider-owned, owner-readable/executable and have no write or special bits.
Images are limited to 64 MiB. The adapter copies the checked descriptor to a private
executable memfd, applies and reads back every required seal, then verifies SHA-256
and ELF structure on that sealed object. Path replacement and source writes cannot
change retained bytes. Errors close descriptors and expose fixed redacted categories.

The execution primitive consumes this descriptor with `execveat(AT_EMPTY_PATH)`,
explicit policy-derived arguments and an empty environment. It replaces its already
supervised calling process and has no production spawn path. Secret injection,
approval consumption, process supervision and descendant containment remain in
Stories 1.7/1.8. Unsupported kernels, disabled executable memfds, seccomp or LSM
refusal fail closed without a pathname or legacy-command fallback.

Existing populated image bindings lack the required declaration and must be
re-provisioned. They are rejected without rewriting user data or silently assigning
a profile. Empty default state remains supported. Root, profile, image identity
and policy fields are bound into the new policy revision; old approvals cannot
be reused with a newly provisioned policy.
Operator provisioning supports new registrations in valid state; it does not
migrate invalid legacy state or replace existing IDs. Manually editing persisted
fields or revisions, moving a live store, or reusing approvals is not a supported
recovery procedure.

Linux tests need secure temporary ancestry because shared `/tmp` is deliberately
rejected. The checked-in wrapper creates and cleans a dedicated mode `0700`
directory beneath a provider-owned `HOME`, after checking its ancestry, and
preserves command arguments and exit status. Run the complete suite with:

```sh
./scripts/with-secure-test-tmpdir.sh cargo test --all-targets
```

Linux CI and `just test`, `just check`, `just pre-commit`, and `just coverage` use
the same wrapper. It leaves non-Linux commands and temporary-directory behavior
unchanged. Use a home with no symlink ancestry, owned by the provider, with only
root/provider-owned ancestors and no group/other write or special permission bits;
the wrapper never changes shared directory permissions. Linux 6.3+ executable
memfd support is required for the positive adapter tests; unavailable fixtures
fail instead of being silently skipped.

## Protected process containment (Story 1.8)

One-time approval now queues work on a bounded provider worker. `Approved` means
queued; `Running` is written only after the contained helper observes the kernel's
successful protected-image exec event. Lock, request cancellation, requester
revocation, session/request deadlines, transport failure and shutdown revoke
launch authority independently of the worker. Terminal results require confirmed
cleanup, even when launch authority has expired. Uncertain cleanup closes admission
and leaves the durable record nonterminal for startup recovery.
Cancellation also invalidates an approved request still waiting in the queue,
under the same claim/release serialization, so its queued ID cannot execute later.

Install `vaultwarden-access-exec` beside `vaultwarden-accessd`, owned by the provider
UID, executable and without group/other write or special permission bits. Every
installation ancestor must be root/provider-owned and not writable by other users
or groups. Run the daemon as `vaultwarden-accessd.service` using the supplied user
unit: an arbitrary shell process is not an authorized provider instance. The helper
path is fixed by the daemon installation, never chosen by a request. User-manager
connectivity, Linux 6.3+ executable memfds, unified cgroup v2, systemd 255+ and
permitted parent/child ptrace exec-event observation are required; unsupported
setups fail closed.

Reviewed protected operations and their descendants are trusted code running as
the provider UID. Containment manages their lifecycle; it is not a hostile same-UID
sandbox. Deliberate user-manager or cgroup manipulation is outside this guarantee.
Agents must still run under separate restricted OS principals without provider-UID
or user-manager access.

Each random transient service has `BindsTo`, `PartOf` and `After` dependencies on
the provider, `KillMode=control-group`, `CollectMode=inactive-or-failed`, finite
timeouts, `Restart=no`, null streams,
zero core limit and no injected manager environment. The checked private runtime
directory is `/run/user/<uid>/vw-access-<provider-namespace>`. An authenticated Unix
SEQPACKET channel transfers the sealed executable FD and bounded, zeroizing argv
and explicit environment. A separate guarded message releases execution. The
single-threaded helper forks, establishes parent-death SIGKILL and verifies its
actual helper parent, then executes the descriptor. A kernel `PTRACE_EVENT_EXEC`
and CLOEXEC error pipe distinguish protected exec from helper start and pre-exec
signal death. Tracing detaches before workload instructions run. Standard streams
go directly to `/dev/null`; output is discarded by the kernel without decoded or
retained buffers.

The manager-launched helper also has an explicit environment boundary. Typed
`UnsetEnvironment` contains only names: the manager's current inherited names,
loader/runtime controls and systemd-generated names. Values are never copied to
unit properties. systemd v255 applies these removals immediately before helper
exec; an empty `Environment` or `PassEnvironment` alone does not isolate a user
service. The same-UID manager is trusted, including its environment between the
snapshot and start: a hostile manager can already replace unit configuration or
executables. Failure to obtain or establish the removal policy closes execution.
Recovery validates the stable removal contract without comparing old units to a
new manager-environment snapshot. See the authoritative
[systemd v255 environment semantics](https://raw.githubusercontent.com/systemd/systemd/v255/man/systemd.exec.xml).

The helper adopts/reaps descendants as a subreaper. Normal completion carries
its ECHILD report. The manager stops the entire request cgroup; a separate bounded
`/proc` scan checks the exact cgroup/subtree, including zombies and deleted cgroup
paths, while comparing process start times. Forced cleanup and provider crash use
that independent observation. A retained lease preserves the exact cgroup identity
for cleanup proof even after a failed unit is unloaded. Empty `cgroup.procs` alone
is never completion.
Nonsecret per-unit cleanup identities survive provider death and manager unit
unloading. Recovery validates exact ownership and stops only owned services under
the exclusive provider writer lock, before durable startup reconciliation or
transport admission.
Recovery records are fully written and synced before atomic, no-replace
publication. Precisely owned abandoned staging files can be removed at restart;
unrelated files and existing leases remain untouched.

See `docs/implementation/1-8-test-evidence.md` for the tested platform, completed
commands and any outstanding acceptance evidence. The real manager suite is
`scripts/with-secure-test-tmpdir.sh scripts/test-systemd-supervisor.sh`; it uses
only synthetic credentials and uniquely named provider/request harness units.
Its syscall fixture requires x86-64 and rejects other test architectures early;
AArch64 runtime support remains unverified. Journal evidence uses successful reads
and unique markers on both provider streams to prove visibility of prior output,
alongside null request streams. It does not claim a privileged global journal
flush. Exact recorded test resources are stopped and cleaned even on assertions.
