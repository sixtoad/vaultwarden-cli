# Provider-backed identity management (#50)

This slice manages identities already known to the provider. Enrollment,
invitation/discovery, Activity history (#54), desktop installation (#56), native
macOS execution (#49) and automatic abuse suspension (#53) remain separate.

## Identity and authority

An **approval client** is an enrolled mTLS leaf SHA-256, a **requester agent** is
a signed public-key binding with a stable random binding ID and OS UID/group
constraints, and the **executing provider** is the service reached through pinned
TLS. None of these certificates, keys, labels or addresses proves a physical
device. Display labels do not establish identity and may be duplicated across
types. A revoked record cannot be reactivated by matching its label or key.

The existing local administrator is the provider-owner UID authenticated by the
kernel on the private human socket. Enrollment and request approval do not confer
administration. The trusted owner may explicitly delegate management to an exact
already-enrolled certificate while the provider is stopped:

```sh
vaultwarden-accessd --state-root /absolute/private/provider-root \
  --companion-grant-admin EXACT_LOWERCASE_CERTIFICATE_SHA256
```

The owner must separately provision/enroll the certificate through the existing
procedure. The grant does not unlock the vault, submit work or approve a request.
Only explicitly granted, enabled certificates may read inventory/details or
prepare/revoke identities. Any enabled approval client may read the origin of a
request it is already entitled to review. The authenticated TLS identity supplies
the actor; a request-body label or claimed client ID never does.

Every remote revocation requires a fresh owner password and a single-use ticket
bound to the authenticated certificate, exact identity type and stable ID, random
action ID, provider authority generation/retirement epoch and a monotonic deadline
of at most 55 seconds. Ticket consumption precedes authentication. Final mutation
checks are serialized against authority retirement and certificate revocation.
Ordinary reads neither authenticate a password nor unlock or authorize work.

## Protocol and bounds

The existing `/v1/companion` transport and v1 command/reply schemas are unchanged.
Management explicitly uses `version: 2` with commands `identity_list`,
`identity_detail`, `identity_prepare`, `identity_revoke`, `identity_status` and
`request_origin`. Error envelopes retain the existing closed v1 vocabulary.
Unsupported commands/versions and unknown fields fail closed. An old provider's
explicit unsupported-command response permits legacy review with unavailable
origin; a malformed v2 origin response retires approval authority.

Inventory pages contain at most 64 records, ordered lexicographically by
`approval_client:<fingerprint>` then `requester_agent:<binding-id>`. The nullable
cursor names the last row when another page exists. Each page is an independent
fresh read, not a multi-page atomic snapshot. Generation is session authority,
not an inventory revision. The client replaces the page instead of combining
pages, clears records on errors/lifecycle changes, and expires displayed records
within 30 seconds. Background polling does not replace the selected page; explicit
refresh starts a fresh first page. Cached configuration is never proof of remote trust.

Rows contain only kind, stable ID, escaped display label, public fingerprint,
granted roles, enabled/revoked trust and whether this is the authenticated client.
Revoked rows have no granted roles. Provider TLS identity, configured execution
capability and runtime availability are separate fields. No public verification
keys, private keys, passwords, tickets or internal diagnostics enter these views.
The existing request/response transport bounds remain 16 KiB/1 MiB. Certificate
storage is bounded to 64 lifetime identities, including permanent tombstones;
the action journal is bounded to 128 authenticated mutation attempts and 64 KiB.
Capacity exhaustion refuses additional changes; canceled preparations do not
consume durable action capacity. There is no silent audit pruning or cooldown
that re-enables revoked records.

## Consequences and uncertain outcomes

Agent revocation reuses the provider's existing irreversible token denial,
durable tombstone, pending/approved invalidation, provider-owned delivery/signing
cancellation and bounded cleanup. Certificate revocation conservatively retires
the **entire provider session** because existing approvals do not identify their
approving certificate. The confirmation shows this scope, exact ID, roles and
self-revocation consequences before requesting a fresh password.

PR #55 governs execution ownership: consumer programs and established sessions
are not terminated. Previously delivered secrets/signatures cannot be recalled.
Closing provider-owned key services and observation resources does not establish
that consumers stopped.

The native adapter saves only the original action ID and typed target beside the
exact provider configuration before transmitting a mutation. No password or
ticket is persisted. Rust, Dart and native gates reject changed targets, stale
preparations, background/close completions and repeat transmission. Provider setup
cannot be replaced while an action is unresolved. A recreated controller can
resume only the original bound provider, and process relaunch restores the marker.

A lost reply is **unknown**, never optimistic success. Recovery sends only
`identity_status` for the original action and target. The durable journal binds
actor certificate, action and target and distinguishes `pending`, `not_recorded`,
`recorded` and `unknown` revocation from `pending`, `complete`, `not_applicable`
and `unknown` provider cleanup. A proven pre-mutation refusal can settle as
`not_recorded/not_applicable`; transient contention must not become irreversible
uncertainty. A revoked row alone is never evidence that the original action
completed. Unknown crash outcomes fence delivery on restart rather than restoring
possibly revoked in-memory authority.

The owner reconciliation receipt is separate evidence: `owner_reconciled: true`
means an explicit trusted-owner action independently secured the exact target and
verified provider-owned cleanup. Historical revocation/cleanup fields remain
unchanged. The client may then retire its recovery marker, explaining that the
owner resolved the current safety condition without inventing an original
success. With the fixed provider service stopped, the trusted owner runs:

```sh
vaultwarden-accessd --state-root /absolute/private/provider-root \
  --companion-reconcile-action ORIGINAL_ACTION_ID \
  --companion-reconcile-kind approval_client \
  --companion-reconcile-id EXACT_LOWERCASE_CERTIFICATE_SHA256
```

For an agent, use `requester_agent` and its original binding ID. The helper
requires the state-root writer lock and independently verifies the fixed provider
service is absent or inactive with no MainPID. It checks provider-owned cleanup
before clearing persisted session state and records the owner UID separately.
If the provider never received or journaled the original command, also supply
`--companion-reconcile-actor ORIGINAL_APPROVAL_CLIENT_SHA256`. The fingerprint
must name an enrolled or permanently revoked certificate. For an existing action
it must match the recorded actor. The helper records `unknown/unknown` for a
missing original action and appends only the separate owner acknowledgement;
it never fabricates proof that the original command ran. Use the action, target
and approval-client fingerprint displayed by the recovery view.
Do not delete the journal to bypass the recovery fence.
Self-revoked certificates have only narrowly authenticated access to their own
exact action receipt, not general inventory or administration. TLS certificate
expiry or loss can still require trusted-console recovery.

## Request origin

`request_origin` projects the immutable `AgentOwner` snapshot only when the
request contains the signed-admission replay marker. It returns the original
binding ID, public-key fingerprint and label with `signed_os_binding` evidence.
It does not join today's registry, parse requester text or infer a hostname/IP.
Legacy and unsupported requests explicitly report unavailable origin. The v1
review stays closed; unknown v2 security fields cannot be silently discarded.

## Verification and integration

Implementation uses the separate
`codex/issue-50-device-agent-management` worktree based on `60fadd6`, which includes
PR #52 (`93431e6460f5a73c1d0f2e8d8fd087bade4e2f54`). Current main `07b10e7`
(merged Activity #54) was integrated and bindings regenerated. The tested revision and CI
results are tracked in [draft PR #57](https://github.com/sixtoad/vaultwarden-cli/pull/57). No installed application, production
identity, vault or service is modified by source tests.

Shared changes are narrow: a separate management Rust API/session and Flutter
view, serialized through the existing controller transport; additive native
recovery metadata; an optional versioned request-origin read; generated bindings
from FRB 2.13.0 / cargo-expand 1.0.112. Activity and installation agents must
regenerate bindings when integrating, and preserve both recovery markers and
all provider/lifecycle retirement gates.
