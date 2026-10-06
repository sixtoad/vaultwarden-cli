# Story 2.3 signed observation contract

Status: implemented locally; validation evidence is recorded separately. No commit,
push, PR, deployment or live-state migration has been performed.

The existing agent socket remains one LF-terminated JSON envelope followed by
write-half EOF per connection. Admission checks real kernel UID and primary plus
supplementary groups before reading input. Frames remain at most 64 KiB, responses
at most 1 KiB. Server input and response deadlines remain bounded; the client uses
one five-second total exchange deadline. Wait's monotonic deadline can shorten it.

## Query and signed bytes

`SignedStatusQuery` has exactly these required fields:

```json
{"protocol_version":1,"purpose":"status","binding_id":"<32-byte base64url>","nonce":"<32-byte base64url>","request_id":"<32-byte base64url>","signature":"<64-byte base64url>"}
```

All binary values use canonical unpadded base64url. Missing, duplicate, unknown,
null, wrong-type and noncanonical values fail closed. No caller key, owner, label
or timestamp is accepted. JSON order and escapes do not determine signed bytes.

The canonical message is the existing `vaultwarden-access` domain plus NUL,
encoding version byte 1, protocol version byte 1, then each of the following as
u32 big-endian byte length followed by bytes:

1. UTF-8 purpose `status`.
2. Decoded 32-byte binding ID.
3. Decoded 32-byte nonce.
4. Decoded 32-byte request ID.

Ed25519 strict verification uses only the current enabled stored binding key.
Submission bytes remain unchanged. Purpose separation prevents swapping signatures
between submission and status. Freshness means one-use random nonce uniqueness;
there is no assertion of wall-clock message age.

Independent Python cryptography vector: seed `[7;32]`, binding `[0x11;32]`, nonce
`[0x22;32]`, request ID `[0x33;32]`:

```text
7661756c7477617264656e2d61636365737300010100000006737461747573000000201111111111111111111111111111111111111111111111111111111111111111000000202222222222222222222222222222222222222222222222222222222222222222000000203333333333333333333333333333333333333333333333333333333333333333
rnI_EBzbEGy7_MHDfbV_a3Fh13DFBAn7yTgtEaIEQWwGYFVt7fL3ipL92m8OF4TAfTCZnEwqFBtU9vAhwmWNAw
```

Its binding-scoped replay digest is
`75e42aa7d8637d3c73fd58d6eb02d170589be7b6f3e89bd57306b6c1b6df6705`, identical to
submission with that binding/nonce. Replay bytes are the existing replay domain,
encoding version, and length-prefixed decoded binding/nonce; action and request
are deliberately absent so both actions consult both consumed-marker sets.

## Authorization, durability and disclosure

The provider authenticates stored key plus current OS evidence and finds the exact
immutable request owner before checking replay or updating lifecycle state. Unknown,
other-owner, human-owned, unpaired and revoked IDs all reject as:

```json
{"status":"rejected","protocol_version":1,"category":"unauthorized"}
```

They use the same bounded one-response/write-half-EOF close path. Busy/unavailable
admission depends on global capacity/health, not request existence. Invalid input
and replay use existing closed rejection categories without reflected input.

`query_replay_markers` is a schema-2 snapshot array outside request/audit records.
Absent means an older snapshot with no queries. Null/malformed/duplicate markers
and conflicts with submission digests fail validation. Markers persist across
lock/restart and are never evicted. Each successful observation atomically writes
its digest before disclosure; pre-rename write failure discloses nothing and leaves
it unconsumed, post-rename uncertainty discloses nothing but retains consumption.
Both persistence failures close admission, so restart/recovery is required before
retry. Revocation before rename withholds disclosure without consuming the nonce;
revocation after rename retains it and fails closed on uncertain persistence.
Older executables reject the extended snapshot fields: compatibility is new-reader /
old-state only. Never strip replay metadata or restore stale authority to downgrade.

Authority then release gate ordering serializes final disclosure against
revocation intent. Storage reads, guarded nonce writes and expiry refresh do not
retain the control release gate, so revocation/cancellation intent can be published
during a stalled write. The final in-memory token/admission check and projection
retain it; crossed session intent/deadlines trigger refresh outside that gate. Enabled pairing and immutable owner are checked again in the
snapshot path, with revocation token rechecked at disclosure. Provider clocks are
refreshed around slow writes and final reads. Polling only observes existing work;
it cannot launch review, resolve credentials, execute, resubmit or expose history.
Expiry uses existing lifecycle invalidation; cleanup/reaping must still precede
terminal execution records. Terminal request/audit records are never changed by
observation, although replay metadata grows.

## Closed response and CLI contract

A status response is exactly `status:"status"`, `protocol_version:1`, the supplied
canonical request ID and `state`. State is an agent-only DTO with `status` equal to
`pending`, `approved`, `running`, `denied`, `expired`, `completed` or `failed`.
Only `completed` adds `exit_code` (integer 0–255). Only `failed` adds `category`, one
of `review_unavailable`, `execution_unavailable`, `execution_rejected`,
`execution_nonzero`, `execution_signaled`. Unexpected fields are rejected even for
unit states; raw output/backend information is never included.

Client selectors are `--socket`, `--key-file`, `--binding-id` for `submit`, `poll`
and `wait`. `submit` remains acknowledgment-only unless `--wait`; `poll <id>`
observes once; `wait <id>` resumes. Wait immediately observes, then backs off
100/200/400/800/1000 ms capped at 1000 ms. Busy retries silently; other rejection
ends waiting. Each retry/reconnect gets a fresh nonce/signature. Changed states
alone print. Accepted receipt is flushed before waiting; SIGINT/SIGTERM handlers
are armed before wait-mode submission. Positive `--timeout-seconds` defaults to
300; a single checked monotonic deadline covers submission acknowledgment, receipt
output, queries, state output and sleeps. Each output is awaited through a dedicated
OS worker using an owned descriptor, without the global stdout lock or Tokio's
blocking pool. Cancellation detaches at most one outstanding output worker; process
shutdown does not join it. Stderr error delivery has a 50 ms best-effort bound.
Filesystem metadata/open operations remain synchronous and can exceed network/wait
deadlines on stalled filesystems. Canonical binding and request selectors are
validated before key loading; malformed selectors use redacted usage exit 2.

CLI exits: 0 acknowledgment/nonterminal/completed; 1 unsuccessful terminal,
rejection or local failure; 2 usage; 3 transport uncertainty; 4 wait timeout;
130 SIGINT; 143 SIGTERM. JSON operation exit is not a CLI control exit. Local errors
are separate stderr JSON with `event:"client_error"`, a closed category
(`local_failure`, `transport_uncertain`, `wait_timeout`, `interrupted`, `terminated`)
and `request_id` set to the known canonical ID or null. They never claim to change
provider lifecycle. Lost acknowledgment may leave no recoverable ID; no automatic
resubmission or discovery endpoint exists.

Durable per-poll full-snapshot writes and unlimited replay retention are explicit
storage/write amplification costs. Quotas, compaction, real-backend/browser/manual
accessibility acceptance and hosted CI are outside local synthetic verification.
