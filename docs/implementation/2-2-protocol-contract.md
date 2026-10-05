# Story 2.2 wire and persistence contract

Version 1 has exactly these required JSON fields: `protocol_version` (integer 1),
`purpose` (`"submit"`), `binding_id`, `nonce`, `operation_id`,
`expected_policy_revision`, `args` (ordered strings), and `signature`. Unknown or
duplicate fields, null substitutions, incorrect types, invalid UTF-8, trailing
JSON data, and noncanonical encodings are rejected. Binding IDs and nonces are
unpadded canonical base64url of 32 bytes; signatures encode 64 bytes. Revisions
are 64 lowercase SHA-256 hex characters. Existing operation, argument count,
argument length and NUL restrictions apply in addition to the transport frame cap.
JSON field order, ordinary JSON whitespace and equivalent string escaping do not
change the signed semantics; no Unicode normalization occurs.

## Exact signed representation

Append these byte sequences in order. `LP(value)` means the unsigned 32-bit
big-endian byte length followed immediately by the bytes. All numbers below are
binary, not decimal text.

1. ASCII `vaultwarden-access` followed by one NUL byte.
2. One-byte encoding version `1`, then one-byte protocol version `1`.
3. `LP(purpose UTF-8)`.
4. `LP(decoded binding ID)`.
5. `LP(decoded nonce)`.
6. `LP(operation ID UTF-8)`.
7. `LP(decoded 32-byte policy revision)`.
8. Unsigned 32-bit big-endian argument count, followed by `LP(argument UTF-8)`
   for each argument in its original order.

Sign these bytes with Ed25519. Verification uses the current provider-owned key
and `VerifyingKey::verify_strict`; neither a supplied public key nor the legacy
caller-authoritative `SignedAccessRequest` verifier participates.

The deterministic test vector uses seed `[7; 32]`, binding bytes `[0x11; 32]`, nonce
`[0x22; 32]`, operation `deploy`, revision `ab` repeated 32 times and arguments
`["a", "bc", "é"]`. Its exact signing bytes, in hexadecimal, are:

```text
7661756c7477617264656e2d616363657373000101000000067375626d6974000000201111111111111111111111111111111111111111111111111111111111111111000000202222222222222222222222222222222222222222222222222222222222222222000000066465706c6f7900000020abababababababababababababababababababababababababababababababab00000003000000016100000002626300000002c3a9
```

Its signature is
`6_negF7FLGMNQh5ELLOeLoK7dEm2I7J7V90tt2rYzXYhkYKJEIX5rdVgrtse0P-2Psx_P7hgNASBbH53q_kQBQ`.
The vector was independently generated with Python cryptography and is frozen in
`src/access/protocol_tests.rs`. A second independently generated small-order-R
witness is accepted by ordinary dalek verification but rejected by the production
strict verifier, so weakening verification is independently detectable.

## Replay and linearization

The nonce marker is lowercase hex SHA-256 of ASCII `vaultwarden-access-replay`,
one NUL, one-byte encoding version `1`, `LP(decoded binding ID)`, and
`LP(decoded nonce)`. The vector above produces
`75e42aa7d8637d3c73fd58d6eb02d170589be7b6f3e89bd57306b6c1b6df6705`.
It is independent of operation, arguments and session, and is scoped to the
immutable binding ID. Neither the raw nonce nor the marker is returned in the
acknowledgment or human history projection.

`ProviderApplication::submit_signed` holds the authority gate for current registry,
strict signature, policy and replay admission. The stored active-session epoch
must still match published lock intent. It acquires the release gate in existing
authority-then-release order, checks the immutable revocation token and monotonic
deadlines, and passes a live guard to snapshot persistence. Rename is the admission
linearization point; release-gate serialization orders lock/revoke intent against
that rename. The same gate is rechecked around human desktop launch. Revocation
never waits for authority while retaining the release gate.

A signed request's optional durable `DirectRecord.replay_digest` is mandatory on
this admission path and is included with immutable owner attribution in the v3
record integrity projection. Existing human v1 and agent v2 projections remain
unchanged for records without a marker. Store validation rejects malformed,
duplicate or non-agent markers. The marker, request and submitted audit enter the
same atomic snapshot; no separate replay file or transaction exists. Every terminal
transition preserves the marker. No TTL or eviction is implemented.

Pre-rename authority cancellation leaves both objects absent and returns `locked`
without closing admission; the same nonce can be submitted after authority is
renewed. A pre-rename persistence error leaves both objects absent and closes admission;
a fresh process can accept the same message after human unlock. A post-rename
failure poisons storage/admission and leaves durable replay evidence. Restart
invalidates prior unexecuted work without removing markers. Lost responses do not
roll back admission and the CLI never automatically retries.

## Transport and deployment

The dedicated listener is optional; both `--agent-socket-dir` and
`--agent-socket-gid` are required together, with backend/HTTPS setup. Operators
preprovision a provider-owned `0750` directory in a location accessible to agent
group members, separately from private `0700` state. `agent.sock` is `0660`, owned
by the provider and assigned to the configured group. Descriptor-pinned non-symlink
traversal protects binding, stale-socket replacement and owned-inode shutdown
cleanup. Execute-only ancestors are supported. Active sockets are never removed.
The configured pathname must be human-provisioned under ancestors that untrusted
users cannot replace. The client derives the expected provider UID from that
directory owner; it does not independently pin a configured UID.

The public wire is one LF-terminated JSON object followed by write-half EOF, not a
stream of independent requests. Input is capped at 65,536 bytes including LF;
response at 1,024. Thirty-two admitted tasks, listener backlog 32, a 65,536-entry
supplementary-group buffer, and retained blocking-job permits bound work. The
input deadline is five seconds total from accept; response writes get five seconds.
Early rejected connections receive a closed response before bounded unread input
is discarded without parsing, avoiding Linux reset behavior on ordinary unread
frames. Oversized, stalled or overloaded connections may simply close.

The daemon supervises and joins the agent listener with existing human/UI/execution
workers. Synchronous storage/authority work stays off Tokio executor threads.
A filesystem or desktop stall may exceed socket deadlines and delay shutdown;
retained capacity prevents spawning unbounded detached admission jobs.

`vw-access submit` reads a checked agent-owned non-symlink `0600` regular seed file
of exactly 32 raw bytes, zeroizes seed buffers, generates a random nonce, signs,
checks the socket and server UID, sends once, and returns the closed acknowledgment.
It requires no provider-state access, stdin or controlling TTY. There is no agent
polling, waiting, password, key-generation, secret export or browser-launch path.
