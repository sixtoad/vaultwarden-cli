# Request-scoped SSH agent

Protected SSH now keeps the selected private key in provider memory. The approved
SSH process uses a dedicated local agent endpoint to obtain one authentication
signature. No client private-key file is created. Public host-key data and local
socket paths are not secrets.

An approval covers one request, recipient, key, pinned server and remote user.
It is not reusable permission to use a shared SSH agent. Identity discovery and
session-binding messages are permitted; the first attempted signature delivery
consumes the local signing authority, including a partial or failed write.
Another authentication requires its own approved request.

Lock, cancellation, access removal and expiry are checked again at signature
delivery. Withdrawal that wins this check prevents the signature. A delivered
signature cannot be recalled, and an established SSH connection may keep carrying
traffic without another signature. Closing the credential service does not stop
the SSH process, its descendants or a remote session.

## Implementation

The provider polls a bounded, nonblocking agent alongside execution observation.
The authenticated execution helper transfers the exact consumer PID and a Linux
pidfd captured before reaping. Agent peer credentials must match that process,
and its pidfd must still indicate a live process. These descriptors are used
only for identity and observation, never to signal the consumer.

The agent verifies OpenSSH `session-bind@openssh.com` against the pinned host
key. It signs only SSH user authentication for that session, the approved user
and its one loaded public key. It supports ordinary and host-bound public-key
authentication. Arbitrary signing, key management, forwarding and unrelated
extensions are rejected. The provider's existing final authorization gate checks
the durable request binding, lock/revocation generation, cancellation and deadline
before the bounded nonblocking signature response is sent. No signature is queued
for a later ungated flush.

Protocol references: [SSH Agent Protocol, RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html)
and [OpenSSH agent extensions](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent).
RustCrypto `ssh-key` handles key parsing and cryptographic signatures; protocol
framing and application-specific authorization remain in this project.

## Compatibility and resources

Supported client keys use unencrypted OpenSSH private-key encoding: Ed25519,
ECDSA P-256/P-384/P-521 and RSA with SHA-256 or SHA-512 signatures. RSA sizes are
bounded. Encrypted keys, legacy PEM encodings, hardware-backed keys and obsolete
algorithms are rejected; there is no private-file fallback or passphrase prompt.
The client must support OpenSSH session binding. An older client that cannot bind
its authentication to the pinned host cannot obtain a signature.

The existing reviewed self-contained ELF profile still governs production SSH
clients. The agent does not make a normal dynamically linked system OpenSSH
binary eligible for production registration. Real OpenSSH adapter tests are
separate interoperability evidence, not qualification of a new executable profile.
Native macOS protected delivery remains unimplemented and unqualified; it needs
its own authenticated recipient mechanism rather than Linux pidfds.

New public request resources live under `ssh/agents`, separately from historical
`ssh/requests` private files. Agent sockets use a checked private runtime directory
under `/run/user/<uid>/vw-ssh-agents`, avoiding the Unix socket pathname limit
when the state directory has a long path. Ending a request closes its socket and discards its
key regardless of whether consumers have exited. Public host-key resources are cleaned up independently of consumer lifetime.
A cleanup failure does not block subsequent approved requests. Restart recovery
uses recorded file and socket identities to reclaim inactive resources. It
preserves live endpoints, replaced or unknown objects, and legacy private files
that may still be in use.
Historical lifecycle evidence describes the earlier implementation and is not
rewritten as evidence for this agent.

Upgrade provider and execution helper together. Their private exec-confirmation
exchange now includes recipient evidence. Existing workloads are not rewritten
or terminated by the source change. No installed service, policy or real vault
was changed during development.

## Verification

Local Linux verification on 2026-10-28:

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` and `git diff --check` | Passed |
| `cargo clippy --offline --locked --all-targets -- -D warnings` | Passed |
| `scripts/with-secure-test-tmpdir.sh cargo test --offline --locked` | 1,101 passed, zero failed, 24 environment-specific tests ignored by the general runner |
| `scripts/with-secure-test-tmpdir.sh scripts/test-systemd-supervisor.sh` | All 41 lifecycle scenarios, test-owner cleanup, distinct-UID resource/socket denial and real OpenSSH interoperability passed |

The real OpenSSH test performs six logins: Ed25519, ECDSA P-256/P-384/P-521,
RSA/SHA-256 and RSA/SHA-512, with varied server host-key families. Each verifies
successful authentication and a running SSH client after the agent has discarded
its key and closed. Only synthetic server host keys are written as test fixtures;
client private keys stay in memory. Linux CI now invokes this test explicitly.
This records local verification of that command, not a hosted CI run.

Focused tests also cover final authority checks after execution starts, lock and
expiry races, one-use consumption, exact recipient identity, invalid signing
scope, 32/64-byte session identifiers, partial/coalesced protocol messages,
unsupported keys, cleanup failures and restart recovery. Three independent review
lenses completed; all reported actionable findings were addressed.

The first post-review lifecycle run exposed an obsolete socket-name assumption in
the test harness. The fixture now records the endpoint it actually used; the full
lifecycle script passed after that test-only correction. The broad regression run
preceded this final harness correction; production code did not change afterward.
See [verification evidence](issue-49-managed-ssh-agent-evidence.json) for source
hashes, command results and limits.


## CI follow-up, 2026-10-29

PR #55's Linux test matrix exposed signed/unsigned comparisons in the synthetic
SSH fixture under Clang's warnings-as-errors check, before Cargo tests started.
The receive counters now match the unsigned bounded frame lengths; the final
write-result comparison converts the bounded count to the syscall result type.
`./scripts/check-native-fixtures.sh` passes for x86-64 and AArch64, and
`VW18_SCENARIO=app-ssh-nonzero scripts/with-secure-test-tmpdir.sh scripts/test-systemd-supervisor.sh`
passes the real provider/signature exchange. Production code is unchanged.
The earlier evidence hashes remain the record of the earlier test run.
