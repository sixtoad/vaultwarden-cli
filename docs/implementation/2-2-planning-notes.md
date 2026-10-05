# Story 2.2 planning and verification contract

Historical planning contract approved before implementation. Current implementation and verification evidence are recorded in the companion protocol and verification documents.

## Dependency evidence

Read issue [#15](https://github.com/sixtoad/vaultwarden-cli/issues/15) and its discussion on 2026-10-05: open, zero comments. Read the story, epics, architecture spine (including AD-3/4/5/11), and canonical SPEC from `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/docs`; these planning documents are absent from the new worktree. Also read the completed Story 2.1 build spec and its implementation/verification notes.

Fresh worktree: `/home/sixtocantolla/sessions/day-to-day/vaultwarden-submit-signed-request`.
Branch: `feature/submit-signed-request-without-tty`.
Fetched `origin/main`; canonical base: `24ad5d14aa9b72f6e3ddb8cddae34f58335c52d3`.

| Dependency | Merged PR | Merge commit |
|---|---|---|
| 1.1 provider | #19 | b71af8c31fd31a1ebb2b515210a0582b1bd8bf22 |
| 1.2 policy | #20 | 91a6a662cdfb6b27edba2ca93cd3735b630a1931 |
| 1.3 session | #21 | 5e5941bc3ce19c9437532900e2b530d093eff7e8 |
| 1.4 direct requests | #22 | 041c10837c12a9a8d2b92b36eae5c634856bc9cc |
| 1.5 decisions | #23 | fd6b7eb3dea18d686c844189772fb9e5673ec050 |
| 1.6 executable | #24 | fc226624a722e82997f4a280776399971a96c7b4 |
| 1.7 login execution | #25 | ffd8ed4c434f585b2bcb37b0ca9a8517538be662 |
| 1.8 containment | #26 | 7a0ebf352c2c8fd68d2fe73da896039e2f6a4e33 |
| 1.9 history | #27 | 0ea6c996c2b1c3e5cef9e280667f884e0753e53b |
| 2.1 pairing | #28 | 24ad5d14aa9b72f6e3ddb8cddae34f58335c52d3 |

GitHub reports each merged into main. Epic #2 and Story 1.2/#6 and 1.8/#12 tracking issues remain open; this does not mean their implementations are unmerged. No dependency branch is necessary. Preserve existing worktrees and untracked planning documents. Global BMAD sprint status and global Epic 2 context belong to Oriel; do not update them for this repository. Vaultwarden context is namespaced under `_bmad-output/implementation-artifacts/vaultwarden-cli/`.

## Route assessment

One user-facing goal, spanning protocol/core/transport/client/UI validation. No unresolved product intent; no deployment or live-state mutation is authorized. Footprint is substantial and adds public wire and CLI interfaces, so use the dispatch route and its planning checkpoint. Any storage evolution must explicitly preserve existing human and Story 2.1 records. Subagents implement bounded components after approval; workflow review agents run only after all required verification finishes.

## Protocol and client decisions

- Add explicit `vw-access submit <operation> --socket <path> --key-file <path> --binding-id <id> --revision <digest> -- <values...>`. Existing human commands retain `--state-root`; agent submit requires no access to provider state and never enters human waiting/authentication logic.
- The agent key file is an agent-owned, non-symlink regular file with mode `0600`, containing exactly a raw 32-byte Ed25519 seed. Open through a checked descriptor, bound reads, zeroize seed buffers and omit secret-bearing Debug/error formatting. Keys are provisioned outside this story; no key-generation or password input is added.
- Version 1 fields: `protocol_version`, `purpose` (`submit`), `binding_id`, `nonce`, `operation_id`, `expected_policy_revision`, `args` (ordered string array), and `signature`. Require every field; reject unknown/duplicate fields, null substitutes, incorrect types, invalid UTF-8, noncanonical base64url, wrong fixed lengths and trailing data. Binding ID and nonce are 32-byte unpadded base64url; signatures are 64-byte unpadded base64url; revisions are lowercase SHA-256 hex. No identity label, public key, timestamp, expiry or request ID supplied by the caller.
- Sign a fixed `vaultwarden-access` domain prefix, encoding version and protocol version, followed by explicit big-endian length-prefixed purpose, binding ID bytes, nonce bytes, operation ID and revision bytes, then argument count and individually length-prefixed UTF-8 arguments. Freeze exact bytes and a deterministic signature vector in tests/documentation before integrating. Field ordering in JSON is irrelevant; argument order is authoritative. No Unicode normalization or concatenation ambiguity.
- Verify with the provider-owned current key and `VerifyingKey::verify_strict`, retaining Story 2.1 key validation. Never reuse the legacy caller-authoritative `AccessRequest` verifier. API evidence: [dalek 2.2 documentation](https://docs.rs/ed25519-dalek/2.2.0/ed25519_dalek/struct.VerifyingKey.html#method.verify_strict).
- Use a dedicated closed agent response: protocol metadata plus opaque request ID and pending acknowledgment, or a stable rejection category. Do not serialize the richer human `SubmissionReceipt`. Define bounded categories for unauthorized, malformed, unsupported version, replay, stale revision, invalid operation arguments, locked, busy and unavailable; no input reflection.

## Kernel and transport boundary

- Obtain UID and primary GID using `SO_PEERCRED`, supplementary groups using `SO_PEERGROUPS`, with exact returned-length validation and bounded allocation. Required-group membership is membership in their union. Fail closed when the kernel cannot supply trustworthy evidence. No account-database lookup or `/proc` PID lookup. [Linux implementation](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/core/sock.c) reads captured peer credentials for supplementary groups.
- Before decoding any payload, require a non-provider UID matching at least one currently enabled binding and its required group. After decoding, the selector remains untrusted until the selected binding independently matches those same credentials and verifies the signature. Recheck current binding at admission commit.
- Reuse directly declared `libc`; no new peer dependency is needed. Explicitly add Tokio `net`, `io-util`, `time` features; `signal` already exists. Retain Rust 1.88 compatibility and locked dependencies.
- Daemon enables the listener with paired explicit `--agent-socket-dir` / `--agent-socket-gid` options. Use a provider-owned `0750` directory and `0660` socket assigned to the chosen access group, separate from private `0700` state. Validate ownership, group, modes and non-symlink traversal; reject unsafe or active socket paths, clean only a verified stale socket, and unlink only the owned inode on shutdown. Existing installations with no socket configuration retain human-only operation.
- Defaults: at most 32 admitted connections/tasks, 64 KiB request frame, 1 KiB response, five-second total input deadline, five-second response-write deadline. Bound listener backlog, group buffer, key-file reads, all task registries and blocking admission jobs. Acquire capacity before spawning and retain permits until blocking work actually completes; timeout must not detach unbounded authority work.
- One connection carries exactly one LF-terminated JSON object followed by write-half EOF; the client shuts down its write half and reads the response. Reject missing LF, extra frames/trailing bytes, oversized data and disconnect before a complete frame. Reads may be partial. Slow reads cannot reset the deadline.
- A complete message may commit before the peer loses its response. Such disconnection cannot roll back or authorize a second request: replay still fails. Admission acknowledgment describes the commit snapshot; it is not polling. Review-launch failure after commit follows existing failed-request handling and never releases an approval capability to the agent.
- Supervise listener failure/shutdown with existing daemon lifecycle. Perform synchronous core/storage work off Tokio executor threads with bounded outstanding work. Filesystem/browser stalls may outlast socket deadlines; bound retained resources and document this existing platform limitation honestly.

## Atomic admission and restart

Use application authority gate for fresh state, strict signature verification, exact selected binding/peer match, mandatory current revision and existing `normalize_args`. Capture lifecycle/revocation epoch; acquire release gate in existing lock order and recheck closing, epoch, immutable agent revocation token, session deadline and request deadline immediately before persistence. Never wait for authority while holding release gate.

Persist a domain-separated digest of immutable binding ID plus random client nonce on the retained request record in the same guarded snapshot replacement as request creation and submitted audit. Validate uniqueness, canonical digest representation and agent ownership. Preserve legacy records with absent markers; new signed admissions require markers. Bind markers into applicable integrity validation. A failed pre-rename write consumes neither request nor nonce; post-rename uncertainty poisons admission and retains durable replay evidence.

Retain markers through denial, expiry, completion, revocation, lock and restart. Startup still expires old pending/approved work. Restart followed by unlock must reject identical signed submissions. No TTL eviction: future request pruning must preserve replay tombstones. State history remains retained as in the existing provider; storage failure closes admission. Concurrent duplicate requests yield at most one commit; contention may produce busy before commit, but subsequent duplicate attempts produce replay rejection.

Reuse provider-generated random IDs, existing configured request lifetime (default 300 seconds), immutable `AgentOwner` and complete policy review. Recheck authority before human launch. If revocation/lock wins before commit, create nothing. If admission wins, later authority loss invalidates that one request. No rejected pre-admission path calls launch, credential resolution or protected execution.

## Required verification ledger

Each negative case must start from otherwise valid input; explicitly assert zero pending insertion, launcher calls, secret resolutions and child executions. Use synthetic seeds and deterministic clocks/barriers.

| Area | Required evidence |
|---|---|
| Canonical signing | Fixed bytes/signature vector; mutate every semantic field including purpose/version/selector/nonce/revision/argument order and boundaries; alternate JSON order/escaping has identical semantics; strict weak/malformed key and malformed/malleable signature rejection |
| Peer/signature matrix | Real Linux socket peers: valid signature/wrong UID; valid signature/wrong required group; correct UID/group/wrong key or signature; valid matching credentials; primary-only and supplementary-only group membership; provider UID denial |
| Ordering and identity | Ineligible peer rejected before parser invocation; eligible peer with another binding selector denied; unknown/revoked binding independently rejected; kernel credential errors/lengths fail closed |
| Framing/resources | Duplicate/unknown fields, unsupported versions, null/type/encoding errors, LF/EOF contract, partial reads, oversized/truncated/multiple frames, disconnect, read/write deadlines, full capacity and subsequent recovery, clean shutdown |
| Replay/storage | Sequential and concurrent duplicate admission, different nonces, failed pre-commit persistence/retry, uncertain post-rename state, restart/unlock replay, retained terminal markers, malformed/duplicate stored markers |
| Policy/session | Stale revision, missing revision, unknown operation/argument, disallowed target, locked/expired session; all otherwise valid signatures and peers |
| Races | Revoke and lock at preflight, verification, before guarded rename and after commit; scoped revocation preserves another agent; no stale UI launch or execution |
| UI/CLI | Real subprocess with stdin closed and new session/no controlling TTY; immediate response; human command regressions; real Firefox agent label/fingerprint and full target/arguments/credentials/digests/expiry/one-time view; capability isolation |
| Redaction | Captured responses/stdout/stderr/logs contain neither seed/private material, credentials, approval URL/capability nor raw child output; attacker text never reflected |

Run formatting and complete all-targets suite before workflow review, plus focused protocol/socket/pairing/CLI suites, Firefox UI and affected systemd integration. Also run Rust 1.88 all-targets and strict Clippy. Save exact command, exit, duration, source hash, executed/ignored/environment-gated counts and AC-to-test mapping.

Use scoped cargo-mutants plus semantic mutations covering omitted signature fields, ordinary/removed verification, UID/group/binding bypass, replay lookup/insertion/atomicity, stale-policy/argument checks and guarded request creation. Run one source mutation at a time in an isolated copy, verify source restoration, wait for full process-tree termination, and classify caught, survived, equivalent, unviable, timeout and infrastructure failure separately. Fix meaningful survivors; equivalent classifications require a concrete proof or executed witness. Never classify timeouts or compilation failures as caught security checks.

Before review run `git diff --check` and inspect untracked files too. Await all required tests and campaigns. After workflow-directed reviews, fix findings and rerun affected verification and full required gates as warranted, then present human verification evidence. No commit/push/PR until user approval.

## Known environment facts, not test results

Stable and Rust 1.88.0 toolchains, cargo-mutants and Firefox are installed. Prior browser dependencies exist in `/tmp/vw-story21-ui`; NSS certutil must be located or supplied. Multi-ID user namespaces failed inside the sandbox (`newuidmap: write to uid_map failed: Operation not permitted`); attempt the isolated real-peer fixture with authorized outside-sandbox execution. If still unavailable, mark the required OS-boundary test blocked rather than substituting mocks or claiming readiness. Live Vaultwarden is not required for synthetic admission tests and must not be inferred from early-return integration tests.
