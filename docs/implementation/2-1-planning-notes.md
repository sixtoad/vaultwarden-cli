# Story 2.1 planning evidence

Planning approved at bmad-build Checkpoint 1 on 2026-10-05. This file preserves the planning evidence; current verification is recorded in [2-1-verification.md](2-1-verification.md).
Controlling spec: `/home/sixtocantolla/sessions/day-to-day/_bmad-output/implementation-artifacts/spec-2-1-pair-and-revoke-restricted-agent-identity.md`.
Rendered workflow: `/home/sixtocantolla/sessions/day-to-day/_bmad/render/bmad-build/day-to-day-d00ae63d9eda/1fb18c5ba28adad60cd9/workflow.md`.

## Baseline and dependency evidence

Read [issue #14](https://github.com/sixtoad/vaultwarden-cli/issues/14) and its discussion with GitHub CLI on 2026-10-05. It is open, with no comments, and delegates acceptance to the story document. Fetched origin before creating the branch.

Worktree: `/home/sixtocantolla/sessions/day-to-day/vaultwarden-pair-revoke-agent`.
Branch: `feature/pair-and-revoke-restricted-agent-identity`.
Base: updated `origin/main`, `0ea6c996c2b1c3e5cef9e280667f884e0753e53b`.
The new worktree was clean before adding planning artifacts. No dependency branch is necessary.

All nine Epic 1 implementation PRs are merged and appear consecutively on the base's first-parent ancestry:

| Story | Issue | PR | Merge commit |
|---|---|---|---|
| 1.1 | #5 closed | #19 merged | b71af8c31fd31a1ebb2b515210a0582b1bd8bf22 |
| 1.2 | #6 open | #20 merged | 91a6a662cdfb6b27edba2ca93cd3735b630a1931 |
| 1.3 | #7 closed | #21 merged | 5e5941bc3ce19c9437532900e2b530d093eff7e8 |
| 1.4 | #8 closed | #22 merged | 041c10837c12a9a8d2b92b36eae5c634856bc9cc |
| 1.5 | #9 closed | #23 merged | fd6b7eb3dea18d686c844189772fb9e5673ec050 |
| 1.6 | #10 closed | #24 merged | fc226624a722e82997f4a280776399971a96c7b4 |
| 1.7 | #11 closed | #25 merged | ffd8ed4c434f585b2bcb37b0ca9a8517538be662 |
| 1.8 | #12 open | #26 merged | 7a0ebf352c2c8fd68d2fe73da896039e2f6a4e33 |
| 1.9 | #13 closed | #27 merged | 0ea6c996c2b1c3e5cef9e280667f884e0753e53b |

Open issues #6 and #12 do not indicate unmerged dependencies. Existing source and committed verification artifacts implement the relevant administration, persistence, request, containment and audit interfaces. Prior test results are historical evidence only, not current Story 2.1 verification.

Required planning documents are absent from the new worktree and were read from `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/`:

- `docs/stories/2-1-pair-and-revoke-restricted-agent-identity.md`
- `docs/epics.md`
- `docs/architecture/architecture-vaultwarden-access-2026-09-01/ARCHITECTURE-SPINE.md`
- `docs/specs/spec-vaultwarden-access/SPEC.md`

A subagent compiled `epic-2-context.md` in this directory. The shared `_bmad-output/implementation-artifacts/epic-2-context.md` and sprint tracker describe Oriel, not Vaultwarden. Do not overwrite those files or associate their numeric 2-1 key with this story. No preceding Vaultwarden Epic 2 story exists.

## Planning route

This is one goal: human management and revocation of restricted agent authority. It crosses domain, persistence, request ownership, administration and containment, so use the full dispatch workflow rather than oneshot. The user delegated resolution of key retention, duplicates and re-pairing; concrete proposed rules are in the spec. No further intent questions remain. Implementation changes are reversible; this task does not alter deployed state, create OS accounts, deploy, commit or publish. Future runtime state changes must preserve supported prior data and reject unknown formats.

## Identity and administration contract

`vw-access agent pair <label> --public-key <base64url> --uid <uid> --gid <gid>` creates a binding. `agent list` includes binding ID, label, fingerprint, numeric allowed UID/required GID and enabled/revoked status. `agent revoke <binding-id>` avoids a repeated old-label command revoking a newly paired identity. Pair/revoke responses use safe projections. Administration remains possible while the vault is locked.

Use the existing private `human.sock` transport: provider-owned directory/socket, kernel SO_PEERCRED check before parsing, opaque AuthenticatedHuman, and owner revalidation in application/provider handlers. No generic loopback endpoint, caller-provided UID proof, browser password in CLI, or agent administration variant. Browser one-time operation approval remains unchanged except for correct agent requester presentation.

The key format follows `access::encode_public_key`/`decode_public_key`: canonical unpadded base64url of exactly 32 validated Ed25519 verification bytes; reject weak keys as well as malformed encodings/lengths/points. Compute SHA-256 lowercase hex from the validated bytes. Do not accept a fingerprint supplied by a caller. Enforce canonical representation so alternate encodings cannot bypass duplicate detection. Only numeric UID/GID configuration is supported; reject zero, UINT32_MAX and provider UID. A required GID is a membership requirement, not a replacement for the UID check. No NSS existence requirement: restricted/container accounts may be provisioned independently. Tests use synthetic identities, never host account changes.

Reconcile the story's “fingerprint/metadata only” wording with AD-3: provider-owned binding storage also retains the required public verification bytes. No agent private key is accepted or retained. Public keys need not appear in list/audit; expose fingerprints instead. Every pairing gets a cryptographically random immutable ID. Labels must be unique among enabled bindings, and previously used keys remain permanently reserved, including after revocation. Reusing a revoked label requires a new key and binding ID; old tombstones and identity snapshots remain intact.

## Storage and attribution

Replace the unused `ProviderState.pairings: Vec<String>` with validated bindings and add closed administrative audit records. Preserve old schema-1 empty-pairing state through a narrow validated compatibility path; reject populated legacy strings, unknown versions, duplicate/corrupt bindings and mismatched computed fingerprints. Version the new representation explicitly. Never fabricate historical pairing authority from legacy strings. Test repeated restart/migration and prior human request histories.

Reuse ProviderStore's stable exclusive writer, checked read paths, no-symlink files, exact 0700/0600 permissions, ownership checks, private temporary file, file sync, atomic rename and directory sync. Binding lookup must use validated state rather than cached permission assumptions. Pairing plus audit, and revocation plus invalidation plus audit, must each be one state transaction. Any uncertain write blocks further authority. Even pre-rename revocation failure closes application admission and cancels affected in-flight work; do not undo the revocation-intent token. A failed revocation is not acknowledged as durable success: restart follows the last successfully durable state, and recovery still invalidates all old unexecuted requests.

DirectRecord, ApprovalBinding and the request digest currently assume a human UID and literal human requester. Introduce an internal typed request owner that includes immutable agent binding ID and frozen label/fingerprint for agent work. Preserve prior human record validation through explicit compatibility, and keep authority seals private. Human review/admin authority is separate from requester ownership; do not impersonate agents by minting AuthenticatedHuman from an agent UID. HistoryEvent already supports an Agent snapshot, but its constructor currently always emits Human; update construction and validation without joining historical attribution to the current label map.

Pairing/revocation audit is a separate closed administrative event type stored in the same durable state, not a fabricated request HistoryEvent with fake policy/request fields. Record human actor, binding ID, label, fingerprint, configured UID/GID, timestamp and action; never keys, backend data, raw arguments/environment/output, passwords, sessions or approval capabilities. Repeated revoke does not fabricate a new state transition.

## Admission, ownership and containment integration

Provide internal production binding lookup, enabled/OS-match and exact-owner checks for Story 2.2 admission and Story 2.3 polling. Do not expose a transport or reusable proof constructor allowing unverified signatures/peer credentials to authorize requests. Internal fixtures may construct synthetic admitted work under cfg(test); no production inspection/insertion API solely for tests. A successful binding lookup alone is not signature verification. Both UID and required membership remain prerequisites for the future adapter/core handoff.

The existing `revoke_requester(AuthenticatedHuman)` calls global lock and would stop everyone. Do not use it for selective agent revocation or increment global lifecycle_epoch for a successful scoped revoke.

Use immutable binding runtime tokens shared by its in-flight work. Revocation checks authenticated human authority, captures the exact binding ID, publishes its revocation intent under release_gate, releases that lock, then waits for gate. Runtime metadata lookup must never acquire gate while holding release_gate. Pair publication uses gate then release_gate, after durable write. Final release uses that same gate-to-release order and checks the token. No later release may succeed after revocation wins, even while a backend resolver holds gate. Admission persistence guards, claims, backend continuations, approval transitions and poll ownership check current binding state/token.

Claim currently holds gate through execution registration. Once revocation acquires gate, atomically persist the binding's revoked state, redacted audit and expiration of only unclaimed Pending/Approved requests, and signal matching registered work. Snapshot affected execution IDs, drop locks, and wait only for those IDs. A claim racing revocation must either fail or be in the registered set. Claimed Approved and Running requests remain nonterminal until ProcessSupervisor reports NotStarted/Reaped as appropriate; Uncertain, timeout or manager failure cannot become successful cleanup. Keep cleanup/finalization authority valid after execution authority is revoked so the worker can persist its terminal result after reaping.

Repeated revoke still waits for outstanding cleanup and propagates uncertainty. Other agents and human work continue after successful selective revocation. Persistence or containment uncertainty may close the whole provider as existing fail-closed policy requires. Test that a repeated revoke of the old ID cannot target the replacement label's new ID.

## Required verification and review handoff

Use channels/barriers and existing cfg(test) read/write hooks rather than timing guesses. Isolate each negative guard with otherwise valid prerequisites. Capture exact expected statuses, identity snapshots and audit fields as well as non-disclosure sentinels. Required cases:

- Valid pair; malformed encoding/length/point/weak key; duplicate enabled label; duplicate key under another label; revoked-key reuse; invalid UID/GID; missing group; same-provider UID.
- No defaults; state/revocation persistence across restart; old empty schema compatibility; malformed/unknown schema; unsafe file/directory owner/mode/type/symlink; read and every pre/post-rename write failure.
- Unauthorized human proof and wrong peer UID independently; locked-vault administration; closed wire fields; list/audit redaction and immutable historical requester attribution.
- Unknown/enabled/revoked bindings; wrong UID with correct group/key; wrong group with correct UID/key; current owner versus another agent/human/stale binding on poll checks.
- Scoped unexecuted invalidation, claimed/running cancellation, unaffected second agent, repeat revoke, re-pair, concurrent admission/claim/backend resolution/final release/cleanup, supervisor timeout/failure/uncertain cleanup.
- Actual Linux/systemd selective agent revocation with separately observed descendant cleanup and another agent's running work surviving. Existing `app-revoke` is a global human hook and is insufficient for this case.

Run formatting and complete `cargo test --all-targets --offline --locked`, using `scripts/with-secure-test-tmpdir.sh`; run focused administration, persistence, ownership and supervisor suites. Strict all-target/all-feature Clippy is an additional repository-quality check. Extend `src/adapters/supervisor/real_tests.rs` and `tests/systemd_supervisor.rs`, then run the secure-temp wrapper with `scripts/test-systemd-supervisor.sh`. Keep synthetic units and fixture paths isolated; do not change an installed provider or inspect a production vault.

Complete scoped cargo-mutants and targeted semantic mutations covering identity validation, binding lookup, revocation, request ownership, persistence and cleanup decisions. For every mutant preserve patch, baseline result, command/exit, detecting test or survivor evidence, duration and restoration hashes. Fix meaningful survivors, rerun affected checks, and document equivalent mutants with evidence. Distinguish compile failures, timeouts and infrastructure failures from detected mutants. Existing Story 1.9 runners provide conventions, not current evidence. Wait for all required jobs, then git diff --check (also validate untracked whitespace), workflow reviews, and the completed-implementation human checkpoint. No commit, push or PR before approval.

Environment planning probes: cargo-mutants 27.1.0 is installed. The sandbox denies systemd bus access; an approved read-only probe outside it successfully reached the user manager (systemd 255). Actual tests will need equivalent access and secure temporary ancestry. Neither probe counted as a passed integration test. At planning time, implementation tests and mutation campaigns had not run.
