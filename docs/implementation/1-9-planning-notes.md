# Story 1.9 planning evidence

This records the approved planning baseline. Implementation and current verification
are documented in `1-9-test-evidence.md` and `1-9-mutation-classifications.md`. The controlling
build spec is `/home/sixtocantolla/sessions/day-to-day/_bmad-output/implementation-artifacts/spec-1-9-inspect-redacted-operation-history.md`.

## Sources and baseline

Read issue #13 and its discussion through GitHub on 2026-09-28. The issue is open
and has no comments. Its brief requires human-only durable redacted history and
delegates acceptance to the story document.

The new worktree is
`/home/sixtocantolla/sessions/day-to-day/vaultwarden-inspect-redacted-operation-history`,
branch `feature/inspect-redacted-operation-history`, based on freshly fetched
`origin/main`, canonical commit `7a0ebf352c2c8fd68d2fe73da896039e2f6a4e33`.
The initial worktree was clean. No dependency branch is required.

| Story | Issue state | Merged PR | Merge commit on baseline ancestry |
| --- | --- | --- | --- |
| 1.1 | #5 closed | #19 | b71af8c31fd31a1ebb2b515210a0582b1bd8bf22 |
| 1.2 | #6 open | #20 | 91a6a662cdfb6b27edba2ca93cd3735b630a1931 |
| 1.3 | #7 closed | #21 | 5e5941bc3ce19c9437532900e2b530d093eff7e8 |
| 1.4 | #8 closed | #22 | 041c10837c12a9a8d2b92b36eae5c634856bc9cc |
| 1.5 | #9 closed | #23 | fd6b7eb3dea18d686c844189772fb9e5673ec050 |
| 1.6 | #10 closed | #24 | fc226624a722e82997f4a280776399971a96c7b4 |
| 1.7 | #11 closed | #25 | ffd8ed4c434f585b2bcb37b0ca9a8517538be662 |
| 1.8 | #12 open | #26 | 7a0ebf352c2c8fd68d2fe73da896039e2f6a4e33 |

Open issues #6 and #12 do not represent unmerged code. Implementation evidence
and the relevant lifecycle/policy/containment interfaces exist on the baseline.
Story 1.8's completed build spec and committed verification reports provide
continuity; previous test counts are historical, not evidence for Story 1.9.

Planning documents are absent from the new worktree. Read these from
`/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/`:

- `docs/stories/1-9-inspect-redacted-operation-history.md`
- `docs/epics.md`
- `docs/architecture/architecture-vaultwarden-access-2026-09-01/ARCHITECTURE-SPINE.md`, especially AD-5 and AD-9
- `docs/specs/spec-vaultwarden-access/SPEC.md`

The compiled Epic 1 context was refreshed in the shared build artifacts. The
shared `sprint-status.yaml` is explicitly for Oriel; do not associate its numeric
1-9 key with this repository or modify that tracker.

## Implementation contracts

1. Add a closed audit representation constructed from individual allowed fields.
   Include request/operation identifiers, a typed requester snapshot (human UID
   and label, or fixture agent label/fingerprint), policy revision, credential
   labels/use types, creation/event/expiry timestamps where relevant, per-request
   event ordinal, decision and stable outcome. No raw arguments, target, backend
   item data, environment, session objects, approval bindings or record seals in
   history. Types must reject unknown fields and invalid states on input.
2. Existing `DecisionAudit` includes `ApprovalBinding`; do not expose or reuse it
   as the new public/persisted audit shape. Existing live request authority can
   continue using its private approval binding. Test audit objects separately
   from the authority-bearing request section when checking that audit contains
   no reusable approval material. Secrets remain forbidden throughout persistence.
3. `RequestRecord::transition` is the existing event source. Replace its audit
   projection and add the missing submission event in `Provider::create_direct`.
   Current `DecisionOutcome::Approved` also represents execution start/completion;
   use destination status and explicit reason categories to remove ambiguity.
   Preserve one event per transition and atomic lifecycle/audit publication.
4. Keep stable lock ownership, private files, symlink rejection, validated reads,
   temporary-file sync, atomic rename, directory sync and poisoning after an
   uncertain durable write. Never add a second audit-file writer.
5. Query uses provider/application authorization, a bounded limit, durable
   validated state and stable order. An opaque `AuthenticatedHuman` minted from
   kernel peer credentials is the CLI proof; compare it to the provider owner.
   Browser cookie/proof authentication must also carry current generation into
   the serialized query so revocation cannot race an adapter-only check. Never
   mint proof from an arbitrary label or loopback address. Agent protocol gains
   no history variant. Reads can work while the vault is locked.
6. UI uses DOM text nodes/textContent or HTML escaping, plus visible escaping of
   control and bidirectional formatting characters. JSON CLI escaping must cover
   DEL/C1 and Unicode directional controls as well as serde's C0 escapes. Bound
   serialized output to transport capacity; failure is stable and redacted.
7. Keep startup cleanup before recovered state acceptance. Pending/approved old
   requests expire; recovered running requests fail only after cleanup evidence.
   Preserve `finish_execution` cleanup/reaping gate, terminal immutability and
   authority invalidation. A history read cannot reauthorize any record.

## Migration and attribution

Version the history format explicitly and accept supported legacy records only
through a narrow validated projection. The stored `DirectReview` already carries
original labels/revision; use that snapshot, never current policy joins. Legacy
audits conflate some execution outcomes and lack submission events. Derive only
facts proven by validated record/timeline data; use a stable legacy/unknown
category when historical detail cannot be recovered. Never invent timestamps,
requester labels or detailed failure causes. Keep old terminal records readable;
new records must have complete event contracts. Test repeated restart/migration
idempotence, unknown versions, audit/state inconsistencies and duplicate events.

Agent pairing remains unimplemented. Use internal deterministic fixtures for
agent history attribution and label-change stability, plus independent access
denial fixtures. Do not loosen direct-request validation to impersonate an agent
or add a production fixture insertion endpoint.

## Verification plan

Each supported lifecycle event must have exact expected field assertions, not
only forbidden substring checks. Cover submission, deny, approve, expiry, start,
success, nonzero/signal/setup/review failures and lifecycle invalidation (lock,
shutdown, cancellation/revocation hooks, policy change and recovery as supported).
Preserve current lifecycle semantics; history does not add execution authority.

Use independently valid prerequisites for each negative case: wrong UID, absent
cookie, absent proof, mismatched proof, stale generation, malformed request,
invalid limit, unsafe owner/mode/symlink, malformed audit, read failure and each
pre/post-rename persistence failure. A guard must fail for its own reason.
Exercise limit 1, 200, 0, 201, overflow, malformed inputs, default, empty data,
equal timestamps, repeated reads and restart order. Verify historical fields
after policy/credential/fixture identity labels change.

Create synthetic sentinels for vault values, full environment payloads, master
passwords, private keys, both child streams, backend/browser sessions, desktop
launch tokens and reusable approval material. Scan persisted audit, UI/CLI
responses, captured provider diagnostics and logs across successes and failures.
Keep successful stream/log capture assertions so a broken capture cannot pass a
non-disclosure check. Add HTML, ESC/OSC, newline, DEL/C1 and Unicode controls.

Required verification includes:

- `cargo fmt --all -- --check` and strict all-target/all-feature Clippy.
- Complete stable and Rust 1.88 `cargo test --all-targets --offline --locked`,
  through `scripts/with-secure-test-tmpdir.sh`, with bounded test parallelism.
- Relevant persistence, human CLI, direct request, provider session and
  authorization tests; explicit ignored-fixture accounting.
- Extend `tests/ui/direct-request.mjs` using its synthetic Rust HTTPS fixture,
  real Firefox, Puppeteer and axe. See `tests/ui/README.md` for dependency paths.
- Relevant existing real-systemd recovery/cleanup harness; isolate unit names
  and cleanup, never inspect a production vault or alter the installed provider.
- Scoped cargo-mutants and semantic changes covering every changed projection,
  authorization predicate, tie-break/limit, write guard and recovery rule.
  Record exact patches, commands, exits, named detecting tests and durations.
  Fix meaningful survivors; justify equivalents; distinguish compile failures,
  timeouts and infrastructure failures. Verify source hashes after restoration.
- `git diff --check` and whitespace checks for new untracked files.

Reuse the evidence patterns in
`docs/implementation/1-8-evidence/review-2-parent/verification-runner.py` and
`mutation-runner.py`. Cargo-mutants 27.1.0, stable Rust and Rust 1.88 are installed;
availability is not a successful test run. Wait for every required job before
workflow reviews. Record exact current results and any blocked checks. Use
implementation subagents, workflow-directed reviewers, parent verification and
human checkpoints; leave all implementation/evidence uncommitted for approval.
