# Story 1.5 investigation and verification plan

Planning only; implementation and verification have not begun. The workflow spec is
`/home/sixtocantolla/sessions/day-to-day/_bmad-output/implementation-artifacts/spec-1-5-decide-request-exactly-once.md`.

## Baseline and sources

Fresh worktree: `/home/sixtocantolla/sessions/day-to-day/vaultwarden-decide-request`.
Branch: `feature/decide-request-exactly-once`.
Fetched main: `041c10837c12a9a8d2b92b36eae5c634856bc9cc`.

| Dependency | Implementation | GitHub merge time (UTC) |
|---|---|---|
| Story 1.1 | PR #19: fail-closed provider foundation | 2026-09-07 09:23:03 |
| Story 1.2 | PR #20: constrained protected operation | 2026-09-23 09:41:11 |
| Story 1.3 | PR #21: provider Vaultwarden session | 2026-09-23 19:06:16 |
| Story 1.4 | PR #22: one-time human direct request | 2026-09-24 10:12:28 |

All dependencies are merged; no dependency branch is required. GitHub issue #9 is
open and has no comments. Its body requires atomic one-writer decisions,
authentication, binding, terminal immutability and redacted audit, with the story
document as definition of done.

Planning documents are absent from the fresh worktree. Read the originals under
`/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/`:

- `docs/stories/1-5-decide-request-exactly-once.md`
- `docs/epics.md`
- `docs/architecture/architecture-vaultwarden-access-2026-09-01/ARCHITECTURE-SPINE.md`
- `docs/specs/spec-vaultwarden-access/SPEC.md`

The completed Story 1.4 build spec and repository evidence provide continuity.
Its human-approved request lifetime is five minutes by default, configurable by
the provider. Preserve it. Shared sprint-status belongs to Oriel; do not modify
that unrelated project's numerically matching Story 1.5. The unrelated epic
context cache was preserved before regenerating Vaultwarden context.

## Investigated implementation

- `src/access/application.rs`: `gate: Mutex<Authority>` owns provider/backend
  state. `admit`, `expire_requests`, `revoke` and `request_deadlines` enforce
  monotonic session/request lifetime. `authenticate` revokes pending requests
  before backend unlock, so it cannot implement approval unchanged.
- `src/access/provider.rs`: `create_direct`, `expire_direct`, `direct_review`
  and `fail_direct_launch` are current request mutation/projection paths.
  Approval, denial and transition audit are absent.
- `src/access/provider_store.rs`: retain exclusive stable-inode writer lock,
  permissions/integrity validation, private temporary write, fsync, atomic
  rename, directory fsync and post-rename poison behavior. Publish authority
  only after durable success. Add decision and audit in the same state write.
- `src/access/direct_request.rs`: `DirectRecord` seals immutable review
  metadata, excluding status. Add an explicit approval binding, validate it
  against exact fields, and never serialize a capability into requester status.
  Existing local requester identity is kernel-authenticated UID plus the local
  human label. No paired-agent authentication exists yet; do not fabricate a
  fingerprint or implement Epic 2 transport in this story.
- `src/access.rs`: legacy `RequestStatus` still exposes `Failed { message }`
  and approval digest; use tokenless approval and a closed redacted failure
  category, consistent with direct statuses. Include Running in lifecycle
  representation where needed, without implementing execution.
- `src/adapters/loopback_ui.rs`: `serve` currently holds the UI mutex through
  `handle`, including password authentication. Split authentication from locked
  decision preparation/commit so other HTTP deny/lock actions can intervene.
  Preserve TLS, strict Host/Origin, content type, body bounds, duplicate-cookie
  rejection, one-use launch, HttpOnly/SameSite cookie and independent CSRF proof.
- `src/adapters/session.rs`: reuse `load_setup` and `derive_keys` for a dedicated
  password approval authenticator. Bounded PBKDF2 and authenticated encrypted-key
  decryption already validate the password. Immediately drop derived zeroizing
  keys. Do not call backend unlock, renew provider lifetime, mutate keyring, or
  resolve vault items merely to authenticate approval. Wire through
  `src/bin/vaultwarden-accessd.rs` and `src/access/ports.rs`.

## Decision mechanics and compatibility

1. Validate the human surface and current session-bound proof before beginning
   authentication. Under provider serialization, capture exact request binding,
   lifecycle generation and relevant browser-session generation.
2. Authenticate outside UI and provider locks. The password and any intermediate
   result remain internal, scoped and non-reusable.
3. Reacquire locks in a consistent order. Recheck session/proof generation,
   provider admission, shutdown, Pending state, owner, request/authority epoch,
   active policy and normalized arguments, and provider deadlines. Revalidate
   credential eligibility through the provider backend where required, with
   admission/deadline checks after slow work.
4. Persist guarded status, exact binding and audit together. Do not return
   success or retain usable in-memory authority on any write failure. Cover
   pre-rename failure and uncertain post-rename directory-sync failure. Check
   clock/closure around slow persistence so a crossed deadline cannot grant
   stale authority; future execution must independently revalidate too.
5. Centralize explicit legal transitions. Pending and Approved invalidate into
   Expired on authority loss. Denied/Expired/Completed/Failed are immutable.
   Existing startup's Running invalidation must not justify new illegal
   transitions; execution remains deferred. Existing launch failure currently
   makes Pending into Failed; reconcile new behavior with the required lifecycle
   while preserving safe historical records and a redacted failure explanation.
6. Define browser decision-generation staleness across lock/restart without
   accidentally removing authenticated terminal-status inspection. A newly
   launched eligible request must establish current decision proof. Test old
   cookie and old CSRF independently against otherwise eligible new work.
7. Decode safe older records without restoring authority. Changing the existing
   one-time explanatory text requires compatibility with its stored seal and
   strict validator. Do not rewrite immutable terminal history merely for copy.

Audit contains request ID, authenticated requester identity, policy and argument
digests, provider timestamps, decision/outcome and approved non-secret labels.
Exclude passwords, keys, session/CSRF/launch material, raw exceptions, argument
values, backend item values, raw environment and child output. Rejected replays
must not create another successful-decision event.

## Human behavior

Expose Deny and Authenticate and approve once. Denial needs the valid human
browser session/CSRF; approval additionally requires fresh password
authentication. Provide a labeled password input and Cancel authentication
before submission; cancellation clears the input and leaves the request Pending.
Do not equate an aborted/lost HTTP response with successful cancellation of a
decision already submitted. Poll authoritative status after uncertain responses,
without automatically resubmitting approval. Authentication cancellation reported
by the authenticator also grants nothing.

Clear password fields immediately, use safe text rendering and live textual
status, disable decided-request controls, preserve keyboard/focus behavior and
immutable detail rendering. Confirm Approved truthfully; executable verification
and protected execution are later stories, so do not announce Running.

## Verification matrix

Use entered/release channels or barriers to hold authentication. Wait for entry,
perform the intervening action to completion, then release. Do not use sleeps to
select race winners. Exercise both decision orderings and exact deadline equality.

| Area | Required isolated checks |
|---|---|
| Positive | Authenticated approve; valid-session deny; exact durable binding; one corresponding audit event; client status contains no token |
| Authentication | Missing input, empty input, wrong password, authenticator failure, cancellation; otherwise valid request/session/proof in each case |
| Races | Approve/approve, approve/deny, approve/expiry; competing valid actors; no duplicate grant or terminal resurrection |
| Time | Controlled provider time just before, exactly at and after expiry; wall-clock change cannot extend monotonic lifetime; expiry during authentication and slow commit |
| Policy | Active revision changes while authentication blocked on an otherwise unexpired request; changed normalized arguments/identity/binding each isolated |
| Lifecycle | Lock during authentication; lock/unlock cannot revive request; restart invalidates Pending and Approved; old authentication completion cannot commit |
| Browser | Missing/wrong/stale cookie, missing/wrong/stale CSRF, cross-session proof, wrong Host/Origin/content type separately; fresh eligible request prevents expiry masking a session guard |
| Immutability | Replay approve and deny; Denied and Expired stay unchanged across polling, lock and restart; Approved invalidates without execution |
| Persistence | Before-write/replacement failure and post-rename uncertainty; no authority publication, no partial binding/audit success, restart still invalidates |
| Redaction/UI | Synthetic secret sentinels absent from persisted state/audit, client output, UI status and errors; keyboard approve/deny/cancel, input clearing, labels, focus and axe |

Use private unit fixtures, temporary persisted state and test-only synchronization;
do not add production inspection endpoints/accessors. When changing a field to
test a semantic guard, recompute unrelated integrity seals so validation failure
cannot mask the intended guard. Verify no secret resolution/execution call occurs
for decisions using existing fake ports.

Run formatting, complete `cargo test --all-targets`, all-target/all-feature Clippy,
applicable integration tests, CLI build and the real Firefox harness under
`tests/ui/direct-request.mjs`. Check dependency paths before reusing Story 1.4's
temporary browser/NSS setup. Its ignored synthetic fixture is explicitly run by
the harness. Report environment-gated live tests separately from exercised bodies;
automated accessibility is not a manual screen-reader exercise.

Scope generated cargo-mutants to complete changed functions/constants for
authorization, transitions, expiry, binding, persistence and session/proof guards.
Supplement with manual auth bypass, omitted persistence, guard deletion,
cross-session proof and real-browser security mutations that generation misses.
Keep immutable input fingerprints, commands, logs and mutation diffs. Fix
meaningful survivors; document equivalents with observable evidence. Compiler
rejection, inactive-platform cases, timeouts and unrelated test failures are
separate classifications, not successful kills. No mutation result may be
inherited from changed source or tests without justified evidence.

Wait for every required test/mutation process to finish before workflow-directed
review. Map ACs to exact passing tests and finished command results in
`1-5-test-evidence.md`. After review fixes, refresh relevant verification and
mutation evidence. Run `git diff --check`, including untracked files using a
temporary index without staging the user's index. Present completed implementation
and evidence for human acceptance. Do not commit, push or open a PR.

## Planning assessment

One cohesive decision feature spans core, storage, human adapter, tests and docs.
The footprint requires dispatch, not the small-change route. No unresolved
human-visible intent choice remains after repository investigation. Implementation
and synthetic verification are reversible; no production data migration, deployment
or external publication is authorized. Subagents investigated core and UI/tests;
implementation and workflow reviews will use subagents after plan approval.
