# Story 2.3 planning and verification contract

Status: plan approved 2026-10-06; implementation, all three workflow reviews and final verification complete. Completed-implementation approval is pending; commit, push and PR remain unauthorized. Historical evidence is preserved.

## Dependency evidence

Read issue #16 and its discussion via GitHub on 2026-10-05: OPEN, no comments.
Its definition of done incorporates the Story 2.3 document and secret boundary.
Fetched `origin/main`, then created fresh branch
`feature/poll-delegated-work-preserve-ownership` and worktree
`/home/sixtocantolla/sessions/day-to-day/vaultwarden-poll-delegated-work` at
`6081c48764208c1adad03b9d5be31550ff850895`.

- Epic 1 Stories 1.1–1.9: implementation PRs #19–#27 all MERGED.
- Story 2.1: PR #28 MERGED 2026-10-05T10:53:30Z; issue #14 CLOSED.
- Story 2.2: PR #29 MERGED 2026-10-05T14:36:58Z; issue #15 CLOSED.
- Epic 1 issue #2 and Story 1.2/#6 and Story 1.8/#12 remain OPEN despite merged implementation PRs. No issue state was changed.
- No unmerged branch dependency. Previous Story 2.2 build spec is `done`.

Planning documents are absent from the new worktree. Read the requested story,
`docs/epics.md`, architecture spine (particularly AD-3/5/11/12), and canonical
SPEC under `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli`.
Global epic context and sprint-status belong to Oriel; do not match numeric
story keys across projects. Vaultwarden context is namespaced at
`_bmad-output/implementation-artifacts/vaultwarden-cli/epic-2-context.md`.

## Scope and authorization

One goal: safely observe already-submitted delegated work. Footprint spans core,
persistence, existing transport, CLI, deterministic tests and documentation.
No deployment or live provider state migration is authorized. Local fixtures and
backward-compatible schema extension are implementation work. No human intent
questions remain; proposed public CLI/defaults are in the approval spec.
Use subagents for implementation and workflow reviews after planning approval.
Do not commit, push, or open a PR until the user approves completed code/evidence.

## Protocol and authorization design

`SignedStatusQuery`: required `protocol_version: 1`, `purpose: "status"`,
`binding_id`, random 32-byte `nonce`, canonical `request_id`, `signature`.
Reuse canonical Ed25519 encoding (domain, encoding/protocol versions and
length-prefixed semantic values); purpose is signed before the query fields.
Reject missing, duplicate, unknown and noncanonical input. Submission vectors
and meaning stay compatible. No caller-supplied owner, label or public key.

Reuse current binding-scoped nonce digest across actions. Submission and polling
both check consumed submission and query markers: shared nonce reuse cannot
escape through a different action. Distinct signed purposes prevent signatures
from being repurposed. Freshness means nonce uniqueness, as in Story 2.2; this
does not invent a wall-clock message-age guarantee absent from that contract.
Every legitimate poll/reconnect uses new random nonce and signature.

Add strictly validated query replay metadata to the provider snapshot outside
RequestRecord, approval and audit records. Backward-compatible absent field
means no historical queries; reject malformed/duplicate/conflicting markers.
Only authenticated owned queries consume markers. Never evict them; retain them
across lock/restart. This increases durable storage and full-snapshot write cost
per successful poll; quotas/compaction remain outside this story.

Keep authority-then-release lock order. Recheck enabled pairing and immutable
binding ID/fingerprint/OS identity against the stored request owner; labels
cannot transfer ownership. Authenticate/authorize before exposing existence,
including replay distinctions. Consume marker before returning status and
recheck revocation token at disclosure linearization. Do not recursively call
the gate-locking `agent_status` while holding that gate. Guard persistence with
current authority; write failure fails closed, and post-rename failure leaves
the query consumed. Fresh-query reconnect never resubmits the operation.

Unknown, non-owner, unpaired and revoked queries all use the same Unauthorized
payload and protocol-visible close behavior. Do not accidentally expose NotFound,
different response fields, errors or additional frames. Admission before parse
must remain intact; busy/unavailable behavior must not depend on request existence.

Project explicit agent-only lifecycle DTOs, not DirectReview, SubmissionReceipt,
RequestRecord, human history or debug representations. Allow Pending, Approved,
Running, Denied, Expired, Completed with validated permitted exit code, Failed
with a closed stable failure enum. Never include labels, operation, arguments,
digests, timestamps, backend data, raw output, sessions or capabilities in status.
Use current provider clock/expiry machinery. Polling can observe expiry; it cannot
turn unconfirmed cleanup into completion or synthesize terminal states locally.

## Transport and CLI design

Preserve one LF-terminated envelope followed by write-half EOF per connection,
64 KiB request and 1 KiB response limits, peer/server checks, total deadlines,
retained task permits and bounded rejection draining. Do not introduce persistent
multi-message sessions. Test revocation on a connection opened before revocation
with deterministic synchronization before it transmits its query.

Extend agent `submit --wait [--timeout-seconds N]`, add signed `poll <id>` and
`wait <id>` with existing `--socket`, `--key-file`, `--binding-id` selectors.
Keep human request/status/history and their boundary unchanged. Validate options
before submission; arm SIGINT/SIGTERM handling before wait-mode submission.
Flush the opaque receipt immediately; no automatic submission retry, even if an
acknowledgment is lost. Lost acknowledgment means transport uncertainty and may
leave no known ID; no discovery/list endpoint is added to recover it.

Start with an immediate observation, then 100/200/400/800/1000 ms capped backoff;
stop on all terminal outcomes. Clip exchanges/sleeps to a configurable monotonic
300-second client deadline. Explicit `wait <id>` resumes observation after
transport uncertainty. Emit changed provider states only, plus a distinct local
timeout/interruption/transport diagnostic. Never imply those client events
expired, completed or cancelled provider work. Keep execution exit information
in validated JSON, separate from CLI control exits defined in the spec.

## Required independent test matrix

1. Owner access for Pending, Approved, Running, Denied, Expired, Completed and
   every permitted stable failure; repeated terminal queries and restart.
2. Known other-owner ID versus canonical guessed/nonexistent ID; exact rejection
   bytes and transport behavior. Human-owned requests are inaccessible to agents.
3. Unpaired/revoked binding, wrong UID, wrong primary/required group, accepted
   supplementary membership, provider UID, invalid signature, request-ID tamper.
   Hold all unrelated guards valid; re-sign selectors where testing lookup rather
   than signature failure. Use valid independently eligible peers for ownership.
4. Submission→poll and poll→submission signature reuse; shared-nonce replay,
   distinct fresh queries, concurrent identical queries, lock/restart, persistence
   failures before/after rename, and strict Ed25519 versus ordinary verification.
5. Revoke during active waiting and after connect/before query; revocation intent
   during authorization/disclosure. Re-pairing same label or OS principal with a
   fresh binding cannot access old requests. Do not assert forbidden key reuse.
6. Provider clock exact expiry boundaries with separately controlled monotonic
   and wall clocks; skewed client time cannot affect lifecycle. Separate request
   deadline from session expiry so one cannot mask the other.
7. Cleanup/reaping not confirmed keeps work nonterminal or fail-closed according
   to existing containment rules; polling cannot invent completion.
8. Backoff sequence/cap, deadline clipping during sleep AND exchange, every
   terminal exit, timeout, disconnect before/after acknowledgment, SIGINT/SIGTERM,
   explicit reconnect and exactly one original submission.
9. Stdin closed plus setsid/no controlling TTY; no password/browser/authentication
   fallback. Use synthetic secret/output/label/backend/session/URL/capability
   sentinels; inspect raw responses, CLI stdout/stderr and captured diagnostics.
10. Assert no extra request/audit creation, approval launches, secret resolution
    or execution from successful or rejected polling. Terminal RequestRecord and
    audit content remain unchanged although replay metadata grows.

Use deterministic fake clocks, barriers, channels and hooks; no scheduler sleeps
to manufacture race coverage. Exercise real kernel Unix peer authentication in
the existing Story 2.2 namespace harness as well as core unit tests. Add real
production socket/CLI witnesses for signed polling and no-TTY waiting.

## Verification plan and evidence discipline

Run these after implementation, then rerun affected checks after review fixes:

```sh
cargo fmt --all -- --check
./scripts/with-secure-test-tmpdir.sh cargo test --all-targets --offline --locked
./scripts/with-secure-test-tmpdir.sh cargo +1.88.0 test --all-targets --offline --locked
cargo clippy --all-targets --all-features --offline --locked -- -D warnings
./scripts/with-secure-test-tmpdir.sh cargo test --offline --locked --lib protocol_tests
./scripts/with-secure-test-tmpdir.sh cargo test --offline --locked --lib signed_
./scripts/with-secure-test-tmpdir.sh cargo test --offline --locked --lib unix_socket
./scripts/with-secure-test-tmpdir.sh cargo test --offline --locked --test human_cli --test direct_request --test provider_session
VW_AGENT_NAMESPACE=1 unshare --user --map-auto --map-root-user --fork cargo test --offline --locked --test agent_submission real_linux_peer_matrix_and_noninteractive_cli -- --ignored --exact --nocapture
./scripts/with-secure-test-tmpdir.sh ./scripts/test-systemd-supervisor.sh
git diff --check
```

Add focused query/wait/revocation/ownership/lifecycle test filters from final
names. Explicit namespace invocation is necessary because the normal suite
ignores that environment fixture. Inspect early-return live-backend tests:
reported pass does not prove they exercised Vaultwarden. Never replace HOME
to bypass secure temporary-directory setup; request sandbox access if needed.

Reuse Story 2.2 mutation runner patterns from its evidence archive, running
sequentially in disposable copies after passing baseline selections. Mutate
signature/purpose/request-ID binding, peer and enabled checks, exact ownership,
revocation recheck, replay persistence/lookup, response field projection and
failure validation, provider deadline guards, terminal detection and wait
deadline/backoff/signal termination. Assert raw failures are genuine witnesses,
not compile errors or environmental failures. Fix meaningful survivors and rerun;
prove equivalent mutants with exhaustive or invariant evidence. Record exact
commands, source hashes, timings, failures and classifications. Rebuild clean
unmutated production binaries and verify restored hashes afterwards.

Wait for every required check to finish before calling the change review-ready.
Report AC-to-test coverage, exact pass/fail/ignored/early-return counts, mutation
classifications and unavailable checks. Hosted CI cannot be claimed before
publication. Real-backend/browser/manual accessibility checks are not implied
by synthetic fixtures; report scope honestly. Complete workflow-directed reviews
and human implementation/evidence checkpoint without committing or publishing.
