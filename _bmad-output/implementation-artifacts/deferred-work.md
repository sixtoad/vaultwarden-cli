# Deferred work

## Issue 50 follow-up planning — 2026-10-28

PR #51 merged as `3ecaab452cf9f5f5791e135a03aa1a26767e2e99`; #50 remains open.
The historical CI prerequisite below was satisfied by
[CI run 40540760727](https://github.com/sixtoad/vaultwarden-cli/actions/runs/40540760727):
native suites passed 36/36 and 37/37 without skips, all three trust mutations
were detected with exact restoration, and all 17 packaged TLS cases passed
with cleanup. This evidence applies to PR #51 only.

The next proposed slice is
[structured request review](spec-50-typed-request-review.md), approved on 2026-10-28.
Investigation separated the broader read-model work into independent deliverables:

- **Bounded remote history:** add an authenticated command and closed response
  around `src/access/history.rs` and `ProviderApplication::history`. Specify
  privacy, limits, ordering and compatibility. History must never settle an
  uncertain decision; reopening an exact ID requires fresh review.
- **Trust/role/capability metadata:** add an authenticated read API distinguishing
  approver certificates from requester-agent bindings. Saved local configuration
  does not prove current remote trust. Capability claims must come from real
  adapters; remote administration is separate.
- **Origin identity:** add authoritative producer metadata rather than parsing
  the display-only requester field. Specify compatibility before adding fields
  to strict v1 replies.
- **Additional operation reviews:** root DirectReview already supports optional
  `create` and `ssh` structures that the current companion rejects. Supporting
  these requires complete validated projection and presentation; never weaken
  unknown-field rejection to discard their security-relevant scope.

These are proposals, not newly created external issues or completed capabilities.

## Authenticated requester suspension — user request, 2026-10-28

Reject companion reviews exceeding the provider's existing 32-argument and
16-credential operation limits in the current slice. Do not suspend an agent
from a display label or malformed provider reply: credential references are
selected by provider policy, not supplied by the requesting agent.

Automatic suspension requires a separate provider-side design. Agent envelopes
allow 64 arguments/4096-byte values within a 64 KiB frame; structural validation
currently precedes signature verification. Malformed requests therefore do not
establish the claimed binding identity. Only an exact authenticated binding may
be suspended; forged IDs, invalid signatures and ordinary stale revisions must
not suspend another client. Define hard violation classes, durable system-actor
audit, nonce consumption for violations, pending/running-work invalidation and
human-only restoration with fresh authority. Replaying a previous violation
must not re-suspend a restored client. Existing revocation is permanent and its
denied execution token cannot simply be reset to implement suspension.

## Issue 50 verification prerequisite

Run the matching CI environment's native installation test and packaged native
TLS smoke before claiming the full host gate green. The existing `install-save`
mutation survives locally because its detecting test is explicitly CI-only;
local source restoration and the other native tests passed. Do not weaken the
trust test, forge CI, or alter a production identity namespace to obtain a green.

The parent issue's remaining enrollment, installation, history and native-client
requirements are tracked in [the capability checklist](../../docs/implementation/issue-50-capabilities.md).

## From #61 review notifications (2026-11-09)

- Notifications after the window closes need menu-bar/background lifetime (parity item); Windows/Linux notifications follow their approval transport.

## Guided enrollment UI (#59 phase 2) follow-ups — 2026-11-10

- Companion enrollments are still not audited in the identity registry (needs a
  registry format bump); admin-companion approvals are recorded as the provider
  owner's, with no companion actor.
- Phone/QR joining is phase 3 (#60).

## #50 slice 1 (shell conformance) review follow-ups — 2026-11-19

- Wide layout: the "Back to requests" control sits in the section bar, after the
  sidebar in focus order (it was the AppBar leading slot). Consider
  `FocusTraversalOrder` when the review is redesigned (slice 2).
- `DeviceCapabilities.cliInstall` is derived from the OS name; take the
  `InstallationPlatform` and an injectable OS when Settings consumes it (slice 4).
- Token drift left for slices 2–4: fact-row mono at 11 px and top divider of the
  fact grid, mobile title sizes (27/28), `AccessMetrics.copyWith` ignores
  arguments, `back` defined but unused while native window chrome is used.
- Requests list has no distinct "disconnected" rendering or golden yet.
- `provider/page.dart` is ~520 lines: state, lifecycle, notifications and the
  navigation retirement (mutation anchors) stay together.

## #50 slice 2 (request review) review follow-ups — 2026-11-19

- Every automatic poll is `controller.busy`, so the absent-review pane briefly
  shows "Loading or finishing…" instead of the expired notice and its Reload
  button. Count only a review in flight (or `pendingReview`) as loading.
- Suspending the app does not call `ReviewSession.closeStep()`; the step stays
  bound to the old request ID and is hidden only because Rust retires the
  review. Every reload goes through `openRequest` (which starts a new load),
  so it cannot reappear today; close it on suspend for defence in depth.
- A review replaced by another without a null snapshot in between would start
  its countdown at the reply time (overstating it by one round trip).
  `controller.review()` always invalidates first, so this cannot happen yet.
- `provider_test` "password clears on deny": a denial is now reachable only
  after leaving the step (which clears the field), so a mutant that sent the
  approval password with a denial is no longer exercised by that test. Add a
  page-level unit check of `deny()` with a non-empty controller.
- Goldens: no capture of the ticket-expired countdown view ("Review expired…
  Reload review"); the "expired" capture is the provider's `expired` status.
  Add an `expired_ticket` scene if the owner wants it (one more per host).
- The Touch ID explanation in the authorization step mentions a prompt being
  "cancelled" (an action, not a request status); reword if the owner wants the
  word gone from the review entirely.
- `Arguments (1 separate values)` keeps its old wording for existing finders.
