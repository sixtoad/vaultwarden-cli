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
  (Agent bindings: delivered by management v2 `request_origin` and shown in
  the review; see "#50 clean-up findings" below. Device/host identity remains
  a proposal.)
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

Resolved in the #50 clean-up PR (2026-11-21) unless marked open. Tests are in
`companion/test/review_followups_test.dart` unless named otherwise.

- Fixed: wide-layout focus order. The sidebar and the content are traversal
  groups; inside the content the section bar (and its Back) is ordered before
  the body. Before, Tab went from Settings straight to the request row.
  Test: "wide layout: Back follows the sidebar, before the review".
- Open (slice 4): `DeviceCapabilities.cliInstall` is still derived from the OS
  name. Nothing consumes it yet (only `roleText` is read, in
  `app/shell_parts.dart`); take the `InstallationPlatform` and an injectable OS
  when Settings consumes it.
- Token drift:
  - Fixed: fact values in monospace use `AccessType.factMono` (11 px, plan
    §1.2 "fact 11"), in `FactRow` and the review's scope facts (goldens).
  - Already fixed in slice 2: the review's fact grids (`ScopeFacts`,
    `VerificationDetails`) have the top divider. The Devices/Settings fact
    lists belong to the slice 3–4 workpage restyle.
  - Fixed: mobile title sizes. Compact layouts use a 28 px section title
    (default size kept at large text, where 28 px overflowed the toolbar) and a
    27 px request title below the sidebar breakpoint (goldens).
  - Fixed: `AccessMetrics.copyWith` applies its arguments. Test:
    "AccessMetrics.copyWith applies its arguments".
  - Not changed: `AccessTheme.back` stays defined and unused. It is the page
    behind a drawn window; native window chrome draws the window on every
    shipped platform. Remove it only if the owner rules out drawn windows.
- Fixed: the Requests list has a distinct disconnected rendering (configured,
  no current authority, no unknown outcome): no lock state, unlock form or stale
  inbox, only an explanation and the refresh. Test: "an unreachable provider
  lists no requests and no unlock"; goldens `*_shell_disconnected.png`.
- Not changed: `provider/page.dart` (571 lines). The slice 1 spec keeps every
  navigation retirement and its mutation anchors in that file.

## #50 slice 2 (request review) review follow-ups — 2026-11-19

All resolved in the #50 clean-up PR (2026-11-21); tests in
`companion/test/review_followups_test.dart`.

- Fixed: only a review or a decision in flight
  (`ProviderController.reviewWorking`) reads as "Loading or finishing…";
  automatic polls keep the expired notice and its Reload button. Tests: "an
  automatic poll keeps the expired notice and its reload", "a review in flight
  still reads as loading"; mutation `only-reviews-load`.
- Fixed: suspending the app closes the step and clears typed secrets
  (`_ProviderPageState.suspend`). Test: "suspending the app closes the
  authorization step"; mutation `suspend-closes-step`.
- Fixed: `ReviewSession.beginLoad(id, now)` records when a review was asked
  for, and a review of that ID counts from then, even when it replaces another
  without an empty snapshot. Test: "a review replacing another counts from its
  own request"; mutation `countdown-from-request`.
- Fixed: page-level check of `deny()` with a typed approval password (the field
  is cleared and nothing is sent). Test: "a denial never sends or keeps a typed
  approval password". The mutant "deny sends `approvalPassword.text` and skips
  the clear" survives it as an equivalent: `ProviderController.perform` clears
  every password for a decision, and Rust's deny body carries no password, so
  nothing observable changes (checked by hand, 2026-11-21).
- Fixed: `review_states_golden_test.dart` adds `expired_ticket` (the ticket ran
  out: "Reload review"), light desktop and dark compact.
- Fixed, owner may revert: the Touch ID explanation says "dismissed" instead of
  "cancelled".
- Fixed: "Arguments (1 separate value)" in the singular. Test: "one argument
  reads in the singular".

## #50 clean-up findings — 2026-11-21

- Request origin: the provider already sends it, through the management v2
  `request_origin` command (`src/access/provider.rs` `request_origin`), not in
  the v1 review payload. The companion asks for it after each review and shows
  Rust's escaped projection. The heading now reads "Request origin" in every
  case: an `origin: null` reply ("Unavailable: no authenticated origin
  snapshot…") was headed "Authenticated request origin", and "Originating
  device" claimed a device the provider never identifies. A v1-only provider
  still shows "Not supplied by provider protocol v1." Test: "an origin the
  provider could not authenticate is not labelled authenticated"; goldens
  `*_review_origin.png`. Not available from any provider: the physical device
  or host behind an agent binding. Showing it would need authoritative producer
  metadata (e.g. the enrollment record the binding came from) added to
  `request_origin`, with its own compatibility rules; no protocol field was added.
- Open (owner): the page status line above the review shows Rust's status
  summary verbatim (`{"status":"pending"}`) after a review or status read; the
  review's own "Provider status" fact now has a readable label.
- Open: Devices and Settings captures keep "Contacting provider…" as the page
  status after settling (the navigation invalidation leaves the begin message
  of the retired read); worth a look in the slice 3–4 restyle.
