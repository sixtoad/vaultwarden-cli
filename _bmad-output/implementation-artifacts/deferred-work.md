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
