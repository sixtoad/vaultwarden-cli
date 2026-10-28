---
title: 'Issue 50: structured exact-scope request review'
type: feature
created: '2026-10-28'
status: in-review
baseline_commit: 3ecaab452cf9f5f5791e135a03aa1a26767e2e99
context:
  - '{project-root}/docs/implementation/issue-50-capabilities.md'
  - '{project-root}/docs/companion-migration.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Requests flattens already validated provider facts into text, making scope harder to scan.

**Approach:** Expose typed, escaped facts through the Rust bridge and render labeled Quiet Instrument fields. Preserve the current wire schema. Keep #50 open.

## Boundaries & Constraints

**Always:** Rust owns validation, escaping, lifetime and authority. Preserve all facts, argument boundaries, IDs, digests, credential labels/types, expiry, status and scope. Retain password clearing, ticket consumption, generation checks and original-ID recovery. Origin identity is unavailable in v1.

**Ask First:** New wire fields/commands, support for additional operation review schemas, changes to authorization, or production installation/credentials.

**Never:** Parse text into authority, expose secrets/tickets, infer device identity, or discard unknown fields. History, trust inventory, enrollment, installation and native parity are separate. Existing `create`/`ssh` extensions remain rejected.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|---|---|---|---|
| Valid review | Accepted current-schema response | Complete named facts; indexed arguments and credential entries | Decisions retain Rust admission |
| Ambiguous text | Empty arguments, quotes, controls, Unicode/bidi | Existing quoted escaping, exact order/counts | No normalization or joining arguments |
| Invalid review | Wrong ID/version/generation, malformed digest, unknown fields, oversized response | No typed review or decision authority | Existing bounded invalid/unavailable result |
| Unsupported extension | `create`, `ssh`, or future fields | Reject complete response | Never show incomplete approvable scope |
| Retired review | Back/tab/selection, background, lock, expiry | Typed/text projections clear together | Late completion cannot restore authority |
| Lost decision reply | Original request unresolved | Existing status-only recovery | No replay or inferred completion |
| Missing origin | Current v1 response | Explicitly unavailable; requester remains requester | No fabricated identity |

</frozen-after-approval>

## Code Map

The task paths below locate bridge, projection, lifecycle and UI seams.
`src/access/direct_request.rs` defines producer review extensions; it is context,
not an editing target.

## Tasks & Acceptance

**Execution:**

- [x] `companion/rust/src/api/provider.rs` — add nullable ProviderReview and credential display types; retain review text.
- [x] `companion/rust/src/provider/protocol.rs` — project every fact using existing escaping, separate argument/credential entries and closed status.
- [x] `companion/rust/src/provider/session.rs` — derive both projections from the same validated review without exporting tickets or extending lifetime.
- [x] `companion/lib/src/rust/`, `companion/rust/src/frb_generated.rs` — regenerate together with pinned codegen, never edit generated output manually.
- [x] `companion/lib/provider/request_review.dart`, `page.dart` — render complete selectable facts from the typed snapshot; preserve controls/navigation.
- [x] `companion/rust/tests/provider.rs`, `companion/rust/src/provider/session.rs` tests — cover projection completeness, escaping, malformed/extended schemas and clearing on invalidation/expiry.
- [x] `companion/test/provider_test.dart`, `access_shell_test.dart`, `provider_support.dart` — test real bridge values, malicious/empty/long text, completeness, navigation and recovery.
- [x] `companion/test/access_golden_test.dart`, `test/goldens/` — review and update exact desktop/compact light/dark and large-text captures on each supported renderer.
- [x] `scripts/mutate-provider-companion.py`, `mutate-provider-controller.py` — retain mutations; ensure escaping/retirement mutants exercise the typed path.
- [x] `docs/implementation/issue-50-capabilities.md`, `companion/README.md` — record schema limits, supported facts and verification evidence.

**Acceptance Criteria:**

- Given a valid review, when opening Requests, then every accepted fact appears without widget-side decoding.
- Given retired or invalid authority, when navigating or receiving a late reply, then no typed review can enable an approval.
- Given either theme/layout at 200% text, when reading long scope, then all facts/actions remain reachable without truncation.
- Given an unresolved decision, when returning to Requests, then only the original request status can settle recovery.
- Given v1 metadata, when reviewing, then origin identity is explicitly unavailable.

## Spec Change Log

- 2026-10-28: Independent review identified eager widget allocation for near-limit
  argument/credential lists. Bound display work with local pages and lazy rows,
  retaining all entries, global indices and small-list layout. This is an
  implementation correction; frozen scope and wire validation remain unchanged.
- 2026-10-28: User requested rejection/suspension for unreasonable input. Further
  provider investigation established existing operation limits of 32 arguments
  and 16 credentials. Enforce those limits before projecting companion reviews;
  remove the proposed large-list pagination. Pin exact accepted/rejected count
  boundaries in both crates. Automatic requester suspension needs authenticated
  attribution and a separate recovery design; it is not implemented here.

## Verification

- In `companion/`: `flutter_rust_bridge_codegen generate`, pinned codegen 2.13.0 and cargo-expand 1.0.112; commit both generated sides.
- `bash scripts/test-desktop-companion.sh <external-evidence-directory>`: full Rust/Flutter/pilot/native, integration, packaging and AOT gates; also check Dart formatting.
- Run both mutation scripts sequentially; require assertion failures, pristine/restored passes and identical source hashes.
- Require matching desktop CI, packaged macOS TLS and installation checks; report local skips honestly. PR #51 evidence does not verify new changes.
- Inspect every updated host golden with exact comparisons; use isolated synthetic fixtures only.

## Suggested Review Order

**Review presentation**

- Render every validated fact without reconstructing authority.
  [request_review.dart:8](../../companion/lib/provider/request_review.dart#L8)

**Validation and lifetime**

- Reject excessive counts using the provider’s existing operation limits.
  [protocol.rs:76](../../companion/rust/src/provider/protocol.rs#L76)

- Escape typed fields and preserve argument and credential boundaries.
  [protocol.rs:88](../../companion/rust/src/provider/protocol.rs#L88)

- Derive both displays from one validated, expiring review.
  [session.rs:75](../../companion/rust/src/provider/session.rs#L75)

**Bridge and regressions**

- Expose display-only types while keeping tickets internal.
  [provider.rs:43](../../companion/rust/src/api/provider.rs#L43)

- Pin accepted and rejected counts independently of production constants.
  [provider.rs:158](../../companion/rust/tests/provider.rs#L158)

- Verify rendered fields and lifecycle behavior through the actual bridge.
  [access_shell_test.dart:418](../../companion/test/access_shell_test.dart#L418)

- Verify the packaged bridge in debug and AOT checks.
  [provider_checks.dart:7](../../companion/integration_test/provider_checks.dart#L7)

**Evidence**

- Read review findings, verification results and remaining acceptance boundaries.
  [issue-50-typed-review.md:1](../../docs/implementation/issue-50-typed-review.md#L1)
