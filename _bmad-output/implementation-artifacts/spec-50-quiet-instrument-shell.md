---
title: 'Issue 50: Quiet Instrument shell and real request review'
type: feature
created: '2026-10-27'
status: in-review
baseline_commit: 476bf3f506aad6f52628ad32a6ef34e31172d1ba
context:
  - '{project-root}/docs/implementation/issue-50-capabilities.md'
  - '{project-root}/docs/companion-migration.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The Flutter companion combines setup and real approval in one development-oriented page, without the selected Quiet Instrument design.

**Approach:** Deliver #50’s first slice: shared styling, responsive navigation and existing real request flow. Track remaining requirements in the capability checklist; keep #50 open.

## Boundaries & Constraints

**Always:** Rust owns validation. Preserve escaped scope, argument boundaries, identity, password clearing, recovery markers and late-result rejection. Navigation retires review authority. Retain existing native functionality and the separate synthetic signer.

**Ask First:** Changes to security protocols or the agreed slice; production credential migration, installed-app replacement, privileged service changes, or security-setting changes.

**Never:** WebView replacement, fabricated authority/results/metadata, decision replay, browser approval, or hand-edited generated bindings.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|---|---|---|---|
| Review | Valid provider review | Complete exact scope and explicit password approval / denial | No omitted facts or inferred authority |
| Navigation | Tab/back/selection changes during review | Retire ticket, clear passwords; fresh review on return | Late results cannot authorize another request |
| Lifecycle | Background, lock, disposal | Existing invalidation and completion handling | No retained password or stale authorization |
| Unknown result | Lost decision reply | Original request status only; recovery visible across tabs | Never replay approve, deny or unlock |
| Authority unavailable | Locked, disconnected, invalid reply | Honest unavailable/locked state; existing recovery controls | No optimistic success |
| Layout | Compact width, large text, long IDs | Scrollable facts, reachable controls and correct back behavior | No clipped security details |

</frozen-after-approval>

## Code Map

- `companion/lib/main.dart`: app composition and separate synthetic signer.
- `companion/lib/provider/page.dart`: current setup, inbox, review and recovery UI.
- `companion/rust/src/api/provider.rs`: authoritative snapshot exposed to Flutter.
- `companion/rust/src/provider/protocol.rs`: escaped complete review and closed statuses.

## Tasks & Acceptance

**Execution:**

- [x] `companion/lib/design/access_theme.dart`, `components.dart` — shared theme, status, headings, panels and accessible action rows.
- [x] `companion/lib/app/access_shell.dart` — sidebar, compact four-destination navigation, safe areas and list/detail back behavior; invalidate before navigation.
- [x] `companion/lib/provider/page.dart` — compose destinations around one controller; preserve settlement, move manual setup to advanced Settings, retain the pilot build gate.
- [x] `companion/lib/provider/request_review.dart` — complete Rust-escaped review, identity, provider endpoint, expiry guidance and explicit decisions. Never parse display text into authority.
- [x] `companion/lib/provider/support_views.dart` — actual connection/client identity, latest request status and capability limits. Label latest status honestly; reopening requires fresh review. No fake enrollment/repair controls.
- [x] `companion/lib/main.dart` — apply theme while preserving synthetic entrypoint and core-load failure handling.
- [x] `companion/test/provider_test.dart`, `access_shell_test.dart` — test matrix with real Rust core, navigation, recovery and pilot regressions.
- [x] `companion/test/access_golden_test.dart`, `goldens/` — inspect synthetic desktop/compact light/dark goldens and large-text layouts.
- [x] `scripts/mutate-provider-controller.py` — preserve mutation checks; add navigation-boundary coverage with exact restoration.
- [x] `companion/README.md`, `docs/implementation/issue-50-capabilities.md` — delivery evidence, blockers and rollback.

**Acceptance Criteria:**

- Given a configured Mac, when explicitly approving, then the existing password/provider path retains scope and recovery semantics.
- Given compact/desktop layouts, when navigating in either theme at 200% text scale, then all facts and controls remain accessible.
- Given unsupported transport, when opening the shell, then native limits are explicit; phones offer no CLI installation.
- Given provider evidence, when displaying status, then approval, execution and completion remain distinct; review cancellation is not request cancellation.
- Given absent APIs, when opening their destinations, then limitations remain visible and #50 remains open.

## Spec Change Log

- 2026-10-27: Implemented the approved first slice without changing frozen intent.
  Validation evidence and the remaining native CI prerequisite are recorded below.
- 2026-10-27: Independent review patches corrected checked-control contrast,
  navigation/review scroll reset and locked Activity admission. Regressions were
  demonstrated before patching; frozen intent is unchanged.

## Design Notes

Use selected A tokens from `docs/design/issue-50/DESIGN.md`: system typography, semantic light/dark colors, 4px spacing increments, 7px controls and 48px targets. Check actual contrast; prototype behavior never overrides provider contracts.

## Verification

- `bash scripts/test-desktop-companion.sh /private/tmp/vaultwarden-50-evidence/desktop` — full existing host gate, analyzer, Flutter/Rust/native and packaging checks; isolated fixtures only.
- In `companion/`: `dart format --output=none --set-exit-if-changed lib test`; generate and inspect `flutter test --update-goldens test/access_golden_test.dart`, then verify without updating.
- `python3 scripts/mutate-provider-controller.py /private/tmp/vaultwarden-50-evidence/controller` — every mutation detected and baseline restored; include new navigation wiring, no concurrent edits.
- Record cross-platform CI and physical checks separately. Verification used privately provisioned SDKs; see the recorded toolchain versions and evidence below.

## Implementation evidence

- Shared four-destination shell, complete review, truthful capability views,
  advanced setup and separate synthetic signer implemented. Rust/controller and
  native protocol authority are unchanged.
- Flutter 59 tests, pilot-enabled 9, Rust 28, Python 23, companion Swift 12,
  synthetic probe 11 and macOS debug integration 1 passed. Analyzer, Rust format
  and Clippy passed. All 12 readable golden images were inspected.
- All 12 controller/navigation mutants were detected; exact sources restored and
  restoration tests passed.
- Native normal/pilot suites passed with one CI-only skip each, using task-private
  OpenSSL/Swift compatibility overrides. Full host gate remains non-green because
  the native `install-save` mutant survives without its CI-only installation test.
  No trust check was weakened and native sources match the baseline.
- AOT smoke passed with private Rust 1.99.1, which avoids this host's Rust 1.88.0 /
  Xcode 27 malformed LINKEDIT output. Normal entrypoint was rebuilt and the development archive verified.
- Full evidence, toolchains, cross-platform/hardware gaps and rollback are in
  `docs/implementation/issue-50-capabilities.md`. Issue #50 remains open. Independent review is complete; its three actionable
  patches passed regression checks. The CI-only gate remains required.

## Suggested Review Order

**Composition and navigation**

- Follow the destination composition around one controller and shared appearance.
  [page.dart:432](../../companion/lib/provider/page.dart#L432)

- Trace desktop, compact and large-text navigation with explicit back behavior.
  [access_shell.dart:34](../../companion/lib/app/access_shell.dart#L34)

**Authority and request facts**

- Inspect synchronous ticket retirement, secret clearing and scroll reset at navigation boundaries.
  [page.dart:93](../../companion/lib/provider/page.dart#L93)

- Keep uncertain decisions bound to their original request across destinations.
  [page.dart:134](../../companion/lib/provider/page.dart#L134)

- Render complete validated scope without deriving authority from display text.
  [request_review.dart:23](../../companion/lib/provider/request_review.dart#L23)

- Present latest status honestly and require fresh review for another decision.
  [support_views.dart:43](../../companion/lib/provider/support_views.dart#L43)

**Appearance and setup**

- Check semantic contrast, visible focus and accessible control sizing.
  [access_theme.dart:68](../../companion/lib/design/access_theme.dart#L68)

- Keep advanced setup, pilot gating and synthetic signing clearly separated.
  [page.dart:294](../../companion/lib/provider/page.dart#L294)

**Verification and remaining scope**

- Exercise long inbox navigation, locked admission and authority retirement regressions.
  [access_shell_test.dart:111](../../companion/test/access_shell_test.dart#L111)

- Compare both themes across desktop, compact and large-text review states.
  [access_golden_test.dart:11](../../companion/test/access_golden_test.dart#L11)

- Verify both navigation boundaries with deliberate faults and exact source restoration.
  [mutate-provider-controller.py:30](../../scripts/mutate-provider-controller.py#L30)

- Read independent review triage and the accepted implementation patches.
  [issue-50-review.md:1](../../docs/implementation/issue-50-review.md#L1)

- Review evidence and CI prerequisites before expanding or closing the parent issue.
  [issue-50-capabilities.md:114](../../docs/implementation/issue-50-capabilities.md#L114)

## PR #51 CI follow-up (2026-10-27)

- Retain exact golden comparisons and all six layout/theme scenarios. Pin the
  Android widget platform and English locale; load bundled licensed regular,
  medium and bold font outlines plus icon outlines to remove host font synthesis
  and SDK icon-resource variability. Regenerate and inspect all 12 captures.
  Archive failure PNGs from desktop and pilot CI for any remaining host differences.
- Update root crypto-bigint 0.7.5 to 0.7.9, the earliest patched non-yanked release
  (0.7.6–0.7.8 are yanked), plus its required ctutils 0.4.6 dependency. No other
  lock entries changed. Rust 1.88 all-targets tests: 542 passed.
- Pin the native Swift build system in both parent and mutation child, preserving
  the object layout already verified with the local Xcode 27 compatibility run.
- Move the main macOS desktop gate to Intel after ARM runner acquisition failed;
  keep the ARM pilot and universal libraries. Packaging/smoke scripts have no
  host-CPU assumptions. Native install-save and packaged TLS acceptance still
  require the actual CI result, not a locally forged CI environment.
- Local full Flutter suite: 59 passed; analyzer clean; readable regenerated
  captures inspected. Cross-host golden and full native CI outcomes remain pending.
