---
title: 'Issue 50 slice 1: Quiet Instrument theme tokens and shell conformance'
type: 'feature'
created: '2026-11-19'
status: 'in-progress'
baseline_commit: '8f82cd7'
context:
  - '/Volumes/sixto_dev/ai/vaultwarden-cli-wt/plan-50.md (sections 1, 2, 4 slice 1; outside the repo)'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The companion shell reads "COMPANION / Development application", the inbox is a list of `Review <id>` buttons, the theme lacks the direction A tokens (back, statusText, error, actionFill, full type scale, metrics), and `provider/page.dart` is a 730-line monolith.

**Approach:** Bring `design/` to the tokens of plan §1, restyle the four-section shell (brand block, selected rule, pending badge, footer status, section bar, compact nav), add a pure `DeviceCapabilities` model, and split `page.dart` into cohesive view files, with zero behaviour change to the request flow.

## Boundaries & Constraints

**Always:** Keep every navigation retirement (`navigate`, `backToRequests`, `openRequest`) and its mutation anchors in `page.dart`; keep all widget `Key`s; keep `PopScope` behaviour; status by icon and text, never colour alone; ≥4.5:1 text contrast in both themes; keep one `SelectableText` per `FactRow`.

**Ask First:** Any controller, Rust, native or generated-binding change.

**Never:** Review-detail redesign (slice 2), Activity/Devices/Settings restyle (slices 3–4), persisted appearance, list summaries, provider display name, new dependencies.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Pending badge | 2 request IDs | Requests destination shows "2" badge with semantics "2 pending" | 0 IDs: no badge |
| Footer connected | configured, authority known, unlocked | "Connected" + host of endpoint, "This device: approval client" | — |
| Footer locked | `state.locked` | "Locked" with lock icon | — |
| Footer unconfigured | no configuration | "Not configured" | — |
| Footer unavailable | `platform.available == false` | "Unavailable on this platform", "This device: approval unavailable" | — |
| Capabilities | os ∈ {macos, linux, windows, android, ios} | requester only on macos/linux; CLI install only on desktop; never executes | unknown os: all false |

</frozen-after-approval>

## Code Map

- `companion/lib/design/access_theme.dart` -- colour tokens + ThemeData
- `companion/lib/design/components.dart` -- shared widgets; to be split
- `companion/lib/app/access_shell.dart` -- four-destination shell
- `companion/lib/provider/page.dart` -- state, lifecycle, navigation, composition (730 lines)
- `companion/test/access_shell_test.dart`, `access_golden_test.dart`, `enrollment_golden_test.dart` -- shell behaviour and goldens
- `scripts/mutate-provider-controller.py` -- anchors in `page.dart`

## Tasks & Acceptance

**Execution:**
- [ ] `design/access_theme.dart` -- add back/statusText/error/actionFill, map error into ColorScheme, full TextTheme per §1.2 -- tokens
- [ ] `design/typography.dart`, `design/metrics.dart` -- `AccessType` (kicker, mono, code, brand) and `AccessMetrics` extensions -- §1.2/§1.3
- [ ] `design/{facts,status,notice,section_bar}.dart` -- split from components (re-exported): wide two-column `FactRow` with optional sub/mono, `StatusLabel` + `CountBadge`, `AccessNotice`, `AccessSectionBar`
- [ ] `app/capabilities.dart` -- pure `DeviceCapabilities.derive`
- [ ] `app/access_shell.dart` (+ `app/shell_parts.dart`) -- brand, selected rule, badge, footer status, section bar on wide, compact AppBar title/status, breakpoint 850
- [ ] `provider/requests_view.dart`, `provider/settings_view.dart` -- moved from `page.dart`; master/detail (270 px list), `RequestRow`, recovery as `AccessNotice`
- [ ] tests -- re-key `Review <id>` finders to `requestRow(id)`; badge/footer/capabilities/contrast tests; shell goldens (Requests empty/two/locked/recovery, Devices, Settings × light/dark × desktop/compact)

**Acceptance Criteria:**
- Given the existing suite, when run after re-keying, then every test passes unmodified otherwise.
- Given `scripts/mutate-provider-controller.py`, when run, then all 12 mutations are caught.
- Given `flutter analyze`, then no issues.

## Design Notes

The shell keeps one page scroll (`contentScroll`) in both layouts so scroll-reset behaviour is unchanged; independent list/detail scrolling belongs with the slice 2 review redesign. Scaffold background stays `soft`; the shell paints the content pane `surface`.

## Verification

**Commands:**
- `flutter analyze` -- expected: No issues found
- `flutter test --concurrency=2` -- expected: all pass on macos-27-arm64 references
- `python3 scripts/mutate-provider-controller.py <evidence>` -- expected: 12/12 caught
