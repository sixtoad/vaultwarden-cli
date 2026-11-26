# Exact visual baselines

Every supported desktop host executes all six synthetic scenarios and compares
all twelve review/action captures exactly. Baselines are selected with
`Platform.operatingSystem`, plus macOS product major from `/usr/bin/sw_vers`
and process ABI from `Abi.current()`;
no tolerance, skipped comparisons or cross-host
fallback is used. Platform widget behavior is still pinned to Android, locale to
en_US, and the licensed font/icon outlines are bundled under `test/fonts`.

Even with identical outlines, host text rasterizers produce different glyph-edge
pixels. CI run 40538955066 on source 47a2f29 confirmed this: Linux differed at
text/icon edges while panel geometry, wrapping, review facts and actions matched.

- `macos-27-arm64`: original locally generated and visually reviewed ARM macOS 27.0.1
  (26A434) captures.
- `macos-26-arm64`: twelve individually reviewed ARM pilot actuals from CI macOS 26.6.2
  (25G83), image macos-26-arm64/20261013.0424. Their sparse glyph-edge differences
  from macOS 27 confirm that bundled fonts do not pin the OS rasterizer.
- Intel (`macos-26-x64`) references were removed on 2026-11-10: Intel (x86_64)
  macOS is no longer supported or built, and no CI job renders them.
- `windows`: twelve actual PNGs from the same run on windows-latest,
  visually inspected for complete review, layout and actions before adoption.
- `linux`: the twelve actual PNGs from that run's Ubuntu 24.04 failure artifact,
  individually inspected before adoption. Full review and explicit actions are
  retained.

For updates, run `flutter test --update-goldens test/access_golden_test.dart` on
the matching host with the pinned SDK, inspect all captures, then run the full
suite without updates. Never adopt a failing image without reviewing its content
and the isolated diff. CI archives `test/failures` for diagnosis.

## Structured review update, 2026-10-28

The macOS 27 arm64 references were regenerated and individually reviewed locally
for the structured review. The other four hosts use actual captures from
[CI run 40693829222](https://github.com/sixtoad/vaultwarden-cli/actions/runs/40693829222)
on source `f3d03b446b069122fad2ac572b071f6a15cd6470`. For each host, an independent
review inspected ten changed captures, all ten isolated diffs, and the two
unchanged large-text action references before adoption. The changed PNGs are
copied byte-for-byte from the matching host artifact. Both unchanged captures
passed exact comparison in that run.

Changes match the labeled typed fields, quoted identifiers, explicit unavailable
origin, and resulting scroll positions. Desktop review/action pairs cover the
complete scope; compact and 200% text layouts retain accessible actions. Full
matching-host comparisons and packaged checks remain enforced by PR #52 CI.

## Activity history update, 2026-10-28

Activity history adds six synthetic captures per matching host (light/dark,
desktop/compact/200%). On macOS 27 arm64 the six new captures were rendered with
pinned Flutter 3.47.7 and visually reviewed for wrapping, contrast, selected
navigation and reachable event controls. Existing review/action references remain
byte-identical. The 200% capture scrolls the event action into view; widget tests
also check the complete list and exact-ID reopening. Other-host references must
come from that host's reviewed CI captures; comparisons remain exact.

Linux and Windows Activity references were individually visually
reviewed and copied byte-for-byte from [CI run 40721598625](https://github.com/sixtoad/vaultwarden-cli/actions/runs/40721598625),
source `55f10079469bc999dcf2a78c183e724a4a0df59d`. Labels, UTC timestamps, long
request IDs, selected navigation and the fresh-review action remain readable in
both themes and all three layouts. The 200% captures intentionally center the
action using scrolling; content at the viewport edges is clipped by that scroll.

The six macOS 26 arm64 Activity references were individually reviewed on
2026-10-29 and copied byte-for-byte from [ARM capture job 123371110473](https://github.com/sixtoad/vaultwarden-cli/actions/runs/40725130148/job/123371110473),
run 40725130148 attempt 5, source `bcbaddece26c6d74dddcc22308480ddf4627c727`.
The host was macOS 26.6.2 (25G83), image `macos-26-arm64/20261021.0445.8`.
Both themes preserve readable labels, wrapped IDs, selected navigation and
reachable fresh-review/refresh controls at desktop, compact and 200% text sizes.
The large-text images intentionally center the action by scrolling. This capture
run passed 73 tests and failed exactly the six missing Activity references; the
existing review/action references passed and remain unchanged. Adoption keeps
exact comparisons, with full final-revision CI recorded in PR #54.

## Guided enrollment, 2026-11-10 (#59 phase 2)

`enrollment_golden_test.dart` adds four captures per host: the joining
device's comparison step (`*_join_enrollment.png`, a pure widget with a fixed
synthetic code) and the owner's approval form (`*_approve_enrollment.png`,
driven through the test provider oracle), light and dark, 900 px wide. The
macOS 27 arm64 references were rendered locally with pinned Flutter 3.47.7 and
reviewed for the large tabular code, labels above fields, and reachable
actions. The other hosts' references must be adopted from that host's
reviewed CI captures (`EnrollmentCaptureComparator` writes every capture to
`test/failures`). Intel macOS (`macos-26-x64`) is unsupported
(owner decision 2026-11-10); no x64 enrollment reference is adopted.

Linux, Windows and macOS 26 arm64 enrollment references were individually
visually reviewed and copied byte-for-byte from [CI run 43030456636](https://github.com/sixtoad/vaultwarden-cli/actions/runs/43030456636),
source `904d5e2`, where they failed only as missing references (163 other
tests passed on each host). The macOS 26 arm64 host was image
`macos-26-arm64/20261102.0473.1`. Both themes show the complete approval form
(labels above fields, the typed code, reachable Approve/Back/Cancel/Close) and
the joining comparison step (large grouped code, countdown, all three
choices); differences from macOS 27 are glyph-edge rasterization only.

## Shell conformance, 2026-11-19 (#50 slice 1)

The direction A tokens and shell change every existing capture, and
`shell_golden_test.dart` adds 24 per host: Requests empty, two IDs, locked and
recovery, plus the first Devices and Settings references, light/dark,
desktop (1440×900)/compact (390×844). Settings renders a fixed synthetic
installation (`FakeInstallation`) so no host path appears in a capture.
`CaptureComparator` (`golden_support.dart`) writes every shell capture to
`test/failures` for adoption.

The `macos-27-arm64` references (22 changed: review/actions/activity and the
four enrollment captures, whose only change is heading letter spacing; 24 new)
were rendered locally with pinned Flutter 3.47.7 on macOS 27.0.1 and visually
reviewed. The `linux`, `windows` and `macos-26-arm64` references (the same 46
images per host) were adopted from CI run 44614054785's captures
(`companion-slice-*-development` artifacts) after the owner reviewed them on
2026-11-19; exact comparison is kept.

## Request review states, 2026-11-19 (#50 slice 2)

The review redesign changes 16 existing captures per host: review and actions
(light/dark × desktop/compact/200%) and the four `shell_recovery` captures
(the outcome-unknown notice). `review_states_golden_test.dart` adds 18 per
host: the authorization step (password only, Touch ID available, Touch ID
offered but unable to approve) and the running, completed, failed, denied,
expired and outcome-unknown states, light desktop (1440×900) and dark compact
(390×844). A fixed `ProviderPage.clock` keeps the countdown at 55 s. Every
capture is written to `test/failures` by `CaptureComparator`.

The `macos-27-arm64` references (16 changed, 18 new) were rendered locally with
pinned Flutter 3.47.7 on macOS 27.0.1 and visually reviewed. The `linux`,
`windows` and `macos-26-arm64` references were NOT regenerated: CI on those
hosts fails on the same 16 changed and 18 missing references until the owner
reviews and adopts each host's captures from the CI artifacts.

## Request review adoption, 2026-11-21 (#50 slice 2)

The `linux`, `windows` and `macos-26-arm64` references for the slice 2
review redesign (the two-step review and the outcome-unknown shell recovery
notice) were adopted from [CI run 44642376391](https://github.com/sixtoad/vaultwarden-cli/actions/runs/44642376391)
on source `f1dd2fb`, where each host failed exactly the 16 changed
review/actions/`shell_recovery` captures and the 18 missing
`review_states_golden_test.dart` captures (243 other tests passed on Linux).
The `macos-27-arm64` references were regenerated locally in the slice.

All 34 actual captures per host were visually compared with the matching
`macos-27-arm64` reference: same content, wrapping, review facts, status
notices and visible actions (Approve/Deny/Close review, Cancel
authorization, Approve once with Touch ID or password, Back to requests,
View activity, Check status, Refresh authority and inbox); differences are
glyph-edge rasterization only. All 48 isolated diffs of the changed
captures show the old-to-new redesign and nothing host-specific. The 200%
review captures cut the summary at the navigation bar by scrolling, as the
macOS 27 reference does. The macOS 26 captures were identical (sha256) in
the `companion-slice-macOS-arm64-development` and
`companion-macOS-disposable-pilot` artifacts, and the 30 unchanged shell
captures in each artifact matched the committed references byte for byte.
The PNGs are copied byte for byte; comparison stays exact.

## Review reveal and inbox row status, 2026-11-21 (#50 slice 2)

Two review fixes change nine captures per host. In single-pane layouts an
opened review now scrolls to its own top, so the 200% capture shows the whole
"who wants what" sentence above the navigation bar (`*_compact_review.png`,
`*_large_review.png`, light and dark). The inbox row shows the final status the
companion holds for a request instead of a fixed "Pending"
(`light_desktop_review_{running,completed,failed,denied,expired}.png`). The
`macos-27-arm64` references were regenerated locally and reviewed; the other
hosts adopt their reviewed CI actuals.

## Review reveal and inbox row status adoption, 2026-11-21 (#50 slice 2)

The `linux`, `windows` and `macos-26-arm64` references for the review reveal
and inbox row status fixes were adopted from [CI run 44886352824](https://github.com/sixtoad/vaultwarden-cli/actions/runs/44886352824)
on source `d1ede07`, where each host failed exactly the nine changed captures
(`{light,dark}_compact_review.png`, `{light,dark}_large_review.png`,
`light_desktop_review_{completed,denied,expired,failed,running}.png`).

All 27 actual captures were visually compared with the matching
`macos-27-arm64` reference: the compact and 200% reviews open at the review's
own top (status, request ID, operation and the whole "who wants what"
sentence above the navigation bar), and each desktop inbox row shows the
review's final status (Completed · exit code 0, Denied, Expired, Failed,
Running · not completed); differences are glyph-edge rasterization only. All
27 isolated diffs show only the old-to-new scroll position or inbox row
status. The macOS 26 captures were identical (sha256) in the
`companion-slice-macOS-arm64-development` and
`companion-macOS-disposable-pilot` artifacts, and the 47 unchanged shell and
review state captures in each artifact matched the committed references byte
for byte. The PNGs are copied byte for byte; comparison stays exact.

## Clean-up, 2026-11-21 (#50)

The slice 1/2 follow-ups change 44 captures per host and add 18.

Changed: fact values in monospace are 11 px (plan §1.2), "Arguments (1
separate value)", the review's "Provider status" fact gains "Reads as: …",
the origin heading reads "Request origin", the Touch ID note says
"dismissed", and compact layouts use the 28 px section title and 27 px
request title (large text keeps its previous title size). Files: every
`*_review_*.png` of `review_states_golden_test.dart` (18), the eight
`{light,dark}_{desktop,compact}_{review,actions}.png` plus
`{light,dark}_large_review.png` and `{light,dark}_compact_activity.png`, and
the compact shell captures `{light,dark}_compact_shell_{empty,two,locked,recovery,devices,settings}.png`
plus `{light,dark}_desktop_shell_recovery.png`.

New: `shell_golden_test.dart` adds the Requests list when disconnected
(`*_{desktop,compact}_shell_disconnected.png`), a populated Devices
inventory (`*_{desktop,compact,large}_shell_inventory.png`) and Devices and
Settings at 200% text (`*_large_shell_{devices,settings}.png`), light and
dark; `review_states_golden_test.dart` adds `expired_ticket` (the ticket ran
out, "Reload review") and `origin` (an authenticated requester-agent
binding), light desktop and dark compact.

The `macos-27-arm64` references were rendered locally with pinned Flutter
3.47.7 on macOS 27 and visually reviewed. The `linux`, `windows` and
`macos-26-arm64` references were NOT regenerated: CI on those hosts fails on
the same 44 changed and 18 missing references until each host's captures are
reviewed and adopted from the CI artifacts.

## Clean-up adoption, 2026-11-21 (#50)

The `linux`, `windows` and `macos-26-arm64` references for the #50
clean-up were adopted from [CI run 44919123214](https://github.com/sixtoad/vaultwarden-cli/actions/runs/44919123214)
on source `62f4268`. On each host the Flutter suite passed 248 tests and
failed 64, all of them golden comparisons (the Rust tests passed): 52
changed captures and the 18 new ones listed above. The 52 changed captures
are exactly the `macos-27-arm64` references this clean-up regenerated; the
list above names 44 of them, and the other eight are
`{light,dark}_desktop_shell_{empty,two,devices,settings}.png`, whose status
line now reads "Inbox refreshed: N pending".

All 70 actual captures per host were visually compared with the matching
`macos-27-arm64` reference: same content, wrapping, status lines ("Request
status: Awaiting your approval", "Inbox refreshed: N pending"), facts
("Arguments (1 separate value)", "Reads as: …", "Request origin"), notices
and visible actions (Approve…/Deny…, Close review, Cancel authorization,
Approve once with Touch ID or password, Reload review, Back to requests,
View activity, Check status, Refresh authority and inbox, Refresh provider
identities, Review "…", Add a device or agent, Join this device to a
provider); differences are glyph-edge rasterization only. The 200%
captures clip at the navigation bar by scrolling, as the macOS 27
references do. All 52 isolated diffs per host show only the old-to-new
text changes. For the changed captures the actual is
`<name>_testImage.png` (the access test writes no host-prefixed copy of its
review/actions captures); for the new ones it is the host-prefixed capture.
The macOS 26 actuals were identical (sha256) in the
`companion-slice-macOS-arm64-development` and
`companion-macOS-disposable-pilot` artifacts; in every artifact the 10
unchanged Activity, enrollment and desktop locked-shell captures and all
52 master images matched the committed references byte for byte. The PNGs
are copied byte for byte; comparison stays exact.

## Windows/Linux file-path setup, 2026-11-26 (desktop approval, PR #94)

`{light,dark}_{desktop,compact}_shell_filesetup.png` show the unconfigured
Settings screen of a transport that reads the CA and PKCS#12 by path
(Windows and Linux; spec `docs/implementation/desktop-approval-spec.md` D-4).
The macOS 27 arm64 captures were rendered locally with the pinned SDK and
reviewed. The Linux and Windows captures are the actual images of
[CI run 45796191596](https://github.com/sixtoad/vaultwarden-cli/actions/runs/45796191596),
each visually reviewed (same fields, labels, wrapping and disabled import
button as macOS; only glyph-edge rasterization differs) and copied
byte-for-byte. No existing reference changed.
