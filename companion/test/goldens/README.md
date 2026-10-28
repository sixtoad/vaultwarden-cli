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
- `macos-26-x64`: twelve reviewed Intel main-job actuals from the same CI run.
  Every image differs in edge pixels from ARM, so CPU baselines remain separate.
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


Activity history adds six synthetic captures per matching host (light/dark,
desktop/compact/200%). On macOS 27 arm64 the six new captures were rendered with
pinned Flutter 3.47.7 and visually reviewed for wrapping, contrast, selected
navigation and reachable event controls. Existing review/action references remain
byte-identical. The 200% capture scrolls the event action into view; widget tests
also check the complete list and exact-ID reopening. Other-host references must
come from that host's reviewed CI captures; comparisons remain exact.
