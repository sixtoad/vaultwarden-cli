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
  retained; desktop review/actions are intentionally identical because both fit.

For updates, run `flutter test --update-goldens test/access_golden_test.dart` on
the matching host with the pinned SDK, inspect all captures, then run the full
suite without updates. Never adopt a failing image without reviewing its content
and the isolated diff. CI archives `test/failures` for diagnosis.
