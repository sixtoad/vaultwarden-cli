# Golden-test fonts

These test-only files are copied from the pinned Flutter 3.47.7 material-fonts
archive. Roboto regular, medium and bold are loaded together so requested UI
weights do not depend on host synthesis. MaterialIcons is pinned alongside them.
Licenses are included. None of these files is a production application asset.

The golden matrix uses the Android widget platform and en_US locale on every
runner, with exact PNG comparison against reviewed host-specific baselines.
Pinned outlines do not make host rasterizers produce identical edge pixels. The production app retains platform typography.
