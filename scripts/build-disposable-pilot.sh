#!/usr/bin/env bash
# Run in a dedicated Mac build checkout; never installs the operator app.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
[[ "$(uname -s)" == Darwin ]] || { echo 'Disposable pilot packaging requires a Mac build host' >&2; exit 1; }
evidence=${1:?Specify a separate disposable-pilot artifact directory}
mkdir -p "$evidence"
evidence=$(cd "$evidence" && pwd)
cd "$repo/companion"
# A dedicated checkout/output avoids replacing a normal local build bundle.
[[ ! -e build/macos/Build/Products/Release/companion_slice.app ]] || {
  echo 'Use a fresh dedicated pilot build checkout; existing normal build preserved' >&2; exit 1;
}
flutter pub get --enforce-lockfile
cargo build --release --locked --manifest-path rust/Cargo.toml --target-dir rust/target
flutter test --dart-define=COMPANION_DISPOSABLE_PILOT=true
python3 "$repo/scripts/test-pilot-packaged-diagnostics.py"
# Only disposable CI runners launch the separate fixture entrypoint. Actual
# production channel/Keychain/TLS behavior is exercised before operator packaging.
if [[ "${CI:-}" == true ]]; then
  XCODE_XCCONFIG_FILE="$repo/scripts/disposable-pilot.xcconfig" \
    flutter build macos --release --target integration_test/pilot_setup_smoke.dart --dart-define=COMPANION_DISPOSABLE_PILOT=true
  python3 "$repo/scripts/test-pilot-packaged.py" "$repo/companion/build/macos/Build/Products/Release/companion_slice.app" "$evidence/pilot-channel"
fi
# Both sides are enabled in the same command. Neither flag is a secret.
# Always rebuild lib/main.dart: never package the self-exiting CI fixture.
XCODE_XCCONFIG_FILE="$repo/scripts/disposable-pilot.xcconfig" \
  flutter build macos --release --target lib/main.dart --dart-define=COMPANION_DISPOSABLE_PILOT=true
strings build/macos/Build/Products/Release/companion_slice.app/Contents/MacOS/companion_slice > "$evidence/native-build-strings.txt"
# Short Swift strings may be stored inline rather than in the string table.
# Keep the channel method longer than a small string, and require its actual
# compiled entry point marker rather than an unrelated settings/parser symbol.
grep -Fxq 'setupDisposablePilotV1' "$evidence/native-build-strings.txt"
python3 "$repo/scripts/desktop-companion-artifact.py" package macos "$evidence" --disposable-pilot
