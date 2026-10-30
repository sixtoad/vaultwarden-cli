#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo/companion"
evidence=${1:-"$repo/companion/build/evidence"}
mkdir -p "$evidence"
evidence=$(cd "$evidence" && pwd)
exec > >(tee "$evidence/desktop.log") 2>&1

case "$(uname -s)" in
  Linux*) target=linux ;;
  Darwin*) target=macos ;;
  MINGW*|MSYS*|CYGWIN*) target=windows ;;
  *) echo 'Unsupported build host' >&2; exit 1 ;;
esac
python3 "$repo/scripts/desktop-bundle.py" before "$target" "$evidence"
flutter --version
cargo --version
cargo test --locked --manifest-path rust/Cargo.toml
cargo fmt --manifest-path rust/Cargo.toml -- --check
cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings
cargo build --release --locked --manifest-path rust/Cargo.toml --target-dir "$repo/companion/rust/target"
flutter pub get --enforce-lockfile
flutter analyze
flutter test
flutter test --dart-define=COMPANION_DISPOSABLE_PILOT=true test/pilot_setup_test.dart
python3 "$repo/scripts/test-desktop-companion-artifact.py"
python3 "$repo/scripts/test-desktop-bundle.py"
python3 "$repo/scripts/test-macos-provider-plan.py"
python3 "$repo/scripts/test-provider-packaged-diagnostics.py"

case "$(uname -s)" in
  Linux*)
    target=linux
    python3 "$repo/scripts/test-provider-fixture.py"
    python3 "$repo/scripts/mutate-provider-controller.py" "$evidence/controller-mutations"
    python3 "$repo/scripts/mutate-pilot-setup.py" "$evidence/pilot-setup-mutations"
    xvfb-run -a flutter test integration_test/bridge_test.dart -d linux
    ;;
  Darwin*)
    target=macos
    swift test --package-path .
    bash "$repo/scripts/test-provider-native.sh" "$evidence/provider-native"
    swift test --package-path "$repo/macos-touch-id-probe"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    target=windows
    flutter test integration_test/bridge_test.dart -d windows
    ;;
  *) echo 'Unsupported build host' >&2; exit 1 ;;
esac

# flutter test forces debug mode in the pinned SDK. Build/run a separate AOT
# smoke entrypoint with explicit runtime checks (never Dart assert statements).
flutter build "$target" --release --target integration_test/release_smoke.dart
if [[ "$target" == linux ]]; then
  xvfb-run -a python3 "$repo/scripts/desktop-companion-artifact.py" smoke "$target" "$evidence"
else
  python3 "$repo/scripts/desktop-companion-artifact.py" smoke "$target" "$evidence"
fi
# Actual AOT Flutter -> Rust -> native TLS path, using only fresh disposable CI
# identity/configuration and a bounded loopback transport fixture. No live enroll.
if [[ "$target" == macos && "${CI:-}" == true ]]; then
  flutter build macos --release --target integration_test/provider_tls_smoke.dart
  python3 "$repo/scripts/test-provider-packaged.py" "$repo/companion/build/macos/Build/Products/Release/companion_slice.app" "$evidence/provider-packaged"
fi
if [[ "$target" == macos ]]; then
  # Keep the expensive debug build after TLS evidence, then restore release below.
  flutter test integration_test/bridge_test.dart -d macos
fi
# Never publish the self-exiting smoke harness as the operator's application.
python3 "$repo/scripts/desktop-bundle.py" app "$target" "$evidence"
python3 "$repo/scripts/desktop-bundle.py" commands "$target" "$evidence"
python3 "$repo/scripts/desktop-bundle.py" package "$target" "$evidence"
