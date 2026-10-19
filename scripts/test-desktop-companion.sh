#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo/companion"
evidence=${1:-"$repo/companion/build/evidence"}
mkdir -p "$evidence"
evidence=$(cd "$evidence" && pwd)
exec > >(tee "$evidence/desktop.log") 2>&1

flutter --version
cargo --version
cargo test --locked --manifest-path rust/Cargo.toml
cargo fmt --manifest-path rust/Cargo.toml -- --check
cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings
cargo build --release --locked --manifest-path rust/Cargo.toml --target-dir "$repo/companion/rust/target"
flutter pub get --enforce-lockfile
flutter analyze
flutter test

case "$(uname -s)" in
  Linux*)
    flutter build linux --release
    xvfb-run -a flutter test integration_test/bridge_test.dart -d linux
    ;;
  Darwin*)
    swift test --package-path .
    flutter build macos --release
    flutter test integration_test/bridge_test.dart -d macos
    ;;
  MINGW*|MSYS*|CYGWIN*)
    flutter build windows --release
    flutter test integration_test/bridge_test.dart -d windows
    ;;
  *) echo 'Unsupported build host' >&2; exit 1 ;;
esac
