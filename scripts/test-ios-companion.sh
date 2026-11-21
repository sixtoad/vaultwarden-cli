#!/usr/bin/env bash
# iOS approval client checks (#60 phase 2). Unsigned: no provisioning,
# Developer ID or secrets. Needs the aarch64-apple-ios and
# aarch64-apple-ios-sim Rust targets, Flutter 3.47.7 and an iOS simulator
# runtime (GitHub's macos-26 image has them). A simulator has no Secure
# Enclave, so hardware behaviour is scripts/ios-approval-hardware-evidence.sh.
set -euo pipefail
evidence=${1:?usage: $0 <evidence-dir>}
repo=$(cd "$(dirname "$0")/.." && pwd)
companion="$repo/companion"
mkdir -p "$evidence"
export PATH="$HOME/.cargo/bin:$PATH"

echo "== Swift contracts on the host (shared key, transcript, mobile rules)"
swift test --package-path "$companion" 2>&1 | tee "$evidence/swift-contract.log"

echo "== companion_core for the iPhone (aarch64-apple-ios)"
cargo build --release --locked --manifest-path "$companion/rust/Cargo.toml" \
  --target-dir "$companion/rust/target" --target aarch64-apple-ios 2>&1 | tee "$evidence/core-ios.log"
test -s "$companion/rust/target/aarch64-apple-ios/release/libcompanion_core.a"

cd "$companion"
flutter pub get
echo "== Dart iOS channel contract"
flutter test test/ios_approval_client_test.dart test/approval_client_test.dart 2>&1 | tee "$evidence/flutter-ios-contract.log"
# The Rust core is linked into the image the linker produced for the app code
# and keeps its bridge symbols global, for dlsym (ExternalLibrary.process).
# A Debug build since Xcode 16 (ENABLE_DEBUG_DYLIB) splits Runner into a stub
# executable and Runner.debug.dylib, which holds the app code and the
# force-loaded core; inspect that image, never the stub. A Release executable
# keeps the symbols only through -export_dynamic (otherwise -dead_strip drops
# what only dlsym reaches), so both configurations are checked.
check_core_linked() {
  config=$1
  app=build/ios/iphoneos/Runner.app
  test -x "$app/Runner"
  binary="$app/Runner"
  if [ -e "$app/Runner.debug.dylib" ]; then
    binary="$app/Runner.debug.dylib"
    otool -L "$app/Runner" | grep -q '@rpath/Runner.debug.dylib' \
      || { echo "Runner ($config) does not load Runner.debug.dylib" >&2; exit 1; }
  fi
  nm -gU "$binary" | grep -qE '_frbgen_|_frb_' \
    || { echo "companion_core symbols missing from $binary ($config)" >&2; exit 1; }
  shasum -a 256 "$app/Runner" "$binary" | sort -u > "$evidence/runner-iphoneos-$config.sha256"
}
for config in release debug; do
  echo "== Unsigned iPhone build ($config)"
  flutter build ios --no-codesign "--$config" 2>&1 | tee "$evidence/flutter-build-ios-$config.log"
  check_core_linked "$config"
done

echo "== XCTest on an iOS simulator"
device=$(xcrun simctl list devices available -j | python3 -c '
import json, sys
devices = json.load(sys.stdin)["devices"]
ids = [d["udid"] for runtime, entries in sorted(devices.items(), reverse=True) if "iOS" in runtime
       for d in entries if d["name"].startswith("iPhone")]
print(ids[0] if ids else "")')
[ -n "$device" ] || { echo "no available iPhone simulator" >&2; exit 1; }
# One re-run: a simulator that fails to boot or hangs on first launch is a
# runner flake, not a test failure. Each attempt keeps its own log and result
# bundle; a test that fails twice fails the job.
run_simulator_tests() {
  attempt=$1
  xcodebuild test -workspace ios/Runner.xcworkspace -scheme Runner -configuration Debug \
    -destination "platform=iOS Simulator,id=$device" -derivedDataPath "${RUNNER_TEMP:-$evidence}/ios-derived-data" \
    -resultBundlePath "$evidence/RunnerTests-$attempt.xcresult" 2>&1 | tee "$evidence/xcodebuild-test-$attempt.log" | tail -40
}
if ! run_simulator_tests 1; then
  echo "== simulator tests failed; shutting the simulator down and re-running once" >&2
  xcrun simctl shutdown "$device" 2>/dev/null || true
  run_simulator_tests 2
fi
