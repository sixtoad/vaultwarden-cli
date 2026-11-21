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
echo "== Unsigned iPhone build"
flutter build ios --no-codesign --debug 2>&1 | tee "$evidence/flutter-build-ios.log"
binary=build/ios/iphoneos/Runner.app/Runner
test -x "$binary"
# The Rust core is linked in (its bridge symbols are global, for dlsym).
nm -gU "$binary" | grep -qE '_frbgen_|_frb_' || { echo "companion_core symbols missing from Runner" >&2; exit 1; }
shasum -a 256 "$binary" > "$evidence/runner-iphoneos.sha256"

echo "== XCTest on an iOS simulator"
device=$(xcrun simctl list devices available -j | python3 -c '
import json, sys
devices = json.load(sys.stdin)["devices"]
ids = [d["udid"] for runtime, entries in sorted(devices.items(), reverse=True) if "iOS" in runtime
       for d in entries if d["name"].startswith("iPhone")]
print(ids[0] if ids else "")')
[ -n "$device" ] || { echo "no available iPhone simulator" >&2; exit 1; }
xcodebuild test -workspace ios/Runner.xcworkspace -scheme Runner -configuration Debug \
  -destination "platform=iOS Simulator,id=$device" -derivedDataPath "${RUNNER_TEMP:-$evidence}/ios-derived-data" \
  -resultBundlePath "$evidence/RunnerTests.xcresult" 2>&1 | tee "$evidence/xcodebuild-test.log" | tail -40
