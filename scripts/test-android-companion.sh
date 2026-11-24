#!/usr/bin/env bash
# Android approval client (#60 phase 1), on a host with the Android SDK and
# NDK (GitHub's ubuntu-latest). Takes the aarch64-linux-android Rust core from
# ANDROID_COMPANION_CORE (CI: the android-rust-core artifact) or builds it,
# packages it into a debug APK, checks the APK carries it, runs the Kotlin
# unit tests (transcript/DER/key-policy/pinning rules) and the Dart contract
# test. Nothing here needs a device; on-device evidence is separate.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
evidence=${1:-"$repo/companion/build/android-evidence"}
mkdir -p "$evidence"
evidence=$(cd "$evidence" && pwd)
exec > >(tee "$evidence/android.log") 2>&1

ndk=${ANDROID_NDK_LATEST_HOME:-${ANDROID_NDK_HOME:-}}
if [ -z "$ndk" ] || [ ! -d "$ndk" ]; then
  echo 'No Android NDK (ANDROID_NDK_LATEST_HOME/ANDROID_NDK_HOME)' >&2
  exit 1
fi
host=$(ls "$ndk/toolchains/llvm/prebuilt" | head -n 1)
bin="$ndk/toolchains/llvm/prebuilt/$host/bin"
# minSdk 30 (companion/android/app/build.gradle.kts).
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$bin/aarch64-linux-android30-clang"
export CC_aarch64_linux_android="$bin/aarch64-linux-android30-clang"
export AR_aarch64_linux_android="$bin/llvm-ar"

if [ -n "${ANDROID_COMPANION_CORE:-}" ]; then
  # CI: the library the android-rust-core job built and published.
  core=$ANDROID_COMPANION_CORE
else
  cargo --version
  cargo build --locked --release -j 2 --lib --target aarch64-linux-android \
    --manifest-path "$repo/companion/rust/Cargo.toml"
  core="$repo/companion/rust/target/aarch64-linux-android/release/libcompanion_core.so"
fi
test -s "$core"
# Each listing goes to a file before grep: `cmd | grep -q` under pipefail can
# fail when grep exits early and the writer dies of SIGPIPE.
"$bin/llvm-readelf" -h "$core" >"$evidence/core-header.txt"
grep -q 'AArch64' "$evidence/core-header.txt"
# The bridge entry points Dart resolves by name must be exported.
"$bin/llvm-nm" -D --defined-only "$core" >"$evidence/core-symbols.txt"
grep -q 'frb_get_rust_content_hash' "$evidence/core-symbols.txt"
jni="$repo/companion/android/app/src/main/jniLibs/arm64-v8a"
mkdir -p "$jni"
cp "$core" "$jni/libcompanion_core.so"

cd "$repo/companion"
flutter --version
flutter pub get --enforce-lockfile
flutter analyze
flutter test test/android_channel_contract_test.dart test/approval_client_test.dart
flutter build apk --debug --target-platform android-arm64
apk=build/app/outputs/flutter-apk/app-debug.apk
unzip -l "$apk" >"$evidence/apk-contents.txt"
grep -q 'lib/arm64-v8a/libcompanion_core.so' "$evidence/apk-contents.txt"
cp "$apk" "$evidence/"

cd android
# `flutter build` generated the Gradle wrapper (it is not committed).
./gradlew --no-daemon testDebugUnitTest
mkdir -p "$evidence/unit-tests"
cp -R app/build/test-results/testDebugUnitTest/. "$evidence/unit-tests/" 2>/dev/null \
  || cp -R ../build/app/test-results/testDebugUnitTest/. "$evidence/unit-tests/"
echo "Android companion: core, APK and unit tests passed."
