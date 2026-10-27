#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
evidence=${1:-"$repo/companion/build/provider-native"}
mkdir -p "$evidence"
fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/flutter-provider-native.XXXXXX")
stage="$fixture_root/package"
# Preserve the staged package in evidence for diagnosis; the test fixture itself
# creates/removes its own temporary Keychain and restores the search list.
mkdir -p "$stage/Sources/CompanionCore" "$stage/Tests/CompanionCoreTests" "$stage/Tests/Fixtures"
cp "$repo/companion/provider_native_tests/Package.swift" "$stage/Package.swift"
cp "$repo/macos/Sources/CompanionCore/Protocol.swift" "$repo/macos/Sources/CompanionCore/Trust.swift" "$repo/macos/Sources/CompanionCore/DecisionController.swift" "$stage/Sources/CompanionCore/"
cp "$repo/companion/macos/Runner/ProviderSettings.swift" "$stage/Sources/CompanionCore/"
cp "$repo/macos/Tests/CompanionCoreTests/TLSTests.swift" "$repo/macos/Tests/CompanionCoreTests/ProtocolTests.swift" "$repo/companion/provider_native_tests/ProviderSettingsTests.swift" "$stage/Tests/CompanionCoreTests/"
cp "$repo/macos/Tests/Fixtures/tls_fixture.py" "$stage/Tests/Fixtures/"
# TLSTests resolves the canonical review relative to the package root.
mkdir -p "$fixture_root/tests/fixtures/companion"
cp "$repo/tests/fixtures/companion/review.json" "$fixture_root/tests/fixtures/companion/review.json"
swift test --package-path "$stage" 2>&1 | tee "$evidence/native.log"
# Inspect the actual normal object: the optional parser/import must not exist.
nm "$stage/.build/debug/CompanionCore.build/ProviderSettings.swift.o" > "$evidence/normal-settings-symbols.txt"
if grep -E 'installPilot|DisposablePilotBundle' "$evidence/normal-settings-symbols.txt"; then
  echo 'Disposable pilot entry leaked into normal native build' >&2
  exit 1
fi
swift test --package-path "$stage" -Xswiftc -DCOMPANION_DISPOSABLE_PILOT 2>&1 | tee "$evidence/pilot-native.log"
nm "$stage/.build/debug/CompanionCore.build/ProviderSettings.swift.o" > "$evidence/pilot-settings-symbols.txt"
grep -q 'installPilot' "$evidence/pilot-settings-symbols.txt"
python3 "$repo/scripts/mutate-provider-trust.py" "$stage" "$evidence/trust-mutations"
