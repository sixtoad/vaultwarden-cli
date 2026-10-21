#!/usr/bin/env bash
# Isolated development probe. Build only: never launches the app or creates keys.
set -euo pipefail
if [[ "$(uname -s)" != Darwin ]]; then
    echo "The Touch ID probe must be built on macOS." >&2
    exit 1
fi
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
package="$root/macos-touch-id-probe"
output="${1:-$package/dist}"
mkdir -p "$output"
output="$(cd -- "$output" && pwd -P)"
bundle="$output/Touch ID Probe.app"
if [[ -e "$bundle" || -L "$bundle" ]]; then
    echo "Refusing to replace an existing probe bundle; choose a fresh output directory." >&2
    exit 1
fi
swift test --package-path "$package" -Xswiftc -warnings-as-errors
swift build --package-path "$package" -c release --product TouchIDProbe -Xswiftc -warnings-as-errors
bin_path="$(swift build --package-path "$package" -c release --show-bin-path)"
mkdir "$bundle"
mkdir -p "$bundle/Contents/MacOS"
cp "$bin_path/TouchIDProbe" "$bundle/Contents/MacOS/TouchIDProbe"
/usr/bin/plutil -create xml1 "$bundle/Contents/Info.plist"
for entry in 'CFBundleIdentifier:dev.vaultwarden.TouchIDProbe' \
    'CFBundleName:Touch ID Probe' 'CFBundleExecutable:TouchIDProbe' \
    'CFBundlePackageType:APPL' 'CFBundleShortVersionString:0.1.0' \
    'CFBundleVersion:1' 'LSMinimumSystemVersion:13.0'; do
    /usr/bin/plutil -insert "${entry%%:*}" -string "${entry#*:}" "$bundle/Contents/Info.plist"
done
/usr/bin/plutil -lint "$bundle/Contents/Info.plist"
/usr/bin/codesign --sign - "$bundle"
/usr/bin/codesign --verify --strict "$bundle"
printf 'Built (not launched): %s\n' "$bundle"
