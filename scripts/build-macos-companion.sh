#!/usr/bin/env bash
# Local development bundle only. No distribution signing or notarization.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(uname -s)" != Darwin ]]; then
  echo "The companion must be built on macOS with Swift/Xcode installed." >&2
  exit 1
fi
output="${1:-${root}/macos/dist}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
swift build --package-path "$root/macos" -c release
bin_path="$(swift build --package-path "$root/macos" -c release --show-bin-path)"
bundle="${output}/Approval Companion.app"
mkdir -p "$bundle/Contents/MacOS"
cp "$bin_path/ApprovalCompanion" "$bundle/Contents/MacOS/ApprovalCompanion"
cat > "$bundle/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.vaultwarden.ApprovalCompanion</string>
<key>CFBundleName</key><string>Approval Companion</string>
<key>CFBundleExecutable</key><string>ApprovalCompanion</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>LSUIElement</key><true/>
<key>NSHighResolutionCapable</key><true/>
<key>NSLocalNetworkUsageDescription</key><string>Connect securely to your chosen Linux approval provider on your local network.</string>
<key>NSAppTransportSecurity</key><dict>
<key>NSAllowsArbitraryLoads</key><true/>
</dict>
</dict></plist>
PLIST
plutil -lint "$bundle/Contents/Info.plist"
codesign --force --sign - "$bundle"
codesign --verify --strict "$bundle"
printf 'Development bundle: %s\n' "$bundle"
