#!/usr/bin/env bash
# Local Apple Silicon development download; no distribution signing/notarization.
set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "Usage: $0 [output-directory]" >&2
  exit 1
fi
if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
  echo "Usage: $0 [output-directory] (default: macos/dist)"
  exit 0
fi
if [[ "$(uname -s)" != Darwin ]]; then
  echo "Package on an Apple Silicon Mac with Swift/Xcode installed." >&2
  exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="${1:-${root}/macos/dist}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
# Keep staging private and on the destination filesystem for no-clobber links.
umask 077
work="$(mktemp -d "$output/.companion-package.XXXXXX")"
name=''
cleanup() {
  local status=$?
  local suffix
  if [[ $status -ne 0 && -n "$name" ]]; then
    for suffix in '' .sha256; do
      # Roll back only our published hard links, never another output or symlink.
      if [[ ! -L "$output/$name$suffix" &&
            "$output/$name$suffix" -ef "$work/$name$suffix" ]]; then
        rm -f "$output/$name$suffix"
      fi
    done
  fi
  rm -rf "$work"
  return "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# Fail before building if the output filesystem cannot publish hard links.
touch "$work/link-test-source"
if ! ln "$work/link-test-source" "$work/link-test-destination"; then
  echo "Choose an output directory on a filesystem supporting hard links (APFS or HFS+)." >&2
  echo "You can copy the completed DMG and checksum elsewhere afterward." >&2
  exit 1
fi
rm "$work/link-test-source" "$work/link-test-destination"

(umask 022; "$root/scripts/build-macos-companion.sh" "$work/build")
app="$work/build/Approval Companion.app"
plist="$app/Contents/Info.plist"
version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$plist")"
build="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$plist")"
for component in "$version" "$build"; do
  if [[ -z "$component" || "$component" == *[!0-9A-Za-z._-]* ]]; then
    echo "Unsafe or empty version/build value in the built app." >&2
    exit 1
  fi
done
architecture="$(lipo -archs "$app/Contents/MacOS/ApprovalCompanion")"
if [[ "$architecture" != arm64 ]]; then
  echo "Expected an arm64 app; the built payload is: $architecture" >&2
  exit 1
fi
codesign --verify --deep --strict "$app"

name="Approval-Companion-${version}-${build}-${architecture}.dmg"
for candidate in "$output/$name" "$output/$name.sha256"; do
  if [[ -e "$candidate" || -L "$candidate" ]]; then
    printf 'Refusing to overwrite existing output: %s\n' "$candidate" >&2
    exit 1
  fi
done

payload="$work/payload"
mkdir "$payload"
ditto "$app" "$payload/Approval Companion.app"
ln -s /Applications "$payload/Applications"
cat > "$payload/README.txt" <<'README'
Approval Companion — local development build
Requires an Apple Silicon Mac running macOS 13 or newer.

INSTALL
Drag Approval Companion.app to the Applications shortcut. Eject this disk image,
then open the installed app from Applications. The app uses a menu-bar icon.
Enable Start at login only after opening the installed copy.

UPGRADE
Quit Approval Companion before replacing it. If your current copy is in your
home folder's Applications folder (~/Applications), replace it there to retain
the same install location; the shortcut on this disk points to /Applications.
If moving the app, turn off Start at login in the old copy first, then turn it
back on from the new installed copy. Avoid keeping two installed copies.
Keep your saved settings and Keychain identity; do not erase them to upgrade.
macOS may ask again for Keychain access after replacing this development build.
If login startup stops working, turn Start at login off and back on in the
installed copy and check System Settings > General > Login Items.

FIRST OPEN
This app is signed for local development, with no verified publisher identity
or Apple notarization. If macOS blocks it and you trust its source, try opening
it once, then use System Settings > Privacy & Security > Open Anyway if offered.
Do not disable Gatekeeper or remove quarantine attributes. If macOS reports a
damaged or modified app, obtain a fresh verified copy instead of forcing it open.

CONNECTION SETUP
This download contains no connection settings, passwords or client credentials.
An existing Linux approval provider and separately provisioned client identity
are required. New installations must follow the companion setup instructions:
https://github.com/sixtoad/vaultwarden-cli/blob/main/docs/companion-setup.md
Installing this app does not configure Linux.
README
# Staging stays private; the disk's contents must be readable by its installer.
chmod 755 "$payload"
chmod 644 "$payload/README.txt"
codesign --verify --deep --strict "$payload/Approval Companion.app"
hdiutil create -quiet -volname "Approval Companion" -fs HFS+ -format UDZO \
  -srcfolder "$payload" "$work/$name"
hdiutil verify "$work/$name"
(cd "$work"; shasum -a 256 "$name" > "$name.sha256")
chmod 644 "$work/$name" "$work/$name.sha256"

# A directory destination makes ln fail if either basename already exists,
# including dangling symlinks. Never replace a competing output or follow it.
ln -h "$work/$name" "$output/"
ln -h "$work/$name.sha256" "$output/"
printf 'Development disk image: %s\nSHA256 file: %s\n' \
  "$output/$name" "$output/$name.sha256"
