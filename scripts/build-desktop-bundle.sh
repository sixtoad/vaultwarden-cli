#!/usr/bin/env bash
# Development-signed portable desktop installation. Never installs into this host.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
evidence=${1:?Usage: build-desktop-bundle.sh EVIDENCE-DIRECTORY}
mkdir -p "$evidence"
evidence=$(cd "$evidence" && pwd)
case "$(uname -s)" in
 Linux*) target=linux ;;
 Darwin*) target=macos ;;
 MINGW*|MSYS*|CYGWIN*) target=windows ;;
 *) echo 'Unsupported desktop build host' >&2; exit 1 ;;
esac
python3 "$repo/scripts/desktop-bundle.py" before "$target" "$evidence"
python3 "$repo/scripts/desktop-bundle.py" commands "$target" "$evidence"
cd "$repo/companion"
flutter pub get --enforce-lockfile
flutter build "$target" --release --target lib/main.dart
python3 "$repo/scripts/desktop-bundle.py" package "$target" "$evidence"
