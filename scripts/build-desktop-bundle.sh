#!/usr/bin/env bash
# Development-signed portable desktop installation. Never installs into this host.
# Developer ID signing and notarization happen in the package stage when
# configured (scripts/macos-release-signing.py, #62).
#   build-desktop-bundle.sh EVIDENCE-DIRECTORY [all|build|package]
# `build` compiles everything (including the packaged-command test binary);
# `package` signs, writes the manifest, notarizes and archives. The release
# workflow runs them as separate steps so signing material exists only for
# `package`.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
evidence=${1:?Usage: build-desktop-bundle.sh EVIDENCE-DIRECTORY [all|build|package]}
stage=${2:-all}
case "$stage" in all|build|package) ;; *) echo "unknown stage: $stage" >&2; exit 2 ;; esac
mkdir -p "$evidence"
evidence=$(cd "$evidence" && pwd)
case "$(uname -s)" in
 Linux*) target=linux ;;
 Darwin*) target=macos ;;
 MINGW*|MSYS*|CYGWIN*) target=windows ;;
 *) echo 'Unsupported desktop build host' >&2; exit 1 ;;
esac
if [[ "$stage" != package ]]; then
  python3 "$repo/scripts/desktop-bundle.py" before "$target" "$evidence"
  python3 "$repo/scripts/desktop-bundle.py" commands "$target" "$evidence"
  (cd "$repo/companion" && flutter pub get --enforce-lockfile)
  python3 "$repo/scripts/desktop-bundle.py" app "$target" "$evidence"
  cargo test --locked --no-run --manifest-path "$repo/companion/rust/Cargo.toml"
fi
if [[ "$stage" != build ]]; then
  python3 "$repo/scripts/desktop-bundle.py" package "$target" "$evidence"
fi
