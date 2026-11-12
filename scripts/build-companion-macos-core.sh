#!/usr/bin/env bash
set -euo pipefail
companion=$(cd "$(dirname "$0")/../companion" && pwd)
export PATH="$HOME/.cargo/bin:$PATH"
libraries=()
for arch in $ARCHS; do
  case "$arch" in
    arm64) target=aarch64-apple-darwin ;;
    # Owner decision 2026-11-10: the macOS app is Apple Silicon only.
    x86_64) echo 'Intel (x86_64) macOS is no longer supported or built; build on Apple Silicon (ARCHS = arm64)' >&2; exit 1 ;;
    *) echo 'Unsupported companion architecture' >&2; exit 1 ;;
  esac
  cargo build --release --locked --manifest-path "$companion/rust/Cargo.toml" --target-dir "$companion/rust/target" --target "$target"
  libraries+=("$companion/rust/target/$target/release/libcompanion_core.dylib")
done
destination="$TARGET_BUILD_DIR/$FRAMEWORKS_FOLDER_PATH"
mkdir -p "$destination"
lipo -create "${libraries[@]}" -output "$destination/libcompanion_core.dylib"
codesign --force --sign "${EXPANDED_CODE_SIGN_IDENTITY:--}" "$destination/libcompanion_core.dylib"
