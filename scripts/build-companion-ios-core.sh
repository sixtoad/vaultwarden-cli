#!/usr/bin/env bash
# Xcode build phase of the iOS companion (#60 phase 2): builds companion_core
# as a static library for the platform being built and leaves it at
# $BUILT_PRODUCTS_DIR/libcompanion_core.a, which the Runner force-loads (Dart
# opens it with ExternalLibrary.process). Apple Silicon/arm64 only.
#
# COMPANION_IOS_CORE=absent links an empty archive instead, for a local
# compile check on a host without the iOS Rust targets. That app cannot start
# its core; CI never sets it and always builds the real library.
set -euo pipefail
companion=$(cd "$(dirname "$0")/../companion" && pwd)
export PATH="$HOME/.cargo/bin:$PATH"
for arch in $ARCHS; do
  [ "$arch" = arm64 ] || { echo "Unsupported iOS companion architecture: $arch (arm64 only)" >&2; exit 1; }
done
case "$PLATFORM_NAME" in
  iphoneos) target=aarch64-apple-ios ;;
  iphonesimulator) target=aarch64-apple-ios-sim ;;
  *) echo "Unsupported iOS companion platform: $PLATFORM_NAME" >&2; exit 1 ;;
esac
output="$BUILT_PRODUCTS_DIR/libcompanion_core.a"
mkdir -p "$BUILT_PRODUCTS_DIR"
if [ "${COMPANION_IOS_CORE:-}" = absent ]; then
  echo "warning: COMPANION_IOS_CORE=absent: linking an EMPTY companion core; this build cannot run" >&2
  scratch=$(mktemp -d)
  trap 'rm -rf "$scratch"' EXIT
  echo 'void companion_core_absent(void) {}' > "$scratch/absent.c"
  xcrun --sdk "$PLATFORM_NAME" clang -arch arm64 -c "$scratch/absent.c" -o "$scratch/absent.o"
  rm -f "$output"
  xcrun ar rcs "$output" "$scratch/absent.o"
  exit 0
fi
if ! rustup target list --installed 2>/dev/null | grep -qx "$target"; then
  echo "error: Rust target $target is not installed (rustup target add $target), or set COMPANION_IOS_CORE=absent for a compile-only check" >&2
  exit 1
fi
cargo build --release --locked --manifest-path "$companion/rust/Cargo.toml" \
  --target-dir "$companion/rust/target" --target "$target"
cp "$companion/rust/target/$target/release/libcompanion_core.a" "$output"
