#!/usr/bin/env bash
set -euo pipefail

BENCH_NAME="vaultwarden_cli_bench"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
DHAT_DIR="$TARGET_DIR/dhat"
DHAT_OUT="$DHAT_DIR/${BENCH_NAME}.dhat"

if ! command -v valgrind >/dev/null 2>&1; then
  echo "DHAT allocation profile skipped: valgrind is not installed or not on PATH." >&2
  echo "Install Valgrind with DHAT support, then rerun: just benchmark" >&2
  exit 1
fi

if ! valgrind --tool=dhat --help >/dev/null 2>&1; then
  echo "DHAT allocation profile skipped: this valgrind build does not support --tool=dhat." >&2
  echo "Install a Valgrind build with DHAT support, then rerun: just benchmark" >&2
  exit 1
fi

mkdir -p "$DHAT_DIR"

# Ask Cargo where the benchmark binary is. Cargo >= 1.100 builds each unit in its
# own build-dir directory (target/release/build/<pkg>/<hash>/out) and no longer
# fills target/release/deps, so the path is never assumed.
bench_bin="$(
  cargo bench --bench "$BENCH_NAME" --no-run --message-format=json |
  python3 -c 'import json,sys; print(next((x["executable"] for x in [json.loads(line) for line in sys.stdin] if x.get("reason")=="compiler-artifact" and x["target"]["name"]==sys.argv[1] and x["target"]["kind"]==["bench"] and x.get("executable")),""))' "$BENCH_NAME"
)"

if [[ -z "$bench_bin" || ! -x "$bench_bin" ]]; then
  echo "DHAT allocation profile failed: Cargo reported no benchmark binary for ${BENCH_NAME}." >&2
  exit 1
fi

rm -f "$DHAT_OUT"

echo "DHAT benchmark binary: $bench_bin"
echo "DHAT output path: $DHAT_OUT"

valgrind \
  --tool=dhat \
  --dhat-out-file="$DHAT_OUT" \
  "$bench_bin" --bench --profile-time 1

test -s "$DHAT_OUT"
echo "DHAT output written: $DHAT_OUT"
