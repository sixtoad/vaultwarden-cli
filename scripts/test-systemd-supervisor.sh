#!/usr/bin/env bash
set -euo pipefail
if [[ "$(uname -m)" != x86_64 ]]; then
    echo "unsupported test architecture: this synthetic syscall fixture requires x86_64; run on x86_64. AArch64 runtime support remains unverified." >&2
    exit 2
fi
# Run through with-secure-test-tmpdir.sh; helper and fixture require safe ancestry.
: "${TMPDIR:?run with scripts/with-secure-test-tmpdir.sh}"
VW18_RUN_DIR="$(mktemp -d "$TMPDIR/vw18-run.XXXXXX")"
trap 'rm -rf -- "$VW18_RUN_DIR"' EXIT
cargo build --offline --locked --lib --bin vaultwarden-access-exec --message-format=json > "$VW18_RUN_DIR/artifacts.json"
cargo test --offline --locked --lib --no-run --message-format=json > "$VW18_RUN_DIR/build.json"
VW18_TEST_BINARY="$(python3 -c 'import json,sys; print(next(x["executable"] for x in map(json.loads,open(sys.argv[1])) if x.get("profile",{}).get("test") and x.get("executable") and x["target"]["kind"]==["lib"]))' "$VW18_RUN_DIR/build.json")"
export VW18_TEST_BINARY
VW18_HELPER="$(python3 -c 'import json,sys; print(next(x["executable"] for x in map(json.loads,open(sys.argv[1])) if x.get("reason")=="compiler-artifact" and x["target"]["name"]=="vaultwarden-access-exec" and x.get("executable")))' "$VW18_RUN_DIR/artifacts.json")"
VW18_LIBRARY="$(python3 -c 'import json,sys; print(next(p for x in map(json.loads,open(sys.argv[1])) if x.get("reason")=="compiler-artifact" and x["target"]["name"]=="vaultwarden_cli" and x["target"]["kind"]==["lib"] for p in x["filenames"] if p.endswith(".rlib")))' "$VW18_RUN_DIR/artifacts.json")"
VW18_DEPS="$(dirname "$VW18_HELPER")/deps"
export VW18_HELPER
VW18_ENV_HELPER="$VW18_RUN_DIR/helper-environment"
export VW18_ENV_HELPER
rustc --edition=2024 tests/fixtures/helper-environment.rs -L "dependency=$VW18_DEPS" --extern "vaultwarden_cli=$VW18_LIBRARY" -o "$VW18_ENV_HELPER"
chmod 500 "$VW18_ENV_HELPER"
VW18_IMAGE="$VW18_RUN_DIR/protected-tree"
export VW18_IMAGE
cc -nostdlib -static -no-pie -fno-stack-protector -fno-builtin -O2 -Wl,--build-id=none -o "$VW18_IMAGE" tests/fixtures/protected-tree.c
chmod 500 "$VW18_IMAGE"
VW18_FILTER=()
if [[ -n "${VW18_SCENARIO:-}" ]]; then
    VW18_FILTER=(independent_descendants_provider_crash_and_recovery)
fi
timeout --signal=TERM --kill-after=15s 900s cargo test --offline --locked --test systemd_supervisor -- "${VW18_FILTER[@]}" --ignored --nocapture
