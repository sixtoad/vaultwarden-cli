#!/usr/bin/env bash
# Run the live tests against an already running, disposable Vaultwarden (the
# CI service container). Same environment isolation as scripts/test-live.sh,
# without Docker Compose. Usage:
#   VAULTWARDEN_LIVE_TEST_URL=http://127.0.0.1:PORT \
#   VAULTWARDEN_LIVE_ADMIN_TOKEN=THROWAWAY ./scripts/ci-live-vaultwarden.sh
# Refuses to run without both values: a missing server must fail, never skip.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
if [[ "$(uname -s)" != Linux ]]; then
    echo "Live isolation requires Linux." >&2
    exit 2
fi
url="${VAULTWARDEN_LIVE_TEST_URL:?VAULTWARDEN_LIVE_TEST_URL is required}"
token="${VAULTWARDEN_LIVE_ADMIN_TOKEN:?VAULTWARDEN_LIVE_ADMIN_TOKEN is required}"
[[ "$url" == http://127.0.0.1:* ]] || { echo "Non-loopback live URL rejected: $url" >&2; exit 2; }
if [[ "${1:-}" != --isolated-run ]]; then
    # Clear the parent environment before Cargo or any CLI subprocess starts.
    exec env -i HOME="$HOME" PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
        CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
        CI=true VAULTWARDEN_LIVE_TEST_URL="$url" VAULTWARDEN_LIVE_ADMIN_TOKEN="$token" \
        "$REPO_ROOT/scripts/with-secure-test-tmpdir.sh" "$0" --isolated-run "$@"
fi
shift
umask 077
run_root="$(mktemp -d "${TMPDIR:?private wrapper required}/live.XXXXXX")"
export HOME="$run_root/home"
mkdir -m 700 "$HOME"
export XDG_CONFIG_HOME="$HOME/config" XDG_RUNTIME_DIR="$HOME/runtime"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$HOME/unavailable-bus"
export DBUS_SYSTEM_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS"
cd "$REPO_ROOT"
for ((i=1; i<=60; i++)); do
    if curl --noproxy '*' --connect-timeout 2 --max-time 5 -sf "$url/alive" >/dev/null; then
        break
    fi
    [[ "$i" != 60 ]] || { echo "ERROR: Vaultwarden readiness timeout" >&2; exit 1; }
    sleep 1
done
echo "→ Checking CLI isolation"
cargo test --locked --offline --test live_tests isolation:: -- --test-threads=1
echo "→ Running live tests against $url (Vaultwarden 1.36.0)"
cargo test --locked --offline --test live_tests -- --test-threads=1 --nocapture "$@"
