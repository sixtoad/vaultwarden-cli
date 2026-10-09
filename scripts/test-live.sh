#!/usr/bin/env bash
# Run live integration tests against a real Vaultwarden instance.
#
# Usage:
#   ./scripts/test-live.sh [test binary args...]
#
# Any extra arguments are passed directly to the test binary as test-harness
# args. This script inserts the `cargo test ... --` separator internally, so
# pass filters/flags directly here (for example: --ignored).
#
# Example:
#   ./scripts/test-live.sh                # run all live tests
#   ./scripts/test-live.sh session::login # run one test by filter
#   ./scripts/test-live.sh --ignored      # run ignored live tests
#
# The script starts Vaultwarden via Docker Compose, waits for it to be ready,
# runs the live_tests binary, and tears everything down on exit.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
if [[ "$(uname -s)" != Linux ]]; then
    echo "Live isolation requires Linux; refusing provisioning." >&2
    exit 2
fi
if [[ "${1:-}" != --isolated-run ]]; then
    # Reject a selected remote/rootless/nondefault engine before clearing its
    # settings. This runner intentionally supports only the local default socket.
    if [[ "${DOCKER_HOST:-unix:///var/run/docker.sock}" != unix:///var/run/docker.sock ]] ||
       [[ "${DOCKER_CONTEXT:-default}" != default ]] ||
       [[ "$(docker context show)" != default ]]; then
        echo "Live tests require Docker's local default context at unix:///var/run/docker.sock; nondefault engines/contexts are unsupported." >&2
        exit 2
    fi
    # Clear the parent environment before Cargo or any CLI subprocess starts.
    # The wrapper checks every ancestor and removes its exact private root.
    exec env -i HOME="$HOME" PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
        CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
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
export DOCKER_HOST=unix:///var/run/docker.sock DOCKER_CONFIG="$run_root/docker"
if [[ ! -S /var/run/docker.sock ]] || ! timeout 10s docker info >/dev/null 2>&1; then
    echo "Live tests require an accessible local Docker engine at /var/run/docker.sock." >&2
    exit 2
fi
project="vw-live-$(basename "$run_root" | tr '[:upper:].' '[:lower:]-')"
compose_file="$REPO_ROOT/docker-compose.live-test.yml"
if docker compose version >/dev/null 2>&1; then
    compose=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    compose=(docker-compose)
else
    echo "A system-installed Docker Compose plugin or standalone docker-compose on PATH is required; user-local plugins/configuration are not inherited." >&2
    exit 2
fi
compose+=(--project-name "$project" --file "$compose_file")
cleanup() {
    result=$?
    trap - EXIT
    echo "→ Cleaning owned Compose project $project"
    if ! "${compose[@]}" down --volumes --remove-orphans --timeout 10; then
        echo "ERROR: cleanup failed for $project" >&2
        [[ "$result" != 0 ]] || result=1
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cd "$REPO_ROOT"
echo "→ Checking CLI isolation before provisioning"
cargo test --locked --test live_tests isolation:: -- --test-threads=1
echo "→ Starting owned Compose project $project"
"${compose[@]}" up -d
endpoint="$("${compose[@]}" port vaultwarden 80)"
[[ "$endpoint" == 127.0.0.1:* ]] || { echo "Non-loopback endpoint rejected: $endpoint" >&2; exit 1; }
service_url="http://$endpoint"
for ((i=1; i<=60; i++)); do
    if curl --noproxy '*' --connect-timeout 2 --max-time 5 -sf "$service_url/alive" >/dev/null; then
        break
    fi
    if [[ "$i" == 60 ]]; then
        echo "ERROR: Vaultwarden readiness timeout" >&2
        "${compose[@]}" logs --tail 40
        exit 1
    fi
    sleep 1
done
export VAULTWARDEN_LIVE_TEST_URL="$service_url"
export VAULTWARDEN_LIVE_ADMIN_TOKEN="live-test-admin-token"
echo "→ Running configured live tests against $service_url (Vaultwarden 1.36.0)"
cargo test --locked --test live_tests -- --test-threads=1 --nocapture "$@"
