#!/usr/bin/env bash
# Generated (cargo-mutants) campaign for one macOS native adapter file (#49).
#
# usage: mutate-native-generated.sh FILE OUTPUT_DIR [TEST FILTER...]
#   FILE        e.g. src/adapters/native/reaper.rs
#   OUTPUT_DIR  absolute, outside the repository (receives mutants.out/)
#   TEST FILTER libtest name filters; default: every native-adapter consumer
#   MUTANT_RE   optional cargo-mutants --re selection (e.g. to retest survivors)
#
# cargo-mutants copies this tree below a private $HOME scratch directory (umask
# 077), so tests that check working-directory ancestry pass. Only the library test
# target is built, without debug info, and tests run serially in one process: the
# native reaper and stopped-provider checks are process-global. Run one campaign
# at a time. Source mtimes are refreshed first because cargo keys the crate by
# package, not directory: a target directory shared with an earlier campaign could
# otherwise satisfy the baseline with that campaign's last mutant build.
set -euo pipefail
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo 'requires Apple Silicon macOS' >&2; exit 2; }
file="${1:?usage: mutate-native-generated.sh FILE OUTPUT_DIR [TEST FILTER...]}"
output="${2:?usage: mutate-native-generated.sh FILE OUTPUT_DIR [TEST FILTER...]}"
shift 2
repository="$(cd "$(dirname "$0")/.." && pwd -P)"
case "$output" in /*) ;; *) echo 'OUTPUT_DIR must be absolute' >&2; exit 2;; esac
case "$output/" in "$repository/"*) echo 'OUTPUT_DIR must be outside the repository' >&2; exit 2;; esac
if [[ $# -eq 0 ]]; then
    set -- adapters::native:: adapters::ssh_agent:: adapters::human_socket:: adapters::unix_socket::native_tests
fi
umask 077
scratch="$(mktemp -d "$HOME/.vw-native-mutants.XXXXXX")"
# A failed test may leave an ACL ("deny delete") on a fixture file; clear it first.
trap 'chmod -R -N "$scratch" 2>/dev/null || true; rm -rf -- "$scratch"' EXIT
mkdir -p "$output"
cd "$repository"
find src -type f -exec touch {} +
# The same-PID exec SSH test re-signs and execs a fresh binary; where new
# executables are assessed before launch it can exceed the mutant timeout even
# unmutated, so generated campaigns skip it. It still runs in the library gate.
cargo fetch --locked
TMPDIR="$scratch" CARGO_NET_OFFLINE=true CARGO_PROFILE_DEV_DEBUG=0 CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" \
    cargo mutants --no-config -C --locked -C --lib -f "$file" \
    --timeout "${MUTANT_TIMEOUT:-300}" --build-timeout "${MUTANT_BUILD_TIMEOUT:-900}" \
    --output "$output" ${MUTANT_RE:+--re "$MUTANT_RE"} \
    -- -- --test-threads=1 --skip native_same_pid_exec_keeps_socket "$@"
