#!/usr/bin/env bash
# Disposable source qualification only. Never installs accounts, services or Keychain items.
set -euo pipefail
umask 077
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo 'requires native Apple Silicon macOS' >&2; exit 2; }
[[ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" != 1 ]] || { echo 'Rosetta is unsupported' >&2; exit 2; }
VW_NATIVE_REPOSITORY="$(cd "$(dirname "$0")/.." && pwd -P)"
VW_NATIVE_EVIDENCE="${1:?usage: test-native-protected-macos.sh EVIDENCE_DIRECTORY}"
mkdir -p "$VW_NATIVE_EVIDENCE"
VW_NATIVE_EVIDENCE="$(cd "$VW_NATIVE_EVIDENCE" && pwd -P)"
case "$VW_NATIVE_EVIDENCE/" in "$VW_NATIVE_REPOSITORY/"*) echo 'evidence directory must be outside source repository' >&2; exit 2;; esac
VW_NATIVE_SCRATCH="$(mktemp -d "$HOME/.vw-native.XXXXXX")"
trap 'rm -rf -- "$VW_NATIVE_SCRATCH"' EXIT
mkdir "$VW_NATIVE_SCRATCH/source" "$VW_NATIVE_SCRATCH/tmp"
export TMPDIR="$VW_NATIVE_SCRATCH/tmp"
export CARGO_TARGET_DIR="$VW_NATIVE_SCRATCH/target"
export CARGO_HOME="${VW_NATIVE_CARGO_HOME:-$VW_NATIVE_SCRATCH/cargo}"
# Include this exact working tree, including untracked implementation files.
(cd "$VW_NATIVE_REPOSITORY" && git ls-files --cached --others --exclude-standard -z | tar --null -T - -cf "$VW_NATIVE_EVIDENCE/source.tar")
tar -xf "$VW_NATIVE_EVIDENCE/source.tar" -C "$VW_NATIVE_SCRATCH/source"
(cd "$VW_NATIVE_REPOSITORY" && git rev-parse HEAD && git status --short) > "$VW_NATIVE_EVIDENCE/revision.txt"
(cd "$VW_NATIVE_REPOSITORY" && git diff --binary HEAD) > "$VW_NATIVE_EVIDENCE/working-tree.patch"
shasum -a 256 "$VW_NATIVE_EVIDENCE/source.tar" > "$VW_NATIVE_EVIDENCE/source.sha256"
(sw_vers; uname -a; id; cargo --version; rustc --version; xcodebuild -version) > "$VW_NATIVE_EVIDENCE/environment.txt"
(codesign -dvvv --entitlements :- /usr/bin/ssh; shasum -a 256 /usr/bin/ssh; otool -L /usr/bin/ssh) > "$VW_NATIVE_EVIDENCE/system-ssh.txt" 2>&1
cd "$VW_NATIVE_SCRATCH/source"
cargo fetch --locked 2>&1 | tee "$VW_NATIVE_EVIDENCE/fetch.log"
cargo fmt --all -- --check 2>&1 | tee "$VW_NATIVE_EVIDENCE/fmt.log"
cargo clippy --offline --locked --all-targets -- -D warnings 2>&1 | tee "$VW_NATIVE_EVIDENCE/clippy.log"
cargo test --offline --locked --lib -- --test-threads=1 2>&1 | tee "$VW_NATIVE_EVIDENCE/library-tests.log"
# Explicit safe targets only: other CLI suites assume Linux private-bus isolation.
cargo test --offline --locked --bin vaultwarden-accessd --bin vw-access --test native_protected_cli -- --test-threads=1 2>&1 | tee "$VW_NATIVE_EVIDENCE/protected-cli-tests.log"
cargo test --offline --locked --lib -- --ignored --exact adapters::ssh_agent::openssh_tests::real_openssh_authenticates_with_memory_only_client_key_and_survives_agent_close --nocapture 2>&1 | tee "$VW_NATIVE_EVIDENCE/openssh.log"
# A missing ignored test is not successful qualification.
grep -q '1 passed; 0 failed' "$VW_NATIVE_EVIDENCE/openssh.log"
printf '%s\n' 'Source qualification finished. Installed distinct-UID endpoints, service Keychain, launchd stop/upgrade/reboot and release signing remain UNQUALIFIED.' > "$VW_NATIVE_EVIDENCE/scope.txt"
