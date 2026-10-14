#!/usr/bin/env bash
# No passwords, tokens, UI capabilities, or private keys are shell arguments.
set -euo pipefail
umask 077
for dependency in /usr/bin/dirname /usr/bin/uname; do
    [[ -f "$dependency" && -x "$dependency" ]] || { echo "FAIL: missing prerequisite $dependency"; exit 2; }
done
repo="$(cd -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
mode="${1:---check}"
case "$mode" in --check|--automated|--human|--human-check|--interrupt|--cleanup-failure|--collision-check) ;; *) echo 'usage: rehearse-protected-workflow.sh [--check|--automated|--human|--human-check|--interrupt|--cleanup-failure|--collision-check]' >&2; exit 2;; esac
[[ $# -le 1 ]] || exit 2
[[ "$(/usr/bin/uname -s)" == Linux ]] || { echo 'FAIL: Linux required'; exit 2; }
case "$(/usr/bin/uname -m)" in x86_64|aarch64) ;; *) echo 'FAIL: unsupported architecture'; exit 2;; esac
for tool in cargo node; do
    command -v "$tool" >/dev/null || { echo "FAIL: missing prerequisite $tool"; exit 2; }
done
# These paths are dependencies, never command snippets. Nothing is installed.
export VW_REHEARSAL_XVFB="${VW_REHEARSAL_XVFB:-/usr/bin/Xvfb}"
export VW_REHEARSAL_CERTUTIL="${VW_REHEARSAL_CERTUTIL:-/usr/bin/certutil}"
export VW_REHEARSAL_FIREFOX="${VW_REHEARSAL_FIREFOX:-/usr/bin/firefox}"
export VW_REHEARSAL_NODE="$(command -v node)"
export VW_REHEARSAL_UI_DEPS="${VW_REHEARSAL_UI_DEPS:-$repo/tests/ui/node_modules}"
export VW_REHEARSAL_MODE="$mode"
desktop_dependencies=("$VW_REHEARSAL_CERTUTIL" "$VW_REHEARSAL_FIREFOX")
if [[ "$mode" != --human && "$mode" != --human-check ]]; then desktop_dependencies+=("$VW_REHEARSAL_XVFB"); fi
for dependency in "${desktop_dependencies[@]}"; do
    [[ "$dependency" == /* && -x "$dependency" ]] || { echo 'FAIL: private desktop dependency unavailable'; exit 2; }
done
# Check the paths actually invoked by the harness/browser, including the
# external test binary (command -v test would accept Bash's builtin).
for dependency in /bin/bash /bin/sh /bin/rm /usr/bin/{cc,openssl,docker,systemctl,systemd-run,unshare,newuidmap,newgidmap,dbus-daemon,gnome-keyring-daemon,secret-tool,gdbus,setpriv,xdg-open,journalctl,xauth,timeout,id,cat,env,true,sleep,chown,dd,test}; do
    [[ -f "$dependency" && -x "$dependency" ]] || { echo "FAIL: missing prerequisite $dependency"; exit 2; }
done
[[ -r "$VW_REHEARSAL_UI_DEPS/puppeteer-core/package.json" ]] || { echo 'FAIL: private browser automation dependency unavailable'; exit 2; }
[[ "${DOCKER_HOST:-unix:///var/run/docker.sock}" == unix:///var/run/docker.sock && "${DOCKER_CONTEXT:-default}" == default ]] || { echo 'FAIL: only local default Docker is supported'; exit 2; }
[[ "$(timeout 5s docker context show)" == default ]] || exit 2
[[ "$(timeout 5s systemctl --user show vaultwarden-accessd.service --property=LoadState --value)" == not-found ]] || { echo 'FAIL: occupied or unavailable provider unit'; exit 2; }
timeout 5s docker info >/dev/null 2>&1 || { echo 'FAIL: local Docker unavailable'; exit 2; }
cd "$repo"
cargo build --locked --bins
# The test owns its private directory. Unlike the generic secure-temp wrapper,
# it deliberately retains it if cleanup cannot prove all children have exited.
# Test preflight validates safe HOME ancestry before creating this directory.
exec cargo test --locked --test protected_rehearsal production_chain -- --ignored --exact --nocapture --test-threads=1
