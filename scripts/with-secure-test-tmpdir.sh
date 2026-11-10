#!/usr/bin/env bash
# Run tests with the private ancestry required by executable verification.
set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "usage: $0 command [arguments...]" >&2
    exit 2
fi
# Linux and Apple Silicon macOS run the native provider's private-ancestry
# checks; the default macOS TMPDIR (/var/folders, behind the /var symlink) fails
# them. Other hosts run the command unchanged.
case "$(uname -s)" in
    Linux)
        owner_of() { stat -c %u -- "$1"; }
        mode_of() { echo $(( 8#$(stat -c %a -- "$1") )); }
        ;;
    Darwin)
        owner_of() { /usr/bin/stat -f %u -- "$1"; }
        mode_of() { echo $(( 8#$(/usr/bin/stat -f %p -- "$1") & 8#7777 )); }
        ;;
    *) exec "$@" ;;
esac

secure_home="${HOME:?HOME must name a safe, provider-owned directory}"
case "$secure_home" in
    /*) ;;
    *) echo "secure test setup requires an absolute HOME" >&2; exit 2 ;;
esac
case "/${secure_home#/}/" in
    */./*|*/../*) echo "secure test setup rejects dot components in HOME" >&2; exit 2 ;;
esac
while [[ "$secure_home" != / && "$secure_home" == */ ]]; do
    secure_home="${secure_home%/}"
done
test_uid="$(id -u)"
ancestor="$secure_home"
while :; do
    if [[ -L "$ancestor" || ! -d "$ancestor" ]]; then
        echo "secure test setup requires directory ancestry without symlinks" >&2
        exit 2
    fi
    owner="$(owner_of "$ancestor")"
    mode="$(mode_of "$ancestor")"
    if (( (owner != 0 && owner != test_uid) || (mode & 8#7022) != 0 )); then
        echo "secure test setup requires root/provider-owned ancestry without unsafe modes" >&2
        exit 2
    fi
    [[ "$ancestor" != / ]] || break
    ancestor="$(dirname -- "$ancestor")"
done
if [[ "$(owner_of "$secure_home")" != "$test_uid" ]]; then
    echo "secure test setup requires provider-owned HOME" >&2
    exit 2
fi

umask 077
test_tmpdir="$(mktemp -d "$secure_home/.vaultwarden-cli-tests.XXXXXX")"
trap 'result=$?; rm -rf -- "$test_tmpdir" || true; exit "$result"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
TMPDIR="$test_tmpdir" "$@"
