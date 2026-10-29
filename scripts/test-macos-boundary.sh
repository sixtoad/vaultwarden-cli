#!/usr/bin/env bash
# Qualification only: never installs services or enables protected execution.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' 'qualification: unavailable; Python 3 is required to write evidence' >&2
  exit 2
fi
exec python3 "$root/tests/fixtures/macos-boundary/qualify.py" "$@"
