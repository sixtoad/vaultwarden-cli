#!/usr/bin/env bash
# Run on the Mac. Captures separate evidence without claiming GUI acceptance.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(uname -s)" != Darwin ]]; then
  echo "Native tests require macOS, Security.framework, Keychain, and Swift." >&2
  exit 1
fi
report="${1:-${root}/macos/acceptance/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$report"
report="$(cd "$report" && pwd)"
{
  sw_vers
  swift --version
  python3 --version
  openssl version
  if [[ -e "$root/.git" ]]; then
    git -C "$root" rev-parse HEAD
    git -C "$root" status --short
  elif [[ -f "$root/source-manifest.json" ]]; then
    shasum -a 256 "$root/source-manifest.json"
    cat "$root/source-manifest.json"
  else
    printf '%s\n' 'Source snapshot without Git metadata or source-manifest.json.'
  fi
} > "$report/environment.txt"
swift test --package-path "$root/macos" --filter ProtocolTests 2>&1 | tee "$report/protocol-tests.log"
swift test --package-path "$root/macos" --filter AppModelTests 2>&1 | tee "$report/app-model-tests.log"
swift test --package-path "$root/macos" --filter TLSTests 2>&1 | tee "$report/real-urlsession-tls.log"
python3 "$root/macos/Tests/Fixtures/bundle_tls.py" --report "$report/bundle-tls" 2>&1 | tee "$report/bundle-tls.log"
"$root/scripts/build-macos-companion.sh" "$report/bundle" 2>&1 | tee "$report/bundle.log"
printf '%s\n' 'Native checks passed. Logged-in Mac/Linux acceptance is still required; follow docs/companion-setup.md.' | tee "$report/result.txt"
printf 'Evidence: %s\n' "$report"
