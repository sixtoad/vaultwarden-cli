#!/usr/bin/env bash
# Operator checklist for the iOS approval client on a PHYSICAL iPhone
# (#60 phase 2, ties to #41). It records what the operator observes; it
# builds, signs, installs, enrolls and approves NOTHING itself, never touches
# Face ID / Touch ID enrollment, the Keychain or the provider, and refuses to
# run in CI or without a terminal. See docs/ios-approval-client.md.
#
# Usage: scripts/ios-approval-hardware-evidence.sh <evidence-dir> [path/to/Runner.app]
set -euo pipefail
if [ -n "${CI:-}${GITHUB_ACTIONS:-}" ]; then
  echo "refusing: hardware evidence is recorded by an operator on a physical iPhone, never in CI" >&2; exit 2
fi
[ -t 0 ] && [ -t 1 ] || { echo "refusing: run interactively in a terminal" >&2; exit 2; }
[ $# -ge 1 ] || { echo "usage: $0 <evidence-dir> [Runner.app]" >&2; exit 2; }
evidence=$1
app=${2:-}
mkdir -p "$evidence"
out="$evidence/ios-hardware-evidence-$(date -u +%Y%m%dT%H%M%SZ).txt"
repo=$(cd "$(dirname "$0")/.." && pwd)

record() { printf '%s\n' "$*" | tee -a "$out"; }
ask() { # ask <prompt> -> REPLY
  local reply
  read -r -p "$1 " reply
  REPLY=$reply
}

record "# iOS approval client hardware evidence (#60 phase 2, #41)"
record "recorded_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
record "source_revision: $(git -C "$repo" rev-parse HEAD)"
record "source_dirty: $([ -z "$(git -C "$repo" status --porcelain)" ] && echo no || echo yes)"
if [ -n "$app" ]; then
  [ -d "$app" ] || { echo "not an app bundle: $app" >&2; exit 2; }
  binary="$app/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Info.plist")"
  record "app_bundle_id: $(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Info.plist")"
  record "app_executable_sha256: $(shasum -a 256 "$binary" | cut -d' ' -f1)"
else
  record "app_executable_sha256: not recorded (no Runner.app given)"
fi
ask "iPhone model (Settings > General > About):"; record "device_model: $REPLY"
ask "iOS version:"; record "ios_version: $REPLY"
ask "Biometry (faceID/touchID):"; record "biometry: $REPLY"
ask "Provider host and revision used (no secrets):"; record "provider: $REPLY"
record ""

steps=(
  "enroll|Enroll this iPhone as an approval client from Devices & agents. Expect one Face ID or Touch ID prompt naming enrollment, then the provider lists the client. Record the approval key fingerprint shown."
  "approve|Create one request on the desktop, open it on the iPhone, Approve..., authenticate once. Expect exactly that request approved; the provider verifies one proof."
  "approve_again|Approve a second request. Expect a NEW prompt (no reuse window) and one more verified proof."
  "cancel|Open a request, Approve..., then Cancel the system prompt. Expect: nothing approved, no password submitted, the request still pending."
  "passcode|At the prompt, fail biometry until the system offers a passcode. Expect: no device-passcode fallback is offered by the app prompt; nothing approved."
  "background|Start Approve..., then swipe home while the prompt is open. Expect: prompt cancelled, review retired, nothing approved; reopening loads a fresh review."
  "lock|Start Approve..., then press the side button to lock. Expect: prompt cancelled, review retired, nothing approved."
  "notification|With notifications on and the app in the background, create a request. Expect generic copy only (no request content), no action buttons; tapping opens a fresh review of that request and approves nothing."
  "relaunch|Force-quit and relaunch. Expect the SAME approval key fingerprint as at enroll; approving still works."
  "enrollment_change|ONLY with explicit owner authorization: add or reset Face ID (or a Touch ID finger). Expect the app to report the key invalidated, approval refused, nothing signed."
  "re_enroll|Delete the invalidated key from the app and enroll again. Expect a NEW fingerprint; the old one is rejected by the provider."
  "identity_renewal|Re-run provider setup with a renewed client certificate on the SAME private key (new PKCS#12). Expect setup to succeed, the provider to accept the new certificate, and the old identity gone from the app (no duplicate-item failure)."
  "ats_on|Separate build, ONLY for this check: delete NSAllowsArbitraryLoads from ios/Runner/Info.plist, rebuild and install, then set up the provider and approve one request. Record whether the custom trust delegate alone (enrolled private CA + leaf pin) works with ATS on, or the exact ATS error. Reinstall the normal build afterwards."
  "revoke|Revoke this iPhone's approval client from the desktop. Expect a later approval from the iPhone rejected by the provider."
)
for step in "${steps[@]}"; do
  id=${step%%|*}; text=${step#*|}
  echo; echo "[$id] $text"
  while :; do
    ask "Result (pass/fail/skipped):"
    case "$REPLY" in pass|fail|skipped) break ;; esac
  done
  result=$REPLY
  ask "Observed behaviour (fingerprints, messages; never passwords):"
  record "step: $id"
  record "  result: $result"
  record "  observed: $REPLY"
done
record ""
record "# Failures remain failures. Do not edit this file after recording."
echo; echo "evidence written to $out"
