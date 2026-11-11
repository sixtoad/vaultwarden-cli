#!/usr/bin/env bash
# Publisher-local Developer ID build of the arm64 macOS desktop bundle (#62):
# signs every component with the Developer ID Application identity in the login
# Keychain, embeds the companion's Developer ID provisioning profile and, unless
# --no-notarize, notarizes and staples with a notarytool keychain profile.
# Nothing is installed; no Keychain item, trust setting or credential is changed.
#
#   scripts/release-macos-desktop-bundle.sh EVIDENCE-DIR [--no-notarize]
#       [--notary-profile NAME]   default: vaultwarden-notary
#       [--profile FILE]          default: .signing/Vaultwarden_companion.provisionprofile
#       [--team-id TEAMID]        default: 9884BZY594
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
usage() { sed -n '2,12p' "$0" >&2; exit 2; }
evidence=${1:-}; [[ -n "$evidence" && "$evidence" != -* ]] || usage
shift
team=9884BZY594
notary_profile=vaultwarden-notary
profile="$repo/.signing/Vaultwarden_companion.provisionprofile"
notarize=1
while (($#)); do
  case "$1" in
    --no-notarize) notarize=0 ;;
    --notary-profile) notary_profile=${2:?}; shift ;;
    --profile) profile=${2:?}; shift ;;
    --team-id) team=${2:?}; shift ;;
    *) usage ;;
  esac
  shift
done
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo 'Developer ID bundles are built on Apple Silicon macOS only' >&2; exit 1; }
[[ -f "$profile" ]] || { echo "provisioning profile not found: $profile (copy the Developer ID profile there; .signing/ is gitignored)" >&2; exit 1; }
# Exactly one valid Developer ID Application identity of the team; signed by SHA-1.
identities=$(/usr/bin/security find-identity -v -p codesigning \
  | /usr/bin/awk -v team="($team)\"" '/"Developer ID Application: / && index($0, team) {print $2}' | /usr/bin/sort -u)
count=$(printf '%s' "$identities" | /usr/bin/grep -c . || true)
if [[ "$count" -ne 1 ]]; then
  echo "expected exactly one valid \"Developer ID Application: ... ($team)\" identity in the Keychain, found $count" >&2
  exit 1
fi
export MACOS_SIGNING_IDENTITY=$identities
export MACOS_TEAM_ID=$team
export MACOS_PROVISIONING_PROFILE=$profile
export DESKTOP_EXPECTED_ARCHITECTURE=arm64
unset MACOS_SIGNING_KEYCHAIN MACOS_NOTARY_KEY_PATH MACOS_NOTARY_KEY_ID MACOS_NOTARY_ISSUER_ID
if ((notarize)); then
  export MACOS_NOTARY_KEYCHAIN_PROFILE=$notary_profile
else
  unset MACOS_NOTARY_KEYCHAIN_PROFILE
fi
python3 "$repo/scripts/macos-release-signing.py" status
exec bash "$repo/scripts/build-desktop-bundle.sh" "$evidence"
