#!/usr/bin/env bash
# CI-only Developer ID material for the macOS desktop release job (#62).
#
#   ci-macos-signing.sh setup     temporary keychain + profile + notary key from secrets
#   ci-macos-signing.sh cleanup   delete them (run with `if: always()`)
#
# Secrets (repository Actions secrets, passed as environment variables):
#   MACOS_DEVELOPER_ID_P12_BASE64      Developer ID Application certificate + key (.p12, base64)
#   MACOS_DEVELOPER_ID_P12_PASSWORD    its export password
#   MACOS_COMPANION_PROFILE_BASE64     Vaultwarden_companion.provisionprofile (base64)
#   APPLE_NOTARY_API_KEY_P8_BASE64     App Store Connect API key (.p8, base64)
#   APPLE_NOTARY_API_KEY_ID            its key id
#   APPLE_NOTARY_API_ISSUER_ID         its issuer id
# None set (forks, pull requests): the development build, with a notice. The
# signing three must be all set or all unset; so must the notary three. Values
# are never printed. Refuses to run outside GitHub Actions: it changes the
# runner user's keychain search list.
set -euo pipefail
team=${MACOS_TEAM_ID:-9884BZY594}
[[ "${GITHUB_ACTIONS:-}" == true && -n "${RUNNER_TEMP:-}" && -n "${GITHUB_ENV:-}" ]] || { echo 'ci-macos-signing.sh runs only in GitHub Actions' >&2; exit 2; }
material="$RUNNER_TEMP/developer-id"
keychain="$material/signing.keychain-db"

present() { local n=0 name; for name in "$@"; do [[ -n "${!name:-}" ]] && n=$((n + 1)); done; echo "$n"; }

setup() {
  local signing notary password identities count
  signing=$(present MACOS_DEVELOPER_ID_P12_BASE64 MACOS_DEVELOPER_ID_P12_PASSWORD MACOS_COMPANION_PROFILE_BASE64)
  notary=$(present APPLE_NOTARY_API_KEY_P8_BASE64 APPLE_NOTARY_API_KEY_ID APPLE_NOTARY_API_ISSUER_ID)
  if [[ "$signing" -eq 0 ]]; then
    echo '::notice::Developer ID signing secrets are not set: building the development (ad hoc) macOS archive; signing and notarization skipped'
    [[ "$notary" -eq 0 ]] || echo '::warning::notary secrets are set but signing secrets are not; notarization skipped'
    return 0
  fi
  [[ "$signing" -eq 3 ]] || { echo '::error::set all of MACOS_DEVELOPER_ID_P12_BASE64, MACOS_DEVELOPER_ID_P12_PASSWORD and MACOS_COMPANION_PROFILE_BASE64, or none'; exit 1; }
  [[ "$notary" -eq 0 || "$notary" -eq 3 ]] || { echo '::error::set all of APPLE_NOTARY_API_KEY_P8_BASE64, APPLE_NOTARY_API_KEY_ID and APPLE_NOTARY_API_ISSUER_ID, or none'; exit 1; }
  umask 077
  rm -rf "$material"; mkdir -p "$material"
  password=$(/usr/bin/openssl rand -hex 32)
  /usr/bin/security create-keychain -p "$password" "$keychain"
  /usr/bin/security set-keychain-settings -lut 7200 "$keychain"
  /usr/bin/security unlock-keychain -p "$password" "$keychain"
  printf '%s' "$MACOS_DEVELOPER_ID_P12_BASE64" | /usr/bin/base64 --decode > "$material/identity.p12"
  /usr/bin/security import "$material/identity.p12" -k "$keychain" -f pkcs12 -P "$MACOS_DEVELOPER_ID_P12_PASSWORD" -T /usr/bin/codesign >/dev/null
  rm -f "$material/identity.p12"
  /usr/bin/security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$password" "$keychain" >/dev/null
  # Search list: the temporary keychain first, then the runner's own.
  eval "set -- $(/usr/bin/security list-keychains -d user | /usr/bin/tr '\n' ' ')"
  /usr/bin/security list-keychains -d user -s "$keychain" "$@"
  identities=$(/usr/bin/security find-identity -v -p codesigning "$keychain" \
    | /usr/bin/awk -v team="($team)\"" '/"Developer ID Application: / && index($0, team) {print $2}' | /usr/bin/sort -u)
  count=$(printf '%s' "$identities" | /usr/bin/grep -c . || true)
  [[ "$count" -eq 1 ]] || { echo "::error::the .p12 must hold exactly one Developer ID Application identity of team $team (found $count)"; exit 1; }
  printf '%s' "$MACOS_COMPANION_PROFILE_BASE64" | /usr/bin/base64 --decode > "$material/companion.provisionprofile"
  {
    echo "MACOS_SIGNING_IDENTITY=$identities"
    echo "MACOS_SIGNING_KEYCHAIN=$keychain"
    echo "MACOS_TEAM_ID=$team"
    echo "MACOS_PROVISIONING_PROFILE=$material/companion.provisionprofile"
  } >> "$GITHUB_ENV"
  if [[ "$notary" -eq 3 ]]; then
    printf '%s' "$APPLE_NOTARY_API_KEY_P8_BASE64" | /usr/bin/base64 --decode > "$material/AuthKey.p8"
    {
      echo "MACOS_NOTARY_KEY_PATH=$material/AuthKey.p8"
      echo "MACOS_NOTARY_KEY_ID=$APPLE_NOTARY_API_KEY_ID"
      echo "MACOS_NOTARY_ISSUER_ID=$APPLE_NOTARY_API_ISSUER_ID"
    } >> "$GITHUB_ENV"
    echo "Developer ID signing (team $team) and notarization configured"
  else
    echo '::warning::notary secrets are not set: the macOS archive will be Developer ID signed but NOT notarized'
  fi
}

cleanup() {
  if [[ -f "$keychain" ]]; then
    /usr/bin/security delete-keychain "$keychain" || true
  fi
  rm -rf "$material"
}

case "${1:-}" in
  setup) setup ;;
  cleanup) cleanup ;;
  *) echo 'usage: ci-macos-signing.sh setup|cleanup' >&2; exit 2 ;;
esac
