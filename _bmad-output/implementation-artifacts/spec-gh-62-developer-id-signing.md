---
title: 'Developer ID signing and notarization of the macOS desktop bundle (#62)'
type: 'feature'
created: '2026-11-11'
status: 'done'
context: ['{project-root}/docs/desktop-installation.md', '{project-root}/docs/native-macos-plan.md', '{project-root}/AGENTS.md']
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The arm64 macOS desktop archive is ad hoc (development) signed, so Gatekeeper refuses it after download, the companion's data-protection Keychain (Secure Enclave approval key) has no entitlement, and nothing in the provider names the release publisher.

**Approach:** When Developer ID material is configured, the bundler signs every nested Mach-O, framework, helper and the app with the Developer ID Application identity of team 9884BZY594, hardened runtime, secure timestamp and minimum entitlements (the app embeds the matching Developer ID provisioning profile for `keychain-access-groups`), then notarizes and staples when notary credentials are configured. Without the material the build stays the current development build and says so. The provider's image trust names the release publisher explicitly and rejects everything that is not Apple, Developer ID (with the Developer ID intermediate) or the release team.

## Boundaries & Constraints

**Always:** secrets only from CI secrets or the owner's Keychain/notary profile, never the repository; missing secrets skip signing/notarization with a clear notice and leave forks/PRs green; signing happens before the bundle manifest is hashed so `bundle.json` stays exact; arm64 only; release requirement identical in the Rust provider and the installer.

**Ask First:** (autonomous run: decisions logged in the PR) the archive variant names; Windows signing.

**Never:** export or import keys, change Keychain trust, set GitHub secrets, store notary credentials, run sudo or a real install (owner actions, documented instead); Intel jobs; a `get-task-allow`, JIT, library-validation or DYLD exception in any signed component; commit a provisioning profile.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| No signing material | `MACOS_SIGNING_IDENTITY` unset | development (ad hoc) archive, notice printed | N/A |
| Signing, no notary | identity + profile, no notary creds | Developer ID signed, verified, `-signed` archive, warning that it is not notarized | N/A |
| Signing + notary | identity + profile + keychain profile or API key | signed, notarized, stapled, `spctl` assessed, `-notarized` archive | rejected submission prints the notary log and fails |
| Wrong profile | team/app id/platform/expiry mismatch | refuse before signing | clear message naming the field |
| Wrong identity | not `Developer ID Application: … (9884BZY594)` | refuse | clear message |
| Ad hoc image | provider image check | rejected; not release | `UnsupportedImage` |
| Apple system image | `/usr/bin/ssh` | accepted, publisher Apple, not release | N/A |
| Release-signed image | Developer ID, team 9884BZY594 | accepted, publisher Release | N/A |
| Mixed-publisher FAT image | slices of different publishers | rejected | `UnsupportedImage` |

</frozen-after-approval>

## Code Map

- `src/adapters/native/image.rs` -- image trust: Apple / Developer ID, cdhash pinning; gains the release publisher.
- `src/adapters/native/identity.rs` -- service-account identities (UIDs/UUIDs); independent of code signing, unchanged.
- `scripts/desktop-bundle.py` -- bundler: ad hoc signing before manifest hashing; gains the release path.
- `scripts/macos-release-signing.py` -- new: profile check, entitlements, signing order, verification, notarization.
- `scripts/release-macos-desktop-bundle.sh` -- new: local signed (optionally notarized) build.
- `scripts/ci-macos-signing.sh` -- new: CI temporary keychain from secrets, cleanup.
- `scripts/desktop-companion-artifact.py` -- archive variant name and signing record.
- `.github/workflows/release.yml`, `.github/workflows/ci.yml` -- secrets wiring (`secrets: inherit`).
- `scripts/macos-provider-install.py` -- existing `--team-id` designated requirement (pinned to Rust).
- `docs/desktop-installation.md`, `docs/native-macos-plan.md` -- owner secrets and one-time commands.

## Tasks & Acceptance

**Execution:**
- [x] `src/adapters/native/image.rs` (+ `image/tests.rs`) -- `RELEASE_TEAM_ID`, Developer ID clause with intermediate, `Publisher` classification, one publisher across slices; tests for ad hoc / Apple / release fixture.
- [x] `scripts/macos-release-signing.py` + `scripts/test-macos-release-signing.py` -- signing library and CLI with fake-tool tests.
- [x] `scripts/desktop-bundle.py`, `scripts/desktop-companion-artifact.py`, `scripts/test-desktop-bundle.py` -- release path before manifest; notarize before archive.
- [x] `scripts/ci-macos-signing.sh`, `scripts/release-macos-desktop-bundle.sh` -- CI and local entry points.
- [x] workflows -- signing setup/cleanup on the macOS desktop release job, `secrets: inherit`.
- [x] `scripts/test-macos-provider-install.py` -- pin the installer requirement to the Rust clause.
- [x] docs -- secrets list, owner commands, rehearsal steps (not run), Windows out of scope.

**Acceptance Criteria:**
- Given no secrets, when the release workflow runs, then the macOS archive is the development archive and the log says signing was skipped.
- Given a development-signed binary, when the provider classifies it, then it is not the release publisher; given the release-signed fixture, then it is.

## Verification

**Commands:**
- `cargo fmt --check`, `cargo clippy -j 4 --all-targets -- -D warnings` -- clean
- `TMPDIR=$HOME/.vwtmp cargo test -j 4 --lib adapters::native::image` -- pass
- `python3 scripts/test-macos-release-signing.py`, `python3 scripts/test-desktop-bundle.py`, `python3 scripts/test-macos-provider-install.py` -- pass
