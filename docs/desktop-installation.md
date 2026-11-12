# Desktop bundle installation and terminal commands

This package contains the existing Flutter `companion_slice` application and
applicable command-line tools. It does not rename the product or replace the
separately supported Swift Approval Companion. Build one bundle with
`scripts/build-desktop-bundle.sh /absolute/private/evidence` on the target OS.
Flutter 3.47.7, the locked Rust toolchain dependencies and native build tools are
required. The CI desktop matrix performs the full native gates before packaging.
The release workflow publishes the same coherent **development** archives:
`companion-linux-development.tar.gz`, `companion-windows-development.tar.gz`,
and `companion-macos-arm64-development.tar.gz` (Apple Silicon, with the protected
commands), all listed in the release `SHA256SUMS.txt`. Once the owner sets the
Developer ID secrets, the macOS archive is instead
`companion-macos-arm64-notarized.tar.gz` (Developer ID signed, notarized and
stapled; see [Developer ID signing and notarization](#developer-id-signing-and-notarization-macos-62)). Intel (x86_64) macOS is no
longer supported or built (owner decision 2026-11-10): there is no Intel macOS
archive, and the packaging helper refuses an x86_64 macOS build.
Without signing material the helper builds the development bundle and refuses
to replace a non-ad-hoc signature with development signing.
Do not bypass Gatekeeper, remove quarantine or modify an installed application.

| Platform | Bundled tools | Request / approve / execute capability |
| --- | --- | --- |
| Linux | `vaultwarden-cli`, `vw-access`, `vaultwarden-accessd`, `vaultwarden-access-exec`, command launcher | `vw-access` requests protected work; provider/helper implement approved Linux delivery. Flutter provider transport/approval is unavailable. |
| macOS, Apple Silicon (arm64) | `vaultwarden-cli`, `vw-access`, `vaultwarden-accessd`, command launcher | Vault CLI works. `vw-access` and the native provider are bundled in `Contents/Helpers` and advertised. An administrator installs the provider into `/Library/VaultwardenAccess` and its launchd service with a root-owned copy of `scripts/macos-provider-install.py` run under sudo, from a plan reviewed with `scripts/macos-provider-plan.py` (see below); the app itself installs nothing. Development (ad hoc) or Developer ID signed, team 9884BZY594 (#62). The provider verifies production Touch ID approval v2; the companion's approval settings list the approval methods the installed app version offers. Guided enrollment and notifications are not available (#59, #61). |
| macOS, Intel (x86_64) | none: not supported or built | Intel Macs are no longer supported. No Intel macOS bundle or CLI binary is published, and the packaging helper refuses to build one. The native provider also rejects Intel and Rosetta at runtime. |
| Windows | `vaultwarden-cli.exe`, command launcher | Vault CLI works. Protected requesting/provider execution and Flutter approval transport are unavailable. |

The manifest records the actual app, core and CLI versions separately: currently
0.1.0+1, 0.1.0 and 0.5.4. Equal version strings are not the compatibility rule.
Bundle schema 1, launcher ABI 1, the expected runtime platform/architecture and
running app/core versions are checked. Old ABI-1 command launchers can select
new compatible app/core versions. A bundle records its host command architecture;
the macOS app, its core library and its commands are all arm64: `companion/macos/Runner/Configs` sets `ARCHS = arm64` for every target, `scripts/build-companion-macos-core.sh` refuses an x86_64 slice, and the bundler checks every executable with `lipo`. The `vaultwarden-access-exec` helper is Linux's systemd helper and is not shipped on macOS: the native provider does not use it.

The CI and release desktop matrices build the macOS bundle once, on an Apple Silicon runner (`macos-26`), giving the arm64 archive with `Contents/Helpers/vw-access` and `Contents/Helpers/vaultwarden-accessd`. Each job sets `DESKTOP_EXPECTED_ARCHITECTURE`, and packaging fails if the bundle's architecture or its helper set differs from it, so a runner change cannot publish another architecture as the arm64 one; an expected or actual x86_64 macOS architecture is refused outright. Without the Developer ID secrets the archive is development-signed (ad hoc); with them it is Developer ID signed and notarized (#62, below). A command folder enabled from an earlier macOS arm64 bundle (which listed only `vaultwarden-cli`) is reported as an incompatible command setup by the new bundle: enable commands in a new empty user folder, as for any command-set change.

`bundle.json` (macOS: `Contents/Resources/bundle.json`) binds every regular
payload, required runtime libraries, command paths, supported roles and internal
framework links. Only closed command names and relative paths are admitted.
The macOS executable's outer signature binds the manifest, so its own hash is
recorded in the external `artifact.json` after signing rather than introducing a
circular signature. The complete extracted archive inventory, modes and hashes
must match. Runtime validation also verifies the macOS signature with the fixed
system `codesign` executable. A manifest hash detects damage; on unsigned platforms
it is not proof of publisher identity. Verify the release checksum through the
trusted release channel before opening an archive.

## First installation

Extract the archive into a fresh folder inside your home. Preserve the complete
app structure, libraries, executable modes and links. Linux desktop CI/release archives target Ubuntu 24.04 with its GTK 3 and glibc runtime (the Flutter engine/AOT library and ICU data are bundled). Other distributions require matching native runtime compatibility; the package does not install desktop OS libraries. Protected provider operation has additional, source-enforced prerequisites:

- Linux **6.3+**, permitted executable memfds with WRITE/GROW/SHRINK/EXEC/SEAL support, and permitted parent/child ptrace exec-event observation.
- Unified **cgroup v2**, **systemd 255+**, and the provider user's D-Bus user-manager connection at `/run/user/<uid>/bus`. There is no separately enforced minimum D-Bus daemon version.
- The supplied `vaultwarden-accessd.service` user unit and independently authorized provider setup. An arbitrary shell-launched daemon is not an authorized provider instance.
- A native little-endian x86-64 or AArch64 reviewed self-contained ELF64 ET_EXEC operation image under the existing policy; scripts, dynamic executables and static PIE are not admitted by that profile.
- Provider-owned helper and installation ancestors with the required ownership/modes; restricted agents run under separate OS principals. See [the current protected-access contract](access-mvp.md#supported-platform) and its executable/runtime sections. These are delivery prerequisites, not a promise to supervise or terminate consumers.

 Installation does not start or configure a privileged service.
Windows ships the app-local MSVC runtime with Flutter and statically links the CRT
for copied Rust command launchers/tools. macOS preserves the app sandbox. Explicit folder selection grants only user-selected read/write and executable-file access. Apple's [sandbox file-access documentation](https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox) requires the `com.apple.security.files.user-selected.executable` entitlement for this executable-publication flow; packaging checks it in the actual signed bundle alongside the sandbox/read-write entitlements. NSOpenPanel starts the selected scope, which is released after activation; no extra unbalanced scope is opened.

Open the normal application, then Settings → Desktop installation. Inspection
shows the bundled tool path and version separately from terminal PATH resolution.
It never executes a PATH candidate to discover its version. Missing, damaged,
incompatible and conflicting installations give repair/update guidance.

Choose **Enable / repair user commands**. On macOS a native folder chooser grants
write access to the selected directory for this operation only; select or create
a bin directory inside your home. Linux/Windows show the exact destination and
create the selected user directory on the explicit action. Directories outside
your account home, unsafe links and unrelated commands are refused. Every directory from the account home to the destination must be owned by you and not writable by other users on Unix. Windows validates owner/DACL permissions, allowing writes only by the account, SYSTEM or Administrators. Reparse points and complex unsupported access rules fail closed.

The operation publishes native command launchers and one activation receipt. Unix publication is relative to opened, no-follow directory descriptors; Windows pins all directory ancestors against renaming. Unix launchers replace themselves with the CLI so PID, signals and terminal job control remain intact.
The launchers select only the complete validated bundle; Linux provider/helper
binaries remain adjacent inside it. No shell wrapper is used, so spaces, Unicode
paths and arguments do not undergo shell interpolation. Add the displayed
directory to your **user** PATH using your shell profile or Windows user
Environment Variables UI if it is absent, then open a new terminal. Settings uses
the application's inherited PATH; restart the app after changing PATH. No PATH is
silently edited, and no system-level installation is offered.

Installing a command grants no enrollment, approval, secret access, credential
migration or service authority. Android/iOS never display these controls;
a narrow desktop window still does.

## Upgrade, moved app and recovery

1. Retain the previous complete bundle. Extract the new archive into a new folder;
   never merge the files of two versions and never mutate a running bundle.
2. Verify the checksum/signature and open the new app. Its Settings inspection
   must succeed before enabling its commands.
3. Enable/repair the same user directory. A kernel lock serializes activation.
   Fully written/synced temporary files are published without overwriting an
   unrelated command; one atomic receipt replacement activates the whole bundle.
   The prior receipt is preserved as `.vaultwarden-commands.previous.json`.
4. If staging or activation fails, the prior receipt remains active. Reopen the
   retained old application and repair its commands to roll back. Keep its bundle
   until the new commands have been checked. A moved app is repaired from its new
   location. If an old managed launcher is missing and its bytes differ from the
   new launcher, enable a fresh user directory; do not overwrite an unidentified
   executable. A damaged bundle requires complete replacement, not file patching.

Kernel locks release on process death. An interrupted first activation can leave
inactive launcher files or uniquely named staging files; rerunning enablement
accepts only byte-identical launchers and never treats a stage as authority.
Recovery does not execute or delete unrelated files. Retained ABI-1 launchers are compatible with newer component versions on the same architecture. Retention requires either byte identity with the current bundled launcher or full validation of the recorded original bundle/manifest and its launcher payload hash; a receipt alone cannot bless a discovered executable. Keep that original proof bundle if retaining its different launcher bytes. If it is missing or damaged, preserve the current setup and enable a fresh user folder. An architecture change requires a fresh user command directory, preserving the previous setup. A future launcher ABI requires a separately qualified migration. Lost executable permissions are repaired by replacing only the verified managed directory entry; permissions of unrelated hard links are never changed.

If the active command setup is malformed but the saved previous setup and managed launchers validate, explicit Repair retains the unexplained bytes in a uniquely named `.vaultwarden-quarantine-*` file and recovers safely. Without a valid previous setup, preserve the folder and enable a new empty user folder; the error states this recovery path. Payloads, final modes and directory entries are synchronized before activation. If the final durability confirmation fails after switching, Settings reports that the new setup is active but storage durability is uncertain, rather than falsely claiming the old setup remains selected.

## Reproducible isolated verification

Run `cargo test --locked --manifest-path companion/rust/Cargo.toml`, then
`flutter analyze` and `flutter test` from `companion/`. Filesystem unit tests use
private temporary homes and synthetic inert payloads; they explicitly do not
prove native signing. They cover missing/damaged components, omitted required
libraries, unknown ABI, independent versions, path escape, extra payloads,
conflicts, hostile/stale links, lost executable modes, repeat activation, moves,
failed upgrades and interrupted publication. Widget tests prove actual platform
exclusion and truthful unsupported roles.

Run `python3 scripts/test-desktop-bundle.py` and
`python3 scripts/test-desktop-companion-artifact.py`. A complete
`scripts/test-desktop-companion.sh /absolute/private/evidence` runs native and
security gates, the release AOT smoke, rebuilds **lib/main.dart**, then packages.
Packaging extracts the archive and explicitly runs the ignored Rust
`installation::tests::packaged_bundle_command_invocation` test with
`COMPANION_TEST_BUNDLE` pointing to that extracted bundle. It installs production
launchers in an isolated temporary home, checks repeated repair and invokes each
applicable command's `--version` with empty PATH and unrelated cwd. Those launcher
processes use production integrity/signature validation. No production vault,
trust store, installed app or service is touched.

`source-before.json` and `source-after.json` preserve exact porcelain status,
tracked diffs, all tracked/untracked input paths, file/link kinds, modes and hashes. Packaging refuses
if any source input changes during build, recording `source-changed-paths.json`.
The historic PR #52 Windows artifact did not retain changed paths. Instrumented Windows CI run **40867575316**, job **123426118530**, on this slice's first commit reproduced the report and refused packaging. Exactly seven Flutter-generated registrant/CMake files changed from checkout CRLF bytes to generator LF bytes. Each before hash equals the committed LF bytes converted to CRLF; each after hash equals the exact committed LF bytes. Those seven LF hashes also match PR #52 commit `93431e6460f5a73c1d0f2e8d8fd087bade4e2f54`, so the reproduction uses the exact historical inputs rather than inferring a cause from the old boolean alone. Git's normalized diff was empty despite seven modified status entries. The narrow `.gitattributes` rules fix checkout normalization for those exact seven files only. A regression checks `core.autocrlf=true` checkout and regeneration without source drift. Final matching Windows CI must still show clean provenance; no flag is forced false and no files are discarded or ignored.

## Developer ID signing and notarization (macOS, #62)

The release publisher is the Developer ID Application identity of team
**9884BZY594**. When signing material is configured, `scripts/desktop-bundle.py`
signs the arm64 bundle with it (`scripts/macos-release-signing.py`); otherwise it
builds the development (ad hoc) bundle exactly as before and prints that it did.

What a Developer ID bundle carries:

| Component | Signature | Entitlements |
| --- | --- | --- |
| `Contents/Helpers/vw-access`, `vaultwarden-accessd`, `vaultwarden-cli`, `companion-command` | Developer ID, hardened runtime, secure timestamp, identifier `dev.vaultwarden.<name>` | none |
| `Contents/Frameworks/libcompanion_core.dylib`, `FlutterMacOS.framework`, `App.framework` (and any other nested Mach-O) | Developer ID, hardened runtime, secure timestamp | none |
| `companion_slice.app` | Developer ID, hardened runtime, secure timestamp | `companion/macos/Runner/Release.entitlements` (sandbox, network client, user-selected read/write and executable) plus `com.apple.application-identifier` = `9884BZY594.dev.vaultwarden.companionSlice`, `com.apple.developer.team-identifier` and `keychain-access-groups` = `[9884BZY594.dev.vaultwarden.companionSlice]` |

`keychain-access-groups` is a restricted entitlement: the companion's Secure
Enclave approval key lives in the data-protection Keychain, so the app embeds
the Developer ID provisioning profile `Vaultwarden_companion.provisionprofile`
(app id `9884BZY594.dev.vaultwarden.companionSlice`) as
`Contents/embedded.provisionprofile`. Before signing, the profile is checked: a
macOS profile of team 9884BZY594 that provisions all devices (Developer ID, not a
development profile), unexpired, for exactly this app id, without
`get-task-allow`, and granting the keychain group. Xcode's ad hoc build adds
`get-task-allow`; it is dropped, and any other difference from
`Release.entitlements` refuses the build. No component carries
`get-task-allow`, JIT, unsigned memory, library-validation or DYLD exceptions.
The second profile, `Approval_Companion_Provider_Developer_ID.provisionprofile`
(`9884BZY594.dev.vaultwarden.ApprovalCompanion.ProviderBridge`), matches no
artifact built today: the Swift Approval Companion is `dev.vaultwarden.ApprovalCompanion`
and is not part of this bundle. It is not used.

Every signature exists before `bundle.json` hashes the payloads (the embedded
profile is a recorded payload); the app is sealed last. The bundle is then
verified: `codesign --verify --deep --strict -R '=<Developer ID requirement of
9884BZY594>'` on the app and the same requirement, the team identifier, the
hardened-runtime flag, a timestamp and the entitlements for every component.

With notary credentials, the app is submitted (`xcrun notarytool submit --wait
--timeout 30m`), the ticket is stapled (`xcrun stapler staple`, `stapler
validate`) and Gatekeeper must report `source=Notarized Developer ID`
(`spctl --assess --type execute`). A rejected submission saves and prints the
notary log and fails the build. The stapled ticket (`Contents/CodeResources`)
is written after the final signature, so the manifest cannot list it; the
companion's runtime inventory treats exactly that path as signature metadata on
macOS, like `_CodeSignature`, and `codesign --verify --deep --strict` still
covers the bundle. Archive names and `artifact.json` say which build
you have:

| Archive | Meaning |
| --- | --- |
| `companion-macos-arm64-notarized.tar.gz` | Developer ID signed, notarized and stapled; `artifact.json` `signing` = `{"kind": "developer-id", "team_id": "9884BZY594", "notarized": true}` |
| `companion-macos-arm64-signed.tar.gz` | Developer ID signed, NOT notarized (no notary credentials); Gatekeeper refuses it after download |
| `companion-macos-arm64-development.tar.gz` | ad hoc development build (no signing material) |

The native provider recognizes the release publisher: its image trust
(`src/adapters/native/image.rs`) admits Apple, the release team's Developer ID
(`RELEASE_TEAM_ID`, the same requirement as the installer's `--team-id
9884BZY594`) and other teams' Developer ID images, all with the Developer ID
intermediate; anything else (ad hoc, Apple Development, other chains) is
rejected, and the native slices of one image must share one publisher. Operator
images signed by another team's Developer ID stay trusted, as before (the
provider runs operator-registered images, not the bundle's helpers); the
classification names the release publisher and enforces one publisher per image. Install
a Developer ID bundle with `--team-id 9884BZY594`; the installer refuses it
under `--allow-development-signature`, and refuses a development build under
`--team-id`.

### Release workflow secrets (owner, one time)

The release workflow (`.github/workflows/release.yml`, which receives exactly
these six secrets from `ci.yml`) builds everything first, then runs
`scripts/ci-macos-signing.sh setup` and only then the package step that signs,
notarizes and archives, so no build script or dependency runs while the signing
material exists. Setup imports the identity into a temporary keychain under
`$RUNNER_TEMP` with a non-extractable private key; cleanup deletes the keychain,
profile and API key in an `always()` step. With no secrets (forks, pull
requests) the macOS archive stays the development build and the job prints a
notice; a partial set fails the job. After setting the secrets, set the
repository **variable** `MACOS_REQUIRE_DEVELOPER_ID` to `true`: from then on a
release fails instead of publishing an unsigned or unnotarized macOS archive
(`gh variable set MACOS_REQUIRE_DEVELOPER_ID --body true --repo
sixtoad/vaultwarden-cli`). Set these repository Actions secrets:

| Secret | Value |
| --- | --- |
| `MACOS_DEVELOPER_ID_P12_BASE64` | base64 of a `.p12` holding only the "Developer ID Application: Sixto Cantolla (9884BZY594)" certificate and its private key |
| `MACOS_DEVELOPER_ID_P12_PASSWORD` | the `.p12` export password |
| `MACOS_COMPANION_PROFILE_BASE64` | base64 of `Vaultwarden_companion.provisionprofile` |
| `APPLE_NOTARY_API_KEY_P8_BASE64` | base64 of the App Store Connect API key `AuthKey_<KEYID>.p8` (Developer role) |
| `APPLE_NOTARY_API_KEY_ID` | its key id |
| `APPLE_NOTARY_API_ISSUER_ID` | its issuer id |

One-time commands (run by the owner; nothing here is automated):

```bash
# 1. Export the Developer ID identity: Keychain Access > login > My Certificates >
#    "Developer ID Application: Sixto Cantolla (9884BZY594)" > Export... > .p12 with a
#    strong password, saved as ~/developer-id.p12 (only that identity, not all of them).
# 2. Store the secrets (gh reads each value from standard input; nothing in shell history):
gh secret set MACOS_DEVELOPER_ID_P12_BASE64 --repo sixtoad/vaultwarden-cli < <(base64 -i ~/developer-id.p12)
gh secret set MACOS_DEVELOPER_ID_P12_PASSWORD --repo sixtoad/vaultwarden-cli   # paste the password at the prompt
gh secret set MACOS_COMPANION_PROFILE_BASE64 --repo sixtoad/vaultwarden-cli \
  < <(base64 -i ~/Downloads/Vaultwarden_companion.provisionprofile)
gh secret set APPLE_NOTARY_API_KEY_P8_BASE64 --repo sixtoad/vaultwarden-cli < <(base64 -i ~/AuthKey_<KEYID>.p8)
gh secret set APPLE_NOTARY_API_KEY_ID --repo sixtoad/vaultwarden-cli       # paste the key id
gh secret set APPLE_NOTARY_API_ISSUER_ID --repo sixtoad/vaultwarden-cli    # paste the issuer id
# 3. Remove the exported files.
rm -P ~/developer-id.p12
```

The API key is created in App Store Connect > Users and Access > Integrations >
App Store Connect API (Team Keys, role Developer); the `.p8` downloads once.

### Local signed build

`scripts/release-macos-desktop-bundle.sh EVIDENCE-DIR` builds the same bundle on
the owner's Apple Silicon Mac. It signs with the one valid "Developer ID
Application: … (9884BZY594)" identity in the login Keychain (by SHA-1), embeds
`.signing/Vaultwarden_companion.provisionprofile` (gitignored; copy the profile
there, or pass `--profile FILE`) and notarizes with the notarytool keychain
profile `vaultwarden-notary` (`--notary-profile NAME` to change, `--no-notarize`
to skip). It installs nothing and changes no Keychain item. The keychain profile
is created once by the owner:

```bash
xcrun notarytool store-credentials vaultwarden-notary \
  --key ~/AuthKey_<KEYID>.p8 --key-id <KEYID> --issuer <ISSUER-ID>
# or, with an app-specific password:
xcrun notarytool store-credentials vaultwarden-notary --apple-id <apple id> --team-id 9884BZY594
```

`python3 scripts/macos-release-signing.py status` says what the environment
configures (never a value); `verify APP` re-checks a built bundle and
`notarize APP` notarizes an already signed one.

The release-publisher acceptance tests of the provider need a release-signed
binary, which CI cannot make. Run them on the owner's Mac:

```bash
mkdir -p ~/.vwtmp/release-fixture && cd ~/.vwtmp/release-fixture
printf 'int main(void){return 0;}\n' > f.c && clang -arch arm64 f.c -o release-fixture
codesign --sign "Developer ID Application: Sixto Cantolla (9884BZY594)" --options runtime --timestamp release-fixture
cd <checkout> && TMPDIR=$HOME/.vwtmp VW_RELEASE_SIGNED_FIXTURE=$HOME/.vwtmp/release-fixture/release-fixture \
  cargo test -j 4 --lib adapters::native::image -- --include-ignored
```

Windows code signing is out of scope (#62): Windows archives stay unsigned
development builds.

### Upgrade, rollback and uninstall rehearsal (with the owner, not yet run)

On the owner's Apple Silicon Mac, from a notarized archive downloaded through a
browser (so it carries quarantine):

1. Verify the checksum against the release `SHA256SUMS.txt`, extract into a new
   folder in your home, and confirm `spctl -a -vv -t exec companion_slice.app`
   reports `source=Notarized Developer ID` and `xcrun stapler validate` passes.
   Open the app: no Gatekeeper override is offered or needed.
2. `codesign -dvv` on every `Contents/Helpers/*` shows team 9884BZY594 and
   `flags=0x10000(runtime)`.
3. Plan and install the provider with `--team-id 9884BZY594` (sections above);
   confirm the installer refuses the same bundle with
   `--allow-development-signature`.
4. Upgrade to the next notarized version with `upgrade --team-id 9884BZY594`;
   confirm `status`, the launchd service (`launchctl print
   system/com.cantolla.vaultwarden-accessd`) and that the service-account
   secret store and the companion's Keychain approval key survive.
5. `rollback` to the previous version, then upgrade again.
6. `uninstall` (keeps state and accounts), confirm the LaunchDaemon and versions
   are gone and state is kept; then `uninstall --purge --remove-accounts` on the
   disposable setup only, and confirm the companion's data-protection Keychain
   item is removed with the app (`security` cannot list it; re-enrollment
   creates a new key).

Record each step's output as evidence before closing #62.

## macOS provider installer plan (review material, installs nothing)

`scripts/macos-provider-plan.py` resolves
`packaging/macos/native/com.cantolla.vaultwarden-accessd.plist.in` and
`native-identities.json.in` from explicit inputs into a new or empty output
directory you choose. Run it, like the installer, with the isolated system Python
from the root-owned copy of the reviewed commit (made as shown in the next
section; it needs no root itself):

```bash
/usr/bin/python3 -I /usr/local/libexec/vw-provider-installer/scripts/macos-provider-plan.py --output ~/vw-provider-plan \
  --version 0.5.4 --provider-account _vwaccess --provider-group _vwaccess \
  --provider-uid 491 --provider-uuid <GeneratedUID> \
  --operator-uid 501 --operator-uuid <GeneratedUID> \
  --human-gid 600 --agent-gid 601 \
  [--provider-gid 491] [--human-group _vwhuman] [--agent-group _vwagent] \
  [--agent-account _vwagent1 --agent-uid 602 --agent-uuid <GeneratedUID>] \
  --bundle /path/to/companion_slice.app
```

Every input is validated (decimal non-zero IDs, distinct provider/operator/agent
UIDs and UUIDs, distinct provider/human/agent GIDs and group names, short
account/group names that are not well-known system names such as `staff` or
`admin`, `MAJOR.MINOR.PATCH[-pre]` version), and any `@PLACEHOLDER@` left after
resolution is an error. A GeneratedUID may be given as 32 hex digits or in the
uppercase dashed form `dscl` prints; it is recorded as 32 lowercase hex digits.
The provider primary GID defaults to the provider UID. Choose a free provider
UID/GID pair and two free GIDs, 500 or above for any group you may have to adopt
(`dscl . -list /Users UniqueID`, `dscl . -list /Groups PrimaryGroupID`); generate
GeneratedUIDs with `uuidgen`, and read the operator's with `dscl . -read
/Users/$USER GeneratedUID`. The optional agent account (one for now) is a
restricted identity whose primary group is the agent group.
The resolved plist has exactly the reviewed keys (no `Program`, sockets or
environment), keeps `AbandonProcessGroup`, zero core limits and `/dev/null`
standard streams (the provider requirements discard them; there is no log file),
and runs `/Library/VaultwardenAccess/versions/<version>/vaultwarden-accessd`, the
bundle's `Contents/Helpers/vaultwarden-accessd` at the bundle's `cli_version`;
`--bundle` checks that version and records the payload hashes (the installer
requires them). `plan.json` (schema 2) lists the accounts, the exact group
memberships, the forbidden ones and every directory and file of
[the native provider installation surface](implementation/issue-49-native-provider.md#concrete-installation-approval-surface)
with owner, group, numeric IDs, mode, link count and who creates it
(`installer`, `bundle`, or `operator` for credentials). The generator runs no
command, writes only into the output directory, refuses system locations, never
overwrites, and prints the `plan.json` SHA-256 you pin when installing.

## macOS provider installation, upgrade and removal

`scripts/macos-provider-install.py` executes exactly a reviewed plan directory
and the same bundle. Run it with the system Python under sudo on an Apple Silicon
Mac; it refuses Intel, Rosetta and other systems, and every mutating command
refuses without root.

**What is pinned.** The plan directory and the bundle may sit in your home: you
review `plan.json` and pass its digest with `--expect-plan-sha256`, and the
installer refuses any other plan. The digest covers the resolved plist, the
identity record and every binary's SHA-256; the installer also rebuilds the plan
from its own inputs and refuses any edited file. The code that runs as root
cannot be pinned that way, so mutating commands refuse unless the installer
script, `macos-provider-plan.py`, the templates and every ancestor directory are
root-owned and not group- or other-writable; this check runs for every run as
root (a dry run and `status` included) and before the plan module is executed.
Every code file and ancestor directory must also carry no access control list
(checked with `/bin/ls -led`; remove one with `chmod -N`). Always run
`/usr/bin/python3 -I` on the root-owned copy, never `python3` on a checkout
(`-I` keeps the environment and the current directory out of the import path;
the script also drops its own directory and the current directory from it
before importing anything). Make the root-owned copy of the reviewed commit:

```bash
sudo install -d -o root -g wheel -m 0755 /usr/local/libexec/vw-provider-installer
git archive <reviewed commit> scripts/macos-provider-install.py scripts/macos-provider-plan.py packaging/macos/native \
  | sudo tar -x -C /usr/local/libexec/vw-provider-installer
sudo chown -R root:wheel /usr/local/libexec/vw-provider-installer
sudo chmod -R go-w /usr/local/libexec/vw-provider-installer
I=/usr/local/libexec/vw-provider-installer/scripts/macos-provider-install.py
```

Choose the signature policy: `--team-id TEAMID` requires an Apple-issued
Developer ID signature of that team (`codesign --verify --strict -R '=anchor
apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and
certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate
leaf[subject.OU] = "TEAMID"'`: the Developer ID intermediate and a Developer ID
Application leaf; TEAMID is 10 uppercase letters or digits; required whenever
the binaries carry a team identifier); `--allow-development-signature` accepts ad-hoc development
builds only. Every binary must also be an arm64-only Mach-O (`lipo -archs`),
whatever `bundle.json` says. The policy is recorded per version and reused by
`status`, `rollback` and `uninstall`.

```bash
# Dry run (also the default with no subcommand): prints every action and the plan digest, changes nothing.
/usr/bin/python3 -I $I plan --plan ~/vw-provider-plan --bundle /path/to/companion_slice.app
sudo /usr/bin/python3 -I $I install --plan ~/vw-provider-plan --bundle /path/to/companion_slice.app \
  --expect-plan-sha256 <reviewed digest> --allow-development-signature
sudo /usr/bin/python3 -I $I status
```

`install` creates the provider group, the human and agent socket groups
(`dseditgroup`), the hidden provider account and the optional agent account
(`dscl`: fixed UID, primary GID, plan GeneratedUID, shell `/usr/bin/false`, home
`/var/empty`, no password, hidden), adds the provider to both socket groups and
the operator to the human group. Group membership must be exactly the plan's;
the agent account belongs to the agent group only through its primary GID and
never to the human, provider or `admin` groups. Memberships are verified with
`dsmemberutil checkmembership` after `dsmemberutil flushcache`. A record without
an attribute reads as no values (real `dscl . -read` exits 0 with `No such key:`
on stderr). It then creates the empty layout, copies the
binaries into a new `versions/<version>/` through a staging directory and a
rename (with the resolved plist as
`versions/<version>/com.cantolla.vaultwarden-accessd.plist`), writes
`native-identities.json`, `installer-receipt.json` and the LaunchDaemon. Any UID,
GID, name or GeneratedUID collision refuses before the first write. An account or
group that exactly matches the plan but was not created by this installer is
refused unless you pass `--adopt-existing-accounts` after reviewing it; a group
below GID 500 or with a well-known name is never adopted, and adopted accounts are
never removed. An existing version directory is never overwritten: an identical
one is accepted, a different one refuses. The receipt is written before every
mutation it records, so a re-run after an interruption at any step converges.

The installer never generates or copies credentials (only `uninstall --purge`
deletes them). Until `state/backend.json`, `provider-cert.pem`,
`provider-key.pem` and `companion-ca.pem` exist (provider-owned, `0600`, one
link), the provider has stored its API client secret in its file store
(`state/secrets/`, provider-owned `0700`, with
`vaultwarden-accessd.bootstrap-client-secret` provider-owned `0600`, one link)
and a companion is enrolled (`state/companion-identities.json`, written by the
provider's `--companion-enroll-cert`, provider-owned `0600`, one link; without it
the provider refuses to bind its companion listener and launchd would restart it
in a loop), the service stays disabled (`launchctl disable`) and the installer
prints the manual steps (see the next section and [macos-setup.md](macos-setup.md)).
The order is: install the state files, store the secret, enroll the companion
with the service stopped, and only then run `start` (or re-run the same
`install` command): it changes nothing else and starts the service (`launchctl
enable`, `bootstrap`), then waits for launchd to report `state = running` and
otherwise reports the last exit code.
The provider runs as the provider account, never root, and always starts locked.
`stop --acknowledge-active-work` closes admission and boots the service out;
`start` verifies the active version and credentials and starts it. `status`
shows the launchd state, PID and last exit code, the accounts and memberships,
the sockets in `run/human` and `run/agent`, the credential files, the secret
store and the companion registry (naming each missing or wrong one), and any
pending switch. A receipt or tombstone file that is not the
documented structure is refused with a clean error naming the file.

**Upgrade.** Generate and review a plan for the new version with the same
identity inputs, then:

```bash
sudo /usr/bin/python3 -I $I upgrade --plan ~/vw-provider-plan-0.6.0 --bundle /path/to/new/companion_slice.app \
  --expect-plan-sha256 <reviewed digest> --allow-development-signature --acknowledge-active-work
```

The order is fixed: install and verify the complete new version and record it in
the receipt, close admission (`launchctl disable`), `launchctl bootout` (the
plist keeps `AbandonProcessGroup`, so released consumers keep running; the
installer never signals them), switch the LaunchDaemon plist and the receipt,
then `enable` and `bootstrap`; the provider restarts locked and every new request
needs a fresh approval. `--acknowledge-active-work` records that you notified the
execution owner of active work. Failed verification leaves the current version
active. A re-run of an interrupted upgrade finishes it. State (secrets included)
is untouched. Identity changes (accounts, IDs, groups) are not an upgrade and are
refused.

**Rollback.** `rollback [--to-version V] --confirm-state-compatible
--acknowledge-active-work` switches back to a recorded version in the same order,
after re-verifying it against its stored plist copy and the receipt's hashes (not
against the checkout's templates, which may have changed). Confirm first that the
target understands the current native profile, account UUIDs and consumed-request
schema; consumed approvals are never reactivated and no state backup is restored.

Interrupted switches converge. Before the plist changes, the receipt records the
switch (`switching`: from, to, and whether an upgrade or a rollback started it);
the marker stays until the target's service is verified running (or deliberately
left stopped because credentials are incomplete), and `status` reports it as a
problem meanwhile. Re-running the same `rollback` command with a rollback
pending resumes it towards its recorded target, even when the receipt already
names that target active; it never flips back to the version it left. Once a
rollback completed, re-running it is a no-op that only makes sure the service
runs; pass `--to-version V` to switch again. A failed upgrade's pending switch
does not capture `rollback`: without `--to-version` it switches back to the
version that upgrade left (the marker's `from`), even when the upgrade was
interrupted after the plist write but before the receipt named the new version
active, never to an older `previous_version`.

**Uninstall.** `uninstall --acknowledge-active-work` closes admission, boots the
service out, then removes only installer-owned, unchanged files: the
LaunchDaemon plist, verified version directories, `native-identities.json` and
empty `run/` directories, and clears the label's `launchctl disable` override.
State (including the `state/secrets/` file store) and the accounts are
preserved and the receipt is kept so a later install recognizes them. Anything changed or non-empty is retained, listed,
and the command exits 3 (incomplete removal). `--purge` also removes `state/`
(credentials, the provider secret file store, consumed-request tombstones and
audit history) without following any link. `--purge --remove-accounts` also
removes the
accounts and groups this installer created and its memberships, but only when
nothing provider-owned was retained. Their GeneratedUIDs are first written to the
root-owned `/Library/VaultwardenAccess/account-tombstones.json`, which stays
after removal: a later install refuses a removed GeneratedUID, so a recreated
account can never revive old enrollment. The operator account is never touched.

`/usr/bin/python3 -I scripts/test-macos-provider-install.py` exercises all of this under a
temporary root prefix with fake `dscl`, `dseditgroup`, `dsmemberutil`,
`launchctl`, `chown`, `stat`, `codesign` and `lipo`, including a crash after
every single step of install, upgrade, rollback and full removal; no test uses sudo,
creates an account, writes to `/Library` or talks to launchd. A real installation
on a Mac has not been performed.

## macOS provider credentials and companion enrollment

The complete post-install sequence (certificates, `backend.json`, the API client
secret, enrollment, the companion app, an agent account and key) is
[macos-setup.md](macos-setup.md). The installer prints a summary; this is the
reference for what it checks. Each state file is provider-owned, mode `0600`,
one link:
`sudo install -o _vwaccess -g _vwaccess -m 0600 <file> /Library/VaultwardenAccess/state/<name>`.

- `provider-cert.pem` / `provider-key.pem` / `companion-ca.pem`: generated by
  `vw-access setup tls` (as the operator). The server certificate carries
  **subjectAltName IP:127.0.0.1** with server-auth usage; `companion-ca.pem` is
  the **client** CA that verifies companion client certificates, not the server
  CA. The companion app itself needs the server CA (DER), the server leaf pin and
  its own client PKCS#12.
- `backend.json`: written by `vw-access setup backend-json --from-cli-login --kdf
  pbkdf2 --kdf-iterations N` (N is the account's PBKDF2 iteration count, shown in
  the web vault under Settings > Security > Keys; both flags are required and
  Argon2id accounts are refused) with the account setup fields described in [access-mvp.md](access-mvp.md#human-setup-and-launch):
  `server` (an HTTPS origin), `client_id`, `email`, `encrypted_key` and
  `kdf_iterations`, plus `encrypted_private_key` and `org_keys` for organization
  bindings. No secrets.
- The API client secret: a file store under `state/secrets/` (provider-owned
  `0700`; each record a provider-owned `0600` single-link file), written by the
  provider itself, prompted without echo:
  `cd / && sudo -u _vwaccess /Library/VaultwardenAccess/versions/<version>/vaultwarden-accessd --state-root /Library/VaultwardenAccess/state --store-bootstrap-secret`.
  The installer requires `secrets/` and
  `vaultwarden-accessd.bootstrap-client-secret` with that owner and mode before it
  starts the service: without the secret the provider fails closed and launchd
  would restart it in a loop.
- The companion registry `state/companion-identities.json`: written by the
  provider's `--companion-enroll-cert` (below), provider-owned `0600`, one link.
  The installer requires it before it starts the service, for the same reason.

After storing the secret, enroll the companion client certificate with the
service stopped (after a fresh install it has never started; `stop` is then
harmless), and only then start it. The client PEM must be provider-owned `0600`
with one link, so copy it in rather than pointing at your own file:

```bash
sudo /usr/bin/python3 -I $I stop --acknowledge-active-work
sudo install -o _vwaccess -g _vwaccess -m 0600 ~/vw-setup/tls/companion-client.pem /Library/VaultwardenAccess/state/companion-client.pem
cd / && sudo -u _vwaccess /Library/VaultwardenAccess/versions/<version>/vaultwarden-accessd \
  --state-root /Library/VaultwardenAccess/state \
  --companion-enroll-cert /Library/VaultwardenAccess/state/companion-client.pem \
  --companion-client-ca /Library/VaultwardenAccess/state/companion-ca.pem --companion-label "Mac operator"
sudo rm /Library/VaultwardenAccess/state/companion-client.pem
sudo /usr/bin/python3 -I $I start
```

The administrative CLI is `/Library/VaultwardenAccess/versions/<version>/vw-access`
(its default state root is the human endpoint `/Library/VaultwardenAccess/run/human`),
reachable by the operator through the human group. Restricted agents create their
key with `vw-access setup agent-key` and use
`/Library/VaultwardenAccess/run/agent/agent.sock` with their own UID and the agent
GID. The provider always starts locked: unlock with a fresh password approval in
the companion.
