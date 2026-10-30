# Desktop bundle installation and terminal commands

This package contains the existing Flutter `companion_slice` application and
applicable command-line tools. It does not rename the product or replace the
separately supported Swift Approval Companion. Build one bundle with
`scripts/build-desktop-bundle.sh /absolute/private/evidence` on the target OS.
Flutter 3.47.7, the locked Rust toolchain dependencies and native build tools are
required. The CI desktop matrix performs the full native gates before packaging.
The release workflow publishes the same coherent **development** archives.
macOS distribution signing/notarization remains a publisher prerequisite;
this helper refuses to replace a non-ad-hoc signature with development signing.
Do not bypass Gatekeeper, remove quarantine or modify an installed application.

| Platform | Bundled tools | Request / approve / execute capability |
| --- | --- | --- |
| Linux | `vaultwarden-cli`, `vw-access`, `vaultwarden-accessd`, `vaultwarden-access-exec`, command launcher | `vw-access` requests protected work; provider/helper implement approved Linux delivery. Flutter provider transport/approval is unavailable. |
| macOS, Apple Silicon (arm64) | `vaultwarden-cli`, `vw-access`, `vaultwarden-accessd`, command launcher | Vault CLI works. `vw-access` and the native provider are bundled in `Contents/Helpers` and advertised. Installing the provider into `/Library/VaultwardenAccess` and its launchd service is a reviewed manual step: `scripts/macos-provider-plan.py` resolves the templates into files, and nothing installs them yet (see below). Development signing only. Flutter approves through the existing pinned-TLS Linux-provider connection; approving the native provider from the app is tracked in #49. Guided enrollment and notifications are not available (#59, #61). |
| macOS, Intel (x86_64) | `vaultwarden-cli`, command launcher | Vault CLI works. Flutter approves through the existing pinned-TLS Linux-provider connection. The native provider rejects Intel and Rosetta, so an Intel bundle neither ships nor advertises `vw-access`/`vaultwarden-accessd`. |
| Windows | `vaultwarden-cli.exe`, command launcher | Vault CLI works. Protected requesting/provider execution and Flutter approval transport are unavailable. |

The manifest records the actual app, core and CLI versions separately: currently
0.1.0+1, 0.1.0 and 0.5.4. Equal version strings are not the compatibility rule.
Bundle schema 1, launcher ABI 1, the expected runtime platform/architecture and
running app/core versions are checked. Old ABI-1 command launchers can select
new compatible app/core versions. A bundle records its host command architecture;
the normal macOS app is built for the same host architecture as its commands. The core may retain universal library slices, but the application is explicitly single-architecture. An Intel archive on Apple Silicon requires an already available Rosetta environment for the vault CLI; the package never installs Rosetta or claims a native ARM command, and macOS protected commands are only in arm64 bundles. The `vaultwarden-access-exec` helper is Linux's systemd helper and is not shipped on macOS: the native provider does not use it.

The CI and release desktop matrices currently build the macOS bundle on an Intel runner, so published macOS archives do not yet contain the protected commands. Build on an Apple Silicon host with `scripts/build-desktop-bundle.sh` to obtain an arm64 bundle. A command folder enabled from an earlier macOS arm64 bundle (which listed only `vaultwarden-cli`) is reported as an incompatible command setup by the new bundle: enable commands in a new empty user folder, as for any command-set change.

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

## macOS provider installer plan (review material, installs nothing)

`scripts/macos-provider-plan.py` resolves
`packaging/macos/native/com.cantolla.vaultwarden-accessd.plist.in` and
`native-identities.json.in` from explicit inputs into a new or empty output
directory you choose:

```bash
python3 scripts/macos-provider-plan.py --output ~/vw-provider-plan \
  --version 0.5.4 --provider-account _vwaccess --provider-group _vwaccess \
  --provider-uid 491 --provider-uuid <32 lowercase hex> \
  --operator-uid 501 --operator-uuid <32 lowercase hex> \
  --human-gid 492 --agent-gid 493 [--bundle /path/to/companion_slice.app]
```

Every input is validated (decimal non-zero IDs, distinct provider/operator UIDs
and UUIDs, distinct human/agent GIDs, lowercase 32-hex GeneratedUIDs without
dashes, short account/group names, `MAJOR.MINOR.PATCH[-pre]` version), and any
`@PLACEHOLDER@` left after resolution is an error. The resolved plist keeps
`AbandonProcessGroup`, zero core limits and `/dev/null` standard streams, and
runs `/Library/VaultwardenAccess/versions/<version>/vaultwarden-accessd`, the
bundle's `Contents/Helpers/vaultwarden-accessd` at the bundle's `cli_version`;
`--bundle` checks that version and records the payload hashes. `plan.json` lists
each file's destination, owner and mode from
[the native provider installation surface](implementation/issue-49-native-provider.md#concrete-installation-approval-surface).
The generator runs no command and writes only into the output directory; it
refuses system locations and never overwrites. Copying the files into place,
creating accounts and loading the service remain separately reviewed manual
steps.
