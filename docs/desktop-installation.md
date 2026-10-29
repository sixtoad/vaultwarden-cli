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
| macOS | `vaultwarden-cli`, command launcher | Vault CLI works. Flutter approves through the existing pinned-TLS Linux-provider connection. Protected `vw-access` requesting and native provider execution are unavailable; #49 owns that port. |
| Windows | `vaultwarden-cli.exe`, command launcher | Vault CLI works. Protected requesting/provider execution and Flutter approval transport are unavailable. |

The manifest records the actual app, core and CLI versions separately: currently
0.1.0+1, 0.1.0 and 0.5.4. Equal version strings are not the compatibility rule.
Bundle schema 1, launcher ABI 1, the expected runtime platform/architecture and
running app/core versions are checked. Old ABI-1 command launchers can select
new compatible app/core versions. A bundle records its host command architecture;
a universal macOS Flutter/core build does not make its command tools universal.

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
app structure, libraries, executable modes and links. On Linux the host needs a
compatible GTK 3/glibc desktop runtime; protected provider operation additionally
needs the existing Linux systemd/DBus setup and independently authorized provider
configuration. Installation does not start or configure a privileged service.
Windows ships the app-local MSVC runtime with Flutter and statically links the CRT
for copied Rust command launchers/tools. macOS preserves the app sandbox.

Open the normal application, then Settings → Desktop installation. Inspection
shows the bundled tool path and version separately from terminal PATH resolution.
It never executes a PATH candidate to discover its version. Missing, damaged,
incompatible and conflicting installations give repair/update guidance.

Choose **Enable / repair user commands**. On macOS a native folder chooser grants
write access to the selected directory for this operation only; select or create
a bin directory inside your home. Linux/Windows show the exact destination and
create the selected user directory on the explicit action. Directories outside
your account home, unsafe links and unrelated commands are refused. A directory
must be owned by you and not writable by other users on Unix.

The operation publishes native command launchers and one activation receipt.
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
Recovery does not execute or delete unrelated files. Retained ABI-1 launchers
are compatible with newer component versions; a future launcher ABI requires a
separately qualified migration.

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
tracked diffs, all tracked/untracked input paths and hashes. Packaging refuses
if any source input changes during build, recording `source-changed-paths.json`.
The historic PR #52 Windows `source_dirty=true` artifact did not retain paths;
it cannot establish a cause. A matching instrumented Windows run must identify
and explain it before clean provenance is claimed. Never force the flag false
or broadly ignore files to make the report clean.
