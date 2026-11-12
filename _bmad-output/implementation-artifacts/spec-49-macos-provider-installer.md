---
title: Native macOS provider installer, upgrade, rollback and uninstall
type: feature
created: 2026-11-09
status: in-review
baseline_commit: 7bc3753
context: [docs/secret-access-boundary.md, docs/implementation/issue-49-native-provider.md, docs/native-macos-plan.md]
---

<frozen-after-approval reason="explicit implementation request supplied by the orchestrator">

## Intent

**Problem:** Nothing installs the native Apple Silicon provider. `scripts/macos-provider-plan.py` resolves templates only, and its `plan.json` lists four of the files the documented layout needs.

**Approach:** Make `plan.json` describe every directory and file of the documented layout (owner, group, mode, link count, who creates it), then add a stdlib-only installer that executes exactly a reviewed plan directory plus a validated arm64 bundle: dry run, install, upgrade, rollback, uninstall and status. It creates accounts, the secure empty layout, versioned binaries and the LaunchDaemon; it never generates or copies credentials.

## Boundaries & Constraints

**Always:** Python 3.9 compatible (sudo runs `/usr/bin/python3`). Fail closed and idempotent. Arm64 macOS for every command; euid 0 for mutating ones. Fixed validated IDs; refuse every UID/GID/name collision; adopt an existing account only with an explicit flag. Never overwrite a version directory; one hard link and bundle-manifest hashes for every copied binary. Upgrade order: verify new version, close admission (`launchctl disable`), `bootout`, switch plist, `enable`, `bootstrap`; the provider restarts locked. Preserve state, Keychain and accounts by default. `--root` test prefix only with fake tools.

**Ask First:** Real privileged installation (the owner runs it).

**Never:** sudo, real accounts, writes to `/Library`, real `launchctl` in tests. Never kill or contain consumer processes (AGENTS.md). Never generate, copy or delete credentials or Keychain items. Never run the daemon as root.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected | Error handling |
|---|---|---|---|
| Dry run | any plan + bundle | prints every action | writes nothing, runs no mutating tool |
| Fresh install | free IDs | accounts, layout, version, plist; starts only when credentials are present | — |
| Re-run | installed | no mutation | — |
| Upgrade | new version | verify → disable → bootout → switch → enable → bootstrap | failed verification leaves current version |
| Rollback | previous version recorded | same switch order | requires state-compatibility acknowledgement |
| Uninstall | installed | service, plist, versions, identities removed; state/accounts/Keychain kept | uncertain resources retained and reported |
| Purge | `--purge` | state removed too; Keychain listed for manual removal | — |
| Collision | ID or name taken | refuse before any write | — |
| Existing version | `versions/<v>` differs | refuse | — |
| Wrong arch / non-root | — | refuse | — |
| Hard link / tampered binary | bundle payload | refuse before staging completes | — |

</frozen-after-approval>

## Code Map

- `scripts/macos-provider-plan.py` -- plan generator; gains provider GID, human/agent group names and the full layout.
- `scripts/macos-provider-install.py` -- new installer.
- `scripts/test-macos-provider-plan.py`, `scripts/test-macos-provider-install.py` -- unittest suites with fake tools.
- `scripts/test-desktop-companion.sh` -- runs both suites.
- `docs/desktop-installation.md`, `docs/implementation/issue-49-native-provider.md`, `companion/lib/provider/support_views.dart` -- procedure and truthful status.
