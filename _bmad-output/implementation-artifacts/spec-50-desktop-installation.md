---
title: Desktop bundle installation and command repair
type: feature
created: 2026-10-29
status: in-progress
baseline_commit: 60fadd6
context: [docs/secret-access-boundary.md]
---

<frozen-after-approval reason="explicit implementation request supplied by the user">

## Intent

**Problem:** Desktop Flutter artifacts omit applicable command-line tools and have no inspectable compatibility or working command activation. Users cannot distinguish a missing terminal command from a damaged or unsupported bundle.

**Approach:** Deliver coherent platform bundles with build-derived manifests, runtime validation, real Settings inspection and explicit user-level activation/repair. Preserve independent component versions, platform signing and last usable bundles. Installation confers no vault authority.

## Boundaries & Constraints

**Always:** Use normal Flutter entrypoint. Validate manifest and actual components together; show truthful requesting/approving/executing roles. Keep independently versioned app/core/CLI versions. Separate bundled presence from PATH resolution. Treat filesystem, manifests and command candidates as untrusted. Never execute discovered PATH commands to determine versions. Capture exact dirty paths/diffs and input hashes before/after builds. Use isolated temporary roots and CI only. Keep protected access named `vw-access`.

**Ask First:** Any production installation, system-level PATH/service changes, credentials or trust-store changes. Those actions are outside this implementation task.

**Never:** Change Activity, enrollment, device administration, approval protocols or abuse protection; promise macOS provider execution (#49); overwrite unrelated commands; disable signing/security checks; silently install into real user locations. Do not rename prototype product. Do not merge the PR or close issue #50.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|---|---|---|---|
| Valid bundle | Manifest and payload match | Actual versions, roles, identity and paths | No invented compatibility from version equality |
| Missing/damaged | Missing executable/library or hash/mode mismatch | Distinct missing/damaged state | Refuse activation; replace complete bundle |
| Incompatible | Unknown schema or incompatible protocol/core | Incompatible state | Explain whole-bundle update |
| PATH conflict | Earlier unrelated executable | Show conflicting path without running it | Never replace it |
| Enable/repair | Explicit action, user destination | Usable platform-appropriate command | Atomic publication and recoverable old state |
| Hostile paths | Symlinks/reparse points, unexpected files, unsafe names | Fail closed | Leave unrelated data untouched |
| Move/upgrade | Old activation, new validated app | Explicit repoint to complete bundle | Failure preserves last usable activation |
| Mobile | Actual Android/iOS platform, any screen width | No desktop installation controls | Compact desktop still has controls |
| Windows provenance | Build changes tracked/untracked files | Record exact paths, hashes and relevant diffs | Fix proven cause; preserve truthful dirty flag |

</frozen-after-approval>

## Code Map

- `scripts/desktop-companion-artifact.py`, `scripts/test-desktop-companion-artifact.py`: current archive inventory and extraction verification.
- `scripts/test-desktop-companion.sh`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`: native matrix, normal entrypoint rebuild, publication.
- `scripts/build-macos-companion.sh`, `scripts/package-macos-companion.sh`: legacy Swift packaging; preserve identity and clarify distinct artifacts.
- `companion/lib/provider/page.dart`, `support_views.dart`: Settings insertion only, avoid Activity changes.
- `companion/lib/platform/`, `companion/rust/src/api/`: add narrowly scoped installation interfaces if needed; regenerate any bridge changes using pinned tools.
- `Cargo.toml`, `companion/pubspec.yaml`, `companion/rust/Cargo.toml`: version authorities.
- `src/bin/`: Linux-only protected commands explicitly fail on other platforms. Cross-platform `vaultwarden-cli` is functional.

## Tasks & Acceptance

**Execution:**
- [x] Implement and test build-derived bundle manifest and complete payload validation, compatibility, platform capabilities and artifact identity.
- [x] Package app and applicable CLI/helpers for three desktop platforms, retain executable modes/libraries and normal entrypoint; integrate release and native CI.
- [x] Implement installation inspection, terminal resolution, explicit enablement/repair with platform mechanisms and failure-safe activation, isolated tests for the matrix above.
- [x] Add Settings UI, actual runtime mobile exclusion, actionable guidance, widget tests and visually inspected synthetic captures.
- [x] Capture Windows provenance at relevant build stages; establish exact source_dirty cause with matching CI evidence and fix only explained changes.
- [x] Update capability checklist, migration/installation docs and reproducible isolated upgrade/repair instructions with real prerequisites and remaining dependencies.
- [ ] Run full affected Rust/Flutter/analyzer/packaging/native CI; obtain independent review, fix findings, integrate current main and create draft PR related to #50.

**Acceptance Criteria:**
- Given a supported platform bundle, when extracted, then the normal app and every applicable command/library exist with recorded hashes, modes, versions and supported roles.
- Given an explicit command activation in an isolated user root, when invoked, then the packaged command runs; repeating or moving/repairing is deterministic without mixing components.
- Given interrupted staging/activation or conflicts, when inspected, then the last usable installation remains recoverable and no unrelated command or authority changes.
- Given different app and CLI version strings with compatible contracts, when inspected, then compatibility succeeds; incompatible contracts fail.
- Given the exact tested commit, when reviewing the draft PR, then evidence distinguishes passing platform checks from unresolved external dependencies and documents narrow shared interfaces.

## Spec Change Log

## Design Notes

The source-backed platform inventory supersedes historical prose: Linux has `vw-access`, `vaultwarden-accessd`, `vaultwarden-access-exec` and `vaultwarden-cli`; macOS/Windows must not ship unsupported protected-command stubs as functioning roles. macOS has real Flutter password approval; Windows/Linux Flutter provider transport remains absent. Consumer execution ownership follows the current boundary document.

## Verification

Full affected Rust suites and Clippy/rustfmt; full Flutter test/analyze plus isolated repair and platform UI tests; artifact tests and extracted command invocation; macOS/Windows/Linux matching CI and archive inspection. Preserve native security/mutation gates and exact golden comparisons. Any signing/hardware/host limitation remains explicit.

## Review and local verification

Three independent reviews (blind diff, edge cases, acceptance) were completed and all concrete findings remediated; follow-up reviews found no remaining blockers. Local verification: 58 companion Rust tests passed (packaged invocation separately passed), Clippy/rustfmt clean; 81 Flutter tests passed, analyzer clean; bundle/artifact/diagnostics Python suites passed. Normal macOS release bundle, signature, extracted inventory and production launcher invocation passed. Root Rust suite: 542 passed. Windows permission module cross-compilation passed; native CI remains authoritative.

Windows initial CI recorded exactly seven Flutter generated plugin files changing from checkout CRLF to generator LF, with no semantic changes and hashes matching PR #52. Exact-path .gitattributes rules preserve LF under core.autocrlf=true; a real-checkout regression verifies the fix. The interactive macOS sandbox picker was exercised successfully by the user in a uniquely identified test app; the installed launcher independently returned vaultwarden-cli 0.5.4 with empty PATH. Final native matrix evidence remains pending.

## Main integration

Integrated current main `07b10e7` (merged Activity #54), preserving its authenticated history and future-access-only revocation contract. Rust/Dart bridge regenerated with pinned FRB 2.13.0 for both Activity and installation APIs. Settings retains both features. Windows packaging now resolves the native Flutter batch launcher explicitly; regression runs a real batch file from a path containing spaces. No Activity protocol implementation was changed by this slice.
