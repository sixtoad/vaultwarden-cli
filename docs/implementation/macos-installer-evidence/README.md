# Local Mac installer evidence — 2026-10-08

Prepared from merged main `0a96b2bdc0f6cad1337c84f19145c728454c3558` on branch `feature/macos-companion-installer`. Only the new packager and installation documentation change product source. The Swift application, package, test sources and existing app builder match the baseline byte for byte; `source-manifest.json` records the transferred inputs. No provider or SSH implementation changes.

## Delivered artifact

- `Approval-Companion-0.1.0-1-arm64.dmg`, 258049 bytes.
- SHA256: `63d661827435a214272cd6596a72b0fcfe770c9a4547f37445ea352b5f240beb`.
- The DMG and matching `.sha256` file were copied without overwriting existing files into the operator Mac's Downloads and this checkout's ignored `macos/dist/` directory. See `delivery.json`.
- Apple Silicon, macOS 13 minimum; ad-hoc development signing, no Developer ID or notarization. This is a local artifact, not a published release.

## Verification

The actual image was built on the operator's Apple Silicon Mac using the existing release app builder. `package.log` records the successful build, plist validation, signature verification and image integrity check.

`verification.json` records successful compressed UDZO image verification, read-only mount, exact three volume entries (app, Applications shortcut and README), arm64 executable, bundle ID/minimum OS/unchanged ATS policy, strict signature validation, system-only library dependencies, and byte equality plus signature verification after copying the app to a disposable installation directory. The image was detached. `verify-artifact.py` preserves the verification procedure. The installed app was neither replaced nor launched; settings, Keychain, login registration and provider state were untouched.

All four native negative cases passed; nonzero packager exit codes are expected rejections:

1. Existing DMG/checksum retained byte for byte.
2. Existing dangling checksum symlink preserved.
3. Unsupported hard links rejected before any Swift build.
4. Injected checksum publication failure removed the invocation's partial DMG while preserving the competing checksum.

See `failure-tests.json`, the four case logs and `failure-checks-as-run.py`. The last script preserves the exact private temporary paths used for this run. There were no surviving injected packaging faults. Bash syntax and `git diff --check` passed on Linux.

The first native attempt used an incomplete transferred snapshot: SwiftPM rejected missing test target sources even for a release build (`initial-incomplete-snapshot.log`). The snapshot was corrected to include the declared test sources and fixtures; the same product script then built successfully. This was a transfer omission, not an app or packaging code failure.

## Review triage

One independent packaging review identified three findings:

- **Medium, fixed:** a failure publishing the checksum could leave a partial image. EXIT cleanup now removes only final hard links belonging to that invocation; the native race injection verified preservation of competing output.
- **Low, fixed:** hard-link-incompatible output filesystems failed late. A pre-build capability check now gives APFS/HFS+ guidance; documentation explains copying completed files to exFAT. Native injection proved no build was started.
- **Low, addressed in verification:** image integrity alone does not establish mounted payload contents. The actual delivered image was mounted read-only and its app copied and verified as described above. Routine packaging retains its signature and image-integrity checks; it does not automatically mount every output.

## Scope and limitations

No missing infrastructure blocked this packaging task. Full Swift/provider tests, prior security mutation suites and logged-in notification/password/login/sleep acceptance were not repeated: their application source is unchanged from the merged feature. This record establishes installer packaging and copy integrity, not a fresh end-to-end acceptance run. GUI drag-install, first-launch Gatekeeper behavior and minimum macOS 13 execution were not tested in this packaging run. No notarization or public release was attempted. The user subsequently authorized opening a pull request and publishing the verified DMG on GitHub; release publication does not add notarization or further acceptance results.
