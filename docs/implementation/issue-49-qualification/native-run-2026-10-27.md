# Authorized M1 qualification observations

The user authorized the prepared unprivileged run on the existing M1 Mac mini on 2026-10-27. All work used a new private directory, `/private/tmp/vw49-qualification.NYd1dF`, with separate source copies and evidence per attempt. No service/account installation, production credentials, Keychain change, production signing or toolchain installation occurred.

The host was Apple M1, native arm64, macOS 27.0.1 build 26A434, with Python 3.9.6. This is evidence for that host, not certification of macOS 13, other releases, Intel or Rosetta.

## Results

| Check | Observed result |
| --- | --- |
| Corrected native probes | All nine observations passed: disposable signatures, peer UID, wrong expected UID, writable-path replacement negative control, invalid image rejection, private-channel inspection, crash, descendants, descendants with parent crash |
| Native harness unit tests | 15 passed, one Linux-only test skipped; 16 total, Python 3.9.6 |
| Linux harness unit tests | 16 passed after the compatibility correction |
| Recorded fixture identities | Eight kernel exit observations; independent follow-up found all eight absent; no unwaited direct children |
| Cargo unsupported-platform regression | Passed on the subsequent authorized continuation: one native test executed, exit 0, existing Cargo/rustc 1.99.1; the earlier offline attempt remains recorded as unavailable |
| Production qualification | Blocked: no mechanism selected, all sixteen production requirements remain unavailable |

The corrected run's [result](evidence/macos-arm64-2026-10-27-attempt-2/result.json), [observations](evidence/macos-arm64-2026-10-27-attempt-2/observations.json), [process follow-up](evidence/macos-arm64-2026-10-27-attempt-2/post-run-observation.json) and [native harness tests](evidence/macos-arm64-2026-10-27-attempt-2/portable-tests.json) are retained. The [original Cargo receipt](evidence/macos-arm64-2026-10-27-attempt-1/unsupported-platform-regression.json) records the exact earlier source copy and its unavailable result. The [subsequent passing receipt](evidence/macos-arm64-2026-10-27-regression-2/unsupported-platform-regression.json) identifies the corrected source copy; production Rust files are identical in both copies.

## Completed native platform regression

After the user instructed continuation, `cargo fetch --locked --target aarch64-apple-darwin` populated a new private cache under `regression-attempt-2/` in the existing temporary workspace. This downloaded project dependencies without installing a toolchain or changing system services. The exact regression command then ran with networking disabled and returned exit 0. Its single test checked both protected binaries against valid, invalid and non-Unicode arguments, with empty and prepopulated state; it verified the fixed rejection message, empty stdout and unchanged state/configuration.

The complete source manifest was identical before and after execution (`66c08ffd5deb9b0033c97bab66f6b4225b319c2e3d1d9984a761580bf6047d4a`). The retrieved receipt, manifest digest and qualification source-hash digest were independently checked locally against the retained evidence and tested code. The private cache, build outputs and diagnostics remain in the temporary workspace; only the receipt and source manifest were retrieved. This passing regression establishes preserved rejection behavior, not native protected execution.

Exit 2 from the corrected runner means qualification is blocked, even though its primitive observations passed. A successful replacement negative control demonstrates the weakness of checking a writable pathname before executing it; it does not establish a safe replacement mechanism. Same-account UID/inspection observations do not establish isolation from restricted agent accounts. Observed exits of bounded fixtures do not prove containment and reap of arbitrary protected descendants.

## Native-discovered correction and retained first attempt

The original prepared archive had SHA-256 `f11e287cb3db9acf53725aba9a2bcc3b443a1b830c2c29f47196de0f30eb4b12`. Archive contents and all 2,491 source files were verified before execution.

The first attempt completed five observations, then raised an `AttributeError` at the `kqueue` context-manager boundary. Python 3.9 provides `close()` without the context-manager protocol used by the initial harness. The uncaught exception also exposed a reporting defect: its `result.json` incorrectly said blocked with no failures, despite wrapper exit 1. Preserve that original report; the [adjudication](evidence/macos-arm64-2026-10-27-attempt-1/adjudication.json) and [execution receipt](evidence/macos-arm64-2026-10-27-attempt-1/native-run-receipt.json) identify the actual failed outcome. All direct children from this attempt were waited; no descendant fixture was released.

The correction uses `contextlib.closing` and `ExitStack` for queue/descriptor cleanup, and records unexpected runtime exceptions using a closed failure code and active case. Two focused tests cover the observed defects. Only the harness and its unit tests changed; the C fixture and production code did not.

A new source copy received those two verified files, with full manifest SHA-256 `66c08ffd5deb9b0033c97bab66f6b4225b319c2e3d1d9984a761580bf6047d4a`. The [corrected execution receipt](evidence/macos-arm64-2026-10-27-attempt-2/native-run-receipt.json) records the reason for the new attempt and unchanged source verification. This was a diagnosed correction, not an automatic retry of the failed source. The locally retrieved manifest and executable/harness source hashes were independently checked against the tested files. Documentation subsequently updated to describe the results is not the earlier tested documentation snapshot.

## Remaining boundary and retained resources

Separate agent identities, key/server authentication, a supported all-descendant containment contract, exact executable launch, service Keychain, recovery, lock/expiry/revocation and production signing remain unqualified. The [containment audit](containment-decision-2026-10-27.md) records concrete limitations from the actual host's manual/SDK and Apple sources. No native platform implementation was enabled and issue 49 remains open.

Private synthetic materials and evidence remain in the run directory as specified by the retention policy. `cleanup.json` intentionally remains `uncertain-retained` for production cleanup: independent fixture exit/absence observations do not authorize claiming `CleanupEvidence::Reaped` for a future provider. No running recorded fixture was left behind. Only redacted JSON, source/signature metadata and manifests were retrieved; raw diagnostics and synthetic material were not copied into the repository.
