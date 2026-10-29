# Native provider source verification — 2026-10-29

The native Apple Silicon source passed the checks below. This does **not** qualify
an installed service or all macOS versions. See the
[implementation contract and installation requirements](../issue-49-native-provider.md).

The test host was an M1 Mac running macOS 27.0.1 (26A434), Xcode 27.1 (27A9275),
and system OpenSSH 10.3p1. Rust 1.88.0, Clippy and rustfmt were installed only in a
private temporary workspace because the host's default compiler was too old.
That workspace, including its isolated toolchain and build cache, was removed
after verification and evidence collection.
No default toolchain, accounts, installed services, real vault/Keychain records,
or SIP/Gatekeeper settings were changed. Native fixtures used synthetic credentials
and test-only identity injection. The loopback sshd used a synthetic server host
key file; client private keys stayed in the request-local agent's memory.

| Check | Actual result |
| --- | --- |
| `scripts/test-native-protected-macos.sh` | Passed formatting, strict all-target Clippy, 353 library tests and the explicit real OpenSSH test. |
| Final native review fixes | 365 library tests and 12 protected binary/CLI tests passed. Formatting, strict all-target Clippy, the affected environment-delivery test and real OpenSSH passed after the final test-only lint correction. One separately executed OpenSSH test remained ignored in the ordinary suite. |
| Real native OpenSSH | Ed25519, ECDSA P-256/P-384/P-521 and RSA-SHA2-256/512 authenticated; consumers survived agent closure. |
| Linux workspace, all targets | Passed: 773 library tests, integration suites and benchmark executions. Intentionally ignored tests are listed in the retained log. |
| Linux real systemd/SSH | Passed two lifecycle tests, distinct-principal isolation, and the six-algorithm OpenSSH test. |
| Linux Clippy | All targets and all features passed with warnings denied. |
| Dependency checks | Refreshed `cargo-audit` and `cargo-deny check all` passed, with the existing allowed warning for yanked `inout` 0.2.3. |

The stricter optional local recipe enabling Clippy's entire pedantic/nursery groups
was also attempted; it is not clean across the repository. The CI-equivalent
Clippy checks listed above passed. Unrelated lint cleanup is not included here.

The staged-secret scanner reported existing `agent_token` assignments and test
private-key format headers in the three modified shared files. Every reported
line was compared with the merged baseline and is unchanged; the headers are
synthetic serialization/rejection fixtures. Added lines contain none of the
scanner's private-key or credential-token patterns. These verified false positives
were not treated as leaked credentials or silently reported as a clean scanner run.

Native tests exercised approved launch and single consumption, replay, wrong
request identity, revocation, reused account UUIDs, revoked history after account
removal, locked restart, denial, cancellation and expiry before resolution,
unsafe image selection, ACL grants, actual kernel Unix credentials, and withdrawal
without consumer termination. Shared SSH tests verified signatures and rejected
wrong host/session/user, wrong PID and correct PID with wrong code identity. The
code-identity check was exercised both at connection acceptance and final release.
Review added actual mapped-environment/descriptor observation through production
spawn, a same-PID executable transition on an accepted SSH connection, expiry
during recipient validation, private-file ACL rejection, bounded natural reaping,
and malformed loader/FAT/signature-policy rejection. All these tests passed.

The Mac run found and fixed a real signature-selection difference: static default
inspection and execution selected different native slices of system SSH. Each
native slice is now separately validated and included by its exact code hash;
the real interoperability test passed after that correction.

Evidence is retained in
[`evidence/macos-arm64-2026-10-29-native-provider`](evidence/macos-arm64-2026-10-29-native-provider/receipt.json).
The receipt identifies the baseline commit, exact transferred source archives,
the complete script's internal archive, review-fix snapshot and corrections, and
hashes of retained logs. Compressed full file manifests identify the initial tested
source. Final code manifests identify the library/CLI run and final lint/delivery/SSH
run; all 171 final source/build/test files were independently hash-compared on the
Mac. The only difference between those final runs replaces a forbidden macro in an
unused test-only port. The complete script passed before review; its expanded
checks were then run individually with the existing isolated build cache.
Documentation and this evidence record were added afterward. Logs can be read
with `gzip -dc FILE.gz`. This record does not replace later CI results.

Installed distinct-account endpoint/companion approval, service-account Keychain,
launchd stop/reboot/upgrade survival and release signing/packaging remain
unqualified. The macOS 26 CI job has been added but has not run in this local
verification. Native producer/create-secret output remains unavailable and denies
before secret resolution. Intel/Rosetta retain rejection gates; these successful
native runs are not a new Intel/Rosetta qualification result.
