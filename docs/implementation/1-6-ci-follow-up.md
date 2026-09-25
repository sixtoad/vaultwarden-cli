# Story 1.6 CI follow-up

The initial [PR #24 CI run](https://github.com/sixtoad/vaultwarden-cli/actions/runs/36136046822)
exposed platform compilation failures and a vulnerable locked TLS dependency.
This follow-up preserves the original Story 1.6 verification archive rather than
describing its manifests as current after dependency and compilation-boundary edits.

## Diagnosis and correction

- Both macOS builds and the macOS beta test job failed because `human_socket.rs`
  referenced Linux socket flags. Both Windows builds failed on unconditional Unix
  imports and descriptor/filesystem APIs across the provider and adapters.
- The access architecture's AD-10 scopes this provider to Linux. `access` and
  `adapters` now compile only on Linux. Both provider binaries return exit 1 and
  fixed unsupported-platform diagnostics elsewhere, before parsing caller input
  or accessing state. Linux implementation bodies and existing test identities
  are preserved. The general CLI remains cross-platform.
- Linux-only integration suites have matching compilation gates. A separate
  native unsupported-platform test checks both binaries, help/version/malformed
  and valid-shaped inputs, exact redacted output, and no filesystem creation.
- The Linux stable/beta and macOS stable test jobs were **cancelled**, not
  demonstrated test failures. Test-matrix fail-fast is now disabled so each
  platform can complete independently. No existing matrix target was removed.
- The audit rejected rustls 0.23.43 for
  [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285).
  The direct minimum and lock entry are updated to patched 0.23.45. No advisory
  suppression was added.

## Verification

All required local checks completed:

| Check | Exit | Elapsed |
|---|---:|---:|
| `cargo fmt --all -- --check` | 0 | 1.221 s |
| `cargo test --all-targets --locked --offline` (Rust 1.98.1) | 0 | 404.421 s |
| `cargo clippy --all-targets --all-features --locked --offline -- -D warnings` | 0 | 42.454 s |
| `rustup run 1.88.0 cargo test --all-targets --locked --offline` | 0 | 346.048 s |
| `cargo audit --json` (0.22.2) | 0 | not timed |
| `cargo deny check all` (0.20.2) | 0 | not timed |

Both full suites used the checked-in secure-temp wrapper with `RUST_TEST_THREADS=4`.
Each reports 774 passes across 16 targets: 703 non-live tests executed, 71 live-account
early returns and 13 additional benchmark smoke checks. The library has 518 passes
and nine ignored entries; eight are fixtures invoked by passing parents, and the
browser fixture was not run. The new non-Linux test target has zero tests on Linux.
Real Linux descriptor execution, deterministic races and all 66 original acceptance
matrix tests passed. No new live-account or browser coverage is claimed.

The 69 input hashes were stable throughout both local runs. Afterward, only the CI
Windows test step and the non-Linux-only regression test were refined; production
Rust, dependencies and Linux test inputs still match. Formatting and whitespace
checks were repeated. Both source snapshots are retained in
[CI evidence](1-6-ci-evidence/results.json), with [raw logs](1-6-ci-evidence/raw.tar.gz)
and [checksums](1-6-ci-evidence/SHA256SUMS).

Audit reports zero vulnerabilities under the existing repository policy. The prior
RSA advisory exception was not changed. Audit/deny still warn about the existing
yanked `chacha20 0.10.1` dev dependency; deny also reports existing duplicate
versions. All four deny categories pass; no new exception was added. The official
cargo-deny release checksum was verified. Its redundant source-build attempt was
stopped after cargo-audit finished installing; no interrupted test or audit is
counted as successful verification.

Native macOS/Windows checks require their CI hosts, not Linux cfg simulation. The
macOS stable/beta suites exercise the unsupported-platform test, and the Windows
x86_64 build job explicitly runs it. Both Windows architectures and both macOS
architectures retain build jobs. Native results are pending publication at the time
of this local evidence snapshot; see the latest [PR checks](https://github.com/sixtoad/vaultwarden-cli/pull/24/checks).

The workflow's blind review completed. Its five findings were documentation and
regression-test gaps: final result recording, bounded child execution, existing-state
preservation, valid environment-only commands and non-Unicode arguments. All were
patched. No new production defect or additional deferred item was identified.

## Retained security evidence

All 44 production function/constant ranges in the original mutation provenance
still match their recorded SHA-256 hashes. No descriptor, path, ownership,
permission, digest, approval-precondition or secret-resolution algorithm changed.
The original 585-case inventory remains historical evidence for those unchanged
algorithms; it is not claimed as rerun for this correction. The new platform
boundary is checked by native builds and the unsupported-platform process test.
The previously deferred durable snapshot hashing cost remains deferred.
