# Story 1.9 native CI extension — completed local evidence

The native CI extension and all confirmed review fixes are implemented. All local
required checks completed. The user approved publication on 2026-10-03. Hosted
Actions completed on 2026-10-03: native x86/ARM tests, Firefox and systemd
passed; the musl build exposed an ABI type mismatch in the supervisor bridge.
The repair and follow-up evidence are recorded below.

## What changed

The test matrix runs native Ubuntu 24.04 x86_64 and ARM64 with stable and Rust
1.88, retaining Linux beta and macOS stable/beta. It runs all targets and the
three existing feature combinations, with explicit doctest passes, locked/offline
Cargo after prefetch, secure temporary ancestry and bounded jobs.

Separate Firefox and real user-systemd jobs run on both Linux architectures and
are prerequisites for Merge Ready and release-tag detection. Browser setup uses
Node 24, locked npm dependencies, the runner Firefox executable and NSS certutil;
it warms the CLI/fixture and uses locked/offline Cargo for the actual launch.
Systemd setup starts and checks the user manager and a transient unit before
running the existing synthetic cleanup/recovery harness. Missing prerequisites
fail rather than silently skip assertions.

AArch64 fixtures now preserve the argument/environment oracle, concurrent output,
signal handling, detached descendants and readiness semantics. The former ARM
exit-only shortcut is removed and descriptor/output assertions run on ARM too.
`scripts/check-native-fixtures.sh` reproduces all four embedded bytecode files,
rejects relocations and cross-compiles the C fixture with warnings denied. Linux
CI runs it. ARM C cross linking also produced an ELF64 EXEC without an interpreter;
[ELF evidence](1-9-evidence/native-ci/aarch64-cross-linked-elf.log.gz) is retained.
Cross compilation is not a runtime result.

Review also corrected the history form's stalled-fetch/body recovery with a
15-second abort deadline, made U+200B/U+2060/U+FEFF visible in both renderers,
included the terminal newline in its output bound, and strengthened browser
limit/refresh and mutation-selector verification. Authentication, lifecycle
persistence and cleanup authority boundaries remain unchanged.

## Final verification

| Check | Completed result |
| --- | --- |
| Stable 1.98.1, all targets | 839 passed, 0 failed, 13 accounted fixture ignores; 13 benchmark smoke checks |
| Rust 1.88.0, all targets | 839 passed, 0 failed, 13 accounted fixture ignores; 13 benchmark smoke checks |
| Human CLI, direct-request/persistence, provider-session integrations | 12 passed, 0 failed |
| Firefox 151.0.2 | All history/authentication/escaping/race/limit/deadline assertions passed; axe 24 passes, 0 violations; 0 unexpected diagnostics |
| Real user-systemd 255.4 | 2 tests passed, 29 scenarios plus panic cleanup, 0 failed |
| Doctest configurations | Stable/MSRV × default/all/no-default features: 6 commands passed; currently 0 defined doctest examples |
| Formatting and strict all-target/all-feature Clippy | Passed |
| actionlint 1.7.11 + ShellCheck 0.9.0, fixture assembly/C checks | Passed |
| Verification/mutation-selector guard tests | 17 isolated cases passed, including interrupted-mutation restoration |
| git diff --check | Passed |

[Exact commands, durations and exits](1-9-evidence/native-ci-review/verification-results.json),
[doctest commands](1-9-evidence/native-ci-review/doc-results.json),
[static checks](1-9-evidence/native-ci-review/static-checks.json),
[counts and browser assertions](1-9-evidence/native-ci-review/summary.json), and
[the final runner](1-9-evidence/native-ci-review/final-runner.py) are retained.
Source and workflow hashes stayed unchanged throughout verification:
[source manifest](1-9-evidence/native-ci-review/source.sha256),
[workflow hash](1-9-evidence/native-ci-review/workflow.sha256).

The [13 ignored entries](1-9-evidence/native-ci-review/ignored-fixtures.json)
comprise nine subprocess helpers exercised by their parent tests, one browser
fixture exercised by Firefox, one internal systemd fixture and two opt-in
integration tests exercised by the dedicated systemd job. The systemd invocation
filters its ordinary journal helper test, which the all-targets suite exercises.
Benchmark smoke checks do not measure large-history latency.

## Scoped mutation evidence

All **15 extension mutation executions were caught**: three native-oracle guard
mutations and twelve reviewed CLI/browser mutations. The latter comprise five
terminal cases (control escaping, each new invisible character, newline bound)
and seven browser cases (control/HTML escaping, each new invisible character,
selected limit, and the recovery deadline).

Of the twelve, eight failed direct assertions and four failed bounded 30-second
browser assertion waits at the intended conditions. All process budgets were
240 seconds; there were **no process timeouts, build/infrastructure failures,
survivors or equivalent classifications**. The fixture campaign's three cases
failed direct assertions. Source/fixture hashes confirm restoration.

- [Fixture mutation results](1-9-evidence/native-ci/fixture-mutations.json) and [runner](1-9-evidence/native-ci/fixture-mutation-runner.py).
- [Reviewed renderer/browser results](1-9-evidence/native-ci-review-mutations/results.json), [classification audit](1-9-evidence/native-ci-review-mutations/classification-audit.json), and [runner](1-9-evidence/native-ci-review-mutations/runner.py).

Three of the twelve repeat previously covered display guards; nine are new.
Together with three new fixture cases and the original 44 mutation cases, there
are 56 distinct cases across the recorded phases. The original 44 were not all
rerun wholesale: three were repeated here, and earlier evidence for unchanged
history projections, authorization, ordering, persistence and recovery remains
in [the original classifications](1-9-mutation-classifications.md). Do not treat
all historical evidence as one identical source snapshot.

## Reviews and remaining limits

All three workflow-directed layers completed. All twelve findings were
individually classified; seven patch groups were fixed and reverified. Three
claims were refuted; the existing unverified large-history latency concern was
carried without creating a duplicate deferral. See [review triage](1-9-review.md).
A temporarily unavailable third reviewer started successfully on retry; no
required review remains missing.

At the pre-publication verification snapshot above, hosted x86/ARM, macOS and
Windows jobs had not run. The completed hosted results below supersede those
platform limitations. Local browser execution used x86_64 Linux and Node 26.3.1.
Manual screen-reader verification and large-history latency measurements were
not performed. Agent
attribution uses synthetic fixtures; pairing, retention selection and export
remain outside this story.

Pre-review runs in `1-9-evidence/native-ci/` and focused review-fix captures remain
provenance, including one browser test attempt that exposed a premature wait;
`browser-retry.log.gz` and the final run above are successful. The Story 1.9
[acceptance-criteria mapping](1-9-test-evidence.md) remains applicable, with the
latest CI/rendering evidence in this report. No production inspection API was
added for tests. This report records local verification before publication.

## Hosted results and musl repair (2026-10-04)

[Initial Actions run](https://github.com/sixtoad/vaultwarden-cli/actions/runs/37121572620)
for `73d9f64fb9996380a558eb34eec418e2f53f88e7` completed with 21 successful
jobs and one failed job: `Build (x86_64-unknown-linux-musl)`. The merge gate
was skipped because of that failure. Native Ubuntu x86/ARM stable/MSRV tests,
Linux beta and macOS stable/beta tests, Firefox and real systemd on both Linux
architectures, other build targets, lint and security checks passed. This
supersedes the pre-publication ARM runtime limitation above.

The failed target reported ten compile errors from one cause: musl declares
ancillary socket lengths as `u32`, while glibc uses `usize`. The bridge now
uses the destination ABI types for fixed, bounded send/buffer lengths and
normalizes received lengths to `usize` before the existing validation and
descriptor iteration. No authorization, redaction, lifecycle or cleanup
conditions were changed.
The [ten original compiler diagnostics](1-9-evidence/musl-repair/original-compiler-diagnostics.txt)
are archived with terminal escapes and Actions timestamps removed.

Repair verification completed before review:

- `cargo build --offline --locked --target x86_64-unknown-linux-musl`: passed.
- Musl `cargo test --offline --locked --target x86_64-unknown-linux-musl --lib adapters::supervisor::bridge::tests`: 9 passed, 0 failed.
- Native `cargo test --offline --locked --all-targets`: 839 passed, 0 failed, 13 previously accounted fixture ignores; 13 benchmark smoke checks.
- Native focused bridge tests: 9 passed, 0 failed.
- Real-systemd integration: 2 passed, 29 scenarios plus panic cleanup, 0 failed.
- `cargo fmt --all -- --check`, strict all-target/all-feature Clippy and `git diff --check`: passed.

Tests used the existing secure temporary-directory wrapper. The musl build used
Rust 1.98.1 and isolated Ubuntu musl 1.2.4 compiler packages under `/tmp` with
`CC_x86_64_unknown_linux_musl` and
`CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER` pointing to that compiler.
[Exact compiler setup and reproduction commands](1-9-evidence/musl-repair/reproduction.md)
include package versions, specs rewriting, wrapper creation and the secure
test invocation. [Tested source provenance](1-9-evidence/musl-repair/provenance.md)
identifies the baseline plus the sole production delta, preserves its patch,
and records the lockfile hash separately from the existing source manifest.
[Build](1-9-evidence/musl-repair/musl-build.log.gz),
[musl runtime tests](1-9-evidence/musl-repair/musl-bridge-tests.log.gz),
[native suite](1-9-evidence/musl-repair/native-all-targets.log.gz),
[Clippy](1-9-evidence/musl-repair/clippy.log.gz),
[systemd](1-9-evidence/musl-repair/real-systemd.log.gz), and
[source hash](1-9-evidence/musl-repair/source.sha256) are retained.
The initial sandboxed native bridge attempt passed 7 of 9 tests; the socket and
ptrace fixtures both passed on the authorized unsandboxed rerun. No failures
remain in completed local checks. The musl test build took 24 minutes under
shared-host contention; all nine runtime tests completed in 0.02 seconds.

No new mutation campaign was run for these ABI-only conversions. The scoped
history mutation evidence above applies to unchanged projections, authorization,
ordering, persistence and recovery code. The original hosted compile failure is
the regression evidence for the invalid glibc-only assignments. Hosted musl
verification of the repair remains pending publication; local success is not
reported as a hosted pass.

All three repair review layers completed: edge and verification-gap reviewers
found no issues. Blind review produced four documentation findings: three
reproducibility/provenance additions were made, and the Windows-runtime claim
was rejected because the report describes Windows build jobs, not general
provider runtime support. No production patch or new deferral resulted.
Source hashes remained unchanged after review; formatting, manifests, document
links, reproduction syntax and whitespace checks passed.
