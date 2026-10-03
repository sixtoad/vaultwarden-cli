# Story 1.9 native CI extension — completed local evidence

The native CI extension and all confirmed review fixes are implemented. All local
required checks completed. The user approved publication on 2026-10-03. Hosted
Actions results, including native ARM runtime validation, remain pending and
will be tracked in the pull request checks.

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

At the local verification snapshot, hosted x86/ARM stable/MSRV, hosted Firefox/systemd,
macOS/beta, Windows and other existing Actions jobs **had not run**. Publication
was approved on 2026-10-03; consult the pull request checks for hosted results. Local execution was x86_64
Linux (Node 26.3.1); ARM has assembly/link evidence only. Manual screen-reader
verification and large-history latency measurements were not performed. Agent
attribution uses synthetic fixtures; pairing, retention selection and export
remain outside this story.

Pre-review runs in `1-9-evidence/native-ci/` and focused review-fix captures remain
provenance, including one browser test attempt that exposed a premature wait;
`browser-retry.log.gz` and the final run above are successful. The Story 1.9
[acceptance-criteria mapping](1-9-test-evidence.md) remains applicable, with the
latest CI/rendering evidence in this report. No production inspection API was
added for tests. This report records local verification before publication.
