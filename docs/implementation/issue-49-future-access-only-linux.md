# Issue 49: Linux access and consumer lifetime

Implementation record, 2026-10-28, based on
`476bf3f506aad6f52628ad32a6ef34e31172d1ba` plus the working-tree changes.
The [accepted boundary](../secret-access-boundary.md) governs this migration.
Earlier native qualification reports remain historical evidence.

## Result

Lock, request cancellation, expiry and removal of an app's access prevent future
authorized delivery. They do not terminate a program that already received a
secret. Each new request still needs its own approval; a consumed approval cannot
be reused. Provider shutdown, helper death, natural main-process exit and restart
recovery do not terminate consumer descendants either.

The Linux helper still authenticates the private delivery channel and executes
the exact verified executable. Final delivery is serialized with cancellation.
Cancellation winning the final write check prevents producer output from being
submitted to the vault. An already-admitted write may finish; cancellation waits
for the bounded call and its receipt is preserved. Observed
main-process results remain accurate even when descendants continue. A lost
result is recorded as `observation_lost`, never as successful completion or proof
that the secret was recalled. The companion accepts that new status.

New systemd request units have no provider stop relationship or access-derived
execution deadline. Closing the provider's listener/channel also releases an
unstarted helper without sending a termination signal. Resource observation
checks for actual disuse; detachment is distinct from proven cleanup.

## Resource and upgrade limits

SSH files that may still be in use are retained across detachment and restart.
This restricts further SSH requests until safe cleanup is established; ordinary
password delivery remains available. Natural, positively observed completion
can clean the request's files. There is no automatic garbage collector for every
retained or legacy SSH resource, and deleting such files without evidence of
disuse is not a supported workaround.

Already-running workloads from older releases keep their original service
relationships and helper behavior. Let them finish before stopping or upgrading
their provider. Update provider and clients together for `observation_lost`
compatibility; never erase consumed approvals to accommodate a downgrade.
These source changes do not modify installed production services.

## Verification

All credentials and workloads used below are synthetic. Tests run through
`scripts/with-secure-test-tmpdir.sh` with private, correctly owned ancestry.
Default tests do not substitute for the separately invoked real-systemd cases.

| Check | Observed result |
| --- | --- |
| `cargo test --no-fail-fast` | 1,090 passed, zero failed; 23 explicitly ignored entries, including separately invoked fixture tests |
| Companion Rust suite | 29 passed, zero failed |
| `cargo fmt --check` and strict all-targets Clippy | Passed |
| Real systemd lifecycle suite | 41 lifecycle scenarios, assertion-unwind cleanup and separate cross-account SSH file isolation passed |
| Hardened helper death before exec and at the exec trap | Passed; consumer exits naturally without a stopped/killed remnant |
| Negative exec evidence | Passed; pre-exec death or an injected pre-exec trap cannot confirm execution |
| Six isolated source mutations | All caught: bypassed final authorization, restored control-group kill policy, provider stop dependency, finite consumer runtime, removed producer write gate, removed application SSH lifetime marker |
| Portable native qualification harness | 16 passed; new reports use the current access-only policy |

The [mutation receipts](issue-49-linux-lifecycle-mutations/README.md) retain exact
patches, baseline results and failed assertions, with source and receipt hashes.

The full suite ran after all production changes. Final test-only lint and pipe
isolation corrections were followed by 13 bridge and 9 producer tests.
Three independent review passes produced the fixes and additional regressions;
the retained-SSH limitation above remains explicit.

The default suite covers final-release authorization, durable replay prevention,
exact executable checks, recipient authentication, private descriptors, redacted
history and producer authorization. It also covers detached observation and
retained SSH material, including a subsequent ordinary operation.

The real-systemd fixtures independently observe live consumer PIDs, including
double-fork/`setsid` descendants. Test-owned finish markers end only synthetic
workloads after survival assertions; production code never writes these markers.
Fault and phase tests also verify that cancellation before release starts no
consumer and cleans unused provider resources.

Native macOS delivery remains disabled. This migration removes the rejected
termination requirement; it does not qualify native authentication, storage,
recipient verification, installation or delivery. Those remain separate work in
the [native plan](../native-macos-plan.md).
