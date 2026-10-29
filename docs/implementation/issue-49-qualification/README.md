# Issue 49 native qualification record

Status: **historical qualification record; production macOS protected delivery remains disabled**.

Policy update, 2026-10-28: the operator confirmed [the CLI controls secret access;
consumer execution control is outside its scope](../../secret-access-boundary.md). The intermediate
optional CLI stop feature was withdrawn too. The former blanket containment
no-go is superseded for native secret access. Remaining native boundaries and the revised policy still need
implementation/qualification. Existing reports are historical evidence for the
earlier requirements. New harness reports label the current policy and replace
termination gates with delivery, consumer-survival and resource-lifetime gates;
the primitive observations do not by themselves satisfy those gates.

This implements the disposable qualification slice approved on 2026-10-27.
The user subsequently authorized the prepared unprivileged M1 run. Its nine
native observations passed after a Python 3.9 harness correction. The Cargo
regression subsequently passed after fetching locked dependencies into a private
temporary cache with the existing toolchain. See the
[native run record](native-run-2026-10-27.md) for exact evidence and limitations.
Privileged setup and a production port remain outside this authorization.

The [containment audit](containment-decision-2026-10-27.md) records the remaining
contract gap using the actual host's manual/SDK and Apple sources. The candidates
examined do not establish reliable cleanup of all protected descendants.

The subsequent bounded [feasibility investigation](containment-feasibility-2026-10-27.md)
completed with a **no-go under the previous mandatory-termination policy**. Dedicated UID
cleanup, XPC, sandboxing and resource-limit alternatives did not establish the
missing contract. Those findings remain historical evidence; they must not restore consumer
supervision as a CLI responsibility. A restricted worker model or local VM is
not required by the secret-access boundary.

The [fixture guide](../../../tests/fixtures/macos-boundary/README.md) describes
commands, deadlines, privacy and retained evidence. The
[privileged setup proposal](privileged-setup-plan.md) prepares the next review;
it is intentionally not executed by the harness.

## Evidence and interpretation

Each run creates a new private directory containing:

| Record | Meaning |
| --- | --- |
| `source-hashes.json` | Exact SHA-256 of fixture, runner, documentation and relevant production source; the C bytes are retained read-only in `source-snapshot/probe.c` and that file is compiled; unreadable sources fail closed |
| `environment.json` | Actual OS version/build, kernel, architecture, operator UID and authorization assertion; no certified versions |
| `signatures.json` | Actual fixture hashes, strict verification, selected codesign metadata and ad-hoc provenance, when built |
| `replacement.json` | Checked and launched hashes and a fixed execution marker for the writable-path negative control |
| `observations.json` | Bounded primitive/negative-control outcomes; a pass never satisfies a production gate |
| `matrix.json` | Every production attack/gate, with explicit unavailable prerequisite |
| `resources.json` | Owned files with UID/mode/device/inode and process PID/start time, independent exit observation and direct-child wait state |
| `cleanup.json` | Separate cleanup uncertainty, retention and prohibited reuse; never `CleanupEvidence::Reaped` |
| `result.json` | Failed or blocked; no mechanism selected, no production enablement |
| `unsupported-platform-regression.json` | Optional separately attached native regression receipt, bound to exact source and command as specified below; never production qualification |

Records contain no synthetic secret values. A fixture's self-report is not exit
evidence: libproc observations and kernel NOTE_EXIT subscriptions are separate.
These bounded fixtures make the observation safe to attempt; they provide no
contract for arbitrary operation descendants. Non-child reap and atomic closure
of membership remain unproved, so protected material stays private and retained.
Crash or registration gaps are reported as uncertainty, never inferred clean.

No privileged setup occurred. No macOS version (including macOS 13) is certified.
Intel/Rosetta execution remains unsupported. The portable test run validates
reporting, deadline handling, non-disclosure, preservation of existing evidence
and retention on missing cleanup; it is not macOS security evidence.

The checked-in [Linux evidence](evidence/linux-2026-10-27-review-corrections/result.json)
records exit 2 (`native-macos-arm64-required`) with all sixteen production gates
unavailable and zero native observations. Fourteen focused portable harness
tests passed after review corrections. Earlier shell syntax/whitespace checks
passed; production source remained unchanged. The conditional full Linux
regression run for shared-code edits was not needed. Earlier evidence directories
remain as prior source snapshots; each `source-hashes.json` identifies the exact
input to that run.

## Separate native regression receipt

The runner does not run Cargo. On the authorized native Mac, run this exact
command separately and retain its receipt beside the qualification run:

```sh
cargo test --locked --test unsupported_provider_platform
```

Use a fixed source copy matching the qualification run's recorded source hashes.
For committed inputs, record the full Git commit and verify that all build inputs
are clean, including absence of untracked build inputs. For uncommitted inputs,
copy the complete source tree into a private directory and retain
`regression-source-hashes.json`, a pathname-to-SHA-256 manifest of all copied
build inputs (including Cargo manifests/lockfile, build scripts, configuration,
Rust source and tests). Run only from that copy. Record the manifest digest
before and after the command; a changed source invalidates the receipt. Do not
use the qualification runner's smaller source-hash list as a substitute for
the regression's complete build-input identity.

Write `unsupported-platform-regression.json` with these mandatory fields using
actual observations, never assumed values:

| Field | Required value |
| --- | --- |
| `command` | `["cargo", "test", "--locked", "--test", "unsupported_provider_platform"]` |
| `source_revision` | Full clean Git commit, or `null` when the retained complete source manifest identifies an uncommitted copy |
| `source_manifest_sha256_before`, `source_manifest_sha256_after` | Matching digests of the retained complete regression input manifest, checked against current file bytes before/after |
| `qualification_source_hashes_sha256` | SHA-256 of this run's `source-hashes.json`; the overlapping source hashes must match |
| `os_version`, `os_build`, `architecture`, `rustc_version`, `cargo_version` | Exact native host/toolchain observations; this test must actually run on macOS |
| `started_utc`, `finished_utc`, `exit_code` | Actual execution timestamps and exit status; missing execution uses `null` |
| `tests_executed`, `outcome` | Confirm the unsupported-platform test actually executed; `pass` only for successful execution, otherwise `fail` or `unavailable` |

Retain only the fixed command, source/host metadata and redacted outcome, not raw
test diagnostics or caller values. A Linux zero-test invocation cannot pass this
receipt. Missing prerequisites or a missing receipt leave native regression
evidence unavailable. This attachment is separate regression evidence; it does
not rewrite the original run, satisfy containment/authentication/image gates,
select a production mechanism or certify a macOS version.

## Historical contract decisions

These rows record the initial qualification scope. Consumer containment is no
longer a requirement of the CLI; its blocked row is not a gate on native secret
delivery. Other delivery/storage findings still need reassessment against the
[accepted boundary](../../secret-access-boundary.md).

| Candidate | Contract argument | Native evidence required | Decision |
| --- | --- | --- | --- |
| Hash then spawn a writable pathname | No immutable object/no-writer lifetime binds checked bytes to executed bytes | Replacement, mutation, rename, symlink, hardlink, concurrent upgrade, signature and dependency attacks | Reject this candidate; negative control only |
| Process group, parent wait, launchd job cleanup | Cannot establish lifetime membership after `setsid`/double fork; child wait says nothing about all descendants | Supported atomic containment contract plus independently observed cleanup and recovery | Blocked; never select process groups as containment |
| `getpeereid` alone | Effective UID/GID is only part of peer authentication; lacks enrolled key and connection-bound signed application identity | Distinct enrolled accounts, wrong UID/key, endpoint substitution, revocation and UID reuse | Primitive observation only; unavailable as complete authentication |
| Private pipe and hardened runtime | Restricts one transfer path; does not establish other-account memory/files/log denial | Full deployment identities, descriptors, crash reporting, environment, files, memory and logs | Inspection observation only |
| Non-login service Keychain | Operator login Keychain behavior cannot establish daemon ACL/reboot/lock behavior | Signed service identity, item ACLs, reboot/login/lock denial and recovery | Unavailable; no plaintext fallback |
| Restart invalidation and lock/expiry | Requires durable ownership, fresh unlock and no stale launch/approval authority | Candidate controller/provider crash, restart, replay, cancellation, revocation and sleep | Unavailable; synthetic child crashes do not substitute |

The roadmap already links Apple's published contracts. No new platform mechanism
is selected by this qualification slice; native probes supplement a supported
contract, never replace one. That slice left the Linux provider,
unsupported-platform guard and synthetic Flutter biometric contract untouched.
The subsequent [Linux lifecycle migration](../issue-49-future-access-only-linux.md)
implements the revised access boundary separately. Native macOS delivery remains
unfinished; consumer termination is no longer a qualification gate.
