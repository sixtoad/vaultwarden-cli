# Disposable native boundary fixtures

These fixtures implement issue 49's qualification slice, not a provider. They use
synthetic values only. No account, service, Keychain item, signing identity or
system setting is created or changed. The production macOS rejection stays in
place. There is no successful qualification exit code in this slice.

New reports carry `policy_contract: secret-access-only-2026-10-28`. Their matrix
requires authenticated delivery, denial of future access, consumer survival and
safe resource lifetimes. It does not require consumer termination. Previously
saved reports retain their historical containment matrix; do not interpret those
rows as current production gates or rewrite the original evidence. The primitive
observations alone still cannot qualify a production implementation.

Run portable checks from the repository root:

```sh
bash -n scripts/test-macos-boundary.sh
python3 tests/fixtures/macos-boundary/test_qualify.py
```

To record prerequisites on any host, use a **new** directory inside an existing
directory owned by the operator and not writable by group/others:

```sh
mkdir -m 700 "$PWD/docs/implementation/issue-49-qualification/local-runs"
bash scripts/test-macos-boundary.sh --output "$PWD/docs/implementation/issue-49-qualification/local-runs/run-001"
```

On a separately authorized disposable native Apple Silicon Mac with macOS 13 or
later, Python 3 and the Xcode command-line SDK, run:

```sh
mkdir -m 700 "$PWD/docs/implementation/issue-49-qualification/native-runs"
bash scripts/test-macos-boundary.sh --authorized-disposable-host \
  --output "$PWD/docs/implementation/issue-49-qualification/native-runs/run-001"
cargo test --locked --test unsupported_provider_platform
```

Retain the separately run Cargo command's exact-source outcome in
`unsupported-platform-regression.json` beside the native run. Follow the
[receipt convention](../../../docs/implementation/issue-49-qualification/README.md#separate-native-regression-receipt).
Running the command without that attachment leaves the regression evidence
unavailable. This receipt does not qualify a production boundary.

The flag asserts host authorization already obtained; it is not a way to obtain
authorization and never authorizes privileged setup. Run as the disposable
operator, never root. Do not run native probes on a production Mac. Reports and
fixtures remain private (directory 0700, files 0600 except executable fixtures).
Choose a new directory for every run. Intel/Rosetta and Linux runs report
unavailable; neither is a passing native result. macOS versions are recorded
exactly and never certified automatically.

Exit 2 means blocked/unavailable, even when every baseline observation passed.
Exit 1 means a probe failed. Read `result.json`, `matrix.json`, `observations.json`
(if probes ran), `resources.json` and `cleanup.json` together. Passing observation
rows explicitly carry `production_gate_satisfied: false`.

`probe.c` builds two arm64, ad-hoc-signed hardened-runtime executables. These
signatures are disposable; they do not establish Developer ID/notarization or a
production trust chain. The harness records binary/source hashes and selected
actual codesign metadata. The fixtures exercise:

- `getpeereid` on inherited connected sockets, including a deliberately wrong
  expected UID. No synthetic secret is released on this path. This tests the
  UID primitive; it does not authenticate a named server or a distinct agent.
- Replacement between checking a writable path and executing it. Execution of
  the replacement is an **expected negative control rejecting that candidate**.
  A malformed Mach-O is separately rejected by strict signature verification.
- A random synthetic value delivered through private stdin, held in memory,
  checked for absence from `ps` arguments/environment, and overwritten before
  exit. The expected PID, executable, harmless argument and environment control
  must all be visible before absence counts. Same-account observation does not
  establish agent memory/file/log denial.
- Bounded double fork, `setsid`, ordinary exit, SIGABRT and
  parent SIGKILL. A separate libproc observer checks PID/start-time identities;
  the harness subscribes to kernel `kqueue` NOTE_EXIT before each release.
  The grandchild configures SIGTERM to be ignored, but the harness does not send
  SIGTERM; ignored-signal behavior is configured and **untested**.

The runner snapshots the exact C fixture bytes into private, read-only
`source-snapshot/probe.c`, hashes those bytes and compiles that same file.
Subsequent checkout edits do not change compiler input. Ownership-report
publication fsyncs both the file and parent directory before release; sync
failure stops release and retains failure evidence where storage permits.

Each descendant registers at a gate before doing more work; the source has a
fixed maximum of three processes and no fork after the final release. Each
process resets its eight-second alarm after fork; active lifetime uses
`mach_continuous_time`. Normal observation/tool deadlines are 3–15 seconds,
compilation 45 seconds, and the run's launch budget is 180 seconds. Core dumps
are disabled, command output is private and discarded, reports never include
raw subprocess errors or synthetic values, and subprocess environments contain
only a fixed PATH, locale and private temporary directory, plus the harmless
inspection control for that fixture. File output is capped
at 1 MiB. Descendants retain the private pipe until exit.

Kernel exit observations and root `wait` results are recorded separately. They
do **not** prove a fork barrier, non-child zombie reap, arbitrary workload
membership, or crash recovery. The harness never kills scraped PIDs or process
groups. It can kill/wait its own unreaped child handles; detached fixture
processes have their own bounded exit. A failure between fork and registration
is explicitly unaccounted, retains material and prohibits reuse. An interrupted
controller cannot prove cleanup; preserve its directory and inspect independently.

Every run retains its manifest and fixtures. The synthetic material created for
native lifecycle probes is retained even after observed exits because the
production cleanup contract is unqualified. Do not interpret retention as safe
reuse or delete evidence as part of an automated retry. No actual protected
secret is ever read by this harness.

Cross-account attacks, replay, restart, lock, revocation, real containment,
dependency policy and service Keychain require a concrete candidate and the
separate setup described in the qualification documentation. Their matrix rows
are `unavailable`, not skipped or simulated passes.
