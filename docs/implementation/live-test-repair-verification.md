# Live-test repair verification

Baseline: `d1efb1034fcf500c8dd21ebf485a07d928a07059`; repair branch:
`repair/live-test-isolation-compatibility`. The prior real rehearsal had seven
failures among 71 tests. This repair preserves those tests and uses real type-5
SSH fixtures without login substitution.

## Final reviewed result — 2026-10-08

The results below supersede earlier counts; the execution record retains earlier
attempts for provenance. Three independent review layers ran after initial full
verification. Follow-up patches added CI runtime prerequisites, bounded probes
and readiness requests, exact process-lifecycle tests, a shared CLI constructor,
and precise field assertions. The stricter malformed-field assertion exposed
name lookup decrypting unrelated custom-field names; lookup now decrypts only
the item name before validating the selected item's fields.

The main agent reran verification sequentially on the reviewed source:

- Default, all-features, and no-default-features: each exited 0 with **994
  reported passes, 0 failures, 15 existing ignored entries** and 13 benchmark
  smoke successes. Subtract the 75 unconfigured live early returns: 919 reported
  passes remain per configuration. The helper entry is also executed by the
  outer isolation test; counts are not a claim of distinct requirements covered.
  Logs: [default](live-test-repair-evidence/final-default.log.gz),
  [all features](live-test-repair-evidence/final-all-features.log.gz),
  [no default features](live-test-repair-evidence/final-no-default-features.log.gz).
- Configured real Vaultwarden suite: **79 passed, 0 failed, 0 ignored** in
  520.20s; 75 configured server cases (including all original 71) and four
  server-independent isolation/lifecycle entries. Preflight separately passed
  two entries. [Final live log](live-test-repair-evidence/final-live.log.gz).
- Formatting, full all-feature/all-target Clippy, shell syntax and whitespace
  checks passed. [Lint log](live-test-repair-evidence/final-lint.log.gz).
- All six scoped semantic mutations were rerun on the final source and caught,
  with no survivors or unviable mutants. Evidence:
  [environment](live-test-repair-evidence/final-mutation-environment.log.gz),
  [bus](live-test-repair-evidence/final-mutation-bus.log.gz),
  [header](live-test-repair-evidence/final-mutation-header.log.gz),
  [fields](live-test-repair-evidence/final-mutation-fields.log.gz),
  [lock](live-test-repair-evidence/final-mutation-lock.log.gz),
  [deletion](live-test-repair-evidence/final-mutation-deletion.log.gz).
  The bus mutant hit the bounded preflight timeout; the field mutant failed
  exact-value comparison. These are targeted manual mutations, not a generated
  whole-project mutation score.
- [Final source hashes](live-test-repair-evidence/final-source-before-mutations.sha256)
  and [restoration check](live-test-repair-evidence/final-source-restoration.log.gz)
  prove exact restoration. Restored isolation/lifecycle, HTTP header, mocked
  deletion-error, Clippy and formatting checks passed, followed by live selected
  fields/malformed-field and repeated-lock checks:
  [restored checks](live-test-repair-evidence/final-restored.log.gz),
  [restored live](live-test-repair-evidence/final-restored-live.log.gz).
- Read-only final audit found no `vw-live-live-*` containers, networks or volumes,
  nor matching private foreground bus/keyring processes. All compressed logs
  passed integrity checks. No real vault or desktop-keyring enumeration occurred.

Review findings were triaged and patched, except the low-impact observation
that deliberately calling the undocumented internal `--isolated-run` entry skips
the outer wrapper. It is not an authentication boundary: all credential-bearing
CLI/service subprocesses remain separately isolated. Invoke the public runner
normally. Docker support is deliberately the local default engine with a system
Compose plugin or standalone binary; other contexts are rejected. Hosted CI was
not executed in this local repair; its prerequisite declarations were updated.
Production provider acceptance, operator provisioning, prior desktop-keyring
cleanup and companion work are not certified by these results.

## Isolation and invocation

Use `scripts/test-live.sh` on Linux with Docker Compose (plugin or standalone),
dbus-daemon, gnome-keyring-daemon, gdbus, and secret-tool installed. The runner
clears its environment, uses the existing secure-temp wrapper, assigns a unique
Compose project, and accepts only a loopback endpoint. Per-fixture services use
explicit private bus addresses, private HOME/XDG directories, and a synthetic
keyring password. A synthetic persistence sentinel is verified before any
account is provisioned. The CLI environment excludes inherited passwords,
proxies, DISPLAY, and desktop-bus addresses. Native production keyring selection
and fail-closed deletion/persistence behavior remain unchanged.

The actual CLI isolation preflight runs independently of a server and is repeated
by the runner before provisioning. Its outer test gives a helper process a
synthetic parent secret/password, proxies, DISPLAY, and a listening fake desktop
bus. The helper uses the same builder to run the actual CLI lock operation and
inspect an isolated child environment; the outer test verifies zero connections
to that fake desktop bus. Each fixture kills and reaps its own keyring/bus child
processes before deleting its temporary directory.

## Execution record

Required full-suite verification passed. Logs are compressed in
`live-test-repair-evidence/`; use `gzip -cd <path>.log.gz` to read them. Failed
attempts are retained alongside successful executions.

- Initial sandbox secure-temp invocation exited 2 because its ancestry check
  rejected the sandbox-visible home. Host execution uses the same wrapper;
  no shared directory permissions were changed.
- Initial private-keyring sentinel comparison failed because `secret-tool`
  omits its trailing newline on this host. Comparing the returned value with
  trailing whitespace removed resolved that harness assertion.
- Host isolation preflight: 2 tests passed, exit 0.
- `cargo fmt --all -- --check`, `git diff --check`, and `bash -n
  scripts/test-live.sh`: exit 0.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: exit 0
  after correcting harness constant-assertion and unused-result lint errors.
- Clean-environment secure-wrapper `cargo test --workspace --all-targets
  --locked`: exit 0; 992 reported passes, zero failures, 15 pre-existing ignored
  entries across 19 result blocks, plus 13 successful benchmark smoke cases.
  Of the 77 reported live-binary passes, 75 were unconfigured early returns;
  the 2 server-independent isolation tests ran. These 75 are not claimed as
  live verification. Ignored entries include subprocess helper entry points,
  browser/manual fixtures, namespace tests, and real-user-systemd tests; their
  exact names/reasons are retained in [default.log.gz](live-test-repair-evidence/default.log.gz).
- First configured full run: exit 101, 76 passed / 1 failed, 799.94 seconds
  ([live.log.gz](live-test-repair-evidence/live.log.gz)). All 75 server-configured cases completed successfully, including
  all 71 original cases; the in-suite isolation wrapper failed to spawn
  `current_exe()` with ENOENT. Its earlier preflight passed. A concurrent Cargo
  rebuild after harness lint edits may have replaced the running executable,
  leaving Linux `current_exe()` pointing at its deleted pathname. That cause is
  suspected, not proven: the pathname was not captured. This run is a failure,
  not a passing acceptance result. The full suite was repeated with frozen
  source/binaries and no concurrent build/test commands, as recorded below.
- The first configured run removed project `vw-live-live-rfbcqa`; read-only
  Docker checks found no container/network/volume with that project label.
  `/home/sixtocantolla/.vaultwarden-cli-tests.k7ZyEM` was absent after cleanup.
- Runtime now includes an extra real CLI unlock (100,000-iteration PBKDF) in
  every fixture to establish a native-keyring session, replacing direct legacy
  key-file seeding. The initial run also shared CPU with the default regression
  suite. Isolated service preflights took 0.61s standalone / 1.15s in the runner;
  no systematic service-startup timeout overhead was observed.
- Frozen, sequential full live rerun ([live-final.log.gz](live-test-repair-evidence/live-final.log.gz)): exit 0; preflight 2
  passed in 0.36s; configured suite **77 passed, 0 failed, 0 ignored** in 526.43s.
  All original 71 live cases and 4 added live cases executed against the real
  pinned backend; the other 2 cases are server-independent isolation checks.
  No fixture substitutions or unconfigured early returns occurred in the 75
  configured cases. The failed in-suite isolation wrapper from the earlier run
  passed. Project `vw-live-live-k2kt7u` container and network were removed.
- Read-only post-run checks found no resources carrying project
  `vw-live-live-k2kt7u` and no remaining live temporary roots. Pinned image digest:
  `sha256:d626d04934cd1192ad8ced1adb975099fca78cec33ab467d2d3c923cde7f3b0c`.
- Clean-environment secure-wrapper all-features workspace run: exit 0; 992
  reported passes, zero failures, 15 pre-existing ignored, and 13 benchmark smoke
  successes. As in the default run, 75 of the live-binary passes were unconfigured
  early returns and are excluded from live execution claims
  ([all-features.log.gz](live-test-repair-evidence/all-features.log.gz)).
- Clean-environment secure-wrapper no-default-features workspace run: exit 0;
  identical 992 reported passes, 15 pre-existing ignored, 75 live early returns,
  and 13 benchmark smoke successes, with zero failures
  ([no-default-features.log.gz](live-test-repair-evidence/no-default-features.log.gz)).

## Scoped mutations

Each mutation compiled and was tested sequentially, then restored. All six were
caught; zero survived and zero were unviable. Failing exits were 101.

| Mutation | Detecting assertion | Evidence |
| --- | --- | --- |
| Remove `env_clear` from CLI builder | Synthetic inherited environment reached child | [environment](live-test-repair-evidence/mutation-environment.log.gz) |
| Remove explicit session bus address | Private Secret Service preflight refuses provisioning (2.74s) | [bus](live-test-repair-evidence/mutation-bus.log.gz) |
| Replace protocol compatibility header with app version | HTTP mock rejects incorrect header | [header](live-test-repair-evidence/mutation-header.log.gz) |
| Disable selected custom-field names and values | Expected named value absent from actual CLI child | [fields](live-test-repair-evidence/mutation-fields.log.gz) |
| Restore `require_unlocked` lock route | Actual CLI preflight rejects already-locked synthetic session | [lock](live-test-repair-evidence/mutation-lock.log.gz) |
| Swallow native keyring deletion failure | Existing mock-keyring regression expected error but received success | [deletion](live-test-repair-evidence/mutation-deletion.log.gz) |

The lock mutation was caught by preflight before server provisioning, so its
requested filtered server test did not execute. The bus mutation likewise failed
closed before provisioning. Isolation mutations used synthetic sentinels and
fake endpoints; no desktop keyring mutation was performed.

The [source checksum manifest](live-test-repair-evidence/source-before-mutations.sha256)
and [restoration check](live-test-repair-evidence/source-restoration.log.gz) prove
byte-for-byte restoration of every mutated file and the surrounding test sources.
Restored header/deletion checks, formatting, whitespace, and all-target/all-feature
Clippy passed ([restored checks](live-test-repair-evidence/restored-checks.log.gz)).
Restored selected-fields and repeated-lock live regressions each passed against
fresh disposable backends, with passing isolation preflights and successful
cleanup (combined exit 0; [restored live](live-test-repair-evidence/restored-live.log.gz)).

## Cleanup limits

The runner removes only its uniquely named Compose project and volumes and the
secure wrapper removes its exact private temporary root. A Compose cleanup
failure changes a successful command to failure. Per-account admin deletion is
best effort; removal of the disposable volatile backend is the final cleanup
boundary. This work makes no claim that keyring entries from the earlier unsafe
rehearsal have been removed or verified. It never enumerates or broadly deletes
desktop keyring entries. Companion source, provisioning/approval APIs, deployment,
commits, pushes, and PRs are outside this repair.

After all restored checks, read-only Docker/process/path checks found no remaining
`vw-live-live-*` projects, live temporary roots, or test-only foreground keyring
and bus processes. All 16 logs, including the failed full run and caught mutations,
were gzip-compressed and passed `gzip -t`; their contents remain recoverable.
