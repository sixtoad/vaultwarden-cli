# Protected-workflow review corrections — 2026-10-14

The recorded automated checks and coordinated human rehearsal passed, but
independent review reopened acceptance. No commit or push was performed.

## Review outcome

Three independent reviewers completed against the staged 805,384-byte baseline
diff. Follow-up is required for Xauthority stdin/capture, descendant and trailing
controller-output coverage, persistent controller-reap uncertainty, and explicit
filesystem absence checks. Smaller corrections concern ordinary-test dependency/
architecture guards, launch-cookie and fragment-identity regression coverage,
precise human-rejection evidence wording and portable reproduction instructions.
The detailed per-finding triage is retained in the controlling workspace spec.

No real-credential exposure or published display-cookie leak was established.
The Xauthority setup failure masks a latent uncaptured-listing problem; both
must be corrected together. Discarded output cannot support claims that those
streams were scanned. The human run proves the observed decision sequence;
generic rejection feedback does not identify the backend's exact rejection
cause. Historical passing logs are preserved, not promoted to full acceptance.

The operator subsequently approved the bounded preservation-based closure pass.
Its incremental results are in the [R2 closure supplement](../protected-workflow-r2-closure/README.md).
Nothing was rolled back, and no automatic human retry was started.

Parent matrix audit subsequently added a narrow preflight/test-only correction;
see the [preflight audit supplement](../protected-workflow-preflight-audit/README.md)
for its exact three-file delta, current hashes and executed negative traversal
regression. The other 123 source fingerprints, including all production approval
and browser code, are unchanged. The human run below was not repeated.
Parent also ran the updated runner's `--check` on the host: one passed, zero
failed/ignored, 0.07 s, confirming the prerequisite checks and ordinary restricted
identity preflight without starting any provider, container or browser.

## Coordinated human acceptance

The operator said “ready” on 2026-10-14. The isolated visible Firefox rehearsal
passed in 104.64 seconds: actual unlock, denial, wrong-password rejection then
denial, approved execution, expected wrong-field failure, redaction and cleanup.
No password entry or decision was automated. [human.log](human.log) retains the
redacted output from `/tmp/vw-human-corrections.FZzaUZ/human.log`, omitting only
its final empty line. Parent separately confirmed the provider not-found/inactive
and no rehearsal auxiliary units, labeled containers or private fixture roots.
This run used the fingerprinted corrected source; automated same-profile reset
and endpoint-isolation coverage remains separate from these manual decisions.

The controlling spec is `spec-protected-workflow-review-corrections.md` in the
workspace's implementation artifacts. Baseline commit:
`49649d0e8e0ce8318da06a21be93616eec9a3c34`. Existing staged work and historical
evidence were preserved. This directory supersedes earlier automated evidence
for the corrected source without rewriting its historical results.

## Provenance and retained evidence

[final-source.sha256](final-source.sha256) fingerprints all 126 tracked source,
test, script, CI and Cargo files after final implementation and before the final
campaign. No source was edited during normal verification. Each deliberate
mutation was applied alone, compiled, exercised and exactly restored before the
next mutation; the corresponding `restore-*.log` checks every fingerprint.
[final-source-restoration.log](final-source-restoration.log) confirms the final
unmutated source. Documentation/evidence updates followed testing and are not
included in that executable-source fingerprint.

The original 49 retained logs, patches and source/restoration records were compared
byte-for-byte with their private originals. The subsequent human log is the 50th
entry in [evidence.sha256](evidence.sha256); its final-empty-line omission is
documented above. Parent verified all 50 entries after the human run.
Formatting/whitespace logs are intentionally empty
on success. Logs were checked for the fixed synthetic credential corpus, private
key headers and token-shaped JWT values before publication. Raw service captures,
password entry, browser request bodies and private state are not published.

The full staged diff retains original log whitespace, including Docker progress
trailing spaces and final empty lines; therefore its unfiltered whitespace check
reports those evidence-only warnings. The source/documentation check excluding
these raw `.log` files passed. Existing whitespace logs predate staging all raw
evidence and must not be read as an unfiltered final-diff pass.

Original private command logs remain at `/tmp/vw-review-corrections.22STc0`;
the evidence here does not depend on that temporary directory surviving.

## Final automated results

| Check | Result and exact evidence |
|---|---|
| Formatting; all-target/all-feature Clippy with `-D warnings` | Passed before the campaign and after restoration: `final-fmt.log`, `final-clippy.log`, `post-mutation-fmt.log`, `post-mutation-clippy.log` |
| Default workspace/all-targets | 1,040 reported passes, 0 failures, 18 ignored; `final-default.log` |
| All-features workspace/all-targets | First attempt failed as described below; unchanged-source complete rerun: 1,040 passes, 0 failures, 18 ignored; `final-all-features-rerun.log` |
| No-default-features workspace/all-targets | 1,040 reported passes, 0 failures, 18 ignored; `final-no-default-features.log` |
| Observer and trusted Firefox | 13 observer tests; same-profile/shared-cookie-jar browser suite passed, 0 unexpected diagnostics; `final-browser.log` |
| Configured isolated live suite | 79 passed, 0 failed/ignored, 384.61 s, plus 2 preflight isolation tests; owned Compose container/network removed; `final-live.log` |
| Real systemd supervisor | 2 passed in 74.04 s; distinct-principal provider-material test 1 passed; `final-systemd.log` |
| Real kernel-peer/noninteractive namespace matrix | 1 passed in 4.15 s; `final-namespace.log` |
| Automated production rehearsal | Passed all four scenarios in 34.77 s; `final-rehearsal-automated.log` |
| Occupied-unit collision | Passed in 0.23 s; `final-rehearsal-collision-check.log` |
| Pending-request SIGTERM | Passed in 20.81 s; `final-rehearsal-interrupt.log` |
| Injected cleanup failures/recovery | Passed in 20.36 s, including actual post-container-removal recovery; `final-rehearsal-cleanup-failure.log` |
| Restored focused regressions | Harness 16 passed/1 opt-in ignored; mixed-role lifecycle regression 1 passed; `post-mutation-focused.log`, `post-mutation-role.log` |
| Final restored production rehearsal | Passed in 34.30 s, including output scan and independent cleanup; `final-restored-rehearsal.log` |
| Independent final host audit | Provider not-found/inactive; no owned auxiliary units/cgroups, labeled containers, live Compose resources, rehearsal roots, supervisor runtime or browser controller; `final-host-audit.log` |

Each workspace configuration has 20 suite summaries and includes 75 unconfigured
live-case early returns: these are not executed live coverage. The opt-in
production rehearsal and real-host tests were run separately. Native checker
execution was on x86-64; the AArch64 implementation was not executed here.
Browser diagnostics included 29 known cross-origin/blocked-favicon observations,
allowlisted separately from the zero unexpected diagnostics. No manual
screen-reader acceptance is claimed.

## Attributable compiled mutations

Each row has an exact `mutation-<name>.patch`, `mutation-<name>.log` and
`restore-<name>.log`. All seven compiled and failed at the intended assertion;
none is classified as a kill merely because of a Busy or unrelated rejection.

| Name | Intended failure observed |
|---|---|
| `false-completion` | Wrong-field execution falsely marked completed: immediate restricted-agent terminal mismatch, 34.39 s |
| `missing-injection` | Correct-field approval without injected credential: immediate terminal mismatch, 29.89 s |
| `approval-bypass` | Wrong password incorrectly accepted: browser request-submit gate, 53.78 s |
| `cleanup-omission` | Final owned-root deletion omitted: independent post-cleanup absence assertion, 0.26 s |
| `role-confusion` | Request proof accepted on provider Unlock with both cookies: actual 200 versus required 403 |
| `cleanup-uncertainty` | Failed Docker absence query accepted: dedicated regression rejects uncertain cleanup |
| `provider-leak` | Synthetic login-password fixture emitted to real daemon stderr: private redaction gate rejects and retains material, 21.34 s |

Cleanup-omission used only a harmless owned sleep sentinel. Its exact retained
credential-free ledger, empty captures and FIFOs were inspected and removed only
after independent unit/cgroup absence checks (`recover-cleanup-omission.log`).
The provider-leak mutation ran the genuine production path through a pending
request and SIGTERM. Its raw stderr stayed private. After the gate retained it,
an independent audit privately confirmed the injected value and established all
four recorded units/cgroups, exact container and owned processes absent, with
the supervisor runtime empty. Only then were that exact synthetic fixture,
restricted-owned signing key and empty runtime removed
(`recover-provider-leak.log`). Raw synthetic material is intentionally not
recoverable; the redacted failure and recovery evidence remain.

## Acceptance mapping

- Separate server-derived provider/request roles, separate cookies and tab-local
  proofs, opposite-role rejection with both cookies, provider lifecycle/history
  through Lock/repeated Unlock/expiry, stale request rejection, restart/reload,
  one-use launches, malformed cookies, request guards and delayed authentication:
  adapter/provider-session tests and the same-profile trusted browser suite.
- Real one-shot execution, denial, rejected wrong password, successful correct
  injection and failed wrong injection: automated production rehearsal. Replay
  supplies valid authentication and must return 403 without changing history or
  execution counts; human mode never sends this automated replay.
- Bounded private daemon/supporting-service stdout/stderr, controller stderr and
  retained CLI/browser observations: cleanup scans before deletion; overflow and
  synthetic-password corpus regressions plus the compiled real-provider leak.
  The corpus includes wrong/login/keyring passwords, fields, keys and launch
  credentials. Private X display cookie coverage was intended, but the broken
  historical Xauthority path did not establish it; the closure supplement records
  corrected installation and private audit. Raw captures never enter the journal.
  Firefox, Xvfb and helper output intentionally discarded by the controller was
  not audited; trailing controller stdout was not covered by this historical run.
  The bounded closure supplement records the corrected controller EOF audit.
- Docker uncertainty and post-removal idempotence: dedicated unit regression,
  compiled failed-query mutation and real cleanup-failure recovery.
- Generic rejection during the instructed wrong-password step followed by Deny: boolean transition observer
  armed before guide instructions, 13 read-only observer tests, including
  denial-only rejection. No entered values are recorded. npm verification and
  browser CI now include these tests.
  This observation does not identify the exact backend rejection cause.
- Missing prerequisites/restricted traversal and native architecture gating:
  pre-provisioning checks and focused native/guard tests; home permissions and
  host trust were not changed.

## Failures and limitations retained honestly

`production-smoke.log` is a pre-final smoke, not frozen-source acceptance. It
stopped with the existing closed `restricted agent poll rejected: busy`
diagnostic after the denial phase. No request was resubmitted. Private output
scanning and independent cleanup passed. Its cause remains unconfirmed; later
passing fresh rehearsals do not establish a fix.

The first frozen-source all-features attempt (`final-all-features.log`) reported
736 passes, 1 failure and 13 ignored before stopping in
`history_old_records_without_audits_recover_without_inventing_event_times`, at
the second `Provider::start` (`history_tests.rs:273`), with the closed diagnostic
`PersistenceFailure`. The fixture and provider-start source had no HEAD diff.
Storage was healthy (87 GiB and approximately 23.9 million inodes available).
The exact isolated test passed unchanged (`final-history-recheck.log`, 0.71 s),
then one bounded complete unchanged-source all-features rerun passed. The cause
was not established; this is not claimed to be unrelated or fixed.

Earlier broad pre-final workspace/browser runs remain historical because final
capture/cleanup changes followed them. The full frozen-source campaign above is
the relevant evidence. Historical human evidence in the parent verification
document predates these lifecycle/observer corrections and cannot accept them.
The coordinated human result above supersedes that earlier pending-human gate.
Any additional `--human` run still requires readiness; never retry automatically.

## Historical commands (preserved provenance)

Run from the repository with access to its actual user manager and local default
Docker. Preserve the real home and security preflight; sandbox ownership mapping
on this host required approved normal-host execution, not weakened checks.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
./scripts/with-secure-test-tmpdir.sh cargo test --workspace --all-targets --offline --locked
./scripts/with-secure-test-tmpdir.sh cargo test --workspace --all-targets --offline --locked --all-features
./scripts/with-secure-test-tmpdir.sh cargo test --workspace --all-targets --offline --locked --no-default-features
CERTUTIL=/tmp/vw-rehearsal-tools.W7hQzv/extracted/usr/bin/certutil FIREFOX=/usr/bin/firefox ./scripts/with-secure-test-tmpdir.sh npm test --prefix tests/ui
./scripts/test-live.sh
./scripts/with-secure-test-tmpdir.sh ./scripts/test-systemd-supervisor.sh
VW_AGENT_NAMESPACE=1 TMPDIR=/tmp unshare --user --map-auto --map-root-user --fork cargo test --offline --locked --test agent_submission real_linux_peer_matrix_and_noninteractive_cli -- --ignored --exact --nocapture
VW_REHEARSAL_XVFB=/tmp/vw-rehearsal-tools.W7hQzv/extracted/usr/bin/Xvfb VW_REHEARSAL_CERTUTIL=/tmp/vw-rehearsal-tools.W7hQzv/extracted/usr/bin/certutil scripts/rehearse-protected-workflow.sh --automated
```

Use the same rehearsal dependency environment for `--collision-check`,
`--interrupt` and `--cleanup-failure`. Temporary Xvfb/certutil are public binaries
extracted from distribution packages; they are not host installations and are
separate from each secret-bearing rehearsal ledger. Exact mutation patches are
for a controlled, sequential test campaign only, never deployment. Do not run
tests/reviews concurrently with mutations; verify every source hash after each
restore, finish with an unmutated rehearsal and independently audit absence.

For reusable commands, supply your installed dependency paths first:

```sh
export VW_REHEARSAL_XVFB=/absolute/path/to/Xvfb
export VW_REHEARSAL_CERTUTIL=/absolute/path/to/certutil
export VW_REHEARSAL_FIREFOX=/absolute/path/to/firefox
export VW_REHEARSAL_UI_DEPS=/absolute/path/to/node_modules
CERTUTIL="$VW_REHEARSAL_CERTUTIL" FIREFOX="$VW_REHEARSAL_FIREFOX" VW_UI_DEPS="$VW_REHEARSAL_UI_DEPS" ./scripts/with-secure-test-tmpdir.sh npm test --prefix tests/ui
scripts/rehearse-protected-workflow.sh --automated
```

Replace each placeholder with an existing executable or dependency directory;
the historical `/tmp` extraction above may no longer exist. The active bounded
closure verification is recorded separately in
[`../protected-workflow-r2-closure/README.md`](../protected-workflow-r2-closure/README.md).
