# Bounded R2 closure evidence — 2026-10-14

Incremental corrections implement only the approved bounded closure tasks in
`spec-protected-workflow-review-corrections.md`. Existing staged work, historical
logs and manifests remain preserved. Overall acceptance awaits the parent audit.

This directory retains actual focused results, changed-source fingerprints,
attributable mutations and exact restoration records. Raw historical manifests
in the previous evidence directories were not regenerated.

Scope: authenticated private X setup and negative unauthenticated setup; private
Xauthority audit; complete bounded controller stdout through EOF; retained child
identity across uncertain reap/retry; strict filesystem absence observation;
opt-in desktop prerequisite regression on supported architectures; launch-cookie
and server-selected request regressions; accurate audit/observer claims and
operator-supplied dependency paths. Production authorization is unchanged.

Limitations: discarded Firefox, Xvfb and desktop/helper output is not audited.
Human observation establishes generic rejection during the instructed wrong-
password step, not its exact backend cause. No new human run is authorized or
claimed. The prior Busy and PersistenceFailure observations remain unexplained;
this pass does not claim to fix them. No configured live/systemd/namespace full
campaign is repeated for unchanged production paths. No commit or push.

## Executed verification

All test campaigns ran sequentially. Secure temporary directories require the
actual host ownership mapping; the sandbox attempt correctly refused remapped
root ancestry (`focused-default.log`). Approved host execution preserved the
guard. `focused-default-host.log` is an earlier development checkpoint; use the
final/restored logs below for the fingerprinted source. Initial Clippy identified
one collapsible conditional, fixed before the recorded successful checks.

| Check | Result and evidence |
|---|---|
| Formatting, all-target/all-feature Clippy | Passed before and after mutations; `fmt.log`, `clippy.log`, `restored-fmt.log`, `restored-clippy.log` |
| Focused harness, default/all-features/no-default | 17 passed, 0 failed, 3 ignored in each; `final-focused-default.log`, `focused-all-features.log`, `focused-no-default-features.log`; restored default also 17/0/3 |
| Affected adapters | 31 passed, 0 failed, 1 browser fixture ignored; `adapters.log` |
| Provider sessions | 7 passed, 0 failed; `provider-session.log` |
| Explicit opt-in missing-desktop test | 1 passed, 0 failed, 0 ignored; `missing-desktop-opt-in.log` |
| Actual restricted-identity negative traversal | 1 passed, 0 failed, 0 ignored; `restricted-identity.log` |
| Observer and trusted same-profile Firefox | 13 observer passes, Firefox suite passed with 0 unexpected diagnostics; `browser.log`, repeated successfully after restoration in `restored-browser.log` |
| Automated rehearsal | Passed in 35.19 s; `rehearsal-automated.log` |
| Collision / interrupt / cleanup-failure | Passed in 0.24 / 20.36 / 20.65 s; corresponding `rehearsal-*.log` |
| Restored launch-cookie regression | 1 passed, 0 failed; `restored-launch-cookie.log` |
| Final unmutated automated rehearsal | Passed in 34.56 s; `final-rehearsal.log` |
| Independent host absence audit | Passed; `final-host-audit.log` and its retained `audit-host.mjs` |

Applicable real rehearsals explicitly record both authenticated X setup success
and unauthenticated X setup rejection. Cookies pass through piped xauth stdin;
nonempty listings are verified privately. Rust's absolute-path xauth listing is
piped and retained only in the private rehearsal directory, then its credential
is registered before captured-output scanning. No cookie is published here.

Controller stdout is bounded at 4 MiB, including bytes after protocol replies
through shutdown and EOF. Tests exercise a valid response followed by a sentinel,
overflow, missing EOF, real cleanup refusal and evidence retention. Retry tests
preserve the child handle on false/error observation; filesystem tests distinguish
NotFound from ENOTDIR and exercise real cleanup refusal. Deliberately discarded
Firefox/Xvfb/helper streams remain outside the audit.

The final host audit independently found the provider not-found/inactive and no
rehearsal units/cgroups, labeled containers, private roots, supervisor runtime or
owned controller/process. No executable source changed after restoration.
`source.sha256` fingerprints the six changed source/test files;
`documentation.sha256` fingerprints the three changed documentation indexes;
`evidence.sha256` covers this closure directory excluding itself and its check log.
Overall acceptance remains open for the parent audit and independent closure
review; these results do not substitute for that decision.

Both roles reject malformed/duplicate launch cookies and preserve capabilities
for a later valid one-use exchange. Browser cases use a conflicting request-ID
suffix and no suffix, verify the server-selected review, deny only that request,
and check the other request remains pending. No production role logic changed.

## Attributable mutations

Each mutation was applied alone, executed, inspected for the expected assertion,
and reverted. `mutation-*.source` identifies the exact mutated source; `.patch`
files show the targeted edit snippets. `restore-*.log` checks every fingerprint
in `source.sha256`, not just the changed mutation file. No test/review ran in
parallel with a mutation. The handle-loss mutant's only child was a bounded
30-second synthetic sleep; no provider/private resource was involved.

| Mutant | Observed rejection |
|---|---|
| Controller audit omission | `controller audit accepted deletion of private leak/overflow evidence` |
| Controller overflow guard omission | `controller overflow accepted on initial or retry audit` |
| Metadata errors treated as absence | `metadata failure accepted as absence` |
| Controller handle taken before confirmed reap | `controller identity lost on retry` |
| Launch-cookie prevalidation omission | New both-role regression: 200 versus required 403 |
| Fragment-selected request identity | New Firefox assertion: `server selects request despite fragment suffix` |
| Xvfb `-ac` | `private browser gate failed at private-xserver`; failed in 2.05 s, with output audit and independent cleanup checks passing |

The fragment mutation log contains only synthetic request IDs in the assertion;
these are not launch capabilities, cookies, passwords or proofs.

## Commands and provenance

Commands ran from the repository. Actual existing dependencies were
`/tmp/vw-rehearsal-tools.W7hQzv/extracted/usr/bin/Xvfb`,
`/tmp/vw-rehearsal-tools.W7hQzv/extracted/usr/bin/certutil`, `/usr/bin/firefox`,
the repository's `tests/ui/node_modules`, and Node v26.3.1. These paths identify
this run only; supply existing absolute dependency paths when reproducing.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
./scripts/with-secure-test-tmpdir.sh cargo test --offline --locked --test protected_rehearsal -- --test-threads=1
# Repeat the focused command with --all-features and --no-default-features.
./scripts/with-secure-test-tmpdir.sh cargo test --offline --locked --lib adapters::loopback_ui::tests -- --test-threads=1
./scripts/with-secure-test-tmpdir.sh cargo test --offline --locked --test provider_session -- --test-threads=1
./scripts/with-secure-test-tmpdir.sh cargo test --offline --locked --test protected_rehearsal missing_desktop_prerequisite_fails_before_provisioning -- --ignored --exact --nocapture
./scripts/with-secure-test-tmpdir.sh cargo test --offline --locked --test protected_rehearsal restricted_identity_refuses_inaccessible_directory_before_provisioning -- --ignored --exact --nocapture
CERTUTIL="$VW_REHEARSAL_CERTUTIL" FIREFOX="$VW_REHEARSAL_FIREFOX" ./scripts/with-secure-test-tmpdir.sh npm test --prefix tests/ui
scripts/rehearse-protected-workflow.sh --automated
# Then --collision-check, --interrupt, --cleanup-failure sequentially.
```

Mutation checks used the exact named harness/adapter regression with
`--exact --nocapture`, the trusted Firefox suite for fragment identity, and
`--automated` for display authentication. Post-restoration verification repeated
fmt/Clippy, focused harness, launch-cookie regression, observer/Firefox, then the
final unmutated automated rehearsal. The independent read-only host audit is
`node docs/implementation/protected-workflow-r2-closure/audit-host.mjs`.
