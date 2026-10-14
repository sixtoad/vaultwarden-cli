# Protected workflow rehearsal verification

Baseline: `49649d0e8e0ce8318da06a21be93616eec9a3c34`, branch
`feature/protected-workflow-rehearsal`. Evidence dates: 2026-10-13 and 2026-10-14.

## Current correction checkpoint — 2026-10-14

The approved same-profile lifecycle/request-authority corrections and rehearsal
review corrections are implemented. Their final automated campaign, attributable
mutations, exact source restoration and independent host absence audit are recorded
in [the correction evidence index](protected-workflow-corrections/README.md),
with complete redacted logs and SHA-256 manifests in that durable directory.
The coordinated corrected-source human rehearsal passed in 104.64 seconds;
independent review subsequently reopened acceptance for private-display,
output-observation and failure-cleanup gaps. The preflight matrix supplement
passed separately. See the correction index's review outcome and human evidence;
the historical human run below is not acceptance of the changed behavior.
Two observed failures remain explicitly unexplained: a pre-final closed Busy
rejection and an initial final all-features history persistence failure. Passing
unchanged-source reruns do not establish fixes for either. Nothing was committed
or pushed.

## Historical pre-correction evidence (preserved)

The following account describes the earlier implementation and review checkpoint;
its pending-design language and evidence do not describe the current correction.

The executed automated production chain and genuine human rehearsal passed, but
independent review found acceptance gaps: this change is not ready to merge.
Most importantly, a normal same-profile request launch retires the original
provider tab's proof, leaving its Lock/Unlock controls unusable. The reset fixture
used a separate cookie context and did not establish that normal flow. Review
also found gaps in provider-output redaction evidence, authenticated replay,
cleanup recovery and future CI coverage. Fixes are pending a provider-lifecycle
design/scope decision; all existing work and evidence are preserved.

The latest human run completed its four decision scenarios in 131.01 s. The
earlier intermittent rejection remains unexplained; a passing retry does not
establish a fix. Passing tests below describe only the exercised behaviors,
not closure of the independent-review findings. Nothing was committed or pushed.

Confirmed:

- Focused Rust tests: five passed, production test explicitly ignored. The native
  x86-64 checker accepts only the fixed target plus correct injected field;
  missing/wrong fields, another target and ambient environment entries fail.
  All cases produce no stdout/stderr. AArch64 source is provided but not executed
  on this x86-64 host.
- Parent mutation testing found that omitting final private-root removal could
  falsely pass collision acceptance. Added independent post-cleanup checks using
  a pre-cleanup ownership snapshot: root, owned runtime, controller PID, units,
  cgroups and container must be absent, independently of cleanup's return flag.
  A focused regression rejects a retained empty root and accepts it only after
  actual removal. Collision acceptance with these checks passed in 0.27 s.
  The worker ran no production mutation during this narrow follow-up. Parent
  mutation rerun and final broad verification are recorded below.
- Bounded-I/O regressions passed: blocked 1 MiB stdin, a descendant holding
  inherited output pipes after its parent exits, and continuous output with
  SIGTERM ignored. Each hits a 150 ms command deadline, returns within two
  seconds and proves the exact owned process/descendant reaped. No blocking
  writer or reader-thread join is used. The focused suite finished in 0.50 s.
- A deliberately missing private-desktop dependency fails before provisioning.
  Actual occupied fixed-unit test passed: an owned harmless sleep sentinel was
  refused by nested preflight with its InvocationID unchanged, then stopped.
  Evidence: `docs/implementation/protected-workflow-rehearsal-collision.log`.
- Runner `--check`: passed with temporary Xvfb/certutil and locked local Node
  dependencies. The real user manager was reachable and the fixed production
  unit/runtime absent.
- Independent Unix-socket probe: kernel `SO_PEERCRED` reported subordinate host
  UID 100000 and GID 1000; the agent could not read a provider-private directory
  or regain provider identity; its process was reaped.
- Real desktop probe: private Firefox, NSS CA, Xvfb and D-Bus delivered a benign
  HTML artifact through `/usr/bin/xdg-open` within the production two-second
  bound. No fake launcher or backend was used.
- An initial default private D-Bus autoactivated a document portal. Its exact
  private FUSE mount was inspected, its owned transient service confirmed absent,
  the exact mount unmounted and its private directory removed. The final private
  D-Bus config has no automatic activation; that probe passed and cleaned itself.
- A failed private-bus startup correctly reported uncertain ownership and kept
  private material. Inspection established the service was absent, with no
  container or provider started; its exact retained synthetic directory was
  removed after that check. The missing bus `<listen>` configuration was fixed.
- The next full attempt passed private desktop delivery and created the private
  HTTPS synthetic server, then failed at private-keyring bootstrap. All owned
  services/container were stopped and all private files removed. No production
  approval was claimed. Keyring startup was changed to manager-owned private
  stdin, matching the established private-keyring fixture.
- A subsequent startup rejected a pre-created empty provider state directory:
  the production store requires an absent directory so it can create its own
  lock and initial state. Removed the precreation; no state files were injected.
  That run's stopped services and removed container were independently checked
  before deleting the exact retained private directory.
- Final automated run after independent cleanup checks: **passed**, 33.24 seconds. Retained redacted output:
  `docs/implementation/protected-workflow-rehearsal-automated.log`. The actual
  production daemon used process-scoped `SSL_CERT_FILE`; the independent client
  rejected the same server through ambient trust. Private browser trust stayed
  enabled. Public image/operation/pairing commands succeeded; every request
  remained pending before a real UI decision. Denial and wrong authentication
  produced no execution. Correct approval produced exactly one successful
  native check. Wrong injected field produced `execution_nonzero` after exactly
  one execution. Re-emitting the real approval form handler after each terminal
  decision produced a rejected HTTP approval and unchanged history.
- Redaction checks covered restricted CLI responses, public human history and
  provider journal against synthetic passwords, both fields, setup bearer,
  bootstrap secret, signing seed, raw/base64 symmetric keys, actual provider
  session token/keys and individual launch capabilities. Browser requests and
  passwords were not captured or logged.
- Final cleanup passed: provider, browser, keyring and bus stopped; their cgroups
  empty/absent; Docker container removed; no supervisor leases retained; signing
  key removed by the restricted identity; private files removed afterward.
- Active-work interruption passed in 20.52 s: actual SIGTERM reached the
  installed handler while a genuine signed production request was pending,
  after public provisioning and UI unlock. Cleanup proved termination before
  deletion. This does not claim interruption during the immediate native check.
  Evidence: `docs/implementation/protected-workflow-rehearsal-interrupt.log`.
- Injected cleanup failures passed in 19.77 s. A harness-only provider-stop
  refusal retained the live provider and setup. In-memory unit snapshots were
  discarded and recovered from fsynced InvocationID+cgroup ledger records.
  A second injected failure after actual provider stop, before cgroup-empty
  confirmation, again retained private files. Removing the injected faults
  permitted independently checked recovery and full cleanup. These are harness
  faults, not claims that the real manager failed. Evidence:
  `docs/implementation/protected-workflow-rehearsal-cleanup-failure.log`.
- Focused Clippy with `-D warnings` and focused Rust tests passed after the final
  implementation edits. Source formatting passed before the final full run.

Reproduction command used on this host (run with access to the actual user
manager, outside an environment that denies its bus):

```sh
VW_REHEARSAL_XVFB=/tmp/vw-rehearsal-tools.W7hQzv/extracted/usr/bin/Xvfb \
VW_REHEARSAL_CERTUTIL=/tmp/vw-rehearsal-tools.W7hQzv/extracted/usr/bin/certutil \
scripts/rehearse-protected-workflow.sh --automated
```

Xvfb and certutil were extracted from distribution packages into that disposable
directory without installation. `/usr/bin/firefox` and locked local
`tests/ui/node_modules` were used. The temporary tools are public binaries and
are managed separately from each rehearsal's secret-bearing resource ledger.

Use the same dependency environment with `--collision-check`, `--interrupt` and
`--cleanup-failure` to reproduce the explicit failure cases. Unit records are
durable before dependent secret-bearing setup; ledger recovery validates owner,
mode, file type, record scope, invocation format and cgroup path before use.

## Parent final verification — 2026-10-13 historical baseline

Complete logs are retained outside the repository at
`/home/sixtocantolla/sessions/day-to-day/_bmad-output/implementation-artifacts/protected-rehearsal-verification.WWJ1xR`.
The `final-*` logs were produced after the independent cleanup assertion fix and
exact mutation-source restoration.

- Formatting, staged/working diff whitespace, and all-feature Clippy passed.
- Default, all-features and no-default-features workspace/all-targets runs each
  reported 1,028 passes, zero failures and 17 ignored, with benchmark smoke
  checks passing. Each includes 75 unconfigured live-case early returns, which
  are excluded from executed live coverage. The opt-in rehearsal is ignored in
  these ordinary runs and was executed separately below.
- Configured live suite: 79 passed, zero failures/ignored, 356.00 seconds. Its
  private-isolation preflight passed. Owned container/network
  `vw-live-live-rauwti-vaultwarden-1` / `vw-live-live-rauwti_default` were removed.
- Real systemd: two passed (74.18 seconds); distinct-principal material test:
  one passed; kernel-peer/noninteractive namespace matrix: one passed (4.08 seconds).
- Final rehearsal modes all passed with independent post-cleanup absence checks:
  automated 33.06 seconds, collision 0.25 seconds, pending-request SIGTERM 19.98
  seconds, and injected stop/reap-observation failure recovery 20.54 seconds.
- Compiled false-completion and missing-injection production mutations failed
  with the generic `restricted request rejected` diagnostic. Those failures do
  not establish that the intended acceptance boundary caught either mutation;
  both historical outcomes are inconclusive, not attributable kills. The
  wrong-password bypass failed the actual browser decision gate. Compilation
  succeeded in each case, and owned resources were cleaned. These three runs
  preceded the independent cleanup-assertion addition; production behavior was
  not changed by that fix.
- The final-directory-removal mutation initially survived the credential-free
  collision case. After the assertion fix it compiled and failed with
  `post-cleanup resource still present or absence unconfirmed`. Both retained
  credential-free ledger directories were inspected; their exact units and
  cgroups were absent before their single ledger files and empty directories
  were removed. No secret-bearing resources were used for this mutation.
- SHA-256 checks confirmed exact restoration of every mutated source. Production
  source had no diff in this 2026-10-13 campaign, before the later approved UI
  correction. Final read-only host audit found the fixed provider unit
  not-found/inactive and no rehearsal auxiliary units, labeled containers or
  private rehearsal roots.

## Approved visible human path — 2026-10-14

The operator approved display-transport reuse on COSMIC. Implemented `--human`
with a validated owned Wayland socket, new private Firefox profile, private
session bus/keyring/runtime and profile-local CA. Automated mode retains Xvfb.
Human unlock and approval/denial are read-only observations: the harness never
types the operator's password or submits decisions. A private guide tab supplies
synthetic-only instructions without terminal/password/request-body capture.

- Focused Rust tests: six passed, production case ignored, 0.50 s. The new
  transport guard rejects path traversal, symlinks, foreign ownership and public
  runtime permissions. Its initial sandbox run hit EPERM binding a test-owned
  Unix socket; the normal-host focused rerun passed without changing the guard.
- Human observer tests: ten passed. Coverage includes unlock, denial with the
  real UI status suffix, wrong authentication while pending followed by denial,
  correct and wrong-field terminal outcomes, uncleared fields, unexpected
  decisions, expiry/retired sessions, bounded waits and closed-page failure.
  Read-only page stubs provide no typing/clicking/request capabilities. These
  unit tests are not human or production UI acceptance.
- Focused Clippy `-D warnings`, Rust formatting and shell/Node syntax passed.
- Benign `--human-check` passed in 14.65 s. The new private-profile Firefox used
  the existing COSMIC Wayland socket and received the real `xdg-open` probe.
  No vault or provider was provisioned; no human action was requested. Owned
  browser/bus/keyring services and controller were stopped, private files removed,
  and independent post-cleanup absence checks passed. Exact redacted log:
  `docs/implementation/protected-workflow-rehearsal-human-check.log`.

Reproduction (existing COSMIC session environment retained):

```sh
VW_REHEARSAL_CERTUTIL=/tmp/vw-rehearsal-tools.W7hQzv/extracted/usr/bin/certutil \
scripts/rehearse-protected-workflow.sh --human-check
```

This confirms launch/handoff, not that the operator saw the window. A genuine
`--human` run must be coordinated separately when the operator is ready. Its
manual waits are bounded to five minutes, with existing five-minute request and
fifteen-minute session expiry potentially ending the run sooner. Human mode
only observes disabled terminal controls; actual rejected HTTP replay remains
automated-mode evidence. At this benign-check checkpoint no actual human-mode
unlock, decisions, timeout cleanup or interruption had been exercised. The later
human attempt below observed unlock and failure cleanup. Earlier full campaigns
above precede this visible-path delta and must not be presented as verification
of the delta.

### Parent visible-path regression rerun

Logs: `/tmp/vw-human-verification.fMe6ll` (2026-10-14), after the visible-path
implementation and exact production-status observer fix.

- Formatting, all-targets/all-features Clippy and staged/working whitespace passed.
- Default, all-features and no-default-features workspace/all-targets runs each
  reported 1,029 passes, zero failures and 17 ignored across 20 suite summaries;
  benchmark smoke checks passed. As above, 75 unconfigured live-case early returns
  are excluded from live coverage, and the opt-in production case ran separately.
- Ten human-observer unit tests passed, zero failed/skipped.
- Automated production rehearsal passed in 33.50 s; collision refusal in 0.24 s;
  pending-request SIGTERM in 20.02 s; injected cleanup-failure recovery in 21.53 s.
  All four independently confirmed resource absence after cleanup.
- Independent host audit found the provider not-found/inactive, with no rehearsal
  auxiliary units, labeled containers or private rehearsal roots remaining.
- Configured live/systemd/namespace suites and compiled mutations were not repeated
  in this delta campaign; their earlier evidence is recorded above. Genuine human
  interaction was pending at this checkpoint; see the subsequent attempt below.
  No independent review, commit or push occurred.

### First genuine human attempt

On 2026-10-14 the operator requested `--human`. COSMIC desktop delivery and
synthetic provisioning passed, and the observer confirmed the operator's actual
provider unlock. The first denial scenario then failed with `private browser gate
failed`; no denial or protected execution was confirmed. Total run: 105.40 s.
That run's generic error does not identify the exact failing browser substep.
The operator reported that Firefox closed itself: this was runner cleanup after
the failed gate, not a successful completion.

Owned-resource cleanup and independent absence checks passed. A separate host
audit found the provider not-found/inactive, no rehearsal auxiliary units and no
labeled containers. Redacted log: `/tmp/vw-human-run.UtDoV7.log`. Human acceptance
remains incomplete. The operator subsequently reported re-unlocking from the
request tab. The approved correction separates provider unlock from request
approval; the generic error alone does not prove that was the failed substep.
No password or browser content was captured.

### Approved request UI and harness correction — 2026-10-14

Production changes are limited to the browser shell in `src/adapters/loopback_ui.rs`.
Request tabs remove provider lifecycle controls and preserve their role across
reloads. A fresh provider launch clears any stale request role. Provider tabs
retain Unlock/Lock with a persistent reset warning. Confirmed expired status
explains expiry or reset invalidation and requires a fresh request. Generic
authentication/retirement failure instead advises checking authoritative status
before resubmitting because execution may already have occurred. Backend
authentication, revocation and one-time decision semantics are unchanged.

The guide is prepared before request submission and distinguishes initial
provider unlock, password-free denial and per-request authentication. Invalidated
or retired terminal states fail observation promptly. Browser failures now carry
only an allowlisted stage, independently filtered in JavaScript and Rust; no raw
exception, DOM, URL, password or request content is emitted.

Focused correction evidence is retained at `/tmp/vw-request-ux.oxhzSj`:

- Loopback Rust tests: 29 passed, one browser fixture ignored. Rehearsal guard,
  checker and diagnostic tests: seven passed, production chain ignored.
- Human observer/redaction tests: 12 passed. These read-only stub tests are not
  actual human acceptance.
- Trusted Firefox fixture regression passed, including both tab roles, request
  reload, fresh provider role, denial, authenticated approval, timed expiry,
  re-unlock while already unlocked with pending work, cross-tab Lock, disabled
  decisions, rejected replay and accurate retirement recovery. Provider lifecycle
  controls use an independent fixture cookie context; this does not establish
  that a stale same-profile provider tab survives cookie rotation. The fixture
  uses synthetic adapters, so this is distinct from production rehearsal evidence.
- Three browser mutations were rejected at their intended assertions: exposing
  request lifecycle controls, removing invalidated-request guidance, and removing
  retired-session guidance. Exact source restoration was verified with SHA-256
  `28107cc85b291b5442e3627f8b7adaa4083d53f41f53f5c803c6807debfc0837`.
- Formatting, whitespace, Node syntax and all-target/all-feature Clippy passed.
  The final restored browser suite passed with zero unexpected diagnostics
  (`browser-restored.log`); all 12 observer tests passed (`observer-final.log`).
- Automated production rehearsal passed in 59.78 s (`production-automated.log`):
  actual trusted UI unlock, denial, wrong-password rejection, exactly one approved
  execution, wrong-field execution failure, repeated-decision rejection, redacted
  CLI/history/journal and independent resource-absence checks after cleanup. This
  is automated evidence only. No human retry was run.

The initial browser-test attempts exposed fixture-only issues after moving
lifecycle controls to the separate provider context: keyboard input needed that
context brought forward, and the new re-unlock case had to follow the old timed
expiry case to preserve its distinct history assertion. Both were corrected;
the final restored run passed. A separate host audit after the production run
confirmed provider not-found/inactive and no rehearsal auxiliary units, labeled
containers or private roots.

### Parent correction regression campaign — 2026-10-14

Logs: `/tmp/vw-request-ux-parent.39AG0F`. Formatting passed. Sequential default,
all-features and no-default-features workspace/all-targets runs each reported
1,030 passes, zero failures and 17 ignored across 20 suite summaries, with
benchmark smoke cases succeeding. The 75 unconfigured live-case early returns
in each configuration are excluded from live coverage.

Collision refusal passed in 0.22 s; pending-request SIGTERM passed in 23.42 s;
injected stop/reap-observation failures and recovery passed in 20.29 s. Each
included independent post-cleanup resource-absence checks. A final separate host
audit found the provider not-found/inactive and no rehearsal auxiliary units,
labeled containers or private roots. No private rehearsal data remains; extracted
public tools are retained for reuse.

The parent read the complete 3,283-line baseline diff
`/tmp/vw-request-ux-diff.V25BRI`, verified the restored production-source hash
above, and passed whitespace checks. Configured live, dedicated systemd/namespace
suites and earlier compiled production-boundary mutations were not repeated in
this correction campaign; their historical evidence remains separate. The three
new browser mutations and restored browser/production runs are recorded above.
No corrected human retry, independent review, commit or push has occurred.

### Corrected human retry — 2026-10-14

The operator explicitly requested `start`. The isolated COSMIC/Firefox run
observed actual human provider unlock, denial, wrong-password rejection followed
by denial, and one successful approved execution. Each completed scenario passed
terminal-control and redacted agent-result checks. Before presenting the final
wrong-field scenario, its signed submission failed with `restricted request
rejected`. The test failed after 172.74 s; this is not a full acceptance pass.
Redacted log: `/tmp/vw-human-retry.eVvBC1.log`.

The harness currently collapses every structured agent rejection category into
that generic message. The precise category was not retained in the log, so no
specific cause is established. Source inspection confirms a closed redacted
`AgentRejection` enum that could provide a safe diagnostic without recording
arbitrary response data. No automatic retry or implementation change followed.

Cleanup and independent absence checks passed. A separate host audit confirmed
provider not-found/inactive and no rehearsal auxiliary units, labeled containers
or private roots. Browser closure was cleanup after failure. Human approval now
has genuine evidence, but the final wrong-field scenario and complete-run
redaction audit remain unperformed in this retry; independent review stays open.

### Closed rejection diagnostics and bounded investigation — 2026-10-14

The rehearsal harness now uses an explicit `submit`/`poll` action and parses the
closed production `AgentResponse` protocol after its existing stdout-redaction
gate. Recognized rejections emit only that fixed action and an exhaustively
mapped `AgentRejection` category. Malformed JSON, unknown categories, unexpected
fields, invalid identifiers and unsupported protocol frames produce a generic
invalid-response diagnostic without response bytes or parser errors. Transport
failures also retain only fixed action context. This changes test diagnostics;
provider admission, authentication, rejection and one-shot submission behavior
are unchanged. No automatic resubmission was added.

Evidence directory: `/tmp/vw-rejection-diagnostics.rsEyee`.

- Three new focused diagnostic tests passed: all nine closed rejection
  categories under both actions, 19 malformed/adversarial frames under both
  actions, and unchanged valid pending/completed/failed response shapes.
  Synthetic malformed responses are sanitization-test evidence only, not a
  production reproduction (`diagnostics-before-mutation.log`).
- A compiled diagnostic mutation changed the Busy label to `unspecified`.
  The category regression failed at the intended assertion (`submit` must report
  `busy`), exit 101 (`mutation-category-collapse.log`). Both test sources were
  restored exactly and checked against SHA-256
  (`source-before-mutation.sha256`, `mutation-restoration.log`). Subsequent
  lint-only edits named deliberately discarded errors; final source hashes are
  in `source-final.sha256`.
- The initial sandboxed full focused suite had nine passes, one Unix-socket
  regression failure (`EPERM`) and one ignored production case
  (`focused-restored.log`). Rerunning with host permissions and the secure-temp
  wrapper passed all ten tests, zero failed, one production case ignored in
  0.49 s (`focused-host-final.log`).
- Formatting, whitespace and workspace/all-targets/all-features Clippy with
  warnings denied passed (`format.log`, `whitespace.log`, `clippy-final.log`).
  The initial Clippy run identified three intentionally discarded-error naming
  warnings; those were fixed before final verification.
- Three sequential automated production rehearsals passed in 34.27 s, 34.96 s
  and 34.77 s (`production-automated-1.log`, `production-automated-2.log`,
  `production-automated-3.log`). Each exercised actual production unlock,
  denial, wrong-password rejection, one approved execution, wrong-field failure,
  one-time decisions, final CLI/history/journal redaction and independently
  checked cleanup. These used the existing extracted Xvfb/certutil dependency
  overrides recorded above. They are automated UI evidence only.
- A separate host audit passed after all three runs: provider not-found/inactive
  and no rehearsal auxiliary units, labeled containers or private roots
  (`host-audit.log`). No private rehearsal material remains.

The intermittent final submission failure did not reproduce in these three
bounded runs; no structured rejection was observed. Its original category and
cause remain unconfirmed. Source inspection shows that authority-gate contention
can return Busy in `agent_peer_eligible` or `submit_signed`, but that possibility
does not establish what happened in the human retry. No backend fix is proposed
as proven, and no production behavior was changed. A future actual rejection can
now retain its safe category and action without logging its response body.

No human run, renderer rerun, independent review, commit or push occurred in this
diagnostic campaign. Broader historical verification remains separate; full
human acceptance is still incomplete and another human retry requires readiness
coordination.

Parent follow-up logs: `/tmp/vw-rejection-parent.U8hhZw`. Focused all-features and
no-default-features runs each passed ten tests with one opt-in production case
ignored; the 12 observer tests passed. The final formatting check caught a line
wrap introduced by the named-error lint fix. Formatting was corrected without
behavior changes; final formatting, the ten-test default focused suite and
workspace/all-targets/all-features Clippy all passed. Final support-source SHA-256
is `c3e589ae6eccd41ec2d4555d4973ef8044a660e5b5dbd495a7e780a073731590`;
test-source SHA-256 is
`e60ade508f155c864982a50fb6406684ac44351ee2dd1207b6f382be37e1894a`.
The parent read the complete 3,468-line baseline diff
`/tmp/vw-rejection-audit.cnBBBv.diff` and subsequent documentation/formatting
deltas. A separate parent host audit also confirmed no provider, rehearsal
auxiliary units, labeled containers or private roots. Full workspace, configured
live, dedicated systemd/namespace and previous browser/production mutation
campaigns were not repeated for this diagnostic-only change; their evidence is
historical, not a new full verification claim.

### Full genuine human rehearsal passed — 2026-10-14

The operator requested `start` after the diagnostic update. The full `--human`
run passed in 131.01 s: actual human provider unlock, denial, wrong-password
rejection followed by denial, exactly one successful approved execution, and
the deliberately wrong injected field producing the expected execution failure.
Terminal controls were disabled, restricted-agent results were redacted, and the
final CLI/history/journal redaction checks passed. This is observed human action,
not automated approval. Human mode does not send replay decisions; actual HTTP
replay rejection remains separate automated evidence.

Owned-resource cleanup and independent absence checks passed. A separate host
audit found provider not-found/inactive and no rehearsal auxiliary units, labeled
containers or private roots. The browser closed as normal successful cleanup.
Original log: `/tmp/vw-human-diagnostic-retry.nEbIRP.log`; retained with only the
final empty line omitted in
`docs/implementation/protected-workflow-rehearsal-human.log`. Test result: one
passed, zero failed or ignored. No code changes or automatic retry occurred.

The earlier intermittent submission rejection did not recur; its original cause
is still unconfirmed. This successful run satisfies human-mode acceptance without
claiming that the intermittent failure has been fixed.

### Full verification and mutation audit before terminal assertion — 2026-10-14

Evidence: `/tmp/vw-final-verification.z5QalR`. These checks ran after genuine
human acceptance and before the terminal-status assertion correction below.

- Formatting and workspace/all-targets/all-features Clippy passed. Sequential
  default/all-features/no-default-features workspace/all-targets configurations
  each reported 1,033 passes, zero failures and 17 ignored across 20 summaries;
  benchmark smoke checks passed. The 75 unconfigured live early returns in each
  remain excluded from live coverage (`fmt.log`, `clippy.log`, `default.log`,
  `all-features.log`, `no-default-features.log`). Each workspace command used
  `scripts/with-secure-test-tmpdir.sh cargo test --workspace --all-targets
  --offline --locked` with the corresponding feature flag.
- Configured `scripts/test-live.sh`: two isolation-preflight tests and all 79
  configured tests passed, zero failed/ignored, 344.49 s for the configured
  suite. Its owned container/network were removed (`live.log`).
- Secure-temp `scripts/test-systemd-supervisor.sh`: two real-manager tests
  passed in 74.14 s and the distinct-principal material test passed in 0.12 s
  (`systemd.log`). The CI namespace command, `VW_AGENT_NAMESPACE=1 TMPDIR=/tmp
  unshare --user --map-auto --map-root-user --fork cargo test --offline --locked
  --test agent_submission real_linux_peer_matrix_and_noninteractive_cli --
  --ignored --exact --nocapture`, passed one test in 4.16 s
  (`agent-namespace.log`).
- Trusted Firefox fixture passed with zero unexpected diagnostics, including
  both tab roles, session resets, authenticated decisions and recovery guidance;
  twelve observer tests passed (`browser.log`, `observer.log`). Fixture evidence
  uses synthetic adapters and its documented separate provider cookie context.
- Automated/collision/pending-SIGTERM/cleanup-failure rehearsals passed in
  35.16 s / 0.22 s / 20.32 s / 20.06 s, each with independent post-cleanup
  absence checks (`rehearsal-*.log`). Extracted Xvfb/certutil overrides were
  unchanged. No visible human run was repeated.

All four temporary mutations compiled and were tested sequentially:

- False completion mapped a nonzero child exit to completed/zero. It failed
  after 47.15 s with `restricted agent poll rejected: busy`, not the intended
  terminal-status assertion. This outcome is inconclusive.
- Missing injection retained only the two locale entries in the helper's child
  environment. It failed after 44.27 s with the same poll Busy rejection.
  This outcome is also inconclusive.
- Approval bypass discarded the password-key derivation failure. It failed
  the wrong-password browser `request-submit` gate after 54.08 s.
- Cleanup omission retained the final private root in the credential-free
  collision case. The independent root-absence assertion rejected it in 0.24 s.

Each mutation's exact patch and run are retained as `mutation-*.patch` and
`mutation-*.log`. All six baseline source hashes were checked after every
restoration (`mutation-baseline.sha256`, `restore-*.log`). Secret-bearing mutant
runs passed cleanup and independent absence checks. The cleanup mutation's sole
retained ledger and empty directory were inspected and removed only after the
exact unit/cgroup were confirmed absent. The recovery audit also found no
rehearsal/systemd units or owned live Compose resources
(`cleanup-mutation-recovery.log`).

The two inconclusive outcomes exposed a harness assertion gap: an unexpected
terminal result kept polling for the expected result and could encounter an
unrelated Busy rejection. Poll Busy was actually observed in these mutant runs;
it does not establish the cause of the earlier human submission failure.
Verification paused after exact restoration for the scoped correction below;
there was no claim of an attributable kill or final unmutated pass at this point.
Configured-live/systemd/namespace/browser-fixture results remain evidence for
those unchanged components and are not repeated merely for the test-only
terminal assertion correction.

### Terminal assertion correction and restored final verification — 2026-10-14

Only `tests/support/protected_rehearsal.rs` and `tests/protected_rehearsal.rs`
changed. The harness compares the closed `AgentStatus` model, including exact
exit code or failure category, after the existing redaction and protocol gates.
Pending/approved/running observations continue polling. Any unexpected terminal
observation immediately fails with `restricted agent poll terminal status
mismatch`; malformed status data produces a fixed invalid-status diagnostic.
Agent rejection errors still stop the first failing poll. No production behavior,
submission retry, approval action or human interaction changed.

Final correction evidence: `/tmp/vw-terminal-verification.DM6UqQ`.

- Four new tests passed. They cover all 81 pairings of nine terminal values,
  valid nonterminal progress, malformed/unsupported values, and an explicit
  one-poll limit for terminal mismatch, malformed observations and rejection.
  Synthetic malformed test values never appear in emitted error text.
- Focused secure-temp suite: 14 passed, zero failed, production case ignored,
  0.50 s (`focused.log`). Formatting and workspace/all-targets/all-features
  Clippy with warnings denied passed (`fmt.log`, `clippy.log`).
- Sequential default/all-features/no-default-features workspace/all-targets
  configurations each reported 1,037 passes, zero failures and 17 ignored across
  20 summaries, with benchmark smoke checks passing (`default.log`,
  `all-features.log`, `no-default-features.log`). Commands used the same
  secure-temp wrapper and offline/locked flags as the preceding campaign.
  Each includes 75 unconfigured live early returns, excluded from live coverage.
- All twelve observer tests passed (`observer.log`).
- Automated/collision/pending-SIGTERM/cleanup-failure rehearsals passed in
  34.46 s / 0.23 s / 19.72 s / 20.10 s, each including independent cleanup
  checks (`rehearsal-*.log`). Dependency overrides remained unchanged.
- Refreshed false-completion mutation failed at the intended terminal mismatch
  during the wrong-field scenario in 33.69 s. Refreshed missing-injection
  mutation failed at the intended terminal mismatch during the approved
  scenario in 29.68 s. These are attributable failures; they supersede the
  inconclusive mutant runs above without rewriting those historical outcomes.
- Refreshed approval bypass failed at the wrong-password browser
  `request-submit` gate in 53.52 s. Refreshed final-root-removal omission failed
  the independent root-absence assertion in the credential-free collision case
  in 0.38 s. No mutation survived. Patches and logs are `mutation-*.patch` and
  `mutation-*.log`.
- All seven baseline source hashes were verified after every mutation and once
  more after final verification (`mutation-baseline.sha256`, `restore-*.log`,
  `final-source-restoration.log`). Secret-bearing mutation runs passed cleanup
  and independent absence checks. The cleanup mutant's only retained ledger and
  empty root were inspected and removed after exact unit/cgroup absence checks
  (`cleanup-mutation-recovery.log`).
- Final unmutated automated production rehearsal passed in 34.19 s after exact
  restoration: all four scenarios, final CLI/history/journal redaction and
  independent cleanup passed (`rehearsal-final-restored.log`). Final formatting
  and whitespace checks passed (`fmt-final.log`, `whitespace.log`).
- A separate final host audit confirmed provider not-found/inactive, its cgroup
  absent, no rehearsal/systemd auxiliary units, no labeled rehearsal containers,
  no owned live Compose resources and no private rehearsal roots
  (`host-audit.log`). No private rehearsal material remains.

The just-completed configured live, systemd/distinct-principal, kernel namespace
and trusted browser fixture checks in `/tmp/vw-final-verification.z5QalR` were
not rerun after this test-only assertion correction. Their production and
fixture paths were unchanged. The genuine human interaction pass remains
separate evidence; no visible run was repeated. The earlier human submission
rejection's original cause remains unconfirmed despite the observed poll Busy
in the pre-correction mutant runs. No production retry or backend fix is claimed.
Executable verification is complete; parent matrix audit and independent review
remain outstanding. No renderer rerun, remote operation, commit or push occurred.

## Remaining acceptance and review

Interruption was exercised while approval was pending, not inside the immediate
checker; SIGKILL/power-loss recovery is not automated. AArch64 was not executed.
The extracted public dependency directory remains available for subsequent runs;
it contains distribution binaries, not private rehearsal data.

The approved visible path, human unlock and all four human decision scenarios
passed in the latest run. No
existing browser profile, desktop content/keyring or host trust was accessed or
changed. Final executable verification is recorded above; parent audit and
independent review have not been claimed complete.

Human acceptance for the exercised decision sequence is supported by the genuine
run above. BMAD independent review is complete and has reopened acceptance:
same-profile provider lifecycle, redaction/replay evidence, cleanup recovery,
prerequisites, observer races/CI and durable final evidence need correction.
The spec is in-review, awaiting the provider-lifecycle design decision before
changes outside the approved UI-only scope. The earlier intermittent rejection
remains an unresolved reliability risk. No commit, push or PR was made.
# Bounded R2 closure supplement

The approved incremental correction pass is tracked in
[protected-workflow-r2-closure/README.md](protected-workflow-r2-closure/README.md).
Historical commands and logs above retain their original provenance. Their
temporary dependency paths may be absent; reusable commands in the correction
index use operator-supplied absolute paths. References to human wrong-password
rejection mean generic rejection during the instructed step, not proof of its
exact backend cause. Discarded Firefox, Xvfb and desktop/helper output was not
audited; controller/service captured output is distinguished in the supplement.
