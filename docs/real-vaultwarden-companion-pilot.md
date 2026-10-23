# Disposable real Vaultwarden / Flutter Mac pilot

This opt-in Linux runner uses Docker Vaultwarden 1.36.0, one new test account,
one marked Login/custom credential, and the actual daemon/helper/systemd chain.
The approved native checker accepts only the fixed target and decrypted field;
its sole syscall is exit. No existing vault/account is accessed. The foreground
Flutter development app supplies unlock and all four human decisions. This is
separate from the fake-backend `tests/companion-acceptance.py` evidence.

No installed app replacement, host trust changes, biometric approval, startup,
notifications, cross-platform provider transport, or new operation is involved.
The runner requires the local default Docker engine, systemd user manager with
cgroup v2, subordinate UID/GID mappings, native C compiler, OpenSSL, private D-Bus
and GNOME Keyring/Secret Service tools, Rust/Cargo and Python 3. Firefox/Xvfb/Node
are not required. It installs no software or accounts. Existing production
`vaultwarden-accessd.service` or its fixed supervisor runtime is a collision,
even if stopped; the runner never stops/replaces an unrelated service.

## Prepare and run

```sh
bash scripts/pilot-real-vaultwarden-companion.sh --check
# Retain only the runner's sanitized output in a fresh owner-only location.
umask 077
pilot_evidence=$(mktemp -d /tmp/vw-real-pilot-evidence.XXXXXXXX)
VW_PILOT_HOSTNAME=provider.private.example VW_PILOT_LISTEN=192.168.1.20:8443 \
  bash scripts/pilot-real-vaultwarden-companion.sh --run \
  > "$pilot_evidence/operator-run.log" 2>&1
```

Watch that exact log from a second terminal; it survives Linux pilot cleanup.
Keep its directory 0700 and the log 0600. Do not capture raw provider responses,
private files or service logs into this operator evidence channel.

Choose the actual Linux private LAN/VPN interface address and a free port. The
DNS name must resolve to that interface from the Mac. Wildcard/public/loopback
listener addresses are refused. TLS verifies CA, exact hostname, validity and
leaf pin; no trust exception or tunnel is introduced. The backend itself stays
on a dynamically selected loopback HTTPS port in a disposable container with
tmpfs data. Separate fresh companion server and client certificates are signed
by this run's private CA. The account bootstrap API secret is written by private
stdin into the isolated keyring. No credentials are command arguments or env vars.

`FAIL: pilot listener_unavailable` means the pre-setup bind check failed. An
established outbound connection can occupy a port even when no listener appears;
inspect the exact port across all TCP states and select a free one. Do not stop
an unrelated process. Setup failures use fixed `private_services_failed`,
`certificates_failed`, `vault_startup_failed`, `vault_provisioning_failed`,
`provider_bootstrap_failed`, `enrollment_failed`, `provider_startup_failed` or
`provider_readiness_failed` categories. Collisions use `provider_unit_collision`
or `supervisor_runtime_collision`; explicit stop and signals use `operator_stopped`
and `interrupted`. Other errors use `operation_failed`. The owned root is printed as
soon as its ledger exists; underlying OS/upstream messages are never printed.

After owned setup begins, a failure emits and flushes one bounded JSON record
(`kind: pilot_failure_observation_v1`) before teardown. It includes the phase,
validated request ID when available, observation timestamps, last typed status,
and exact-request counts when the existing bounded history read succeeded.
This uses no extra provider queries and never retries submission. Counts and
status are explicitly historical and may be stale, not a final outcome; absent
snapshots are `unavailable`, and null IDs/timestamps are unavailable. A pending
snapshot or a zero count in bounded history does not establish eventual zero
execution. Only an observed `expired` status supports an expiry observation;
`decision_observation_timeout` alone does not. Malformed or failed polls preserve
the older snapshot, visibly marked as potentially stale.

Closed failure categories distinguish `status_poll_failed`,
`invalid_status_observation`, `unexpected_terminal_status`,
`decision_observation_timeout`, `readiness_timeout`, `history_read_failed`,
`invalid_history_observation`, `history_verification_failed` and
`invalid_request_id`. Other failures remain `operation_failed`. Output is scanned
against the private secret corpus before emission; a scan failure retains private
material under the existing cleanup rules. Output-write failure still attempts
normal teardown and reports `failure_observation_unavailable`. No raw error chain
or response body is emitted. If the output sink itself is unavailable, do not
claim durable evidence. The record describes execution failure, not cleanup
success; read the subsequent cleanup result separately.

The runner prints the exact private root, endpoint, public certificate hashes,
binary hashes and readiness phase. The Linux root is group-traversable solely
for the restricted agent; `private` and its handoff/control directories are 0700.
Before public offline enrollment, the real daemon is started in locked-only mode
under the fixed production service. It creates the complete provider state and
advances its lifecycle generation. The harness verifies its exact InvocationID,
stops it, proves its cgroup and unit absent, and durably records retirement before
enrolling the fresh certificate and starting the final provider. The two service
lifetimes retain distinct capture files and ledger entries. No lifecycle files
are fabricated; a directory and empty lock alone are not initialized state.
Public image/operation registration and agent pairing run
after the first readiness advance, when the human has unlocked the provider.

## Private Mac handoff and prior configuration

Before changing Flutter setup, ensure its existing decision has settled through
authoritative status. Never erase an unresolved marker to switch providers.
Quit the development app and preserve its exact existing configuration file,
including its `pendingID`, if present, in a new owner-only backup without printing
it. The sandboxed development app resolves Application Support inside its
container, normally:
`~/Library/Containers/dev.vaultwarden.companionSlice/Data/Library/Application Support/dev.vaultwarden.companionSlice.provider/configuration-v1.json`.
Confirm the exact path for the agreed bundle ID and build before copying. An
unsandboxed build may instead use
`~/Library/Application Support/dev.vaultwarden.companionSlice.provider/configuration-v1.json`;
do not assume this is the active file or back up an unrelated copy. Inspect only
the expected development app locations, not installed Swift app preferences.
Record the backup's exact location/hash and whether the configuration previously
existed. Preserve the old Keychain identity. Do not touch installed Swift app
preferences, identity or bundle. Launch only the agreed foreground Flutter build;
record the app/source hashes and Mac version in sanitized evidence.

For the optional quick-setup build, transfer only
`private/mac-handoff/quick-setup.json` to a fresh owner-only directory on the Mac
through the agreed trusted channel. This versioned, bounded bundle includes only
this run's disposable endpoint, CA DER, pinned server leaf hash, expected client
fingerprint, dedicated PKCS#12, import passphrase and disposable unlock password.
The harness writes it 0600 inside a 0700 directory and registers both raw and
base64 private material with its output redaction checks. Never put the bundle
in Git, CI artifacts, logs, command arguments, environment variables or this chat.
Open it locally in a trusted editor, copy the complete JSON, paste it into
**Paste disposable test bundle** in the foreground test app, and click
**Configure and unlock** once. No file navigation is needed. Setup imports the
dedicated identity, compares its fingerprint before saving, then makes exactly
one unlock attempt through the existing controller. It does not submit or decide
a request. Invalid input, import failure, mismatched identity, unresolved decision
recovery, an in-flight operation, or lifecycle/route invalidation cannot continue
into an automatic unlock. A failed attempt is never retried automatically.

The app clears the paste field after use and lifecycle/route invalidation.
Managed strings and system clipboard history are not guaranteed zeroized;
clear the clipboard explicitly and avoid clipboard synchronization/history while
handling this disposable bundle. Keep the source file and all transferred copies
in the exact Mac handoff ledger, separately from Linux teardown.

Quick setup is absent from ordinary builds. Build the separate test artifact on
a Mac build host in a fresh dedicated checkout (this command never installs or
launches it):

```sh
bash scripts/build-disposable-pilot.sh /absolute/path/to/disposable-pilot-evidence
```

The script enables Dart `--dart-define=COMPANION_DISPOSABLE_PILOT=true` and native
Swift `COMPANION_DISPOSABLE_PILOT` together through the explicit
`scripts/disposable-pilot.xcconfig` Xcode override. The native method-channel
entry and parser/import are compiled out without the Swift flag. The CI job
`disposable-companion-pilot` produces only
`companion-macOS-disposable-pilot/companion-macos-disposable-pilot.tar.gz`, with
archive root `companion_disposable_pilot.app` and separate `pilot-artifact.json`.
It is a merge gate. The normal app/artifact remains separately built and named.
Normal desktop CI also runs opt-in Dart tests and both normal and opt-in native
tests, checking compiled symbols for the native entry's absence/presence.

Retain the prior manual backup described above. Quick setup additionally saves
an owner-only `configuration-before-pilot-<UUID>.json` next to an existing valid
configuration before import; it preserves the original identity. Failed import
attempts may leave these backups, and fingerprint mismatch may leave an imported
test identity in Keychain, but never replaces saved configuration or unlocks.
Retain and track those exact files/identity for separately agreed cleanup.
No host trust settings are changed.

Manual setup remains available in either build. For that path, transfer only the
four payload files listed in `private/mac-handoff/public.json`
and that public metadata file to a freshly created owner-only directory on the
Mac through the agreed trusted channel. The payload files are CA DER, client
PKCS#12, its passphrase file and the disposable vault password file.
Record exact source/destination paths and the new certificate fingerprint in a
separate owner-only handoff ledger; Linux teardown does not know remote paths.
Never publish the ledger if it contains private metadata. Do not transfer CA or
server private keys. Keep all payload files 0600 and the directory 0700. Do not
print or paste password-file contents into a terminal, assistant conversation,
logs or screenshots. The human opens these files locally and enters their values
only in Flutter's native import/unlock/approval controls.

In Flutter setup explicitly import this dedicated PKCS#12 and CA DER, enter the
displayed endpoint and exact leaf pin, and compare the client fingerprint with
the trusted Linux metadata. The human unlocks the real provider in Flutter.
Do not automate typing, reviewing, approval or denial. The only combined setup
and unlock action is the human's explicit quick-setup click described above.

## Explicit phases

With ROOT replaced by the exact advertised run directory, each command admits
one request; it never makes a decision. Execute only when the named phase is
advertised READY and the human is ready to decide on the Mac:

```sh
bash scripts/pilot-real-vaultwarden-companion.sh --advance ROOT human-deny
bash scripts/pilot-real-vaultwarden-companion.sh --advance ROOT human-approve
bash scripts/pilot-real-vaultwarden-companion.sh --advance ROOT agent-deny
bash scripts/pilot-real-vaultwarden-companion.sh --advance ROOT agent-approve
bash scripts/pilot-real-vaultwarden-companion.sh --advance ROOT finish
```

Do not issue these together. Wait for the current terminal PASS and next READY.
Human phases execute the actual owner CLI `vw-access request --no-wait`; agent
phases use the actual signed `submit`/`poll` CLI from a capability-dropped distinct
kernel UID with null stdin and no controlling-terminal interaction. Both reach
the same Flutter inbox. Review the complete operation/target/arguments/requester
and choose deny or approve once with a fresh password as instructed by the phase.
The Linux runner never submits an approval/password to the companion endpoint.

Each readiness wait is bounded to 20 minutes; each submitted request retains the
normal five-minute lifetime, with a 310-second observation ceiling. Session
expiry is unchanged. If setup took too long, unlock before advancing; unlocking
while a request is pending invalidates it. Duplicate, stale and out-of-order
advance controls fail. Expiry, unexpected results, disconnect or rejection fail
the run and trigger cleanup; there is no automatic request or decision retry.
After a lost Mac decision reply use the app's existing status-only recovery.
Do not replace its configuration while that recovery is unresolved.

Each denial must have zero execution starts; each approval must finish exit 0
with one start and one success. Complete history must contain exactly two starts.
CLI observations and private bounded service captures are scanned against the
test-secret corpus. The runner prints status metadata only. A leak retains private
material and fails acceptance. Four real human decisions are required; unit tests
and automated mutation results are not human acceptance.

## Stop, cleanup, recovery

```sh
bash scripts/pilot-real-vaultwarden-companion.sh --stop ROOT
```

Stop is available once readiness/control is published. During earlier setup use
SIGINT/SIGTERM on the exact runner. Stop/interruption produces a failed/incomplete
acceptance result and still attempts cleanup. SIGKILL/power loss cannot guarantee
cleanup. Never blindly rerun or delete retained directories.

The durable ownership ledger records exact unit InvocationIDs/cgroups and the
container ID/label. Cleanup verifies these before stopping the provider, then
keyring and bus; it proves cgroup termination and Docker absence before deleting
owned private files. Independent post-cleanup checks confirm directory, runtime,
unit/cgroup and container absence. Any ownership, termination or redaction
uncertainty preserves private recovery material and reports failure. Recovery is
manual: inspect only the retained exact ledger and owned resources, confirm IDs
and termination, and remove only that run's material. Do not use broad globs or
stop other provider services. The runner has no blind recovery/delete command.

Linux success explicitly excludes transferred files and Mac Keychain cleanup.
Retain the newly imported pilot identity until explicit exact cleanup is agreed.
After settling any decision and quitting Flutter, restore the preserved prior
configuration (or remove only the newly created config if none existed), keeping
the prior identity intact. Track transferred files/backup/identity separately;
do not claim deletion until separately confirmed. Never run Keychain-install
XCTest on the operator Mac.

## Verification

Ordinary tests provision nothing:

```sh
scripts/with-secure-test-tmpdir.sh cargo test --locked --test protected_rehearsal
python3 scripts/mutate-real-vaultwarden-pilot.py
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
scripts/with-secure-test-tmpdir.sh cargo test --locked --all-targets
```

Mutations separately disable readiness, duplicate protection, exact counts,
redaction, independent cleanup confirmation and pre-cleanup failure-evidence
emission. Each must compile and fail its
test; exact source restoration and a passing retest are required. Do not edit
or build concurrently with mutation runs. Real-service collision/interruption
and retained-cleanup evidence remains separate from these non-provisioning tests.
Record all executed checks and unexecuted human/service gates truthfully.

Implementation verification on 2026-10-22: formatting, all-target Clippy with
warnings denied, and shell syntax passed. The secure all-target test command
exited 0 (1,070 passed, 22 ignored across 20 test binaries; benchmark smoke checks
also succeeded). This includes 24 passing protected-rehearsal regressions, with
four explicit live/dependency cases ignored. Unconfigured live tests and ignored
tests do not establish real-backend or Mac acceptance. The pilot's `--check`
passed on the actual Linux host without provisioning resources.

All five targeted mutations failed their tests after compiling; restoration and
retest passed. The source/restored SHA256 was
`8a596dca25ac75592be08fdaeff7bf3489b453c4674a882cd4b041430b854fff`.
Local raw evidence: `target/pilot-mutations/report.json` and its sibling logs,
`/tmp/vw-real-pilot-all-targets.log`, and `/tmp/vw-real-pilot-clippy.log`.
Real-service collision/interruption/cleanup checks and all four actual
Mac decisions have **not** been executed for this implementation at this point.
No container/provider or Mac setup was performed in that initial verification.

Subsequent startup investigation on 2026-10-22: the first live invocation on
`192.168.1.235:49734` refused the bind before creating resources; an unrelated
established outbound connection occupied that port and was left untouched. A
second invocation on `192.168.1.235:34803` created the owned `MQSDXU` pilot root,
then failed after approximately 35 seconds before ready setup was reported.
Cleanup passed and the parent independently confirmed the root, provider unit
and port absent. The exact setup failure remains undiagnosed; no successful
real-backend startup or Mac acceptance is claimed.

Fixed closed setup-stage diagnostics and immediate owned-root reporting were
then added. Nine focused pilot tests, all-target Clippy, formatting and diff
checks passed. Current pilot module SHA256:
`1c7ea643ae5024c71df71e2bd7280b7d9bd1e9e7bb3681446e7607aec166e887`.
Logs: `/tmp/vw-real-pilot-setup-diagnostics-tests.log` and
`/tmp/vw-real-pilot-setup-diagnostics-clippy.log`. The earlier mutation/full-suite
records above precede these diagnostic-only additions.

Two attempted startup-only diagnostic invocations were rejected by automatic
approval review before execution. The second supplied the parent's quoted
user approval and approved spec, but review stated that assistant claims about
spec/prior-run approval did not establish trusted authorization for Docker,
Secret Service/systemd, credential generation and a LAN listener. No resources
were launched by those attempts. Further live attempts are paused pending the
explicit user authorization requested by the parent. After authorization,
resume startup diagnosis using the fixed categories, stop through `--stop` at
the first READY without any request advance, and independently verify teardown.
Those were the outstanding gates at the approval pause; the follow-up below
records the subsequently authorized startup checks.

After the user explicitly authorized “authorization to start disposable
Docker/services and a private-LAN listener”, startup diagnosis resumed. Real
Vaultwarden provisioning and enrollment succeeded, but the provider rejected
the hand-created directory/lock because an existing root must also contain
initialized durable state. The fix uses the actual locked-only daemon to create
state, verifies its positive lifecycle generation, stops and retires that exact
service lifetime, then performs offline enrollment and starts the final daemon.
The runner never writes durable provider state directly. Regressions prove that
directory/lock alone fails and that retirement cannot remove a newer invocation.

Real startup-only verification then passed twice on `192.168.1.235:34803`:

- `gnrBLI` reached first READY. A concurrent preflight refused the occupied fixed
  service without changing InvocationID `f2a73fd3d72b4de3856551af911ffc76`.
  Explicit `--stop` produced verified cleanup; an independent ledger-based check
  confirmed root/runtime/units/cgroups/container/listener absence and distinct
  bootstrap/final InvocationIDs with exact retirement.
- `WeK7JY` reached first READY. The exact tracked runner PID `2114174` was verified
  by executable and command line before SIGTERM. A private state check confirmed
  zero requests, pairings and operations. The signal handler cleaned up; an
  independent check confirmed runner/root/runtime/units/cgroups/container/listener
  absence. This is actual signal evidence, separate from orderly `--stop`.

Both runs intentionally exited 101 because the four-decision acceptance remained
incomplete, even though startup and cleanup succeeded. Neither advanced a request,
accessed the Mac, transferred handoff files or imported an identity. Saved resource
metadata: `/tmp/vw-real-pilot-startup-ownership.jsonl` and
`/tmp/vw-real-pilot-interruption-ownership.jsonl`; collision log:
`/tmp/vw-real-pilot-collision.log`. The metadata contains resource identities,
not passwords/private keys. Uncertain-cleanup behavior is covered by the executed
fail-closed regressions and cleanup-confirmation mutation; no live injected
failure is claimed or required as an additional gate. All four actual Mac
decisions remain outstanding; no complete acceptance is claimed.

Final startup-fix verification (2026-10-22): the new initialization regression
initially failed only at immediate post-drop lock reacquisition during the full
parallel suite. Concurrent fork/exec can briefly inherit the writer descriptor.
The test retains simultaneous-open exclusion and real initialization, and now
requires successful reopening within two seconds; persistent errors still fail.
This changes test timing only, not production behavior or pilot submissions.

On exact restored pilot source SHA256
`9d5c1906786ec5af0f7ab45ce8561e4fd8544a70b9832b5abf7fbec9cb24eeff`:

- `scripts/with-secure-test-tmpdir.sh cargo test --locked --all-targets` exited 0:
  1,074 passed, 22 explicitly ignored across 20 test binaries; benchmark smoke
  checks also succeeded. Log: `/tmp/vw-real-pilot-restored-all-targets.log`.
- `scripts/with-secure-test-tmpdir.sh cargo test --locked --test protected_rehearsal`
  passed 28 tests, 4 ignored. Log: `/tmp/vw-real-pilot-final-focused.log`.
- `cargo clippy --locked --all-targets -- -D warnings` exited 0. Log:
  `/tmp/vw-real-pilot-final-clippy.log`. Formatting and diff checks also passed.
- `python3 scripts/mutate-real-vaultwarden-pilot.py` caught all five mutations
  after compilation, restored the exact hash above and passed the restored
  focused retest. Logs: `/tmp/vw-real-pilot-final-mutations.log` and
  `target/pilot-mutations/report.json` with its sibling logs.

The earlier parallel regression failure remains recorded in
`/tmp/vw-real-pilot-bootstrap-all-targets.log`. These automated results do not
replace the still-pending four human Mac decisions.

Failure-evidence repair (2026-10-23): HC02kL verified human-deny with zero
execution starts, then reached human-approve pending before failing and cleaning
up. The user reported unavailable while refreshing, before clicking Approve.
The old log did not retain an authoritative approval terminal status or cause;
expiry remains unproven. This repair does not recover that lost evidence.

On restored source SHA256
`e379bf6e29e61f56c740f882ecc18ef5f20550967e395e17f8eb8e60aadd247e`,
the complete all-target suite exited 0: 1,078 passed, 22 ignored across 20 test
binaries; benchmark smoke checks passed. The protected harness passed 32 tests
with four ignored. All-target Clippy, formatting and diff checks passed. All six
mutations compiled and were caught; exact restoration and the 15-test pilot
retest passed. No source edits occurred during the final full-suite invocation.
Evidence: `/tmp/vw-real-pilot-failure-evidence-all-targets.log`,
`/tmp/vw-real-pilot-failure-evidence-clippy.log`,
`/tmp/vw-real-pilot-failure-evidence-mutations.log` and
`target/pilot-failure-evidence-mutations/report.json` with sibling logs.
No live service/Mac/request action was performed for this repair. Complete
four-decision real-backend acceptance remains outstanding.

Quick-setup amendment (2026-10-23): the prior verification paragraphs are
historical. The latest pre-amendment live run `4d9wZa` passed human-deny (zero
starts), human-approve (completed with one start and success), and agent-deny
(zero starts). Agent-approve failed with `status_poll_failed` after 48.397 seconds;
its final execution outcome is unknown. Cleanup was independently verified.
That evidence neither proves four-decision acceptance nor diagnoses the poll
failure. This amendment does not alter polling, session/request deadlines or
decision handling, and no live run was started to verify the shortcut.

Local shortcut checks use Flutter 3.47.7 at
`/tmp/companion-sdk/flutter/bin/flutter`, `PUB_CACHE=/tmp/companion-pub-cache` and
`FLUTTER_SUPPRESS_ANALYTICS=true`. Normal and opt-in `flutter test --no-pub
--reporter=expanded` each passed all 39 tests; the opt-in command additionally
uses `--dart-define=COMPANION_DISPOSABLE_PILOT=true`. These are fake-platform
controller/channel/widget checks through the real Rust bridge, not real Mac
acceptance. All 28 companion Rust tests passed with
`cargo test --offline --locked --manifest-path companion/rust/Cargo.toml`.
The focused protected harness passed 33 tests, with four live/dependency tests
explicitly ignored. Root and companion all-target Clippy passed with warnings
denied, and six artifact tests passed, including normal/pilot archive separation.

`python3 scripts/mutate-pilot-setup.py /tmp/vw-quick-setup-mutations` compiled
and caught three targeted mutations: setup/recovery admission, unlocking after
failed import, and expected-identity verification. Exact restoration and the
opt-in retest passed; controller SHA256 was
`0fb5ab3c93be35a50cea6b37b743ced913cede6e9687e781741f98c10e784774`.
Reports/logs are `/tmp/vw-quick-setup-mutations/report.json`,
`/tmp/vw-quick-setup-dart-normal.log`, `/tmp/vw-quick-setup-dart-pilot.log`,
`/tmp/vw-quick-setup-clippy.log` and `/tmp/vw-quick-setup-core-clippy.log`.

No Swift/Xcode, Keychain installation, native packaging, installed-app replacement
or live provider check was performed locally. The new Swift parser/import,
fingerprint failure, backup preservation, recovery guard and compiled-symbol
gating checks are committed for isolated native CI. Native CI and eventual
foreground Mac one-paste acceptance remain required; the separately named pilot
artifact must not be treated as verified until that evidence passes.

After exact mutation restoration, the full root command
`scripts/with-secure-test-tmpdir.sh cargo test --offline --locked --all-targets`
exited 0: 1,079 passed and 22 explicitly ignored across 20 test binaries, with
benchmark smoke checks also succeeding. Log:
`/tmp/vw-quick-setup-all-targets.log`. Harness SHA256:
`d2bc9c9ff99e5ba80ba9d32250e94abfd55664698964e58c9c23b15f41cc00d3`.
All ten existing controller mutations were also caught with exact restoration
and passing retest; report: `/tmp/vw-quick-setup-controller-mutations/report.json`.
Final Flutter analyze found no issues (`/tmp/vw-quick-setup-analyze.log`), Dart
formatting changed no files, both Rust formatting checks, shell syntax and
`git diff --check` passed. These results apply to the local amendment baseline;
the later integrated native CI source/revision must be recorded separately.

Parent reran all six real-pilot harness mutations on that exact harness hash:
readiness, duplicate submission, execution counts, redaction, cleanup and failure
evidence all compiled and were caught; exact restoration and retest passed.
Report: `/tmp/vw-quick-setup-harness-mutations/report.json`.
