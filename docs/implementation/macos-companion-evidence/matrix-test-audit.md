# Frozen matrix automated witness audit

## Current review-fix native audit — 2026-10-08

The current native snapshot passed **23 XCTest methods and 20 signed-bundle
cases**, both before mutation and after exact restoration. The 23 methods comprise
13 protocol/controller, eight actual AppModel lifecycle/polling tests, and two
real URLSession tests. Every scoped mutation compiled and failed its intended
runtime assertion: **21 killed, zero survivors, invalids, timeouts or unexecuted
cases**. Baselines had zero failures/skips. All 15 input hashes match the repository.
The actual host was macOS 27.0.1, Xcode 27.0 and Swift 6.4 on arm64.

[Current summary](review-fixes/full-native-summary.json) and
[exact mutation plan](review-fixes/native-mutation-plan.json) map each guard to
its named witness. The [raw archive](review-fixes/review-verification.tar.gz)
contains both passing baselines, all mutation patches/logs and source backups.
Archive SHA256 `0b7705d1f1c27acf5e804ad965c43c6e0e6f61291d5c63a7209aba8121becb4e`
and every byte/hash in its 157-file member manifest were verified locally.

| Review-fix guard | Named passing witness (short names) |
|---|---|
| Visible invisible characters and closed response schema | `testReviewTextExposesInvisibleAndDirectionalScalars`; `testClosedV1ResponseAndNestedReviewKeys` |
| HTTP/body agreement | `testRealURLSessionRejectsHTTPBodyStatusMismatch` |
| Ambiguous errors and unresolved-request selection | `testAmbiguousProviderErrorsUseOnlyStatusAndNeverResend`; `testDifferentSelectionPreservesUnresolvedDecisionUntilItsStatusIsKnown` |
| Delayed unlock result/cleanup | `testLateUnlockCannotMutateReplacementOrClearItsBusyFlag`; `testLateUnlockCannotUndoSleepOrRefresh` |
| Delayed notification/review/poll replies | `testLateNotificationSessionOrListCannotUndoLifecycleChange`; `testSleepDuringNotificationReviewLoadingCannotRestoreReview`; `testLatePollCannotMutateReplacementOrSleepingState` |
| Actual generation/disconnect invalidation and password clearing | `testActualPollingInvalidatesReviewForGenerationChangeAndDisconnect`; `testUnlockPasswordClearsOnSessionProviderAndLifecycleChanges` |

Eight retained mutants separately rechecked pin, CA, hostname, consumed tickets,
no retry, response bounds, quoted display and HTTP422 handling. The unchanged
HTTPS-scheme and TLS-minimum guards retain their earlier mutation witnesses and
passed the current bundle baseline. This does not claim exhaustive mutation coverage.
Prepared executable SHA256 is
`97c1c9a768e400975c7e80c8424939cdb2ada24c8516a921f0001c0e66ba0113`.
**Refreshed installed-app smoke is pending**; earlier live acceptance belongs to
the preceding navigation build. The dated audits below retain their original
Linux/native snapshot scope and are not claims that old manifests match changed
review-fix sources.

## Historical matrix audit — 2026-10-07

Recorded **2026-10-07 13:50 UTC** from a read-only audit of retained evidence.
This records the audited snapshot below, not completion of live acceptance or
verification of subsequent changes. No tests were rerun for this audit.

## Witnesses checked against actual passing output

Archive references name exact members; test names below omit their Rust module
prefixes. **L** means [Linux archive at this snapshot](password-rejection-fix/linux-evidence.tar.gz),
members `default.log`, `all-features.log`, `no-default-features.log` and
`restored-companion.log`. Each listed Linux test has an explicit `... ok` in all
four members and in [revoked-fixture focused output](fixture-revoked-client/focused.log).
**N** means [native archive at this snapshot](notification-navigation/evidence.tar.gz),
members `evidence/protocol-tests.log` and `evidence/real-urlsession-tls.log`.
Every named native test has an explicit passing XCTest result.

| Frozen row | Named passing automated witnesses | Evidence |
|---|---|---|
| Approval | `companion_decision_is_device_bound_single_use_and_lost_reply_is_read_only`; `companion_wrong_password_consumes_ticket_and_rate_limits_per_device`; `testWrongPasswordConsumesVisibleTicket`; `testSharedCanonicalReviewIncludesEveryField` | L; N protocol log |
| Locked | `companion_inbox_expires_and_locked_submission_never_creates_work`; `companion_unlock_is_separate_and_authentication_is_serialized` | L |
| Unavailable Mac | `companion_inbox_expires_and_locked_submission_never_creates_work`; `testGenerationOrDisconnectInvalidationDisablesDecision`; `testLateReviewCannotUndoAuthorityInvalidation` | L; N protocol log |
| Ambiguous reply | `companion_decision_is_device_bound_single_use_and_lost_reply_is_read_only`; `testLostDecisionNeverResendsAndPendingRemainsUncertain`; `testRealURLSessionAuthenticationAndSingleTransmission` | L; both N logs; bundled `lost_decision_not_retried` records exactly `decision,status` |
| Stale authority | `companion_snapshot_generation_review_and_deadline_are_bound_at_commit`; `companion_rejects_changed_review_generation_expiry_and_revocation`; device-bound/single-use decision test above | L |
| Untrusted peer | `companion_real_mtls_requires_ca_and_exact_enrolled_leaf`; `companion_identity_enrollment_requires_valid_client_chain_and_stopped_provider`; `companion_identity_private_atomic_closed_store_and_revocation`; `testRealURLSessionAuthenticationAndSingleTransmission` | L; N URLSession log; signed-bundle trust cases |

The native archive contains **8 protocol tests + 1 real URLSession test**, all
passed, and **15/15 signed-bundle cases**, no failures or skips. Its
`evidence/bundle-tls/results.json` exactly matches the checked-in
[bundle results](notification-navigation/bundle-results.json), including wrong
CA/pin/hostname, expired leaf, foreign/revoked client, HTTP, TLS 1.1, redirects,
oversized responses, explicit wrong passwords and lost-reply single transmission.
No named automated matrix witness was missing or skipped.

## Independently checked integrity and mutation evidence

- All nine checked-in archive `.sha256` files matched their archive bytes.
  Linux archive SHA256 at this snapshot:
  `de4fd5f58d9a8ddca3ab3c000a8693c8f407a90191ab827c560a00f0e7efd02a`.
  Native archive SHA256 at this snapshot:
  `4659434289c55ad8e466ba01a09bbe4771e3817b9866cc941867114676fbd926`.
- Every byte count/hash in the member manifests matched: current Linux **29/29**,
  original Linux **32/32**, original native **25/25**, bundle fix **240/240**,
  notification diagnostics **43/43**, document history **4/4**, continuation
  history **1/1**. Both fixture verification manifests also matched every entry.
- The [native source manifest](notification-navigation/source-hashes.json)
  matched **13/13** workspace files and the archive's `source-manifest.json`.
  The [Linux correction source manifest](password-rejection-fix/linux-source-hashes.json)
  matched **10/11** entries; only the expected test fixture differed.
  Audited fixture SHA256: `bc41651d9f5933bd64513d4a237577ea0058270cc93c5863a28ff6b286ee1823`.
  Audited launcher SHA256: `61533f1b6499ce032b588935d88776aa8acdd881c43ba38a3b445311b3371db2`.
  Audited `src/adapters/companion.rs` SHA256:
  `022dce1d98e21a8391481efe48fad4ab46a4645d61239e4ae9feda39ec4d4736`.
- All **12** [Linux mutation records at this snapshot](password-rejection-fix/security-mutations.json)
  independently matched their named runtime `FAILED` lines and failed-test
  summaries in L's corresponding `<mutation-name>.log`. They were runtime kills,
  not compiler-only failures: **0 survivors, invalids, skips or timeouts**.
- Retained native campaigns report **7 controller/transport**, **7 bundled
  security**, and **1 HTTP422 allowlist** runtime kills, zero survivors. Sources:
  `native-evidence.tar.gz` member `native-mutations/results.json`,
  [bundle results](bundle-fix/results.json), and
  [HTTP422 mutation](authentication-response/mutation-results.json).
  This audit verified archive integrity and reviewed the latter two result
  records; it did not independently reclassify every native mutant's raw log.

The optional revoked-client harness passed **15 focused tests**, with the manual
fixture ignored, plus formatting, Rust check and Python compilation; see
[its results](fixture-revoked-client/results.json). Subsequent `cfg(test)`
lost-reply instrumentation is covered by the supplemental snapshot below.

## Supplemental test-fixture audit — 2026-10-07 13:58 UTC

Independently matched all **13** entries in
[the lost-reply manifest](fixture-lost-reply/manifest.json), including retained
initial failure, command outcomes, mutation logs and restored passing output.
[Restored focused output](fixture-lost-reply/restored-focused.log) explicitly
passes all preceding Linux matrix witnesses and the new
`companion_fixture_lost_reply_is_after_commit_and_only_once`: **16 passed,
0 failed, 1 ignored manual fixture**. Formatting, production/test Rust checks,
strict library/test Clippy and Python compilation passed; exact commands are
in [results](fixture-lost-reply/results.json).

Both supplemental mutants compiled and failed the new test at their intended
runtime assertions: [dropping a failed approval](fixture-lost-reply/drop_failed_approval.log)
breaks the expected HTTP422 response; [dropping more than once](fixture-lost-reply/drop_more_than_once.log)
breaks the second successful approval's HTTP200 response. Independent raw-log
inspection confirms **2 runtime kills, 0 survivors/invalids/skips**. These are
fixture fault-injection checks, additional to the 12 production security mutants.
The initial test sent forbidden `password:null` for denial; the corrected test
omits that field. Its failure remains retained; the closed production parser
was not relaxed.

Restored workspace hashes independently match the supplemental results:

- Adapter: `b9a09e64f891c8bb6b670e546336777e6008cbb10ec747ca2349c16623ad1ec3`.
- Manual fixture: `37391f7bb676dcadea321d6890387700c92a9ca034b47dca28375896abcfc5dd`.
- Launcher: `127425b0b5d62f646a11e3a2198ebf66add042759ca1493f8fd62a7dcd51170d`.

The other **9/11** prior Linux manifest entries and **13/13** native entries
still match. Inspected observer type/field, command recording and response-drop
hooks are all `cfg(test)`, default disabled, and retain only bounded static
command names/counts. The drop occurs after dispatch and only once after a
successful approval. This is preparation for installed-app fault acceptance,
not a claim that the operator has completed that scenario.

## Limits and separate live acceptance

Each Linux feature profile reports 965 passes, but **71 live-backend early
returns are excluded**, leaving **894 exercised passes**, plus 15 ignored entries.
Backend URL/admin credentials were unavailable. The manual acceptance fixture is
ignored in ordinary suites and is never counted as an automated pass. The full
hosted OS/toolchain CI matrix was not run. Dedicated mapped-UID, browser and
systemd regressions are recorded separately; the initial mapped-agent failure
and unchanged passing rerun remain preserved, with cause unconfirmed.

This automated audit does not close the installed-app gates: actual sleep/wake
and quit/disconnect expiry/recovery; deliberately lost decision reply with
status-only recovery; stale review after lock/restart, changed binding and replay;
wrong-peer/missing-identity rejection and stop/revoke/restart. Later operator
observations belong in [the live continuation ledger](interactive-continuation.json)
and [acceptance audit](acceptance-audit.md). Their current status supersedes this
snapshot's open-gate list. Passing automated tests alone does not authorize a
completion claim, human-review handoff, commit, push, PR or deployment.

At the supplemental snapshot, the sleep-check request `onF0G3Pu5OURikb2tivNSB4PO3YHfiegMkJcRSBbF90`
had durable submitted → expired audit and zero execution; operator sleep/wake
and authoritative refresh confirmation remained pending. The observer exited
143 before retaining CLI terminal output, so no CLI timeout/result is claimed.

## Historical pre-review source and retained-evidence audit — 2026-10-08

A separate read-only agent revalidated all nine archive hashes, 374 archived
manifest members, and every current fixture manifest (resume, lost reply, revoked
client, cadence and the three stale cases). All thirteen native source hashes
and all four current hashes in [resume results](fixture-resume/results.json)
match the workspace. Nine other Linux manifest entries remain unchanged.
The older fixture/launcher hashes above describe their dated snapshots.

All nine named Rust and six named Swift matrix witnesses have explicit passing
output. The latest [focused run](fixture-resume/focused-final.log) passed
16 tests, with zero failures and one ignored manual harness; the then-current native
bundle passed 15/15 cases. Twelve production-security and two fixture-hook
mutants were independently rechecked as runtime kills. All three isolated stale
cases passed with complete cleanup. No missing automated matrix witness was found.

Parent read the refreshed baseline diff, including untracked evidence and the
latest test-harness changes, by comparing unchanged sections with previously
read snapshots and reading every delta. Baseline HEAD and the actual empty Git
index are unchanged; frozen intent SHA256 still matches the approved block.
At that pre-review snapshot, actual sleep/wake was running separately. It later
passed on the navigation build; see the acceptance audit. The current review-fix
verification is recorded above, with refreshed installed smoke still pending.
