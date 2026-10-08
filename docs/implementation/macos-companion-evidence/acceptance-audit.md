# Acceptance audit

Status: **verification and final logged-in acceptance passed; ready for human review**. The final installed executable is `ad6413f8ce4ae15596f2646a4ae0d30f06385cc2354f311067f791c5bd086daf`. The operator confirmed “Approved; notification opened the full review.” Request `WIeps7IdX4O1e2CuqeYzl4D0Vkh8UDPzTjgFWH7O3mk` completed at13:47:53UTC: submitted → approved → execution_started → succeeded, exactly one protected Linux execution, redacted signed CLI exit0. A prior wrong-password attempt left it pending with zero execution; no exact GUI rejection text is inferred. The provider stopped cleanly at13:48:57UTC, inactive/MainPID0. See [operator result](review-fixes/renewed-final-smoke/operator-result.json), [provider result](review-fixes/renewed-final-smoke/provider-result.json), and [cleanup](review-fixes/renewed-final-smoke/final-cleanup.json).

Certificate renewal exposed and corrected exact Keychain identity selection. The app now rejects substitution of an older certificate; unique synthetic leaf serials avoid test-fixture collisions. Native verification passed25XCTest,20bundle cases and the startup regression; the new old-import mutation failed its intended assertion. Earlier21mutation witnesses retain their unchanged-guard scope. The initial native fixture-reaping stall was preserved and cleaned; one bounded run of individual TLS tests passed. All16input hashes were verified. [Current native evidence](identity-import-fix/README.md).

Earlier reboot/login startup, sleep/reconnect, denial, unlock, lost reply and stale-authority observations below retain their dated build scopes. The final focused smoke reconfirms the changed executable's notification and protected approval flow; it does not relabel all historical observations as runs on the latest binary. Frozen intent is unchanged.

Prior operator/provider evidence is in [the continuation ledger](interactive-continuation.json).
Current native tests and mutation witnesses are in
[the automated witness audit](matrix-test-audit.md) and
[review-fix summary](review-fixes/full-native-summary.json).
The following criterion/matrix rows retain their earlier build scope; a passing
historical row does not itself establish acceptance of the changed executable.

## Previously verified acceptance criteria

| Criterion | Earlier installed-build evidence |
|---|---|
| AC1: native approval without a Linux desktop | Passed. A generic notification switched Setup → Approvals/full review; a fresh correct password authorized request `fy_NI7FeSUlBG8xjgLDoj8o9c0hLcjofFSL2YLIsNMQ`. Linux audited submitted → approved → execution_started → succeeded, with exactly one protected execution. The distinct-UID signed non-TTY CLI returned exit 0 and a redacted completed result. Backend data and credentials were synthetic; the worker and execution were real. |
| AC2: existing browser/agent behavior | Automated regression passed: default/all/no-default Linux suites and dedicated mapped-UID agent, Firefox and real-systemd regressions. External live-backend exclusions remain explicit in the Linux evidence. |
| AC3: automatic login startup and available inbox | Passed. After enabling Start at login, the operator rebooted and saw the shield. Read-only metadata proved a new boot and PID 1352 running the exact verified installed binary; the agent did not launch it. The operator opened the automatically started inbox and unlocked the provider. A fresh signed request was admitted and denied without execution. |

[Startup metadata](login-startup.json) records the initial automatic-launch
observation; its then-pending inbox field is superseded by the later operator
unlock and fresh-request observations in the continuation ledger.

## Frozen matrix evidence before review fixes

| Matrix row | Earlier executed evidence | Scope of earlier acceptance |
|---|---|---|
| Approval | Correct-password exact-once execution/redacted result; explicit `authentication_failed` with zero execution; native denial with zero execution; generic notification opens current full review. Automated device binding, ticket consumption, password/rate-limit and canonical-review checks passed. | None for the ordinary approval/rejection/denial flow. |
| Locked | Signed locked submission rejected without creating work. Post-reboot native unlock changed generation 3 → 4; the first fresh request `lcN8pXjEpxFHBPxlygX09RLDCqe-831zWmls2G3glag` was admitted and denied at 12:06:52 UTC, with no execution. Automated locked-submission and separate-unlock checks passed. | Stale-review lock behavior remains part of the authority-change row below. |
| Unavailable Mac | Confirmed app quit before a fresh signed request; zero companion commands through submitted → expired, no execution, redacted CLI timeout. Original setup restored and operator confirmed an empty inbox after reopen. Earlier proposed sleep was explicitly not performed. | Passed actual sleep/wake: request arrived while asleep; Mac woke 37 seconds before expiry, then the inbox automatically removed it after normal expiry. No execution. This does not claim expiry while asleep; the separate confirmed quit test covers app absence throughout expiry. |
| Ambiguous reply | Passed on the installed app at 14:32:28 UTC: one successful approval reply was deliberately dropped after real commit/dispatch. The app sent exactly one decision then one status read; the operator reported approved. Linux executed exactly once and the signed CLI returned redacted success. Native controller and real URLSession/bundled tests also passed. | None for deliberate lost-successful-reply recovery/no resend. The earlier HTTP403 defect is historical, not this witness. |
| Stale authority | Integrated real-TLS cases passed: lock and agent revocation reject old approval HTTP409; denial replay rejects the consumed ticket HTTP409. Same-state restart preserves binding/policy/request IDs, starts locked and rejects an old ticket HTTP409. Real offline device revocation survives same-state restart and rejects session/decision HTTP403. All had zero execution. See [stale cases](fixture-stale-driver/live-cases/README.md) and [restart results](fixture-resume/runtime-summary.json). | No remaining API rejection case. Deliberate stale-ticket/replay attempts used the authenticated test driver; the unchanged GUI consumes/invalidates tickets and was not used to manufacture replay. |
| Untrusted peer | Installed unchanged app with invalid identity reference sent no authenticated commands; exact saved configuration was restored and reads resumed. Same-state stop/revoke/restart produced actual Mac HTTP403/URLSession −1206. A foreign-CA server leaf caused actual Mac authentication-challenge cancellation/−999 and zero companion commands. Original certificate, enrollment and setup were restored. Native automation separately isolates CA, pin, hostname and expiry guards. | No remaining access-rejection case. Negative GUI messages were not reported by the operator; installed-process/network/provider evidence establishes denial. |

The 2026-10-07 14:32:28 UTC lost-reply witness is request
`Noafj_vhjnVmV0pmcukQeZqIjOzz9_oUWLsBeZ2uR6w`: durable completion with exit 0
and exactly one execution; transport counters decision=1, status=1, dropped=1,
with exact sequence `decision,status`. The signed non-TTY CLI exited 0 with a
redacted completed result, empty stderr and no synthetic secret markers. The
installed native build was unchanged; only the synthetic Linux fixture injected
the dropped reply. See [the continuation ledger](interactive-continuation.json).
Successful reconnection to renewed fixture authority does not establish rejection
of stale review tickets across a restart of the same persisted provider state.

## Earlier verification and current limitations

Earlier review-fix native evidence: **23 XCTest tests and 20 signed-bundle cases passed**
in both full baselines, with no failures/skips, on macOS 27.0.1 / Xcode 27.0 /
Swift 6.4. All **21 scoped mutants** were killed by intended runtime assertions;
zero survivors, invalids, timeouts or unexecuted cases. Release build, strict
signature, cleanup and all 15 restored input hashes passed. The reviewed native
changes cover closed response/status validation, review rendering, ambiguous
outcomes, unresolved selections and lifecycle/polling/password context. These
results supersede the earlier 9-test/15-bundle counts for the navigation build.
The final smoke is now complete as recorded above. See
[native verification](native-verification.md).

The HTTP422 provider correction passed all three Linux feature profiles, each
with 894 exercised tests, 71 live-backend early returns, 15 ignored entries and
13 benchmark smoke checks. Documentation/check/fmt/strict Clippy and dedicated
agent/browser/systemd regressions passed. Twelve refreshed Rust mutations were
killed; zero survivors/invalids/skips/timeouts. See
[correction verification](password-rejection-fix/README.md) and the historical
[Linux ledger](linux-verification.md) for exact scope and retained initial failures.

Before the native review fixes, subsequent Linux changes were limited to test infrastructure: the observer cadence
changed from 100 ms to 1 s; an optional mode enrolls/revokes the synthetic device
before provider startup; and `cfg(test)` hooks can drop one successful approval
reply after real dispatch. Normal production authorization/dispatch are unchanged.
Cadence and revoked-mode checks each passed 15 focused tests. The lost-reply
restored run passed 16, with one manual harness ignored; formatting, production
and test checks, strict library/test Clippy and Python compilation passed.
Two additional fixture mutants were killed at their intended runtime assertions,
with zero survivors/invalids/skips. At that fixture snapshot, nine prior Linux manifest entries and all
thirteen native entries were unchanged; the two changed Rust hashes and launcher
matched supplemental evidence. Native sources have since changed for the review fixes. See [the named witness audit](matrix-test-audit.md)
and [lost-reply results](fixture-lost-reply/results.json). Installed-app deliberate
lost-reply and revoked-device acceptance subsequently passed as recorded above.
Same-state resume and the stale-authority driver also passed their isolated runtime
cases and final focused checks; see [resume verification](fixture-resume/results.json).
Earlier `busy` admissions were authority-gate contention, but the exact competing
holder is unproven. Later locked and post-unlock requests succeeded on their first
attempt; this does not prove the observer was the unique cause. See
[fixture cadence evidence](fixture-observation-cadence/results.json).

Earlier ATS, HTTP403, notification-routing and admission failures are retained.
The app-level ATS exception and development installation were explicitly approved;
HTTPS, TLS minimum, CA/hostname/expiry, pin, mTLS and no-retry guarantees remain.
PR33 was published after explicit user authorization. BMAD verification and review closure are complete; no PR merge or production deployment occurred.

The complete previous audit and three related documents are preserved in the
[verified document archive](acceptance-document-history-2026-10-07.tar.gz)
with [manifest](acceptance-document-history-2026-10-07-manifest.json).
The continuation ledger links its separate complete historical archive.

Operator clarification (2026-10-07 15:50 UTC): the earlier planned sleep check did not involve actual Mac sleep. Its ordinary expiry evidence remains valid; it is not a sleep/wake witness. The later confirmed quit/expiry/reopen test passed, and the operator confirmed an empty inbox after restoration.

Earlier installed-build rejection evidence: [missing identity and restoration](fixture-missing-identity/README.md), [same-state revocation](fixture-resume/installed-mac-revocation.json), [native revoked-client rejection](fixture-revoked-client/installed-app-network.json), [wrong server and restoration](fixture-resume/installed-mac-wrong-peer.json), [native trust rejection](fixture-wrong-peer/installed-app-network.json). These were actual installed-app checks with synthetic credentials; no negative GUI observation is inferred. Final review remains required.

Final sleep evidence: [Linux request result](fixture-sleep/result.json) and
[Mac power events and operator report](fixture-sleep/mac-power-events.json).
The Mac slept during admission at 09:40:30 UTC, woke at 09:44:53, and the request
expired at 09:45:30 with zero execution. The operator observed the pending item
and then its automatic removal. The frozen row requires normal expiry and
authoritative reconnect, not a prescribed wake time. Combined with confirmed
quit-through-expiry and passing stale-deadline tests, this satisfies that row.
Expiry while asleep was not observed and is not claimed.
