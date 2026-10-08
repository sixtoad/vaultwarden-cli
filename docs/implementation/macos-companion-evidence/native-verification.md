# Native verification

The review-fix build passed **23 XCTest tests and 20 signed app-bundle cases**
in both the initial and restored full baselines on **2026-10-08**, using macOS
27.0.1 (26A434), Xcode 27.0 (27A266a), and Swift 6.4 on arm64. All **21 scoped
mutations** were killed by their intended runtime assertions. There were zero
failures/skips in either baseline and zero mutation survivors, timeouts,
compile/launch failures or unexecuted cases. All 15 input hashes were restored
and match the repository. Release build and strict ad-hoc signature verification
passed; test Keychain cleanup and temporary probe-registration absence were verified.

Current evidence: [full native summary](review-fixes/full-native-summary.json),
[exact mutation plan](review-fixes/native-mutation-plan.json),
[source hashes](review-fixes/source-hashes.json), and
[raw archive](review-fixes/review-verification.tar.gz).
Archive SHA256: `0b7705d1f1c27acf5e804ad965c43c6e0e6f61291d5c63a7209aba8121becb4e`.
Verified installed executable SHA256:
`97c1c9a768e400975c7e80c8424939cdb2ada24c8516a921f0001c0e66ba0113`.
The parent installed this exact bundle at 11:16:29 UTC as PID 72015, preserving
saved configuration and Keychain; see [installation](review-fixes/installation.json).
**Refreshed installed-app smoke acceptance remains pending.** Native automation
alone does not establish acceptance of this changed build or finish the BMAD handoff.

The current suite exercises recursive closed response keys, visible rendering of
invisible characters, HTTP/body status agreement, status-only recovery from
ambiguous errors, unresolved-decision selection, lifecycle epochs for delayed
unlock/notification/review/poll replies, polling invalidation and password-context
clearing. The full bundle matrix retains private-CA and TLS/client-identity
rejection checks, explicit wrong-password errors, bounds, redirects and no-retry
recovery, and adds five HTTP/error-envelope cases. The 21-mutant campaign covers
13 review-fix guards and eight retained security guards. Unchanged HTTPS-scheme
and TLS-minimum guards retain their earlier mutation witnesses and passed the
current bundle baseline. This is scoped mutation evidence, not exhaustive coverage.

The prior navigation build passed **9 XCTest tests and 15 signed bundle cases**
on macOS 26.5.2 / Swift 6.3.3. Its executable SHA256 was
`12ce69b8745ddf8580947d140fc39e96d1b39dbd401ca1760b91d6e1be722853`.
Its [verification](notification-navigation/README.md),
[installation](notification-navigation/installation-result.json),
[source manifest](notification-navigation/source-hashes.json) and
[raw archive](notification-navigation/evidence.tar.gz) are historical evidence.
The logged-in observations below belong to that older build, including actual
sleep/wake on October 8 before the review fixes. They are retained without
claiming that every scenario has been repeated against the new executable.

The earlier installed build’s logged-in acceptance established trusted saved setup/Keychain persistence,
explicit wrong-password rejection, denial, generic notification → full review,
exactly one protected Linux execution with a redacted agent result, separate
native unlock/fresh work, and automatic startup after a real reboot. The exact
verified binary ran as PID 1352 after the new boot without an agent launch; the
operator subsequently used its inbox and unlock action. The initial pending
inbox field in [startup metadata](login-startup.json) and earlier pending fields
in installation snapshots are historical; the current
[continuation ledger](interactive-continuation.json) records the passing outcomes.

Installed-app lost-reply acceptance passed at **2026-10-07 14:32:28 UTC** for
request `Noafj_vhjnVmV0pmcukQeZqIjOzz9_oUWLsBeZ2uR6w`. A test-only Linux hook
dropped the successful decision reply after commit/dispatch. The unchanged Mac
app sent exactly one decision and one status lookup, in that order; one reply
was dropped. The operator reported approved. Linux recorded exactly one protected
execution and completed exit 0; the signed non-TTY CLI returned redacted success,
exit 0, empty stderr and no synthetic secret markers.

Confirmed quit/expiry/reopen passed: the app was absent before a fresh request,
no companion commands arrived while closed, the request expired without execution,
and the operator confirmed an empty inbox after reopening.

Installed negative checks also passed with the then-unchanged native code: a deliberately
invalid identity reference exposed no authenticated API access; same-state offline
revocation caused HTTP403/URLSession −1206; a foreign-CA server caused explicit
authentication-challenge cancellation/−999 with zero companion commands. Original
preferences, identity enrollment and server certificate were restored; authenticated
reads resumed. These use process/network/provider evidence, not inferred GUI quotes.
See [the current audit](acceptance-audit.md) for exact evidence and scope.

**Actual sleep/wake passed on 2026-10-08.** Power events prove sleep during
request admission and wake 37 seconds before expiry. The operator observed the
pending item and its automatic removal after expiry; Linux recorded no execution.
This is sleep/recovery evidence, not expiry while asleep. The separate quit test
covers app absence through expiry. See [power events](fixture-sleep/mac-power-events.json)
and [request result](fixture-sleep/result.json). Review-fix verification and the pending refreshed installed smoke are recorded above.

Earlier evidence is preserved: [original native archive](native-evidence.tar.gz),
[ATS/bundle correction](bundle-fix/README.md),
[notification diagnostics](notification-diagnostics/README.md),
[authentication-response correction](authentication-response/diagnosis.md), and
[pre-consolidation documents](acceptance-document-history-2026-10-07.tar.gz).
Historical failures and the terminated permission-prompting diagnostic are not
erased. Companion operation does not require AppleEvents or Accessibility authorization.
