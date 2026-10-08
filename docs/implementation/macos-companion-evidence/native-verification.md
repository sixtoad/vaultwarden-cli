# Native verification

The exact identity-import build passed **25 XCTest methods, 20 signed app-bundle
cases and one Python fixture-startup check** on **2026-10-08**, using macOS 27.0.1
(26A434), Xcode 27.0 (27A266a), and Swift 6.4 on arm64. Release build, strict
ad-hoc signature, temporary Keychain cleanup and probe-registration cleanup passed.
All 16 input hashes match the repository. [Current summary](identity-import-fix/identity-summary.json),
[source hashes](identity-import-fix/source-hashes.json),
[results](identity-import-fix/results.json) and
[raw archive](identity-import-fix/identity-verification.tar.gz) preserve the evidence.
Archive SHA256: `5c7b69b46781711a756a7855cbb6ed5aab566a1d3dff678d27edc9f06d854341`.

The new same-subject renewal and issuer/serial collision tests prove exact
certificate selection and preservation of the older identity. Restoring the old
import implementation failed the collision test at its intended runtime assertion:
**one new runtime mutation kill**, zero survivors or invalid runs. Both identity
tests passed after exact source restoration. The earlier **21 runtime mutation
kills** remain applicable to their unchanged guards; that campaign was not rerun.
A separate DER-guard removal is not claimed killed, because exact-item selection
already rejects the demonstrated collision. These are scoped campaigns, not
exhaustive coverage.

The initial native-script attempt passed startup, 13 protocol and eight AppModel
tests, then stalled in the existing TLS fixture's server-reaping wait. Its sample,
interruption and verified cleanup are retained. A single bounded rerun passed all
four TLS/identity methods in separate processes, then all bundle cases and release
build. No test is counted passed from the stalled filter. The reaping race's exact
underlying cause is unproven; no production harness workaround was added.

Verified installed executable SHA256:
`ad6413f8ce4ae15596f2646a4ae0d30f06385cc2354f311067f791c5bd086daf`.
The [installation](identity-renewal/installation.json) preserved configuration and
Keychain at 13:43:34 UTC. Subsequent approved trusted reprovision preserved the
existing identity, backed up the prior configuration, verified the new certificate
fingerprint `1e13dcda84664b622abcc600d21a31445fd194374ab256d363b2cf8f79a22856`,
and verified exact saved preference bytes; see
[provision result](identity-renewal/provision-local-result.json) and
[readback](identity-renewal/provision-local-check.json).
**Final logged-in acceptance passed on this exact build.** The operator confirmed
“Approved; notification opened the full review.” Request
`WIeps7IdX4O1e2CuqeYzl4D0Vkh8UDPzTjgFWH7O3mk`, admitted at 13:44:42 UTC,
completed at 13:47:53.559 UTC with durable submitted → approved → execution_started
→ succeeded, exactly one protected execution and redacted signed-CLI exit 0.
See [final provider result](review-fixes/renewed-final-smoke/provider-result.json).
The prior wrong-password attempt left the request pending with zero executions;
exact GUI error text was not separately reported for this build. Human review
remains a separate handoff.

The preceding review-fix build `97c1c9a768e400975c7e80c8424939cdb2ada24c8516a921f0001c0e66ba0113`
passed 23 XCTest methods and 20 bundle cases in both full baselines, plus the
21-mutant campaign. Its [summary](review-fixes/full-native-summary.json) and
[archive](review-fixes/review-verification.tar.gz) are retained. The exact-import
correction supersedes that build; its unchanged guards retain their earlier evidence.

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
and [request result](fixture-sleep/result.json). Current verification and passing refreshed installed smoke are recorded above.

Earlier evidence is preserved: [original native archive](native-evidence.tar.gz),
[ATS/bundle correction](bundle-fix/README.md),
[notification diagnostics](notification-diagnostics/README.md),
[authentication-response correction](authentication-response/diagnosis.md), and
[pre-consolidation documents](acceptance-document-history-2026-10-07.tar.gz).
Historical failures and the terminated permission-prompting diagnostic are not
erased. Companion operation does not require AppleEvents or Accessibility authorization.
