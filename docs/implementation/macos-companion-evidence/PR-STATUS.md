# Draft pull request status

The user authorized commit, push and opening a pull request on 2026-10-08. This draft publishes the implemented companion for inspection while preserving the remaining acceptance gate. It does not authorize merging or production deployment. The approved intent and baseline `0c5c1d9a2780132db0c4b313934dbe66716e0851` are unchanged.

## Implemented

Direct private LAN/VPN HTTPS connects the native menu-bar companion to the Linux provider. Native notifications open a full review; separate unlock and fresh-password approval keep secrets, authorization and protected execution on Linux. The transport boundary accommodates a future route implementation; no SSH tunnel is implemented.

Three review layers ran. Accepted corrections cover visible review text, closed response/status validation, uncertain outcomes, unresolved-request selection and async lifecycle/password invalidation. Actual AppModel caller paths now have regression tests. No accepted finding was deferred.

## Verified

- Final native snapshot on macOS 27.0.1 / Xcode 27 / Swift 6.4: both full baselines passed 23 XCTest methods and 20 signed-bundle TLS cases, with zero failures/skips. All 21 scoped mutants failed their intended runtime assertions; zero survivors, invalid runs or unexecuted mutants. Exact source restoration and archive/member hashes were independently verified.
- Linux default/all/no-default suites: 894 exercised tests per profile, plus dedicated mapped-UID agent, Firefox and systemd regressions. Twelve production-security mutations and two test-hook mutations were caught at runtime. Formatting/check/strict Clippy passed.
- Earlier installed-build acceptance covered notification/review, exact-once protected execution and redacted agent result, denial, separate unlock, reboot/login startup, sleep/reconnect, quit/expiry, lost-reply recovery and peer/authority rejection, within the dated scopes in the acceptance audit.
- The final installed build rejected a wrong password explicitly and Linux executed nothing. That request expired before a correct-password approval was observed. The test provider was then stopped cleanly.

## Still required before readiness

- Complete correct-password approval with exactly one protected Linux execution and redacted signed-agent result on the final installed build; explicitly reconfirm notification → full review. This is not established by earlier-build acceptance or Linux-only checks.
- Finish BMAD review closure and human-review handoff after that result.
- Hosted CI is not yet verified for this draft. Main commit `d1efb1034fcf500c8dd21ebf485a07d928a07059` is now integrated; its SSH tests and execution changes are preserved. [Merge verification](merge-main/README.md) passed: 932 exercised default-profile tests, strict Clippy, native fixture checks and three explicit systemd/SSH-isolation tests. The approved feature baseline remains the provenance anchor.

Live-backend credentials were unavailable: 71 early-return tests per Linux profile are excluded from the exercised counts; 15 ignored tests per profile are not claimed passed. The native campaign has no skipped tests or surviving mutations. The current synthetic Mac/Linux certificates expire at 2026-10-08 11:47:41 UTC; a later acceptance run requires properly renewed trusted provisioning, never a validation bypass. The app is ad-hoc signed, not notarized. Its explicitly approved app-wide ATS exception relies on the sole production transport enforcing HTTPS, TLS 1.2+, CA/hostname/expiry validation, exact leaf pin and client authentication.

## Evidence

- [Current native results](review-fixes/full-native-summary.json)
- [Final installed smoke and cleanup](review-fixes/installed-smoke/provider-result.json)
- [Acceptance audit](acceptance-audit.md)
- [Named test/mutation witnesses](matrix-test-audit.md)
- [Linux verification](password-rejection-fix/README.md)

Dated records saying publication was unauthorized or had not occurred describe their original verification snapshots; this document records the subsequent explicit publication authorization.
