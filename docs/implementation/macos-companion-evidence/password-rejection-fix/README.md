# Explicit password rejection over mutual TLS

Logged-in Mac acceptance reached the native review, but a wrong approval password
produced an uncertain outcome. The provider returned HTTP 403, and the actual Mac
reported URLSession client-certificate rejection (-1206), preventing the closed
application error body from reaching the controller. The pending Linux request
expired without execution. The native lane independently reproduced that behavior
and verified HTTP 422 exposes `authentication_failed` after exactly one decision.

The shared protocol now maps password rejection (unlock and approval) to HTTP 422.
Enrollment rejection remains HTTP 403. Password authentication, single-use ticket
consumption, authority binding, rate limits, and protected execution are unchanged.
The Rust wrong-password regression asserts the exact closed error body, pending
request state, consumed tickets, five-attempt limit and zero execution dispatch.

Current Linux verification is recorded in `linux-results.json`, with all 29 original
logs retained byte-for-byte in `linux-evidence.tar.gz` and checked against
`linux-log-manifest.json`. All three full feature profiles passed: 965 reported,
894 exercised, 15 ignored and zero failed per profile. All three doc profiles,
formatting, check, strict Clippy, native fixture checks and helper builds passed.
Live-backend credentials are absent: 71 early-return tests in each full
profile are excluded from exercised counts. Ignored tests are not claimed passed.
Native and logged-in acceptance evidence is separate; Linux checks do not establish
completion. Previous Linux results and archives in the parent directory remain
historical evidence, including their original source hashes.

The real mapped-agent regression passed on its isolated prebuilt rerun. The first
attempt failed at the existing held-query admission handshake (expected an admitted
line, received EOF); its log is retained and the exact cause remains unestablished.
No source changed between attempts. Real Firefox passed with zero unexpected
diagnostics; both real systemd tests passed.

The scoped mutation runner refreshed the previous eleven security guards and added
reversion of password rejection from 422 to 403. Runtime test failure is required
for a killed classification; compiler failures, timeouts and skips are separate.
All twelve mutants compiled and failed runtime tests: zero survivors, invalid
mutants, skips or timeouts. `security-mutations.json` names each failure witness.
All eleven source/document hashes matched after restoration. The restored focused
suite passed 15 tests, with one manual acceptance harness ignored. No approval,
commit, push or deployment is implied by these results.
