# Hosted macOS GUI acceptance

The desktop acceptance job uses `macos-26` (Apple Silicon). Rust tests, native
Swift tests and both macOS CLI builds continue to use `macos-26-intel`. The
desktop job still builds the universal Mac application and runs the same full
test script, including all 17 packaged TLS/controller scenarios, exact request
counts/order, cleanup checks and the original 45-second application deadline.
The packaged Flutter/native integration scenarios now execute only on Apple
Silicon. An Intel build slice and native unit tests do not replace packaged
Intel runtime validation; that coverage remains a limitation until the hosted
Intel GUI image is repaired or another suitable Intel test host is available.

The Intel image `20260824.0517.1`, macOS 26.6.1 (25G76), has a documented
[IconServices crash loop](https://github.com/actions/runner-images/issues/14751)
that blocks GUI applications. Upstream reports Apple Silicon is unaffected.
Our disposable CI probe reproduced the icon timeout and verified the documented
service workaround, but the full Flutter application still intermittently
stalled. Changing only the GUI job's runner avoids depending on that image's
broken GUI services. This is an environment mitigation; it does not establish
the exact cause of every observed delay.

Evidence from the investigation:

- [Original merged-head failure](https://github.com/sixtoad/vaultwarden-cli/actions/runs/39904655601): the first packaged launch stalled at configuration before sending any provider request.
- [Configuration-delay run](https://github.com/sixtoad/vaultwarden-cli/actions/runs/39942673512): 15 scenarios passed, then a launch completed after its deadline. Request counts and cleanup passed; this was a real delay, not just inherited output pipes.
- [Native startup sample](https://github.com/sixtoad/vaultwarden-cli/actions/runs/39948188195): five scenarios passed, then the app remained blocked before any Dart progress. Both early and deadline samples showed its main thread waiting in AppKit/Mach messaging. Cleanup passed.
- [Minimal AppKit comparison](https://github.com/sixtoad/vaultwarden-cli/actions/runs/39954915017): separate fresh Intel VMs each passed 20 launches using abrupt or graceful termination. Abrupt exit alone did not reproduce the fault.
- [Full Apple Silicon comparison](https://github.com/sixtoad/vaultwarden-cli/actions/runs/39955654206): all 17 scenarios and 21 launches passed, with exact request counts/order and successful cleanup. No launch required slow-sample or inherited-pipe handling. The normal release archive checksum was verified; the app, Dart AOT binary and Rust library each contain ARM64 and x86_64 slices.

Temporary samplers, native probes and service-control workarounds used for the
investigation are removed from the final patch. The runner migration changes
no application source or approval flow; the cryptographic dependency fix below
is a separate production dependency change.

The security audit separately flagged `ctutils 0.4.3` under
`RUSTSEC-2026-0385`. The root lockfile now selects `0.4.4`, containing the upstream
[constant-time fixes](https://github.com/RustCrypto/utils/pull/1569). The audit
and 1,063 all-feature/all-target Rust tests passed (22 ignored), using the
repository's secure temporary-directory harness.
