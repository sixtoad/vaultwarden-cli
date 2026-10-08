# Exact identity import correction — 2026-10-08

Renewing a synthetic client certificate exposed an issuer/serial collision with an
older login-Keychain identity. The imported identity contained the new certificate,
but the former `kSecValueRef` lookup returned a persistent reference to the older
certificate. The setup helper's fingerprint check rejected it before preferences
changed. Operator identities were preserved; diagnostic evidence is retained in
[identity renewal](../identity-renewal/).

Production import now constrains `SecItemCopyMatching` with
`kSecMatchItemList: [identity]` and verifies that the persisted identity's certificate
DER equals the imported certificate. Apple's [query documentation](https://developer.apple.com/documentation/security/secitemcopymatching(_:_:))
describes the item-list constraint. A collision that cannot persist the exact new
identity fails closed. TLS, reference resolution, ACLs and trust policy are unchanged.

Two real native tests use both generations in the same isolated temporary Keychain:
same-subject renewal with distinct serials must return the exact new certificate
and preserve the old reference; same-issuer/same-serial renewal must either reject
or return the exact new certificate, never the old one. Reimport is also checked.

Verification on macOS 27.0.1 / Xcode 27.0 / Swift 6.4:

- 25 XCTest methods passed: 13 protocol, eight AppModel and four TLS/identity.
- One Python fixture-startup test and all 20 signed-bundle cases passed.
- Release build and strict signature verification passed.
- Restoring the complete old import behavior failed the collision test at its
  intended fingerprint assertion: one runtime kill, zero survivors/invalids/skips.
- Exact source restoration and both restored identity tests passed. All 16 input
  hashes match the repository. The prior 21 security guards are unchanged and retain
  their [passing mutation evidence](../review-fixes/full-native-summary.json).

The first complete-script attempt passed startup/protocol/AppModel checks, then
stalled in the existing TLS fixture's `Process.waitUntilExit`. A passive stack
sample showed server reaping, with the Python child already absent. This attempt
was stopped with exact-process SIGTERM; source restoration and deletion of its
single temporary test Keychain/directory were verified, preserving the original
login search-list entry. No mutation had been applied. A single bounded rerun used
one process per TLS test, retained the earlier passing checks, and completed bundle,
build, mutation and restored tests. Every temporary Keychain/probe cleanup passed.
The hang and its cleanup evidence are preserved; its exact underlying race is not
claimed to be established. No production fixture workaround was added.

[Summary](identity-summary.json), [results](results.json),
[source hashes](source-hashes.json), and [mutation plan](mutation-plan.json).
The [raw archive](identity-verification.tar.gz) retains the original attempt,
sample, cleanup, bounded rerun, mutation and restoration logs. Its 74 member hashes
were independently checked after retrieval; archive SHA256 is
`5c7b69b46781711a756a7855cbb6ed5aab566a1d3dff678d27edc9f06d854341`.

Prepared executable SHA256:
`ad6413f8ce4ae15596f2646a4ae0d30f06385cc2354f311067f791c5bd086daf`.
Installation and renewed logged-in acceptance are parent-controlled follow-ups;
this verification lane did not launch/install the app or change login-Keychain
identities, permissions or preferences.
