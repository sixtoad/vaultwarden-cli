# Exact identity selection during certificate renewal

The final logged-in acceptance setup exposed a real import defect. Fresh synthetic certificates reused the original issuer name and client serial3. The macOS Keychain retained the old certificate for that issuer/serial. `SecPKCS12Import` returned the new in-memory identity, while the existing `kSecValueRef` lookup returned a persistent reference to the old certificate. The setup helper's exact fingerprint guard rejected the result before saving any preferences.

The [native diagnostic](diagnostic-result.json) records public certificate fingerprints only. Both ways of resolving the old query result selected the old certificate; constraining the query with `kSecMatchItemList` rejected the collision with `errSecItemNotFound`. [Apple documents this key for filtering a supplied identity](https://developer.apple.com/documentation/security/secitemcopymatching(_:_:)).

The production import now uses that exact-item query and verifies that the persisted certificate DER matches the imported certificate before returning its reference. The existing resolution and TLS validation remain unchanged. The acceptance launcher generates unique, nonzero random leaf serials; its reuse-TLS branch still preserves existing certificates. Existing operator identities are retained.

Two real native tests cover distinct-serial same-subject renewal, repeat import, old-reference preservation, and issuer/serial collision rejection without substituting an older identity. The focused security mutant restores the previous import implementation; its required witness is a runtime failure of the collision test. A standalone removal of the DER comparison is not claimed killed: exact-item selection can already reject the demonstrated collision.

Verification completed on macOS 27.0.1 / Xcode 27.0 / Swift 6.4: **25 XCTest methods,
20 signed-bundle cases and one fixture-startup check passed**, with a signed release
build. The old-import mutation failed the intended collision assertion; both
identity tests passed after exact source restoration. All 16 input hashes matched.
The earlier 21-mutant campaign remains applicable to its unchanged guards; it was
not rerun. See [verification summary](../identity-import-fix/identity-summary.json),
[results](../identity-import-fix/results.json), and
[raw archive](../identity-import-fix/identity-verification.tar.gz).

The first run passed startup, 13 protocol and eight AppModel tests, then stalled in
the existing TLS fixture's server-process reaping. It was interrupted rather than
counted passed; the exact remaining temporary Keychain and fixture directory were
removed and the original search-list entry preserved. A single bounded rerun
passed every TLS method in a separate process, followed by bundle/build/mutation
and restored checks. The interrupted attempt and passive stack sample remain in
the archive; no exact underlying race cause or harness production fix is claimed.

The corrected executable SHA256
`ad6413f8ce4ae15596f2646a4ae0d30f06385cc2354f311067f791c5bd086daf`
was [installed](installation.json) at 13:43:34 UTC with the previous bundle backed
up. [Trusted reprovision](provision-local-result.json) subsequently verified client
certificate SHA256
`1e13dcda84664b622abcc600d21a31445fd194374ab256d363b2cf8f79a22856`
and preserved the existing identity; [readback](provision-local-check.json) matched
the saved configuration exactly. No operator identity deletion or ACL/trust change
was needed. No Linux production code changed.

**Final logged-in acceptance passed.** The operator reported “Approved; notification
opened the full review.” On the verified `ad6413…` executable, request
`WIeps7IdX4O1e2CuqeYzl4D0Vkh8UDPzTjgFWH7O3mk` was admitted at 13:44:42 UTC
and completed at 13:47:53.559 UTC. Linux recorded submitted → approved →
execution_started → succeeded, exactly one protected execution, and redacted
signed-CLI exit 0. The preceding wrong-password attempt remained pending with
zero execution; exact GUI error text was not separately reported for this build.
See [final provider result](../review-fixes/renewed-final-smoke/provider-result.json).
Human-review handoff remains separate.
