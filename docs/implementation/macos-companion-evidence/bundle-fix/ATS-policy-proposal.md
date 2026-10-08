# Private-CA bundle policy — approved and applied

The packaged app fails before its manual trust callback: the observed diagnostics
are `AnchorTrusted`, `ATS failed system trust`, TLS error `-9802`, URL error
`-1200`, and clientCertificateState `0`. The saved endpoint, CA, pin and TCP route
were independently checked. Unbundled tests did not exercise the app's ATS policy.

The [proposed patch](proposed-ats.patch) adds `NSAllowsArbitraryLoads=true` to the
app's `NSAppTransportSecurity` dictionary. Automatic approval review initially
rejected changing this app-wide security setting without explicit authorization.
The user subsequently answered **“Approve the app-level ATS exception”** after
the app-wide scope and preserved HTTPS/TLS/CA/hostname/expiry/pin/client-authentication
checks were explained. The three-line plist change was then applied; transport
trust checks remain unchanged.

The policy allows the existing manual trust evaluation to use the configured
private CA. Its scope is the whole app because the provider endpoint is selected
at runtime; a static exception-domain list would require rebuilding whenever the
operator changes provider hostnames. No system trust store is changed.

This removes ATS as a separate app-wide guard. Production networking must continue
to use `PinnedTransport`, which accepts HTTPS only, enforces TLS 1.2 or newer,
requires the operator's CA as the only trust anchor, checks certificate validity
and the exact hostname, requires the exact leaf SHA256 and a Keychain client
identity, rejects redirects, and does not retry decisions. No trust callback is
changed by this patch. Any future networking path must preserve those guarantees.

Apple documents that [NSAllowsArbitraryLoads](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowsarbitraryloads)
removes ATS restrictions while HTTPS retains normal trust evaluation unless an
app supplies manual evaluation. Apple also documents
[domain-specific manual-trust exceptions](https://developer.apple.com/documentation/bundleresources/information-property-list/nsexceptionallowsinsecurehttploads)
and [manual server trust authentication](https://developer.apple.com/documentation/foundation/performing-manual-server-trust-authentication).

The regression harness must run inside a real `.app` using the packaged policy,
include a strict-ATS failing control, and reject wrong CA/pin/hostname, expired
certificates, foreign/revoked clients, HTTP configuration, TLS below 1.2,
redirects and oversized responses. A dropped decision reply must cause one
transmission followed only by a status read. Temporary synthetic-only proposal
bundles are distinct from applying this setting to the actual app.
