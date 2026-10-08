# App network-policy correction — explicitly authorized

Logged-in acceptance found that macOS App Transport Security (ATS) rejects the
operator-selected private CA in the app bundle before the existing custom trust
validator runs. The saved endpoint and pin match, TCP is reachable, and the app
logs `ATS failed system trust`, TLS error `-9802` and URLSession error `-1200`.
Unbundled native tests did not reproduce the app-bundle policy boundary.

The [proposed patch](ats-policy-proposal.patch) adds `NSAllowsArbitraryLoads=true`
to this development app's generated Info.plist. Automatic approval review initially
rejected applying this broad app-level security-setting change without explicit
user authorization. On 2026-10-06, after its scope and retained TLS checks were
explained, the user answered **“Approve the app-level ATS exception”**. Application
and verification are now authorized; see the subsequent bundle-fix evidence for
the actual result. This file preserves the reviewed proposal and decision.

This exception removes the additional ATS policy gate for all networking in this
app. It does not install a trusted CA, change system-wide trust, or itself make a
TLS connection trust an invalid certificate. The current sole network transport
continues to require all of the following:

- An HTTPS endpoint and TLS 1.2 or newer.
- Security.framework validation against only the configured CA, including the
  certificate chain, validity and expected hostname.
- The exact server leaf SHA256 pin and a Keychain client identity.
- No redirects, no automatic decision retry and bounded request/response sizes.

The material tradeoff is loss of ATS as an additional app-wide protection: any
future networking code must also use the validated transport. Domain-specific ATS
exceptions would have a smaller scope, but require the provider hostname to be
fixed in the signed bundle; the approved client configures its endpoint at runtime.

The authorized correction also needs a signed app-bundle regression that
reproduces the strict-ATS failure and verifies successful private-CA connections,
rejection of wrong CA/hostname/pin/client identity, HTTPS/TLS requirements, and the
existing security mutation checks. Logged-in acceptance must then resume; previous
automated results do not establish this corrected bundle's acceptance.

Apple documents the policy boundary in [Performing manual server trust
authentication](https://developer.apple.com/documentation/Foundation/performing-manual-server-trust-authentication)
and the scope of ATS exceptions in [Preventing insecure network
connections](https://developer.apple.com/documentation/Security/preventing-insecure-network-connections).
