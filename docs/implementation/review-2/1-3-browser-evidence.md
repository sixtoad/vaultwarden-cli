# Story 1.3 browser evidence

Iteration 2 adds an actual Firefox 151.0.2 run to the Rust transport fixtures.
A synthetic backend accepts a test password and counts calls; item resolution
panics if invoked. No real Vaultwarden credentials or desktop keyring are used.

A disposable Firefox profile trusts only the synthetic fixture CA added for this
run; `acceptInsecureCerts` is false. The normal user profile and machine/browser
trust stores are untouched. A replacement certificate from a different CA is
not trusted.

Verified successfully:

- Trusted HTTPS launch, one-use exchange, unlock and lock work in Firefox even
  with an unrelated cookie for the same host.
- The input clears when submitting a password.
- A copied session cookie cannot recover the separate proof from GET or unlock
  without it; replaying the consumed launch fails.
- Raw HTTP directed to the TLS port does not invoke authentication.
- After shutdown, a different TLS identity binds the old port. The stale page
  attempts unlock, the browser rejects its handshake, the UI displays the stable
  unavailable result, and the replacement receives zero HTTP requests. The
  password field is empty after this failure.
- Password sentinel is absent from captured browser console/errors and URLs.

Artifacts under `target/story-1-3-evidence/`: `browser-check.log`,
`browser-harness-build.log`, and the `browser-harness/` Rust fixture. Automation
source is copied as `browser-check.mjs`; dependencies reside only in
`/tmp/vw-story13-browser/`. NSS certutil was downloaded/extracted to
`/tmp/vw-story13-nss/`, without installing a system package. These checks exercise
browser transport and UI behavior; they do not substitute for real backend or
OS-keyring integration testing.
