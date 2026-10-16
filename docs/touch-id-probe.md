# Native Touch ID signing feasibility probe

This standalone development app is the first gate of the approved Touch ID
feature. It does not connect to a provider, unlock a vault or approve operations.
Production companion/provider source is unchanged. A successful build or unit
test is not fingerprint acceptance.

## Build without touching Keychain

On the M1 Mac, from this checkout:

```sh
bash scripts/build-touch-id-probe.sh
```

The script runs isolated state-model tests and builds/signs
`macos-touch-id-probe/dist/Touch ID Probe.app`. It does not launch it. It refuses
to overwrite an existing bundle; pass a fresh output directory for another build.
The app is ad-hoc signed for development, not notarized. Do not disable Gatekeeper
or remove quarantine flags. Native key access under this signing profile is what
the test must establish, not something the build promises.

Portable state tests can also run with Swift installed on Linux:

```sh
swift test --package-path macos-touch-id-probe
```

## Coordinated human test

Open the probe only when ready for fingerprint prompts. Merely opening the app
does not create a key or request authentication. Do not change fingerprint
enrollment or install/replace the real companion as part of this initial test.

1. Choose **Create test key**, then **Reopen test key**. Expect `created` and `reopened`; record the displayed public fingerprint. An existing key is never replaced. On repeat runs, use Reopen instead of Create.
2. Choose **No-interaction check**. Only `interactionRequired` passes this negative check. `missingKey`, `failed`, `unavailable`, or `unsafe` is not a pass. Run this before signing and again immediately after a successful sign, to detect unwanted authentication reuse.
3. Choose **Sign once with Touch ID**, use one fingerprint, and expect `signatureVerified`. Repeat: a separate touch must be required. The counter records verified signatures, not a count of observed fingerprint touches.
4. Choose Sign once again and cancel the system prompt. Expect `cancelled` and no additional verified signature. The app's Cancel attempt also invalidates its context; buttons stay disabled until the native worker returns. No password fallback is offered.
5. Quit the probe, reopen the same bundle, and Reopen. Verify the fingerprint is unchanged, then repeat the negative and fresh-touch checks. To test update compatibility, make a benign executable change (for example, alter the window title) and build into a fresh output directory. Record each bundle executable's SHA-256 using `shasum -a 256 "path/to/Touch ID Probe.app/Contents/MacOS/TouchIDProbe"` and verify the hashes differ. Repeat the checks with that changed bundle; an unchanged executable rebuild does not prove update compatibility. Failure must not be hidden by recreating the key.
6. Choose **Delete this probe's test key**, expect `deleted`, then Reopen must yield `missingKey`. This is explicit cleanup, not provider revocation. Only the exact probe application tag in the data-protection Keychain is targeted.

The key is permanent until step 6; closing the app intentionally preserves it
for the reopen test. Its tag is `dev.vaultwarden.TouchIDProbe.disposable.v1`.
Cancellation cannot undo a completed key creation/deletion: such results remain
visible and reset the displayed key evidence. An `unsafe` result is also never
hidden by cancellation. Failed create/delete attempts retain existing counters.
If signing/app access fails, preserve the observation and coordinate recovery;
do not delete unrelated Keychain entries or relax authentication.

Report macOS version/build, source/bundle version, public fingerprint continuity,
the fixed result categories, whether each sign required a separate touch, and
cleanup result. Never report passwords, signature bytes, private-key material,
fingerprint images or raw authentication errors. The probe does not emit those.

Actual lockout and fingerprint-set-change acceptance are separate coordinated
tests; do not deliberately lock yourself out or add/remove fingerprints without
explicit approval. This initial probe does not by itself close those gates or
the later provider/protocol integration gate.

## Security boundary

The native adapter requests a Secure Enclave P-256 key with `privateKeyUsage` and
`biometryCurrentSet`, reopens it for each operation and uses a fresh `LAContext`
with device-unlock reuse disabled. Only an internally generated synthetic message
is signed; the signature is verified locally and never displayed. A no-interaction
signature is a security failure, not a convenience success. Cancellation and
sleep invalidate the pending attempt and discard late signing success, without
hiding an unsafe observation or a completed Keychain mutation.

The isolated tests check state accounting and specific negative-error
classification. Native hardware behavior must be demonstrated separately; a
mock result or a generic Keychain failure cannot establish biometric enforcement.
