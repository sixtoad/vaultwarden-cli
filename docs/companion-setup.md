# macOS approval companion (development)

This opt-in companion requires a Linux provider and a logged-in Mac running macOS
13 or newer. The Linux provider still verifies passwords and executes protected
operations. Use direct private LAN/VPN HTTPS. Public-internet deployment, managed
SSH tunnelling, biometric approval, a Mac provider, and notarized distribution are
outside this release.

Linux still needs its existing user D-Bus/Secret Service, provisioned bootstrap
credential, and systemd user manager. These services must be available without
a desktop prompt; the Mac unlock action unlocks the provider vault session.
It does not provision or unlock the Linux operating-system keyring.

## Native build and repeatable evidence

From this checkout on the Mac, install/select Xcode command-line tools and ensure
`swift`, `python3`, and `openssl` are available. Run:

```sh
./scripts/test-macos-companion.sh
```

The runner records environment details, contract/controller tests, real URLSession
mutual-TLS tests, and the development bundle build in separate logs under
`macos/acceptance/<UTC timestamp>/`. An optional first argument selects the report
directory. A nonzero exit means validation failed; later phases are not claimed.
The TLS test creates synthetic certificates and a temporary Keychain, briefly adds
it to the search list, restores the prior list, and deletes its test material. It
requires Keychain access; do not run concurrent invocations in the same account.
No real backend password or production identity is needed. If interrupted during
Keychain tests, inspect Keychain Access for a `companion-tls-*` test keychain and
remove it after confirming it belongs to that interrupted test.

For a build alone:

```sh
./scripts/build-macos-companion.sh
```

The result is `macos/dist/Approval Companion.app`, signed ad hoc for local
use. Copy it into `/Applications` or `~/Applications` and open that installed
copy before enabling login startup. It is not notarized. Keychain ACLs,
notification permission and login registration need a logged-in Mac; a CI build
cannot establish that these operator flows work. Rebuilding an ad-hoc-signed app
may prompt again for Keychain access or require login registration to be refreshed.

## Private CA and packaged app policy

The bundle enables `NSAllowsArbitraryLoads` because ATS otherwise rejects the
operator's private CA before the app can perform its configured trust evaluation.
The provider hostname is runtime configuration, so this exception is app-wide.
No CA is installed in the system trust store. Every production connection must
use `PinnedTransport`: HTTPS only, TLS 1.2 or newer, explicit CA-only chain trust,
hostname and certificate-validity checks, exact leaf pin and client identity.
Redirects and automatic decision retries remain prohibited. Future networking
code must preserve these checks; ATS no longer provides a separate app-wide guard.

The native runner also executes a real `.app` regression matrix against a fully
qualified loopback name. A strict-ATS control must reject a valid private CA; the
production plist must accept it while wrong CA/pin/hostname, expired certificates,
foreign/revoked identities, HTTP configuration and legacy TLS fail. These checks
exercise the packaged policy that command-line Swift tests do not exercise.

## Trusted provisioning

1. Provision a private CA, Linux server key/certificate, and a unique client
   key/certificate per Mac using your trusted certificate process. The server
   certificate must contain the exact DNS name or IP SAN used by the Mac. Include
   serverAuth/clientAuth usages respectively. Protect private keys and provisioning
   packages; never add them to this repository. The provider accepts PEM chain/key
   files; the Mac setup accepts its trusted CA in DER form.
2. On the trusted Linux console, derive the exact server leaf certificate SHA256:

   ```sh
   openssl x509 -in server.pem -outform DER | openssl dgst -sha256
   openssl x509 -in ca.pem -outform DER -out ca.der
   ```

   Transfer the HTTPS endpoint, CA DER, and exact 64-character lowercase leaf
   fingerprint through a trusted channel. The pin is the leaf DER hash, not an
   SPKI/public-key pin. The Mac requires valid CA trust, hostname and certificate
   validity *and* this exact pin. Server renewal requires a trusted pin update.
3. Provision a password-protected PKCS#12 containing the Mac's unique client
   private key, certificate and chain. Use a format accepted by macOS Keychain.
   Import it using Setup → Import client PKCS#12 into Keychain. The import
   passphrase is cleared after that action. The app saves only an opaque Keychain
   reference alongside the public provider configuration in its preferences.
   Compare the displayed client certificate fingerprint with the trusted console.
   Remove the PKCS#12 package and its transfer copies according to your provisioning
   procedure after successful import; the app does not delete operator files.
4. Stop the Linux companion daemon before enrollment. The provider state root
   must already have been initialized by normal provider setup. Enroll the exact
   client certificate through the local console:

   ```sh
   vaultwarden-accessd --state-root /private/provider-state \
     --companion-enroll-cert mac-client.pem --companion-client-ca client-ca.pem \
     --companion-label 'Mac operator'
   vaultwarden-accessd --state-root /private/provider-state --companion-list
   ```

5. Start the provider in companion mode with the existing backend configuration
   and agent socket/isolation options required by your deployment:

   ```sh
   vaultwarden-accessd --state-root /private/provider-state \
     --backend-config /private/backend.json \
     --companion-listen 192.168.1.20:8443 \
     --companion-tls-cert server.pem --companion-tls-key server.key \
     --companion-client-ca client-ca.pem
   ```

   Companion HTTPS flags are mutually exclusive with browser UI TLS flags.
   The provider state root must be an absolute, provider-owned directory with
   mode `0700`, without symlink/path-component indirection or unsafe writable
   ancestors. Every companion PEM input (server chain, private key, client CA,
   and client certificate supplied for enrollment) must be a provider-owned
   regular file with mode `0600`, one hard link, and no final symlink. The maximum
   PEM file size is 65536 bytes. Apply these modes during trusted provisioning;
   even public certificate inputs are checked. The server private key is
   unencrypted PEM. Protect the backend configuration as required by existing
   provider setup. Restrict
   access to the intended private LAN/VPN. Companion mode is opt-in; existing
   browser deployments retain their existing startup configuration.
6. In Mac Setup, enter `https://provider.example:8443`, choose the trusted CA DER,
   enter the console-verified leaf fingerprint, and save. The path is fixed to
   `/v1/companion`. A wrong CA, hostname, pin, expired certificate, missing client
   identity, or revoked client must prevent access.
   If macOS requests Local Network access for Approval Companion, allow it to
   reach the configured Linux provider. On macOS versions with this privacy
   control, check System Settings → Privacy & Security → Local Network if access
   was denied. After changing access, reopen the app and refresh the inbox.
7. Enable notifications if desired. Notifications contain only a generic prompt
   and fetch the current authoritative inbox, opening the first pending full
   review when available. All review and decisions happen inside the app.
   If permission was denied, enable Approval Companion in System Settings →
   Notifications. A separate “Notification setup failed” message includes the
   operating-system error; that indicates a request/registration error rather
   than an ordinary denial. The inbox remains usable in either case.
   Choose Start at login from the installed app and approve it in System Settings
   → General → Login Items if macOS requests that approval.

To revoke a Mac, **stop the daemon first**, run the local command, then restart:

```sh
vaultwarden-accessd --state-root /private/provider-state \
  --companion-revoke CLIENT_CERTIFICATE_SHA256
```

Stopping retires live TLS connections and review tickets. A changed enrollment
file is not a substitute for stopping/restarting. Remove a retired client identity
from macOS Keychain using Keychain Access when it is no longer needed. A lost Mac
must be revoked at the provider even if its local Keychain cannot be erased.

## Operator behavior

The inbox polls every five seconds, with capped reconnect delays after failure.
It displays at most 256 pending requests. At capacity, the app explains this limit;
later pending requests appear as slots become available.
Select a pending request to obtain a fresh full review. The review displays every
canonical field: request ID, requester, operation, effect, target, every argument,
credential label/use, all three digests, expiry, one-time wording and status; it
also shows the authority generation. All review text is quoted; control, invisible and bidirectional formatting
characters are escaped so values and argument boundaries remain distinguishable. Requests expire on the provider whether
or not the Mac is available.

Approve once requires a fresh provider password. Deny does not send a password.
The password input clears when submitted, when the review changes, and when the
view closes. The separate unlock input also clears when the provider setup,
session state or lifecycle changes, including refresh, disconnect and sleep.
Requests use an ephemeral URLSession and are never logged or saved.
Swift/Foundation can make transient memory copies; this implementation does not
claim provable password zeroization. The Linux provider alone verifies the
password. The app discards the review ticket before sending any decision,
including a decision that is rejected for a wrong password.

Unlock is a separate action available when the provider reports locked. It never
approves or revives old work; the agent must submit a fresh request afterward.
After a lost decision reply, the app checks status and never resends the decision.
Pending or unavailable status remains uncertain. A pending operation requires an
explicit new review and a new human decision. Login startup, reconnect and
notifications confer no authorization.

## Logged-in Mac/Linux acceptance record (required)

Current observations and raw evidence are in the [acceptance audit](implementation/macos-companion-evidence/acceptance-audit.md).
Automated tests and a development bundle are necessary but do not complete this
record. Run each row with synthetic vault data and a harmless protected operation;
record Mac/OS/build identity, provider revision, outcome, and redacted evidence.
Never capture passwords, vault values, private keys or PKCS#12 passphrases.

| Scenario | Required observation | Status |
|---|---|---|
| Trusted setup and Keychain | CA/hostname/pin succeed; imported identity survives app restart; no persisted password | Saved setup and Keychain identity survived installed-app restart; automated trust checks passed. See acceptance audit. |
| No Linux desktop | Non-TTY agent request appears; complete native review; correct fresh password executes once; agent receives redacted result | Passed 2026-10-07: actual Mac review/approval, exactly one protected Linux execution, redacted signed-agent success. |
| Wrong password and deny | Wrong password executes nothing and consumes review; fresh review can deny without sending password | Operator confirmed explicit rejection and subsequent request denial; Linux audited both with zero execution. |
| Notifications | Generic banner opens current full review/inbox; no notification action approves | Passed after routing fix: operator confirmed background notification switches Setup → Approvals/full review. |
| Locked and unlock | Locked submission creates no pending work; unlock is separate; fresh agent submission needed | Passed: locked rejection created no work; post-reboot native unlock enabled a first-attempt fresh signed request, then native denial with zero execution. |
| Expiry, sleep, reconnect, quit | Requests expire normally; wake/reconnect loads authoritative inbox; stale review cannot execute | Confirmed quit-through-expiry and reopen passed. Actual sleep/wake passed on October 8: request arrived while asleep; wake occurred 37 seconds before normal expiry, then automatic refresh removed it. No execution; expiry while asleep is not claimed. |
| Lost decision reply | Drop the reply after decision reaches provider; status lookup occurs; exactly one decision transmission; pending/unavailable stays uncertain | Passed installed Mac/Linux fault injection at 2026-10-07 14:32:28 UTC: one dropped successful reply, exact decision/status sequence, one protected execution, redacted signed CLI exit 0; operator reported approved. Pending/uncertain behavior has separate passing native automation. |
| Authority changes | Lock/restart, changed agent binding and replay reject old tickets | Passed integrated real-TLS lock, binding revocation, replay and same-state restart/revocation checks, all without execution. Stale/replay attempts used an authenticated test driver; no GUI replay is claimed. |
| Peer distrust and revocation | Wrong CA/hostname/pin and missing/revoked identity expose no review or decision access; stop/revoke/restart disconnects old client | Passed installed-app missing-reference, revoked-identity and foreign-server rejection using process/network/provider evidence; original configuration, enrollment and server certificate restored. Separate native automation covers each CA/pin/hostname guard. No negative GUI quote is inferred. |
| Login startup | Register installed app; log out/in or reboot; menu icon and inbox work without terminal or manual app launch | Passed after actual reboot: shield and exact verified installed binary launched automatically; operator inbox/unlock and fresh-request denial succeeded. |
| Existing browser/agent modes | Companion-disabled regressions and full Linux suites pass | See Linux validation record |

The native CI job runs contract/controller tests, real URLSession authentication
(wrong CA, hostname, pin, foreign and revoked client identities), bounds and
redirect rejection, a dropped-decision-response transmission counter, and bundle
creation. It does not run a real provider/executor or the logged-in rows above.
No native results can be inferred from a Linux-only environment. Native logs and
the passing operator observations above are available. The acceptance audit records
verification scope and exclusions; BMAD code review remains pending.
