# Desktop approval on Windows and Linux (issue #50)

Status: implemented on branch `feature/desktop-approval-win-linux` (baseline
`origin/main` 355136d, 2026-11-26). The owner delegated every design call; each
one is logged below as D-n with its context, the options and their trade-offs,
the choice, the reason and how to reverse it.

## Goal

A Windows and a Linux approval path that use the same v2 transcript
(`docs/companion-protocol.md`, "Approval transcript"), the same signature
encoding (ASN.1 DER ECDSA P-256 SHA-256) and the same provider rules as macOS,
iOS and Android, without weakening anything the provider accepts from those
platforms, and without calling an approval `biometric` when it is not.

## What existed

- macOS, iOS and Android each implement the method channels of
  `docs/mobile-clients.md` natively: provider transport (pinned mTLS), approval
  key, notifications.
- On Windows and Linux `approvalClientSystems` excluded the platform, so
  `NativeProviderPlatform.available` was false and the app showed "Provider
  transport unavailable on this platform. Provider approvals require macOS."
  The Windows and Linux runners are the stock Flutter templates.
- The provider records every key-based approval as
  `"approval":{"method":"biometric","key_id":...}`. Its key registry has no
  notion of what kind of key, or what user verification, a key has: every
  enrolled key is implicitly a "biometric hardware key" (Secure Enclave with
  `.biometryCurrentSet`, or an Android Class 3 Keystore key).

## Decisions

### D-1. Scope: the desktop transport is part of this work

- **Context.** The brief says Windows and Linux "can view but not approve". In
  fact they cannot reach a provider at all (no transport; see above). A key
  without a transport approves nothing.
- **Options.** (a) Deliver only the approval key and leave the transport to a
  later issue: nothing usable ships, nothing testable end to end. (b) Deliver
  the transport too: larger change, but password approval works on both
  platforms at once and the key path has something to ride on.
- **Choice.** (b).
- **Reason.** The goal is an approval path; the transport is its first half,
  and issue #50 lists "Windows/Linux Flutter approval transport" as open work.
- **Reverse.** Remove `linux`/`windows` from `coreTransportSystems`
  (`companion/lib/platform/core_provider.dart`); the app is transport-less on
  those systems again.

### D-2. The desktop transport lives in the Rust core, not in C++ runners

- **Context.** macOS (Swift), iOS (Swift) and Android (Kotlin) each port the
  same rules: endpoint normalisation, timeouts, closed status/body pairing,
  CA-only trust plus exact leaf pin, the recovery marker, the management gate.
- **Options.**
  1. Native per OS: WinHTTP/Schannel in C++ on Windows, libsoup or libcurl on
     Linux. Two more ports of the same rules, the Windows one untestable on the
     development Mac, and new system libraries on Linux.
  2. Dart `SecureSocket`: one port, but the PKCS#12 and the private key would
     enter Dart (the mobile contract keeps them out of Dart and Rust), and
     Dart's TLS stack cannot be restricted to a CA-only trust root without
     extra handling.
  3. Rust core (`rustls` + `rustls-webpki` with `ring`, the provider's own
     TLS stack): one port shared by both systems, unit-tested with a loopback
     `rustls` server on every CI host including this Mac, no new system
     library. The key is in Rust memory (zeroized), never in Dart.
- **Choice.** 3. `companion/rust/src/desktop/` holds the rules, settings,
  identity and transport; `api/desktop_provider.rs` exposes them through
  flutter_rust_bridge; `CoreProviderPlatform` (Dart) implements the existing
  `ProviderPlatform` interface by calling it. Dart and every screen are
  unchanged.
- **Reason.** One tested implementation instead of two untested ones; the
  macOS/mobile channels are untouched.
- **Reverse.** Implement `ProviderPlatform` natively per OS and drop
  `CoreProviderPlatform`; the Rust module is then dead code to delete.

### D-3. Client identity import and storage

- **Context.** Advanced setup imports a development PKCS#12 (the provider's
  `setup tls` writes 3DES/SHA-1 PKCS#12, the format macOS imports) and the
  provider CA (DER). macOS keeps the key in the Keychain, Android in the
  Keystore.
- **Options.**
  - Windows: (a) import into a CNG key container (non-exportable) and sign the
    TLS handshake through NCrypt: hardware-free but OS-held, larger native
    surface, untestable here; (b) keep the PKCS#8 key DPAPI-protected
    (`CryptProtectData`, current user) in `%APPDATA%`; (c) plain file.
  - Linux: (a) Secret Service (D-Bus, needs a running and unlocked keyring;
    any process of the same user can read it once unlocked); (b) a 0600 file
    under `$XDG_CONFIG_HOME` (same user-level protection, no daemon); (c) a TPM
    (tpm2-tss system library, not present on the build hosts).
- **Choice.** Windows (b), Linux (b). PKCS#12 parsing in Rust with the
  `p12-keystore` crate (3DES/SHA-1 and PBES2 bags). The PKCS#12 bytes and the
  passphrase are dropped right after import; only the key and the leaf/chain
  are stored.
- **Reason.** Both give the protection the platform actually offers to a
  same-user process, with no new runtime dependency; the client identity is
  an mTLS credential, not an approval factor (approval needs the provider
  password or a user-verified key on top of it). Labelled honestly in
  `docs/mobile-clients.md` ("desktop identity at rest").
- **Reverse.** Swap `desktop::store` for a CNG/Secret Service store; the file
  format is versioned (`identity-v1`), so a new version can migrate or refuse.

### D-4. Setup selects files by path on Windows and Linux

- **Context.** macOS and Android open a native file picker from the `setup`
  method so the files never pass through Dart. The stock Windows/Linux runners
  have no picker; the `file_selector` plugin would add plugin code to every
  desktop runner (macOS included) and change its registrant.
- **Options.** (a) `file_selector` plugin; (b) native pickers in the runners
  (COM `IFileOpenDialog`, `GtkFileChooserNative`); (c) two path fields in
  Advanced setup on Windows/Linux only; Rust reads the files.
- **Choice.** (c).
- **Reason.** Advanced setup is the development path (guided enrollment, #59,
  is the product path); paths keep the bytes out of Dart without touching the
  macOS runner.
- **Reverse.** Add a picker and pass its paths to the same Rust call.

### D-5. Lifecycle and the management gate on the desktop

- **Context.** macOS invalidates the provider session natively on sleep, window
  close and loss of activation, and its `ManagementTransportGate` binds an
  administrative ticket to the foreground epoch.
- **Options.** (a) Native observers in each runner calling into Dart; (b) the
  Rust port of the gate and recovery marker, invalidated by Dart's
  `AppLifecycleState` (inactive, hidden, paused, detached), foreground taken
  from the last reported state.
- **Choice.** (b): `desktop::rules::ManagementGate` and `RecoveryState` are
  ports of the Kotlin classes, and `CoreProviderPlatform` reports lifecycle
  changes to Rust and raises its own `invalidate` callback.
- **Reason.** Same rules, tested in Rust; Flutter reports window activation and
  minimisation on both desktop embedders. The residual difference (no system
  sleep notification: a sleeping desktop first reports `inactive`/`hidden`) is
  documented.
- **Reverse.** Add native observers that call the same Rust invalidation.

### D-6. Windows approval key: Windows Hello through the WebAuthn platform API

- **Context.** The brief suggests `KeyCredentialManager` or the NCrypt
  Microsoft Passport KSP with P-256 "if available".
- **Options.**
  1. `KeyCredentialManager` (WinRT): documented and Hello-gated, but RSA-2048
     only. The provider would need RSA keys and RSA signatures: a second key
     type and a second signature format.
  2. NCrypt with the Microsoft Passport (NGC) KSP and `ECDSA_P256`: raw
     signatures over the transcript, identical provider verification, but the
     use of that KSP through NCrypt is undocumented (key naming, prompt and
     PIN-cache behaviour), it has no cancellation, and nothing could prove it
     works before hardware tests.
  3. NCrypt with the Platform Crypto Provider (TPM): documented P-256, but its
     user prompt is the legacy key-protection password dialog, not Windows
     Hello; it is not user verification in any honest sense.
  4. The Win32 WebAuthn API (`webauthn.dll`, Windows 10 1903+) with the
     platform authenticator, ES256, user verification required: documented,
     Windows Hello prompt, TPM-backed credential, documented cancellation
     (`WebAuthNCancelCurrentOperation`), and the authenticator itself asserts
     the user-verified (UV) and not-synchronised (BE/BS) flags. The signature
     is still DER ECDSA P-256 SHA-256 by the same kind of key (key id = SHA-256
     of the 65-byte point), but over `authenticatorData || SHA-256(clientData)`,
     so the provider needs one closed, versioned wrapping (D-7).
- **Choice.** 4.
- **Reason.** It is the only option that is documented, P-256, Hello-gated and
  cancellable; the wrapping is small, fully deterministic and verifiable, and
  it gives the provider an authenticator-asserted UV flag the raw paths do not.
  The transcript, the key type, the key id and the signature encoding are the
  other platforms'.
- **Reverse.** Implement option 2 behind the same Dart channel and enroll with
  `key_class:"biometric"`-style raw proofs under a new class; the D-7 class
  stays readable for existing keys until they are re-enrolled.

### D-7. Provider key classes: closed, versioned, never weaker for existing keys

- **Context.** Windows Hello accepts the Windows Hello PIN as well as a
  fingerprint or face; the provider cannot tell which was used. It must not
  record such an approval as `biometric`.
- **Options.** (a) Record every key approval as `biometric` (dishonest);
  (b) a free-form class string from the client (unbounded); (c) a closed enum
  in the key registry, set at enrollment and immutable for the key, that
  selects both the verification rule and the recorded method.
- **Choice.** (c):
  - Registry entry member `key_class`, omitted for the existing class
    (`biometric`: Secure Enclave/Keystore raw transcript signature, recorded as
    `"method":"biometric"`). The only new value is `windows_hello`
    (WebAuthn-wrapped transcript, recorded as `"method":"windows_hello"`). Any
    other value is refused when the registry is read.
  - Enrollment: `biometric_enroll` version 2 is unchanged and only ever
    enrolls a `biometric` key. Version 3 requires `key_class` (closed:
    `windows_hello`; `biometric` is refused at version 3 so the class is never
    ambiguous) and `enroll_authenticator_data`.
  - Decision: the proof of a `windows_hello` key must carry
    `authenticator_data`; the proof of a `biometric` key must not. A mismatch
    is `authentication_failed` (no class downgrade or upgrade by the client).
  - History: `ApprovalMethod::WindowsHello { key_id }`.
  - Registry version 4 is written only when a `windows_hello` key, or its
    audit record, exists; version 3 stays byte-identical otherwise, so a
    macOS/mobile-only provider can still roll back exactly as before.
- **Reason.** Honest records; the verification of an existing `biometric` key
  is byte-for-byte the same code path; an unknown class fails closed.
- **Residual risk.** The class is declared by the enrolling client (mTLS,
  fresh password and proof of possession). A malicious client could enroll a
  software key and declare it `biometric`; that was already true of every
  platform (no attestation is verified). The `windows_hello` class at least
  requires authenticator data with UV set.
- **Reverse.** Stop accepting version 3 enrollment; existing `windows_hello`
  keys can be revoked (`biometric_revoke`) and the registry then returns to
  version 3 content (it stays version 4 while retired ids or audit records of
  that class exist, as version 3 does for Touch ID).

### D-8. The WebAuthn wrapping (verification class `windows_hello`)

- RP id: `vaultwarden-access.approval-v2` (an application RP id, as OpenSSH uses
  `ssh:`; never a web origin).
- Client data: exactly the bytes
  `{"type":"webauthn.get","challenge":"<b64url(SHA-256(transcript))>","origin":"vaultwarden-access.approval-v2"}`
  (no whitespace, members in that order). Both sides build it; the provider
  never parses client-supplied JSON.
- Authenticator data: exactly 37 bytes (`rpIdHash || flags || signCount`):
  `rpIdHash == SHA-256(rp id)`, flags must have UP (0x01) and UV (0x04) and
  must not have BE (0x08), BS (0x10), AT (0x40) or ED (0x80), and the reserved
  bits 0x02 and 0x20 must be clear. The signature counter is not checked
  (platform authenticators may report 0).
- Signed message: `authenticatorData || SHA-256(clientData)`; signature: DER
  ECDSA P-256 SHA-256 (8-72 bytes), verified with the existing
  `ring` `ECDSA_P256_SHA256_ASN1` verifier.
- The same wrapping proves possession at enrollment over the enrollment
  transcript (domain `...approval-enroll.v2`).

### D-9. Linux: password approval only

- **Context.** Linux has no standard API for a hardware-bound, user-verified
  signing key.
- **Options.** (a) Password only (the existing provider password path);
  (b) a TPM2 key with a TPM PIN (needs tpm2-tss, often absent, and a TPM PIN is
  another password, not biometric); (c) a software key wrapped by a passphrase
  (a second password that is also brute-forceable offline from a stolen
  file, weaker than the provider's rate-limited password); (d) a software key
  "gated" by fprintd (the gate runs in the same user session; any process of
  that user reads the key file without a finger: not user verification).
- **Choice.** (a). The Linux approval key reports `unavailable`; no new key
  class.
- **Reason.** Every alternative is either another password or a bypassable
  gate, and recording it as anything but a password would be dishonest. The
  provider password is verified and rate limited by the provider.
- **Reverse.** Add a class (for example `tpm2_pin`) under D-7's rules.

### D-10. Wording

- Windows: "Windows Hello", "this PC", invalidated by "a Windows Hello sign-in
  change". Linux: key approval is never offered; the messages that name a
  method use "a device key" (never "Touch ID"). macOS and phones unchanged.

## Contract summary (what each side checks)

| Step | Companion (Windows) | Provider |
|---|---|---|
| Key creation | WebAuthn MakeCredential, platform attachment, UV required, ES256 only, resident key not required; public key from the COSE key in the attested credential data (P-256, x/y 32 bytes); credential id stored per binding | — |
| Enrollment | `biometric_enroll` v3, `key_class:"windows_hello"`, proof by GetAssertion over the enrollment transcript | rebuilds the enrollment transcript, checks D-8, records `key_class` |
| Approval | `admits` check of the 14 fields (same as macOS), then GetAssertion; proof `{key_id, signature, authenticator_data}` | rebuilds the transcript, checks D-8, records `windows_hello` |
| Cancel | `WebAuthNCancelCurrentOperation` on the attempt's GUID | ticket consumed only on send |

## Tests

- Provider (Rust): enrollment v3 accepted/refused (unknown class, `biometric`
  at v3, missing or malformed authenticator data, UV/UP clear, BE/BS/AT/ED set,
  wrong rp hash, wrong client data); approval with a `windows_hello` key;
  class mismatch refusals both ways; history method; registry v4 read/write,
  rollback rules; v2 enrollment and `biometric` approval unchanged.
- Companion core (Rust): rules, recovery, gate, settings round trip, PKCS#12
  import (fixture), loopback TLS (pin mismatch, wrong CA, wrong host, wrong
  client, oversize, bad status pairing, timeout), WebAuthn wrapping and COSE
  parsing, transcript admission. Windows-only FFI compiles and runs its
  non-interactive tests on the Windows CI job.
- Dart: `CoreProviderPlatform`, `CoreApprovalKeyPlatform` (fake core),
  wording, capability derivation for Windows/Linux, setup path fields;
  goldens for the changed Settings screen.
- Not testable without hardware: the Windows Hello prompt, TPM backing and
  cancellation on a real PC (tracked in the PR and on #50).
