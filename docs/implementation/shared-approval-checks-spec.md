# Shared approval checks in the Rust core

Status: implemented on branch `feature/shared-approval-checks`, stacked on
`feature/desktop-approval-win-linux` (PR #94, base `6f1ad67`, 2026-11-27). The
owner delegated every design call; each one is logged below as S-n with its
context, the options and their trade-offs, the choice, the reason and how to
reverse it.

## Goal

The approval logic that needs no platform API was written three times: in the
Rust core, in Kotlin (Android) and in Swift (macOS and iOS). It is: checking
the exact v2 transcript bytes before they are signed (14 framed fields,
`review_digest` is field 14; enrollment's 6), checking the ASN.1 DER ECDSA
signature format, and verifying the signature against the public key before it
leaves the device. Implement it once in Rust, expose what Dart needs through
flutter_rust_bridge 2.13.0, and leave Kotlin and Swift as thin layers that hold
the key, show the biometric prompt and sign the bytes they are given.

Out of scope by the owner's framing: key storage, the biometric prompt and
signing stay native (moving them would need hand-written `unsafe` bindings to
the Keystore and the Secure Enclave and would stop following each platform's
documented examples). Never weakened: a fresh biometric authentication per
operation, no passcode fallback, hardware-backed keys, one-time tickets,
refusal of synced credentials. The provider (`src/`) is unchanged.

## What existed

| Check | Rust core | Android (Kotlin) | macOS / iOS (Swift) |
|---|---|---|---|
| Build the v2 approval and enrollment transcripts | `provider/approval_v2.rs` | — | — |
| Signer admission of the transcript (`admits`) | `desktop/hello/admit.rs` (Windows Hello) | `ApprovalTranscript.admits` | `ProductionTranscript.admits` (shared source) |
| Strict DER of the signature | `approval_v2::valid_signature` (approve, enroll) | `SignatureEncoding.isStrictDer` | iOS `MobileApproval.checked`; macOS only `8...72` bytes |
| Verify the signature with the public key | enrollment only (`biometric.rs`), Windows Hello (`keys.rs`) | `ApprovalKeyStore.verifies` | iOS `MobileApproval.checked`; macOS none |
| Key id = SHA-256(public key) of the approval | Dart echoed Rust's own `key_id` back | — | — |

So an approval signature was verified on iOS and Android, natively, but not on
macOS, and Rust only checked its DER shape before building the proof.

## Decisions

### S-1. The signer's transcript admission stays native, on purpose

- **Context.** `ApprovalTranscript.admits` (Android) and
  `ProductionTranscript.admits` (macOS, iOS) parse the framing and refuse to
  prompt or sign unless field 0 is the domain of the prompted purpose, the
  provider identity and approval client are the key's binding, the key id
  (approve) or public key (enroll) is this key's, and the fixed field sizes
  hold. Their comments call them a "second line of defence", and
  `docs/mobile-clients.md` section 2 ("Bound to the exact request", item 2)
  makes it the native side's contract.
- **What it protects, independently of Dart and Rust.**
  1. The prompt's purpose is bound to the signed bytes: the native side picks
     the prompt text from `purpose` ("Approve one provider request" versus
     "Enroll this device's ... key"), so a compromised Dart cannot show an
     enrollment prompt while the key signs an approval.
  2. The production key never signs bytes of another domain (the synthetic v1
     demonstration, or anything else): it is not a general signing oracle.
  3. A key bound to one provider and client never signs a transcript naming
     another binding or another key.
  The fixed field sizes alone protect nothing (the provider rebuilds every
  transcript with those sizes, so a wrongly sized one could never verify),
  but they are part of "well formed" in the contract.
- **Options.**
  1. Remove it; the signer signs whatever bytes it is given. Smallest native
     code, but loses all three properties above when Dart is compromised.
  2. Call the Rust rule from Swift and Kotlin. Swift could reach a C ABI
     export of the static library or dylib; Kotlin needs JNI. Both are
     hand-written `unsafe` FFI (the `jni` crate is not in the lock and cannot
     be fetched here), which is exactly what the owner ruled out, and the
     check would no longer be independent of the Rust core.
  3. Keep a reduced native guard (domain, binding and key only, no sizes).
     Saves about three lines per platform; changes the documented contract and
     is a judgement about which part is "enough".
  4. Keep it as it is natively, and hold every copy to one Rust reference
     with shared vectors (S-2).
- **Choice.** 4.
- **Reason.** The guard is small (about 30 lines per platform), is the
  documented native contract, and gives real protection that does not depend
  on Dart or Rust; when in doubt the brief says keep it. What was actually
  duplicated without an independence purpose is the signature check (S-3).
- **Reverse.** Delete the `admits` calls in `ApprovalKeyStore.prepare` /
  `complete` (Android) and `ProductionApprovalKey.sign` /
  `signAuthenticated` (Swift), the two `admits` functions, and their vector
  tests; update `docs/mobile-clients.md` section 2 item 2.

### S-2. One Rust reference for admission, shared vectors for the native copies

- **Context.** Each platform had its own hand-built mutation table for
  `admits` (Kotlin `ApprovalTranscriptTest`, Swift `ProductionContractTests`,
  Rust `admit.rs` tests). Nothing kept the three in agreement.
- **Options.**
  1. Keep three hand-written case lists: they drift silently.
  2. Generate the native `admits` code from Rust: a code generator for two
     small functions, more machinery than the functions themselves.
  3. One list of cases, built by a Rust test from the provider's golden vector
     with the expected verdict stated per case, checked against the Rust
     `admits`, committed as JSON, and read by the native tests, which must
     return the same verdict for every case. The Rust test fails when the
     committed file is stale.
- **Choice.** 3. The Rust rule moved from `desktop/hello/admit.rs` to
  `provider/admission.rs` (it is not Windows-specific; the Windows Hello
  signer still calls it). `companion/rust/tests/admission_vectors.rs` (cases
  in `tests/support/admission_cases.rs`) writes
  `companion/fixtures/approval-v2-admission.json` (51 cases, 4 admitted) with
  `UPDATE_ADMISSION_VECTORS=1` and otherwise requires it unchanged (compared
  as parsed JSON, so a Windows checkout's CRLF line endings do not count). Swift
  (`native_tests/ProductionContractTests.swift`, the macOS and iOS source) and
  Kotlin (`ApprovalTranscriptTest`) loop over it.
- **Reason.** The rule is specified once; a native copy that diverges fails its
  own platform's test with the case name. The cases cover every field, the
  purpose swap, framing (trailing, truncated, extra, 33 fields, over 4096
  bytes, empty), other bindings and malformed keys, plus admitted variants
  that show fields 5 to 13 are only sized.
- **Reverse.** Restore per-platform tables from git history and delete the
  JSON and the two Rust test files.

### S-3. The approval signature is checked and verified once, in Rust, before the proof is built

- **Context.** See "What existed": three platforms, three behaviours, and the
  macOS path sent an unverified signature (the provider then refused it and
  the ticket was spent). Enrollment was already verified in Rust
  (`biometric_key_begin_enroll`), and Windows Hello in Rust (`keys.rs`).
- **Options.**
  1. Keep the native verifiers and add one to macOS: four implementations of
     DER parsing and ECDSA verification.
  2. A new Dart-visible Rust function that Dart calls before
     `provider_biometric_begin`: one implementation, but skippable by Dart.
  3. Verify inside `provider_biometric_begin` /
     `provider_biometric_begin_wrapped`, which already re-check the handle
     and every binding rule against the review: the last step before the
     decision body exists, so it cannot be skipped.
- **Is native verification an independence layer?** No. A signature that does
  not verify authorizes nothing: the provider verifies every proof against the
  key it enrolled and refuses it. Native verification only caught a faulty
  signature early so that the one-time ticket was not spent; it needs only
  public data (the point, the bytes, the signature), so it gives the same
  result wherever it runs. Rust now does that for every platform.
- **Choice.** 3: `provider/proof_check.rs::approval_proof`: the point must be
  an uncompressed P-256 point (`InvalidPublicKey`), SHA-256 of it must be the
  review binding's key id (`KeyMismatch`), the signature must be DER within 8
  to 72 bytes, Windows Hello authenticator data must be acceptable, and the
  signature must verify over the transcript, or over
  `authenticatorData || SHA-256(clientData)` for Windows Hello
  (`InvalidSignature`). A refusal sends nothing and keeps the review.
- **Reason.** One implementation (the provider's own `p256` crate), on every
  platform, macOS included, at a point Dart cannot bypass.
- **Reverse.** Restore `if key_id != signing.key_id` and the
  `valid_signature` check in `ProviderSession::begin_proof`, the `key_id`
  parameter, and the native verifiers from git history.

### S-4. API shape: `provider_biometric_begin(handle, public_key, signature)`

- **Context.** Verifying needs the signer's public key. Dart passed `key_id`,
  which it had taken from Rust's own `BiometricSigningRequest`: Rust compared
  its value with itself.
- **Options.**
  1. Add `public_key` beside `key_id`: two parameters that must agree, one of
     them an echo.
  2. Replace `key_id` with `public_key`; Rust derives the key id and compares
     it with the review binding's.
- **Choice.** 2, for both `provider_biometric_begin` and
  `provider_biometric_begin_wrapped`. Bindings regenerated with
  flutter_rust_bridge_codegen 2.13.0; the only Dart caller is
  `TouchIdController.approve`, which passes `reply.publicKey`. The refusals are
  existing `BiometricRefusal` values; no new variant.
- **Reason.** The key id check becomes real (the key that signed must be the
  one the provider holds), with fewer parameters.
- **Reverse.** Put `key_id: String` back in both functions and in
  `begin_proof`, regenerate the bindings, pass `request.keyId` from Dart.

### S-5. Error mapping: a non-verifying signature is "not sent", not "signing failed"

- **Context.** iOS and Android turned a non-verifying signature into the
  native outcome `failed`, which Dart worded as a signing failure. Now the
  native reply is `signed` and Rust refuses `begin`.
- **Options.** (a) Keep a native `failed` (needs the native verifier back);
  (b) a new Dart message per refusal (more UI code for a case that only a
  faulty key produces); (c) the existing path: `provider.perform` reports the
  refused `begin` and Touch ID shows `notSent` ("... signed, but the review
  changed or the approval could not start. Nothing was sent; try again.").
- **Choice.** (c).
- **Reason.** It is true (the key signed, nothing was sent, the review is
  kept for another attempt or a password approval) and needs no new wording.
- **Reverse.** Map `InvalidSignature`/`KeyMismatch`/`InvalidPublicKey` from
  the thrown refusal to a dedicated message in `touch_id.dart`.

### S-6. What else stays native, and why

- **Context.** Other logic is also duplicated across platforms but is not
  platform-free: the signer gate (one signature at a time, strictly
  increasing tokens per session, cancel only the open one), the binding's
  key tag/alias, the SEC1 extraction from platform key objects, availability
  and prompt wording, lifecycle cancel triggers.
- **Options.** Move the gate into Rust (it would need a callback into each
  platform's cancel handle and lifecycle), or leave all of it native.
- **Choice.** Leave it native; this change covers only the three checks in
  the goal.
- **Reason.** Each of these holds a platform object (an `LAContext`, a
  `BiometricPrompt`, a Keychain tag or Keystore alias, an `ECPublicKey`) or is
  wording; moving it is the FFI the owner ruled out.
- **Reverse.** Not applicable (nothing moved).

### S-7. Tests: what moved, what was deleted, what changed

- **Moved to Rust.** Kotlin `KeyPolicyTest.derMustBeStrict` became
  `proof_check::tests::der_must_be_strict` (same cases). The native "golden
  signature verifies" and `MobileApproval.checked` tests became the
  `proof_check` unit tests (accepted, other key, malformed points, other
  bytes, raw `r||s`, Windows Hello wrapping) and new cases in
  `tests/approval_v2.rs::submit_rechecks_handle_key_and_signature_before_sending`.
- **Replaced by vectors.** The native admission tables (S-2).
- **Kept native.** Binding parsing and the tag/alias derivation, SEC1
  extraction (`sec1RoundTripsAGeneratedKey`, now without the deleted
  `Sec1` decoder), synthetic-domain separation and key tags on macOS, the iOS
  simulator's golden admission check (`RunnerTests`, which would need an
  Xcode project change to bundle the vectors), every gate, lifecycle,
  availability, wording and key-attribute test.
- **Changed because the contract changed.** Rust tests pass the public key to
  `begin_biometric*`. The Dart fakes now really sign: the golden vector has no
  private key and Rust now refuses an approval signature that does not verify,
  so `test/p256_test_key.dart` (a test-only BigInt P-256 ECDSA signer; Rust is
  its oracle) signs approvals in `FakeKeys`, and Windows Hello's fake signs the
  WebAuthn message. The provider key id these tests expect is the test key's
  (`approvalKeyId`); enrollment tests still use the golden key and signature.
- **New.** `test/approval_proof_check_test.dart`: a signature over other
  bytes, and one by another key, are never sent and keep the review.
- **Reverse.** Revert the test files with the code.

### S-8. macOS drops its signature-length check

- **Context.** `ProductionApprovalKey.signAuthenticated` refused a signature
  outside 8 to 72 bytes; Dart `parseKeyReply` refuses the same, and Rust
  checks the DER (S-3).
- **Choice.** Remove the native line, as on iOS and Android.
- **Reason.** The format check lives in one place; Dart still refuses an
  out-of-range reply as `failed` before Rust sees it.
- **Reverse.** Restore the `guard (8...72).contains(signature.count)`.

### S-9. Mutation coverage follows the moved check

- **Context.** `scripts/mutate-provider-companion.py` (CI job "Companion Rust
  1.88 and security mutations") mutated `if key_id != signing.key_id` in
  `session.rs`, which no longer exists.
- **Choice.** Retarget `v2-proof-key` to `proof_check.rs` and add
  `v2-proof-point`, `v2-proof-verification` (verification skipped) and
  `v2-proof-check-called` (the call removed from `begin_proof`). All four,
  with `v2-proof-handle`, were caught locally.
- **Reverse.** Restore the old mutation entry with S-3's reversal.

## What moved / what stayed native

| Logic | Before | After |
|---|---|---|
| Build the transcripts | Rust | Rust (unchanged) |
| Transcript admission before the prompt and before signing | Kotlin, Swift, Rust (Windows) | still Kotlin, Swift and Rust (S-1), one reference `provider/admission.rs` and shared vectors (S-2) |
| Strict DER of the signature | Kotlin, iOS Swift, Rust | Rust only (`approval_v2::valid_signature` via `proof_check`) |
| Signature length bound | macOS Swift, Dart, Rust | Dart (reply schema) and Rust |
| Verify the approval signature with the public key | Kotlin, iOS Swift (macOS none) | Rust only, every platform (`proof_check::approval_proof`) |
| Key id of the signing key equals the review's | no real check (echo) | Rust (`proof_check`) |
| Verify the enrollment signature | Kotlin, iOS Swift, Rust | Rust only (unchanged Rust code) |
| Key creation, storage, attributes, invalidation | Kotlin, Swift, Rust (Windows) | unchanged |
| Biometric prompt, fresh authentication, cancellation, gate | Kotlin, Swift, Rust (Windows) | unchanged |
| Binding tag/alias, SEC1 extraction, wording | Kotlin, Swift | unchanged |

## Not verified locally

- **Kotlin.** No Android SDK, Gradle or `kotlinc` on the development Mac, and
  nothing may be downloaded: `ApprovalKeyStore.kt`, `SignatureEncoding.kt`
  and the changed unit tests (`ApprovalTranscriptTest`, `KeyPolicyTest`,
  `Fixtures`) compile and run only in CI ("Android companion").
- **iOS.** No simulator runtime is installed and the
  `aarch64-apple-ios(-sim)` Rust targets are not present, so
  `MobileApprovalKeyChannel.swift` and `RunnerTests` build and run only in CI
  ("Unsigned iOS approval client"). `MobileApprovalContract.swift` and its
  host tests ran locally (`swift test`).
- **Windows.** The `#[cfg(windows)]` import in `api/desktop_key.rs` (now from
  `provider::admission`) compiles only on the Windows CI job.
- **Hardware.** No real Secure Enclave, Keystore or Windows Hello signature
  was produced: the platform signer code paths that changed only lost their
  post-signing checks, and Rust verifies the result.
