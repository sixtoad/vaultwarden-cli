# Deferred work

## Zeroize legacy account-key decryption scratch buffer

- Source: Story 1.3 third independent edge-case review, 2026-09-23.
- Location: `src/crypto/stretched_keys.rs`, `StretchedKeys::decrypt_symmetric_key`.
- Observation: `CryptoKeys::decrypt_with_keys` returns a temporary `Vec<u8>`;
  `CryptoKeys::from_symmetric_key` copies it into owned keys, then the temporary
  drops without wiping its allocation. Freed allocator memory can retain bytes.
- Classification: pre-existing crypto hardening. This exact helper exists at
  baseline `91a6a662cdfb6b27edba2ca93cd3735b630a1931` and is unchanged by Story 1.3.
  There is no demonstrated external disclosure or reachable usable authority
  after provider lock; live provider keys and its revocable keyring record clear.
- Follow-up: wrap the temporary in `zeroize::Zeroizing` and examine sibling
  decryption helpers for the same copy/drop pattern. Cover successful and failed
  conversion paths, rerun crypto/provider-session tests, and document the limits
  of memory zeroization rather than claiming forensic erasure of all copies.

## Desktop approval on Windows and Linux: review LOWs (PR #94)

- Source: self-review of `feature/desktop-approval-win-linux`, 2026-11-26
  (spec: [desktop approval](desktop-approval-spec.md)).
- DNS resolution in `companion/rust/src/desktop/transport.rs` is not bounded
  by the 5 s exchange deadline, and only the first resolved address is
  tried. A hung resolver delays one exchange; it grants nothing.
- Deleting a Windows Hello key forgets its credential id; the platform
  credential stays in Windows Hello until the user removes it in Settings
  (never used again; spec D-6). `WebAuthNDeletePlatformCredential` (API v4)
  could remove it.
- `hello::keys::Keys::create` is not serialised against a concurrent create
  of the same binding; Dart serialises key operations today.
- No native sleep or screen-lock notification on Windows/Linux: Flutter's
  `inactive`/`hidden` drive invalidation (spec D-5 residual).
- The closing paragraph of `ProviderCapabilities` and the synthetic signing
  demonstration button remain macOS-centric on Windows and Linux; phones
  still show the Mac wording in `TouchIdKeyPanel` (pre-existing).
- Hardware evidence: the Windows Hello prompt, TPM backing, cancellation and
  the platform's real authenticator flags (UV, BE/BS) are untested on a PC.
