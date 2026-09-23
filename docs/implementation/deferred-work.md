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
