//! Windows Hello approval key (docs/implementation/desktop-approval-spec.md,
//! D-6 to D-8): a WebAuthn platform credential per (provider, client) that
//! signs the v2 transcript through the `windows_hello` wrapping. The pure
//! parts compile and run their tests everywhere; the WebAuthn calls exist
//! only on Windows.
pub mod admit;
pub mod attested;
pub mod keys;
#[cfg(windows)]
pub mod webauthn;
