//! Production Touch ID approval v2 bridge (issue 49 PR B). No UI and no key:
//! the Swift Secure Enclave signer (PR C) signs exactly the transcript bytes
//! returned here, and the Dart screens (PR D) drive these calls. Tickets,
//! passwords and signatures never leave the Rust sessions except inside the
//! request body handed to the native TLS adapter; nothing here logs them.
//!
//! Password approval (`provider_begin`) is unchanged. Responses to work
//! returned by `provider_biometric_begin` go through the existing
//! `provider_finish`; key-management work goes through `biometric_key_finish`.
use super::provider::ProviderWork;
use crate::provider::{biometric::BiometricKeySession, session::ProviderSession};
use std::sync::{Mutex, MutexGuard, OnceLock};

/// Why the companion refuses to produce or send a Touch ID proof. Every value
/// is a local refusal: nothing was sent to the provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BiometricRefusal {
    NotConfigured,
    NotPinned,
    Busy,
    OutcomeUncertain,
    NoDecidableReview,
    /// Version 1 review, or the provider sent `approval_binding: null`.
    BindingUnavailable,
    MalformedBinding,
    MalformedReview,
    ProviderMismatch,
    ApprovalClientMismatch,
    RequestMismatch,
    GenerationMismatch,
    TicketMismatch,
    /// Binding expiry or policy/arguments digests differ from the review.
    ReviewMismatch,
    ReviewDigestMismatch,
    /// No enrolled key, or the provider policy requires a password.
    BiometricNotAllowed,
    NoEnrolledKey,
    KeyMismatch,
    StaleHandle,
    InvalidSignature,
    InvalidPublicKey,
    InvalidPassword,
    NoPreparedOperation,
    RequestTooLarge,
}

/// Whether this session asks the provider for version 2 reviews.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BiometricSupport {
    /// No pinned identities yet: version 1 reviews, password only.
    #[default]
    Unpinned,
    /// Pinned: reviews are requested with version 2.
    Requested,
    /// The provider refused a version 2 review (`invalid_request`): an older
    /// provider. Version 1 reviews and password approval continue.
    Unsupported,
}

/// Result of the last Touch ID decision this session sent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BiometricDecisionResult {
    #[default]
    None,
    InFlight,
    /// Approved (committed, running or completed).
    Approved,
    /// `stale`: ticket expired/consumed or the review changed. Like the
    /// password path, the original request stays status-recoverable only.
    Stale,
    /// `authentication_failed`: the policy requires a password, the key was
    /// retired or replaced, or the proof did not verify. Use a password.
    PasswordRequired,
    RateLimited,
    /// Definite rejection (`invalid_request`/`unauthorized`) or a terminal
    /// status other than approval.
    Rejected,
    /// The response was lost or unusable; recover through status only.
    OutcomeUnknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderBiometricState {
    pub support: BiometricSupport,
    pub binding_available: bool,
    pub biometric_allowed: bool,
    /// The provider's current key id for this device from the review binding
    /// (empty when none or unknown).
    pub key_id: String,
    pub can_prepare: bool,
    /// Why `provider_biometric_prepare` would refuse now, if it would.
    pub refusal: Option<BiometricRefusal>,
    pub result: BiometricDecisionResult,
}

/// Exactly the bytes the Secure Enclave key must sign (ECDSA P-256 SHA-256
/// over the message, ASN.1 DER output), bound to the current review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BiometricSigningRequest {
    pub handle: u64,
    pub request_id: String,
    pub key_id: String,
    pub transcript: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BiometricKeyCommand {
    /// `identity_detail` version 3 for this device: its current key id.
    Read,
    PrepareEnroll,
    PrepareRevoke,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BiometricKeyState {
    #[default]
    Unknown,
    NotEnrolled,
    Enrolled,
    /// The provider does not offer Touch ID key management (older provider).
    Unsupported,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BiometricKeyOutcome {
    #[default]
    None,
    Accepted,
    Enrolled,
    Revoked,
    PasswordRejected,
    RateLimited,
    Stale,
    Rejected,
    Unsupported,
    /// Mutation outcome unknown: read the key state again (never resent).
    Unknown,
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BiometricKeySnapshot {
    pub configured: bool,
    pub busy: bool,
    pub state: BiometricKeyState,
    /// The provider's current key id for this device (empty when none/unknown).
    pub key_id: String,
    pub can_enroll: bool,
    pub can_revoke: bool,
    pub outcome: BiometricKeyOutcome,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BiometricEnrollRequest {
    pub key_id: String,
    pub transcript: Vec<u8>,
}

pub(crate) fn keys() -> &'static Mutex<BiometricKeySession> {
    static SESSION: OnceLock<Mutex<BiometricKeySession>> = OnceLock::new();
    SESSION.get_or_init(|| Mutex::new(BiometricKeySession::default()))
}
fn provider<T>(f: impl FnOnce(&mut ProviderSession) -> T) -> Result<T, BiometricRefusal> {
    let mut state = super::provider::session()
        .lock()
        .map_err(|_| BiometricRefusal::NotConfigured)?;
    Ok(f(&mut state))
}
/// The key session, locked, after the pin rule: its pin must equal the
/// provider session's current pin (read first; the two locks are never held
/// together). A mismatch resets the key session and refuses `NotPinned`.
fn pinned_keys() -> Result<MutexGuard<'static, BiometricKeySession>, BiometricRefusal> {
    let current = provider(|s| s.pinned().cloned())?;
    let mut s = keys().lock().map_err(|_| BiometricRefusal::NotConfigured)?;
    s.require_pin(current.as_ref())?;
    Ok(s)
}

/// Pin the provider leaf SHA-256 and this device's client leaf SHA-256 (both
/// 64 lowercase hex). Call after every `provider_configure`; configuration
/// clears this pin and resets the key session (`biometric_key_configure`).
/// Pinning new values retires any current review so the next one is v2,
/// unless this provider already refused v2 (then v1 for the process lifetime).
#[flutter_rust_bridge::frb(sync)]
pub fn provider_biometric_pin(
    provider_identity: String,
    approval_client: String,
) -> Result<ProviderBiometricState, BiometricRefusal> {
    provider(|s| {
        s.pin(&provider_identity, &approval_client)?;
        Ok(s.biometric_state())
    })?
}
#[flutter_rust_bridge::frb(sync)]
pub fn provider_biometric_state() -> Result<ProviderBiometricState, BiometricRefusal> {
    provider(|s| s.biometric_state())
}
/// The transcript to sign for the current review. Does not consume the review:
/// cancelling Touch ID leaves password approval available.
#[flutter_rust_bridge::frb(sync)]
pub fn provider_biometric_prepare() -> Result<BiometricSigningRequest, BiometricRefusal> {
    provider(|s| s.prepare_biometric())?
}
/// Send the Touch ID approval. Consumes the review exactly as a password
/// approval does; finish with `provider_finish`.
#[flutter_rust_bridge::frb(sync)]
pub fn provider_biometric_begin(
    handle: u64,
    key_id: String,
    signature: Vec<u8>,
) -> Result<ProviderWork, BiometricRefusal> {
    provider(|s| s.begin_biometric(handle, &key_id, &signature))?
}

/// Pin the key session with the SAME values just given to
/// `provider_biometric_pin` (refused `NotPinned` otherwise). Every key call
/// re-checks that rule; `provider_configure` resets the key session.
#[flutter_rust_bridge::frb(sync)]
pub fn biometric_key_configure(
    provider_identity: String,
    approval_client: String,
) -> Result<BiometricKeySnapshot, BiometricRefusal> {
    let current = provider(|s| s.pinned().cloned())?;
    let mut s = keys().lock().map_err(|_| BiometricRefusal::NotConfigured)?;
    s.configure(&provider_identity, &approval_client)?;
    s.require_pin(current.as_ref())?;
    Ok(s.snapshot())
}
#[flutter_rust_bridge::frb(sync)]
pub fn biometric_key_snapshot() -> Result<BiometricKeySnapshot, BiometricRefusal> {
    let current = provider(|s| s.pinned().cloned())?;
    let mut s = keys().lock().map_err(|_| BiometricRefusal::NotConfigured)?;
    // A stale pin resets the session so the snapshot shows it unconfigured.
    let _pinned = s.require_pin(current.as_ref());
    Ok(s.snapshot())
}
#[flutter_rust_bridge::frb(sync)]
pub fn biometric_key_begin(command: BiometricKeyCommand) -> Result<ProviderWork, BiometricRefusal> {
    pinned_keys()?.begin(command)
}
/// The enrollment proof-of-possession transcript for `public_key` (65-byte
/// uncompressed SEC1) under the current `PrepareEnroll` ticket.
#[flutter_rust_bridge::frb(sync)]
pub fn biometric_key_enroll_transcript(
    public_key: Vec<u8>,
) -> Result<BiometricEnrollRequest, BiometricRefusal> {
    pinned_keys()?.enroll_transcript(&public_key)
}
#[flutter_rust_bridge::frb(sync)]
pub fn biometric_key_begin_enroll(
    password: String,
    public_key: Vec<u8>,
    signature: Vec<u8>,
) -> Result<ProviderWork, BiometricRefusal> {
    pinned_keys()?.begin_enroll(password, &public_key, &signature)
}
#[flutter_rust_bridge::frb(sync)]
pub fn biometric_key_begin_revoke(password: String) -> Result<ProviderWork, BiometricRefusal> {
    pinned_keys()?.begin_revoke(password)
}
#[flutter_rust_bridge::frb(sync)]
pub fn biometric_key_finish(
    token: u32,
    response: Vec<u8>,
) -> Result<BiometricKeySnapshot, BiometricRefusal> {
    let mut s = keys().lock().map_err(|_| BiometricRefusal::NotConfigured)?;
    s.finish(token, &response);
    Ok(s.snapshot())
}
