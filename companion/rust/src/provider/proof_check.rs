//! The one check of an approval proof before it leaves the device
//! (docs/implementation/shared-approval-checks-spec.md S-3, S-4). The
//! platform signers (Secure Enclave on macOS and iOS, Android Keystore,
//! Windows Hello) only hold the key, prompt and sign; the signature they hand
//! back is checked here, against the public key that produced it and the
//! exact transcript this session built, before any decision body is made.
//! A refusal sends nothing and keeps the review (the ticket is not spent).
use super::approval_v2::{self as v2, SigningTranscript};
use super::key_class;
use crate::api::biometric::BiometricRefusal;

/// Whether `signature`, made by the key whose 65-byte SEC1 point is
/// `public_key`, is a valid proof for `signing`:
/// - the point is an uncompressed P-256 point (`InvalidPublicKey`);
/// - its key id is the provider's key id in the review binding (`KeyMismatch`);
/// - the signature is ASN.1 DER ECDSA P-256 within 8 to 72 bytes, the
///   authenticator data (Windows Hello only) is acceptable, and the
///   signature verifies over the transcript, or over the WebAuthn message
///   built from it (`InvalidSignature`).
pub fn approval_proof(
    signing: &SigningTranscript,
    public_key: &[u8],
    signature: &[u8],
    authenticator_data: Option<&[u8]>,
) -> Result<(), BiometricRefusal> {
    if !v2::valid_public_key(public_key) {
        return Err(BiometricRefusal::InvalidPublicKey);
    }
    if v2::key_id(public_key) != signing.key_id {
        return Err(BiometricRefusal::KeyMismatch);
    }
    if !v2::valid_signature(signature) {
        return Err(BiometricRefusal::InvalidSignature);
    }
    let message = match authenticator_data {
        None => Some(signing.transcript.clone()),
        Some(data) => key_class::signed_message(&signing.transcript, data),
    };
    if message.is_some_and(|message| v2::verify(public_key, &message, signature)) {
        Ok(())
    } else {
        Err(BiometricRefusal::InvalidSignature)
    }
}

#[cfg(test)]
#[path = "proof_check_tests.rs"]
mod tests;
