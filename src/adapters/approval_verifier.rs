//! `ring` ECDSA P-256 / SHA-256 verifier for production biometric approval v2.
use crate::access::{
    approval_v2::{PUBLIC_KEY_LEN, valid_public_key, valid_signature_len},
    ports::{BiometricApprovalVerifier, SessionError},
};
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};

/// Accepts only 65-byte uncompressed SEC1 keys and DER signatures of at most
/// 72 bytes; `ring` additionally rejects off-curve points and malformed DER.
pub struct RingBiometricVerifier;
impl BiometricApprovalVerifier for RingBiometricVerifier {
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SessionError> {
        if public_key.len() != PUBLIC_KEY_LEN
            || !valid_public_key(public_key)
            || !valid_signature_len(signature)
        {
            return Err(SessionError::AuthenticationFailed);
        }
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
            .verify(message, signature)
            .map_err(|_error| SessionError::AuthenticationFailed)
    }
}

#[cfg(test)]
#[path = "approval_verifier_tests.rs"]
pub(crate) mod tests;
