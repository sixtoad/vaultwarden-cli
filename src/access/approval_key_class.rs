//! Approval-key classes (docs/implementation/desktop-approval-spec.md, D-7
//! and D-8). A closed set: each class fixes how a proof over the v2
//! transcript is verified and how the approval is recorded. Every class signs
//! the same transcript with the same kind of key (P-256, key id = SHA-256 of
//! the 65-byte point) and the same signature encoding (DER ECDSA SHA-256).
//!
//! - `Biometric`: the Secure Enclave (macOS, iOS) or an Android Class 3
//!   Keystore key signs the transcript bytes themselves. The class of every
//!   key enrolled before classes existed; never written explicitly.
//! - `WindowsHello`: a Windows Hello WebAuthn platform credential (user
//!   verification by fingerprint, face or the Windows Hello PIN) signs
//!   `authenticatorData || SHA-256(clientData)`, where `clientData` is built
//!   from the transcript by both sides and is never parsed by the provider.
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyClass {
    #[default]
    Biometric,
    WindowsHello,
}
impl KeyClass {
    pub fn is_biometric(&self) -> bool {
        *self == Self::Biometric
    }
}

/// The application RP id of every `WindowsHello` credential (never a web origin).
pub const WEBAUTHN_RP_ID: &str = "vaultwarden-access.approval-v2";
/// `rpIdHash || flags || signCount`, with no attested credential data or extensions.
pub const AUTHENTICATOR_DATA_LEN: usize = 37;
const UP: u8 = 0x01;
const UV: u8 = 0x04;

/// The exact client data both sides hash: no whitespace, members in this order.
pub fn client_data(transcript: &[u8]) -> Vec<u8> {
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(transcript));
    format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\",\"origin\":\"{WEBAUTHN_RP_ID}\"}}"
    )
    .into_bytes()
}

/// Authenticator data of a user-verified, device-bound assertion for our RP:
/// UP and UV set; BE, BS, AT, ED and the reserved bits clear.
pub fn valid_authenticator_data(data: &[u8]) -> bool {
    data.len() == AUTHENTICATOR_DATA_LEN
        && data[..32] == Sha256::digest(WEBAUTHN_RP_ID.as_bytes())[..]
        && data[32] == UP | UV
}

/// The message a key of `class` signs for `transcript`, or `None` when the
/// proof's shape does not match the class (no downgrade or upgrade).
pub fn signed_message(
    class: KeyClass,
    transcript: &[u8],
    authenticator_data: Option<&[u8]>,
) -> Option<Vec<u8>> {
    match (class, authenticator_data) {
        (KeyClass::Biometric, None) => Some(transcript.to_vec()),
        (KeyClass::WindowsHello, Some(data)) if valid_authenticator_data(data) => {
            let mut message = data.to_vec();
            message.extend_from_slice(&Sha256::digest(client_data(transcript)));
            Some(message)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(flags: u8) -> Vec<u8> {
        let mut out = Sha256::digest(WEBAUTHN_RP_ID.as_bytes()).to_vec();
        out.push(flags);
        out.extend_from_slice(&7u32.to_be_bytes());
        out
    }

    #[test]
    fn client_data_is_the_fixed_canonical_form() {
        let bytes = client_data(b"abc");
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            "{\"type\":\"webauthn.get\",\"challenge\":\"ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0\",\"origin\":\"vaultwarden-access.approval-v2\"}"
        );
    }

    #[test]
    fn authenticator_data_needs_user_verification_and_a_device_bound_credential() {
        assert!(valid_authenticator_data(&data(UP | UV)));
        for flags in [
            0,
            UP,
            UV,
            UP | UV | 0x02,
            UP | UV | 0x08,
            UP | UV | 0x10,
            UP | UV | 0x20,
            UP | UV | 0x40,
            UP | UV | 0x80,
            UP | UV | 0x18,
        ] {
            assert!(!valid_authenticator_data(&data(flags)), "flags {flags:#x}");
        }
        let mut other_rp = data(UP | UV);
        other_rp[0] ^= 1;
        assert!(!valid_authenticator_data(&other_rp));
        let mut long = data(UP | UV);
        long.push(0);
        assert!(!valid_authenticator_data(&long));
        assert!(!valid_authenticator_data(&long[..36]));
    }

    #[test]
    fn the_class_fixes_the_proof_shape() {
        let ad = data(UP | UV);
        assert_eq!(
            signed_message(KeyClass::Biometric, b"t", None).unwrap(),
            b"t"
        );
        assert!(signed_message(KeyClass::Biometric, b"t", Some(&ad)).is_none());
        assert!(signed_message(KeyClass::WindowsHello, b"t", None).is_none());
        assert!(signed_message(KeyClass::WindowsHello, b"t", Some(&data(UP))).is_none());
        let message = signed_message(KeyClass::WindowsHello, b"t", Some(&ad)).unwrap();
        assert_eq!(&message[..37], &ad[..]);
        assert_eq!(&message[37..], &Sha256::digest(client_data(b"t"))[..]);
    }

    #[test]
    fn classes_are_closed_on_the_wire() {
        assert_eq!(
            serde_json::to_string(&KeyClass::WindowsHello).unwrap(),
            "\"windows_hello\""
        );
        assert!(serde_json::from_str::<KeyClass>("\"windows_hello\"").is_ok());
        for other in ["\"tpm\"", "\"WindowsHello\"", "\"\"", "1", "null"] {
            assert!(serde_json::from_str::<KeyClass>(other).is_err(), "{other}");
        }
    }
}
