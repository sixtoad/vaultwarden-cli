//! The `windows_hello` key class of the provider (desktop-approval-spec D-7,
//! D-8; provider `src/access/approval_key_class.rs`): a Windows Hello WebAuthn
//! credential signs `authenticatorData || SHA-256(clientData)` instead of the
//! transcript itself. Both sides build the same client data; the provider
//! verifies. Kept byte-identical with the provider by the shared test vector.
use super::approval_v2::base64url;
use sha2::{Digest, Sha256};

pub const WEBAUTHN_RP_ID: &str = "vaultwarden-access.approval-v2";
pub const AUTHENTICATOR_DATA_LEN: usize = 37;
const UP: u8 = 0x01;
const UV: u8 = 0x04;

/// The exact client data both sides hash: no whitespace, members in order.
pub fn client_data(transcript: &[u8]) -> Vec<u8> {
    let challenge = base64url(&Sha256::digest(transcript));
    format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\",\"origin\":\"{WEBAUTHN_RP_ID}\"}}"
    )
    .into_bytes()
}
pub fn rp_id_hash() -> [u8; 32] {
    Sha256::digest(WEBAUTHN_RP_ID.as_bytes()).into()
}
/// UP and UV set; BE, BS, AT, ED and the reserved bits clear; our RP.
pub fn valid_authenticator_data(data: &[u8]) -> bool {
    data.len() == AUTHENTICATOR_DATA_LEN && data[..32] == rp_id_hash() && data[32] == UP | UV
}
/// What the credential signed for `transcript`, if `data` is acceptable.
pub fn signed_message(transcript: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    valid_authenticator_data(data).then(|| {
        let mut message = data.to_vec();
        message.extend_from_slice(&Sha256::digest(client_data(transcript)));
        message
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The provider pins the same vector (`approval_key_class` tests).
    #[test]
    fn client_data_matches_the_provider() {
        assert_eq!(
            std::str::from_utf8(&client_data(b"abc")).unwrap(),
            "{\"type\":\"webauthn.get\",\"challenge\":\"ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0\",\"origin\":\"vaultwarden-access.approval-v2\"}"
        );
    }

    #[test]
    fn only_user_verified_device_bound_data_for_our_rp_is_accepted() {
        let mut data = rp_id_hash().to_vec();
        data.push(UP | UV);
        data.extend_from_slice(&[0, 0, 0, 9]);
        assert!(valid_authenticator_data(&data));
        assert_eq!(&signed_message(b"t", &data).unwrap()[..37], &data[..]);
        for flags in [
            UP,
            UV,
            UP | UV | 0x08,
            UP | UV | 0x10,
            UP | UV | 0x40,
            UP | UV | 0x80,
            UP | UV | 0x02,
        ] {
            data[32] = flags;
            assert!(signed_message(b"t", &data).is_none(), "{flags:#x}");
        }
        data[32] = UP | UV;
        data[0] ^= 1;
        assert!(!valid_authenticator_data(&data));
    }
}
