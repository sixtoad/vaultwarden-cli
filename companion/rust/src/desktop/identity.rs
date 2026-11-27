//! The client mTLS identity of the desktop transport (desktop-approval-spec
//! D-3): imported once from a development PKCS#12; the PKCS#12 bytes and the
//! passphrase are dropped right after. Only the PKCS#8 key and the
//! certificate chain are kept, at rest under `super::protect`.
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const MAX_PKCS12: usize = 1_048_576;
pub const MAX_CA: usize = 65_536;

pub struct ClientIdentity {
    /// PKCS#8 `PrivateKeyInfo` DER.
    pub key: Zeroizing<Vec<u8>>,
    /// Leaf first.
    pub chain: Vec<Vec<u8>>,
}
impl ClientIdentity {
    /// The approval-client fingerprint: SHA-256 of the leaf DER.
    pub fn fingerprint(&self) -> String {
        hex(&Sha256::digest(&self.chain[0]))
    }
    /// Exactly one private key with its certificate chain; anything else
    /// (no key, several keys, no certificate, a wrong passphrase) is refused.
    pub fn from_pkcs12(bytes: &[u8], passphrase: &str) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > MAX_PKCS12 || passphrase.len() > 4096 {
            return None;
        }
        let store = p12_keystore::KeyStore::from_pkcs12(
            bytes,
            passphrase,
            p12_keystore::Pkcs12ImportPolicy::Strict,
        )
        .ok()?;
        let chains: Vec<_> = store
            .entries()
            .filter_map(|(_, entry)| match entry {
                p12_keystore::KeyStoreEntry::PrivateKeyChain(chain) => Some(chain),
                _ => None,
            })
            .collect();
        let [chain] = chains.as_slice() else {
            return None;
        };
        let certificates: Vec<Vec<u8>> =
            chain.certs().iter().map(|c| c.as_der().to_vec()).collect();
        if certificates.is_empty() || certificates.len() > 8 {
            return None;
        }
        Some(Self {
            key: Zeroizing::new(chain.key().as_der().to_vec()),
            chain: certificates,
        })
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            let pair = text.get(i..i + 2)?;
            if !pair.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                return None;
            }
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const P3DES: &[u8] = include_bytes!("../../tests/fixtures/client-3des.p12");
    const PAES: &[u8] = include_bytes!("../../tests/fixtures/client-aes.p12");
    const PASS: &str = "synthetic-p12-passphrase";

    fn leaf_fingerprint() -> String {
        let pem = include_str!("../../../../tests/companion-tls/client.pem");
        let der = rustls::pki_types::pem::PemObject::from_pem_slice(pem.as_bytes())
            .map(|c: rustls::pki_types::CertificateDer<'static>| c.to_vec())
            .unwrap();
        hex(&Sha256::digest(der))
    }

    #[test]
    fn imports_the_provider_setup_format_and_openssl_defaults() {
        for bytes in [P3DES, PAES] {
            let identity = ClientIdentity::from_pkcs12(bytes, PASS).unwrap();
            assert_eq!(identity.fingerprint(), leaf_fingerprint());
            assert!(!identity.key.is_empty());
        }
        // The 3DES bundle carries the CA after the leaf.
        assert_eq!(
            ClientIdentity::from_pkcs12(P3DES, PASS)
                .unwrap()
                .chain
                .len(),
            2
        );
    }

    #[test]
    fn refuses_wrong_passphrases_and_damaged_or_oversized_bundles() {
        assert!(ClientIdentity::from_pkcs12(P3DES, "wrong").is_none());
        assert!(ClientIdentity::from_pkcs12(P3DES, "").is_none());
        let mut damaged = P3DES.to_vec();
        let middle = damaged.len() / 2;
        damaged[middle] ^= 0xff;
        assert!(ClientIdentity::from_pkcs12(&damaged, PASS).is_none());
        assert!(ClientIdentity::from_pkcs12(&[], PASS).is_none());
        assert!(ClientIdentity::from_pkcs12(&vec![0; MAX_PKCS12 + 1], PASS).is_none());
    }

    #[test]
    fn hex_round_trips_and_refuses_uppercase_or_odd_input() {
        assert_eq!(
            unhex(&hex(&[0, 1, 0xab, 0xff])).unwrap(),
            vec![0, 1, 0xab, 0xff]
        );
        for bad in ["A0", "0", "zz", "0g"] {
            assert!(unhex(bad).is_none(), "{bad}");
        }
    }
}
