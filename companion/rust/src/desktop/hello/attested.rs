//! The credential a Windows Hello `MakeCredential` returns (desktop-approval
//! spec D-6): authenticator data with attested credential data whose
//! credential public key is a COSE ES256 key. Only that exact shape is
//! accepted; the key is returned as the 65-byte SEC1 point every platform
//! enrolls. A minimal CBOR reader: unsigned/negative integers and byte strings.
use crate::provider::key_class::rp_id_hash;

/// UP | UV | AT. BE, BS, ED and the reserved bits must be clear.
const CREATED: u8 = 0x45;

pub struct Credential {
    pub id: Vec<u8>,
    pub public_key: Vec<u8>,
}

enum Item<'a> {
    Int(i64),
    Bytes(&'a [u8]),
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }
    fn header(&mut self) -> Option<(u8, u64)> {
        let first = *self.take(1)?.first()?;
        let (major, info) = (first >> 5, first & 0x1f);
        let value = match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(self.take(2)?.try_into().ok()?)),
            _ => return None,
        };
        Some((major, value))
    }
    fn item(&mut self) -> Option<Item<'a>> {
        match self.header()? {
            (0, v) => Some(Item::Int(i64::try_from(v).ok()?)),
            (1, v) => Some(Item::Int(-1 - i64::try_from(v).ok()?)),
            (2, len) => self.take(usize::try_from(len).ok()?).map(Item::Bytes),
            _ => None,
        }
    }
}

/// The created credential, or `None` for anything but our RP, a user-verified
/// device-bound credential and an ES256 P-256 key.
pub fn parse(authenticator_data: &[u8]) -> Option<Credential> {
    let mut r = Reader(authenticator_data);
    if r.take(32)? != rp_id_hash() || r.take(1)?[0] != CREATED {
        return None;
    }
    r.take(4)?; // signature counter
    r.take(16)?; // AAGUID
    let length = usize::from(u16::from_be_bytes(r.take(2)?.try_into().ok()?));
    if length == 0 || length > 1023 {
        return None;
    }
    let id = r.take(length)?.to_vec();
    if r.header()? != (5, 5) {
        return None;
    }
    let (mut x, mut y, mut seen) = (None, None, 0u8);
    for _ in 0..5 {
        let Item::Int(label) = r.item()? else {
            return None;
        };
        let value = r.item()?;
        let bit = match (label, value) {
            (1, Item::Int(2)) => 1,  // kty: EC2
            (3, Item::Int(-7)) => 2, // alg: ES256
            (-1, Item::Int(1)) => 4, // crv: P-256
            (-2, Item::Bytes(b)) if b.len() == 32 => {
                x = Some(b);
                8
            }
            (-3, Item::Bytes(b)) if b.len() == 32 => {
                y = Some(b);
                16
            }
            _ => return None,
        };
        if seen & bit != 0 {
            return None;
        }
        seen |= bit;
    }
    if !r.0.is_empty() || seen != 31 {
        return None;
    }
    let mut public_key = vec![4];
    public_key.extend_from_slice(x?);
    public_key.extend_from_slice(y?);
    crate::provider::approval_v2::valid_public_key(&public_key)
        .then_some(Credential { id, public_key })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Authenticator data as Windows Hello returns it for `point`.
    pub(crate) fn created(flags: u8, credential: &[u8], point: &[u8]) -> Vec<u8> {
        let mut out = rp_id_hash().to_vec();
        out.push(flags);
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&[0x08; 16]);
        out.extend_from_slice(&(credential.len() as u16).to_be_bytes());
        out.extend_from_slice(credential);
        out.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
        out.extend_from_slice(&point[1..33]);
        out.extend_from_slice(&[0x22, 0x58, 0x20]);
        out.extend_from_slice(&point[33..65]);
        out
    }
    pub(crate) fn point() -> Vec<u8> {
        let key = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
        key.verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn a_user_verified_es256_credential_for_our_rp_is_read() {
        let credential = parse(&created(CREATED, b"credential-id", &point())).unwrap();
        assert_eq!(credential.id, b"credential-id");
        assert_eq!(credential.public_key, point());
    }

    #[test]
    fn anything_else_is_refused() {
        for flags in [0x41, 0x44, 0x4d, 0x55, 0xc5, 0x05] {
            assert!(
                parse(&created(flags, b"id", &point())).is_none(),
                "{flags:#x}"
            );
        }
        let good = created(CREATED, b"id", &point());
        let mut other_rp = good.clone();
        other_rp[0] ^= 1;
        assert!(parse(&other_rp).is_none());
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(parse(&trailing).is_none());
        assert!(parse(&good[..good.len() - 1]).is_none());
        // RS256 (alg -257) instead of ES256.
        let mut rsa = good.clone();
        let at = rsa.windows(2).position(|w| w == [0x03, 0x26]).unwrap();
        rsa.splice(at + 1..at + 2, [0x39, 0x01, 0x00]);
        assert!(parse(&rsa).is_none());
        // An off-curve point.
        let mut off = point();
        off[64] ^= 1;
        assert!(parse(&created(CREATED, b"id", &off)).is_none());
        assert!(parse(&created(CREATED, b"", &point())).is_none());
    }
}
