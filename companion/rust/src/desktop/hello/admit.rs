//! The native second line of defence, identical to `ProductionTranscript.admits`
//! (macOS) and `ApprovalTranscript.admits` (Android): the key signs only a
//! well-formed v2 transcript bound to its own provider, client and key.
use crate::provider::approval_v2::{hex32, APPROVAL_DOMAIN, ENROLL_DOMAIN};
use sha2::{Digest, Sha256};

pub const MAX_TRANSCRIPT: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Approve,
    Enroll,
}
impl Purpose {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "approve" => Some(Self::Approve),
            "enroll" => Some(Self::Enroll),
            _ => None,
        }
    }
}

/// One key per (provider identity, approval client), both SHA-256 pins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub provider_identity: [u8; 32],
    pub approval_client: [u8; 32],
}
impl Binding {
    pub fn parse(provider_identity: &str, approval_client: &str) -> Option<Self> {
        Some(Self {
            provider_identity: hex32(provider_identity)?,
            approval_client: hex32(approval_client)?,
        })
    }
    /// The macOS key tag suffix and the Android alias suffix.
    pub fn alias(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(self.provider_identity);
        hash.update(self.approval_client);
        crate::provider::approval_v2::hex(&hash.finalize())
    }
}

/// Splits 4-byte big-endian length framing; `None` on short or trailing bytes.
pub fn fields(data: &[u8]) -> Option<Vec<&[u8]>> {
    let mut fields = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let (length, tail) = rest.split_first_chunk::<4>()?;
        let length = u32::from_be_bytes(*length) as usize;
        if length > tail.len() || fields.len() >= 32 {
            return None;
        }
        let (field, tail) = tail.split_at(length);
        fields.push(field);
        rest = tail;
    }
    Some(fields)
}

/// Whether the key bound to `binding`, whose point is `public_key`, may sign.
pub fn admits(transcript: &[u8], purpose: Purpose, binding: &Binding, public_key: &[u8]) -> bool {
    if transcript.len() > MAX_TRANSCRIPT || public_key.len() != 65 || public_key[0] != 0x04 {
        return false;
    }
    let Some(f) = fields(transcript) else {
        return false;
    };
    match purpose {
        Purpose::Approve => {
            // record, policy, arguments, expiry, generation, ticket, deadline, review
            const SIZES: [usize; 8] = [32, 32, 32, 8, 8, 32, 8, 32];
            f.len() == 14
                && f[0] == APPROVAL_DOMAIN.as_bytes()
                && f[1] == b"approve"
                && f[2] == binding.provider_identity
                && f[3] == binding.approval_client
                && f[4] == &Sha256::digest(public_key)[..]
                && f[5].len() == 43
                && SIZES
                    .iter()
                    .enumerate()
                    .all(|(i, size)| f[6 + i].len() == *size)
        }
        Purpose::Enroll => {
            f.len() == 6
                && f[0] == ENROLL_DOMAIN.as_bytes()
                && f[1] == binding.provider_identity
                && f[2] == binding.approval_client
                && f[3] == public_key
                && f[4].len() == 32
                && f[5].len() == 43
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(fields: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for field in fields {
            out.extend_from_slice(&(field.len() as u32).to_be_bytes());
            out.extend_from_slice(field);
        }
        out
    }
    fn binding() -> Binding {
        Binding::parse(&"1f".repeat(32), &"2e".repeat(32)).unwrap()
    }
    fn key() -> Vec<u8> {
        let mut key = vec![4];
        key.extend_from_slice(&[9; 64]);
        key
    }
    fn approve(edit: impl FnOnce(&mut Vec<Vec<u8>>)) -> Vec<u8> {
        let b = binding();
        let mut f: Vec<Vec<u8>> = vec![
            APPROVAL_DOMAIN.as_bytes().to_vec(),
            b"approve".to_vec(),
            b.provider_identity.to_vec(),
            b.approval_client.to_vec(),
            Sha256::digest(key()).to_vec(),
            vec![b'A'; 43],
            vec![1; 32],
            vec![2; 32],
            vec![3; 32],
            vec![0; 8],
            vec![0; 8],
            vec![4; 32],
            vec![0; 8],
            vec![5; 32],
        ];
        edit(&mut f);
        frame(&f.iter().map(Vec::as_slice).collect::<Vec<_>>())
    }

    #[test]
    fn only_a_well_formed_transcript_for_this_key_is_admitted() {
        assert!(admits(
            &approve(|_| {}),
            Purpose::Approve,
            &binding(),
            &key()
        ));
        assert!(!admits(
            &approve(|_| {}),
            Purpose::Enroll,
            &binding(),
            &key()
        ));
        let edits: [fn(&mut Vec<Vec<u8>>); 8] = [
            |f| f[0] = b"dev.vaultwarden.companion.synthetic.v1".to_vec(),
            |f| f[1] = b"deny".to_vec(),
            |f| f[2][0] ^= 1,
            |f| f[3][0] ^= 1,
            |f| f[4][0] ^= 1,
            |f| f[5].pop().map(drop).unwrap_or(()),
            |f| f[13].push(0),
            |f| f.push(Vec::new()),
        ];
        for edit in edits {
            assert!(!admits(
                &approve(edit),
                Purpose::Approve,
                &binding(),
                &key()
            ));
        }
        let mut trailing = approve(|_| {});
        trailing.push(0);
        assert!(!admits(&trailing, Purpose::Approve, &binding(), &key()));
        let mut other_key = key();
        other_key[1] = 0;
        assert!(!admits(
            &approve(|_| {}),
            Purpose::Approve,
            &binding(),
            &other_key
        ));
    }

    #[test]
    fn enrollment_transcripts_name_this_binding_and_key() {
        let b = binding();
        let good = frame(&[
            ENROLL_DOMAIN.as_bytes(),
            &b.provider_identity,
            &b.approval_client,
            &key(),
            &[7; 32],
            &[b'B'; 43],
        ]);
        assert!(admits(&good, Purpose::Enroll, &b, &key()));
        let mut other = key();
        other[2] = 1;
        assert!(!admits(&good, Purpose::Enroll, &b, &other));
        assert!(!admits(&good, Purpose::Approve, &b, &key()));
        assert_eq!(b.alias().len(), 64);
        assert!(Binding::parse("AB", &"2e".repeat(32)).is_none());
    }
}
