//! Transcript, key derivation, proofs and the comparison code.
//!
//! Only vetted primitives: HKDF-SHA256 (RFC 5869) derives per-invitation,
//! per-purpose keys from the 256-bit invitation secret; HMAC-SHA256 proves
//! knowledge of it; SHA-256 hashes the length-prefixed transcript. Agent keys
//! sign with Ed25519. There is no key agreement: the secret is delivered out
//! of band and every channel already authenticates its peer (kernel
//! credentials or mTLS), so the secret only binds the two humans' intent.

use super::{Channel, EnrolleeKind, JoinerCancelReason};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"vaultwarden-access/enroll/v1\0";
pub(crate) const JOIN: &str = "join";
pub(crate) const PROVIDER: &str = "provider";
pub(crate) const CONTROL: &str = "control";
const CODE: &str = "comparison-code";
pub(crate) const CONFIRM: &str = "confirm";
pub(crate) const STATUS: &str = "status";
/// The cancel action names its reason, so the reason is covered by the MAC.
pub(crate) fn cancel_action(reason: JoinerCancelReason) -> &'static str {
    match reason {
        JoinerCancelReason::Cancelled => "cancel/cancelled",
        JoinerCancelReason::CodeMismatch => "cancel/code_mismatch",
    }
}
/// Ed25519 proof that the agent holds the key it joined with.
pub(crate) const POSSESSION: &str = "possession";

fn field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend((value.len() as u32).to_be_bytes());
    out.extend(value);
}

fn channel_tag(channel: Channel) -> &'static [u8] {
    match channel {
        Channel::AgentSocket => b"agent-socket",
        Channel::CompanionMtls => b"companion-mtls",
    }
}

/// What the joiner proves before it learns anything about the invitation.
pub(crate) fn join_transcript(
    channel: Channel,
    invitation_id: &[u8; 32],
    joiner_identity: &[u8],
    joiner_nonce: &[u8; 32],
    provider_identity: &[u8],
) -> Vec<u8> {
    let mut out = DOMAIN.to_vec();
    field(&mut out, channel_tag(channel));
    field(&mut out, invitation_id);
    field(&mut out, joiner_identity);
    field(&mut out, joiner_nonce);
    field(&mut out, provider_identity);
    out
}

/// The join transcript plus what the provider adds: the role and its nonce.
pub(crate) fn full_transcript(
    join: &[u8],
    kind: &EnrolleeKind,
    provider_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut out = join.to_vec();
    match kind {
        EnrolleeKind::Agent { label, uid, gid } => {
            field(&mut out, b"agent");
            field(&mut out, label.as_bytes());
            field(&mut out, &uid.to_be_bytes());
            field(&mut out, &gid.to_be_bytes());
        }
        EnrolleeKind::Companion { label } => {
            field(&mut out, b"companion");
            field(&mut out, label.as_bytes());
        }
    }
    field(&mut out, provider_nonce);
    out
}

pub(crate) fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn key(secret: &[u8; 32], invitation_id: &[u8; 32], purpose: &str) -> Zeroizing<[u8; 32]> {
    let mut info = DOMAIN.to_vec();
    info.extend(purpose.as_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(Some(invitation_id), secret)
        .expand(&info, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

fn hmac(key: &[u8; 32]) -> Hmac<Sha256> {
    <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length")
}

pub(crate) fn mac(
    secret: &[u8; 32],
    invitation_id: &[u8; 32],
    purpose: &str,
    message: &[u8],
) -> [u8; 32] {
    let mut mac = hmac(&key(secret, invitation_id, purpose));
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Constant-time comparison through the HMAC implementation.
pub(crate) fn verify_mac(
    secret: &[u8; 32],
    invitation_id: &[u8; 32],
    purpose: &str,
    message: &[u8],
    tag: &[u8],
) -> bool {
    let mut mac = hmac(&key(secret, invitation_id, purpose));
    mac.update(message);
    mac.verify_slice(tag).is_ok()
}

/// A post-join control message: the action bound to the session transcript.
pub(crate) fn control_message(action: &str, transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = DOMAIN.to_vec();
    field(&mut out, action.as_bytes());
    field(&mut out, transcript_hash);
    out
}

/// Eight decimal digits, `1234-5678`, derived from the secret and the whole
/// transcript. A substituted key, nonce, role, channel or provider changes it.
pub(crate) fn comparison_code(
    secret: &[u8; 32],
    invitation_id: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> String {
    let mut info = DOMAIN.to_vec();
    info.extend(CODE.as_bytes());
    info.extend(invitation_id);
    let mut okm = Zeroizing::new([0u8; 8]);
    hkdf::Hkdf::<Sha256>::new(Some(transcript_hash), secret)
        .expand(&info, okm.as_mut())
        .expect("8 bytes is a valid HKDF-SHA256 output length");
    // 2^64 mod 10^8 bias is below 2^-37: negligible.
    let value = u64::from_be_bytes(*okm) % 100_000_000;
    format!("{:04}-{:04}", value / 10_000, value % 10_000)
}

/// Accept `12345678`, `1234-5678` or `1234 5678`; anything else is no code.
pub(crate) fn normalize_code(input: &str) -> Option<String> {
    let digits: String = input.chars().filter(|c| !matches!(c, '-' | ' ')).collect();
    (digits.len() == 8 && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| format!("{}-{}", &digits[..4], &digits[4..]))
}

/// Code equality without early exit, over fixed-size digests.
pub(crate) fn codes_equal(left: &str, right: &str) -> bool {
    let (left, right) = (hash(left.as_bytes()), hash(right.as_bytes()));
    left.iter()
        .zip(right.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}
