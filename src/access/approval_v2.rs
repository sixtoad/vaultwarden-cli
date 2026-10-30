//! Production biometric (Touch ID) approval contract, version 2.
//!
//! Pure transcript construction only: no key storage and no signature
//! primitive. Verification is an adapter behind
//! [`super::ports::BiometricApprovalVerifier`].
//!
//! Transcript framing: every field is a 4-byte big-endian length followed by
//! its bytes, in a fixed order. Encodings are fixed per field kind:
//! - ASCII/UTF-8 strings (domains, action, request id, action id): their bytes;
//! - SHA-256 values (provider identity, approval-client fingerprint, key id,
//!   record/policy/arguments digests, review digest, tickets): the 32 raw bytes
//!   that the lowercase-hex wire value encodes;
//! - integers: unsigned 64-bit big-endian (8 bytes);
//! - the public key: the 65-byte uncompressed SEC1 P-256 point.
use super::direct_request::{ApprovalBinding, DirectReview};
use sha2::{Digest, Sha256};

/// Approval transcript domain. Never shared with enrollment or synthetic tests.
pub const APPROVAL_DOMAIN: &[u8] = b"dev.vaultwarden.provider.approval.v2";
/// Proof-of-possession domain for online enrollment.
pub const ENROLL_DOMAIN: &[u8] = b"dev.vaultwarden.provider.approval-enroll.v2";
/// Only approval is signed; denial stays unsigned and needs no proof.
pub const APPROVE_ACTION: &[u8] = b"approve";
pub const PUBLIC_KEY_LEN: usize = 65;
/// Upper bound of an ASN.1 DER ECDSA P-256 signature.
pub const MAX_SIGNATURE_LEN: usize = 72;
/// Smallest syntactically possible DER ECDSA signature (two one-byte integers).
pub const MIN_SIGNATURE_LEN: usize = 8;

/// Values the provider owns for one companion ticket. Never companion-supplied.
pub(crate) struct ApprovalContext<'a> {
    /// SHA-256 of the provider's TLS leaf certificate DER (the companion's pin).
    pub provider_identity: &'a str,
    /// SHA-256 of the approval client's mTLS leaf certificate DER.
    pub approval_client: &'a str,
    pub ticket: &'a str,
    pub ticket_deadline_unix_ms: u64,
    pub review: &'a DirectReview,
}

/// A companion-supplied biometric proof. Values are parsed, not trusted.
pub struct BiometricProof {
    pub key_id: String,
    pub signature: Vec<u8>,
}
/// The device's currently enrolled key as recorded by the provider.
pub struct EnrolledKey {
    pub key_id: String,
    pub public_key: Vec<u8>,
}

pub(crate) fn hex32(value: &str) -> Option<[u8; 32]> {
    if !super::valid_sha256(value) {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        out[index] = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(out)
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
/// Key id: SHA-256 of the 65-byte uncompressed SEC1 public key, lowercase hex.
pub fn key_id(public_key: &[u8]) -> String {
    hex(&Sha256::digest(public_key))
}
/// Shape check only; the verifier additionally proves the point is on-curve.
pub fn valid_public_key(public_key: &[u8]) -> bool {
    public_key.len() == PUBLIC_KEY_LEN && public_key[0] == 0x04
}
pub fn valid_signature_len(signature: &[u8]) -> bool {
    (MIN_SIGNATURE_LEN..=MAX_SIGNATURE_LEN).contains(&signature.len())
}

fn frame(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// SHA-256 over the canonical JSON of the review object exactly as the
/// provider serializes it into the `review` member of a Review response.
///
/// Canonical JSON (RFC 8785 subset, sufficient for this closed schema): object
/// members sorted by key (byte order; every key is ASCII), no insignificant
/// whitespace, strings escaped as `serde_json` does (`\"`, `\\`, `\b`, `\f`,
/// `\n`, `\r`, `\t`, other controls as lowercase `\u00xx`, everything else
/// literal UTF-8), integers in shortest decimal form. Floats never occur;
/// encountering one fails closed.
pub fn review_digest(review: &DirectReview) -> Option<[u8; 32]> {
    let value = serde_json::to_value(review).ok()?;
    review_digest_value(&value)
}
pub fn review_digest_value(value: &serde_json::Value) -> Option<[u8; 32]> {
    let mut out = String::new();
    canonical(value, &mut out)?;
    Some(Sha256::digest(out.as_bytes()).into())
}
fn canonical(value: &serde_json::Value, out: &mut String) -> Option<()> {
    use serde_json::Value;
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(v) = n.as_u64() {
                out.push_str(&v.to_string());
            } else if let Some(v) = n.as_i64() {
                out.push_str(&v.to_string());
            } else {
                return None;
            }
        }
        Value::String(s) => out.push_str(&serde_json::to_string(s).ok()?),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).ok()?);
                out.push(':');
                canonical(&map[key], out)?;
            }
            out.push('}');
        }
    }
    Some(())
}

/// The 14-field approval transcript. `None` when any provider-owned value is
/// malformed (never silently encoded).
pub(crate) fn approval_transcript(
    context: &ApprovalContext<'_>,
    binding: &ApprovalBinding,
    generation: u64,
    key_id: &str,
) -> Option<Vec<u8>> {
    let provider = hex32(context.provider_identity)?;
    let client = hex32(context.approval_client)?;
    let key = hex32(key_id)?;
    let record = hex32(&binding.record_digest)?;
    let policy = hex32(&binding.policy_digest)?;
    let arguments = hex32(&binding.arguments_digest)?;
    let ticket = hex32(context.ticket)?;
    let review = review_digest(context.review)?;
    if !super::direct_request::valid_request_id(&binding.request_id)
        || context.review.id != binding.request_id
    {
        return None;
    }
    let mut out = Vec::with_capacity(512);
    for field in [
        APPROVAL_DOMAIN,
        APPROVE_ACTION,
        &provider,
        &client,
        &key,
        binding.request_id.as_bytes(),
        &record,
        &policy,
        &arguments,
        &binding.expires_at_unix_seconds.to_be_bytes(),
        &generation.to_be_bytes(),
        &ticket,
        &context.ticket_deadline_unix_ms.to_be_bytes(),
        &review,
    ] {
        frame(&mut out, field);
    }
    Some(out)
}

/// Enrollment proof-of-possession transcript.
pub fn enroll_transcript(
    provider_identity: &str,
    approval_client: &str,
    public_key: &[u8],
    ticket: &str,
    action_id: &str,
) -> Option<Vec<u8>> {
    let provider = hex32(provider_identity)?;
    let client = hex32(approval_client)?;
    let ticket = hex32(ticket)?;
    if !valid_public_key(public_key) || !super::direct_request::valid_request_id(action_id) {
        return None;
    }
    let mut out = Vec::with_capacity(256);
    for field in [
        ENROLL_DOMAIN,
        &provider,
        &client,
        public_key,
        &ticket,
        action_id.as_bytes(),
    ] {
        frame(&mut out, field);
    }
    Some(out)
}
