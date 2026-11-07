//! Production Touch ID approval v2 (issue 49): the companion side of the
//! provider's transcript contract in `src/access/approval_v2.rs`.
//!
//! Pure functions only. The companion never trusts its own copy of a value the
//! provider signs over: every transcript field comes from the provider's
//! Review response (its `approval_binding` and the review JSON exactly as
//! received) or the management `biometric_prepare` response, and is checked
//! against the TLS identities this session pinned. Separate from the synthetic
//! v1 lifecycle (`crate::lifecycle`): the three domains never mix.
use super::protocol::{decode, valid_hex, valid_id, Review, ReviewResponse};
use crate::api::biometric::BiometricRefusal;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const APPROVAL_DOMAIN: &str = "dev.vaultwarden.provider.approval.v2";
pub const ENROLL_DOMAIN: &str = "dev.vaultwarden.provider.approval-enroll.v2";
pub const APPROVE_ACTION: &str = "approve";
pub const PUBLIC_KEY_LEN: usize = 65;
pub const MIN_SIGNATURE_LEN: usize = 8;
pub const MAX_SIGNATURE_LEN: usize = 72;

/// Provider-owned signing inputs for one review ticket (version 2 review).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBinding {
    pub version: u8,
    pub domain: String,
    pub action: String,
    pub provider_identity: String,
    pub approval_client: String,
    #[serde(deserialize_with = "Option::deserialize")]
    pub key_id: Option<String>,
    pub biometric_allowed: bool,
    pub request_id: String,
    pub record_digest: String,
    pub policy_digest: String,
    pub arguments_digest: String,
    pub expires_at_unix_seconds: u64,
    pub generation: u64,
    pub ticket: String,
    pub ticket_deadline_unix_ms: u64,
    pub review_digest: String,
}

/// Version 2 Review response: version 1's members plus `approval_binding`,
/// which must be present (possibly null).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewResponseV2 {
    version: u8,
    review: Review,
    #[serde(deserialize_with = "Option::deserialize")]
    ticket: Option<String>,
    generation: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    approval_binding: Option<ApprovalBinding>,
}
#[derive(Deserialize)]
struct RawReview {
    review: serde_json::Value,
}
/// Parse a version 2 Review response: the closed typed view, plus the
/// `review` member as received (the digest input; never re-serialized).
pub fn decode_review(
    bytes: &[u8],
) -> Result<(ReviewResponse, serde_json::Value, Option<ApprovalBinding>), &'static str> {
    let typed: ReviewResponseV2 = decode(bytes)?;
    let raw: RawReview = decode(bytes)?;
    Ok((
        ReviewResponse {
            version: typed.version,
            review: typed.review,
            ticket: typed.ticket,
            generation: typed.generation,
        },
        raw.review,
        typed.approval_binding,
    ))
}

/// The TLS identities this companion pinned for the provider connection: the
/// SHA-256 of the provider leaf certificate DER and of this device's client
/// leaf certificate DER (the provider's approval-client fingerprint).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    pub provider_identity: String,
    pub approval_client: String,
}
impl Pin {
    pub fn new(provider_identity: &str, approval_client: &str) -> Option<Self> {
        (valid_hex(provider_identity) && valid_hex(approval_client)).then(|| Self {
            provider_identity: provider_identity.into(),
            approval_client: approval_client.into(),
        })
    }
}

/// A received version 2 review, as the session holds it.
pub struct ReceivedReview<'a> {
    /// The `review` member exactly as received (never re-serialized).
    pub raw_review: &'a serde_json::Value,
    pub review: &'a Review,
    pub ticket: Option<&'a str>,
    pub generation: u64,
    pub binding: Option<&'a ApprovalBinding>,
}

/// A transcript the companion may ask the Secure Enclave key to sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningTranscript {
    pub key_id: String,
    pub transcript: Vec<u8>,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
/// The 32 raw bytes a 64-lowercase-hex SHA-256 value encodes.
pub fn hex32(value: &str) -> Option<[u8; 32]> {
    if !valid_hex(value) {
        return None;
    }
    let digit = |b: u8| {
        if b.is_ascii_digit() {
            b - b'0'
        } else {
            b - b'a' + 10
        }
    };
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        *slot = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Some(out)
}
/// Key id: SHA-256 of the 65-byte uncompressed SEC1 public key, lowercase hex.
pub fn key_id(public_key: &[u8]) -> String {
    hex(&Sha256::digest(public_key))
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/// Unpadded base64url; canonical by construction.
pub fn base64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(B64URL[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}
/// Strict unpadded base64url: refuses padding, other alphabets and any
/// encoding that does not re-encode to the same text.
pub fn base64url_decode(value: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut count = 0u32;
    let mut out = Vec::with_capacity(value.len() * 3 / 4);
    for c in value.bytes() {
        let v = B64URL.iter().position(|a| *a == c)? as u32;
        bits = (bits << 6) | v;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    (base64url(&out) == value).then_some(out)
}

/// 65-byte uncompressed SEC1 point that is on the P-256 curve.
pub fn valid_public_key(public_key: &[u8]) -> bool {
    public_key.len() == PUBLIC_KEY_LEN
        && public_key[0] == 0x04
        && VerifyingKey::from_sec1_bytes(public_key).is_ok()
}
/// ASN.1 DER ECDSA P-256 signature within the provider's 8–72 byte bounds.
pub fn valid_signature(signature: &[u8]) -> bool {
    (MIN_SIGNATURE_LEN..=MAX_SIGNATURE_LEN).contains(&signature.len())
        && Signature::from_der(signature).is_ok()
}
/// ECDSA P-256 SHA-256 verification of a DER signature over `message`.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    valid_public_key(public_key)
        && valid_signature(signature)
        && VerifyingKey::from_sec1_bytes(public_key)
            .ok()
            .zip(Signature::from_der(signature).ok())
            .is_some_and(|(key, sig)| key.verify(message, &sig).is_ok())
}

/// SHA-256 over the canonical JSON of the review object as received:
/// members sorted bytewise by key, no whitespace, `serde_json` string
/// escaping, integers in shortest decimal form. A float fails closed.
pub fn review_digest(value: &serde_json::Value) -> Option<[u8; 32]> {
    let mut out = String::new();
    canonical(value, &mut out)?;
    Some(Sha256::digest(out.as_bytes()).into())
}
/// The canonical JSON text itself (exposed for the golden test).
pub fn canonical_json(value: &serde_json::Value) -> Option<String> {
    let mut out = String::new();
    canonical(value, &mut out)?;
    Some(out)
}
fn canonical(value: &serde_json::Value, out: &mut String) -> Option<()> {
    use serde_json::Value;
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => match (n.as_u64(), n.as_i64()) {
            (Some(v), _) => out.push_str(&v.to_string()),
            (None, Some(v)) => out.push_str(&v.to_string()),
            _ => return None,
        },
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

fn frame(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// The 14-field approval transcript, or the reason this review must not be
/// signed. Never consults the companion's clock: `ticket_deadline_unix_ms`
/// is the provider's wall clock and only a signed value.
pub fn approval_transcript(
    received: &ReceivedReview<'_>,
    pin: Option<&Pin>,
) -> Result<SigningTranscript, BiometricRefusal> {
    let binding = received
        .binding
        .ok_or(BiometricRefusal::BindingUnavailable)?;
    let pin = pin.ok_or(BiometricRefusal::NotPinned)?;
    let malformed = BiometricRefusal::MalformedBinding;
    if binding.version != 2
        || binding.domain != APPROVAL_DOMAIN
        || binding.action != APPROVE_ACTION
        || !valid_id(&binding.request_id)
    {
        return Err(malformed);
    }
    let provider = hex32(&binding.provider_identity).ok_or(malformed)?;
    let client = hex32(&binding.approval_client).ok_or(malformed)?;
    let record = hex32(&binding.record_digest).ok_or(malformed)?;
    let policy = hex32(&binding.policy_digest).ok_or(malformed)?;
    let arguments = hex32(&binding.arguments_digest).ok_or(malformed)?;
    let ticket = hex32(&binding.ticket).ok_or(malformed)?;
    let signed_digest = hex32(&binding.review_digest).ok_or(malformed)?;
    if binding.key_id.as_deref().is_some_and(|k| !valid_hex(k)) {
        return Err(malformed);
    }
    if binding.provider_identity != pin.provider_identity {
        return Err(BiometricRefusal::ProviderMismatch);
    }
    if binding.approval_client != pin.approval_client {
        return Err(BiometricRefusal::ApprovalClientMismatch);
    }
    if binding.request_id != received.review.id {
        return Err(BiometricRefusal::RequestMismatch);
    }
    if binding.generation != received.generation {
        return Err(BiometricRefusal::GenerationMismatch);
    }
    if received.ticket != Some(binding.ticket.as_str()) {
        return Err(BiometricRefusal::TicketMismatch);
    }
    if binding.expires_at_unix_seconds != received.review.expires_at_unix_seconds
        || binding.policy_digest != received.review.policy_digest
        || binding.arguments_digest != received.review.arguments_digest
    {
        return Err(BiometricRefusal::ReviewMismatch);
    }
    let review = review_digest(received.raw_review).ok_or(BiometricRefusal::MalformedReview)?;
    if review != signed_digest {
        return Err(BiometricRefusal::ReviewDigestMismatch);
    }
    if !binding.biometric_allowed {
        return Err(BiometricRefusal::BiometricNotAllowed);
    }
    let key_id = binding
        .key_id
        .clone()
        .ok_or(BiometricRefusal::NoEnrolledKey)?;
    let key = hex32(&key_id).ok_or(malformed)?;
    let mut out = Vec::with_capacity(512);
    for field in [
        APPROVAL_DOMAIN.as_bytes(),
        APPROVE_ACTION.as_bytes(),
        &provider,
        &client,
        &key,
        binding.request_id.as_bytes(),
        &record,
        &policy,
        &arguments,
        &binding.expires_at_unix_seconds.to_be_bytes(),
        &binding.generation.to_be_bytes(),
        &ticket,
        &binding.ticket_deadline_unix_ms.to_be_bytes(),
        &review,
    ] {
        frame(&mut out, field);
    }
    Ok(SigningTranscript {
        key_id,
        transcript: out,
    })
}

/// Enrollment proof-of-possession transcript. `None` on any malformed input.
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
    if !valid_public_key(public_key) || !valid_id(action_id) {
        return None;
    }
    let mut out = Vec::with_capacity(256);
    for field in [
        ENROLL_DOMAIN.as_bytes(),
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
