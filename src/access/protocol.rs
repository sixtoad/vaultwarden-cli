//! Closed agent submission protocol. JSON is transport; signatures cover semantic bytes.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::{Deserialize, Serialize};

use super::{MAX_ARG_LEN, MAX_ARGS, PROTOCOL_VERSION, decode_public_key, hex_sha256};

pub const MAX_REQUEST_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_FRAME_BYTES: usize = 1024;
const SIGNING_DOMAIN: &[u8] = b"vaultwarden-access\0";
const REPLAY_DOMAIN: &[u8] = b"vaultwarden-access-replay\0";
const ENCODING_VERSION: u8 = 1;

/// Untrusted selector and signed operation input. No identity or authority is supplied here.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedSubmission {
    pub protocol_version: u8,
    pub purpose: String,
    pub binding_id: String,
    pub nonce: String,
    pub operation_id: String,
    pub expected_policy_revision: String,
    pub args: Vec<String>,
    pub signature: String,
}

impl SignedSubmission {
    /// Caller must check kernel peer eligibility before invoking this parser.
    /// Framing (exactly one LF followed by EOF) is enforced by the transport.
    pub fn parse(bytes: &[u8]) -> Result<Self, AgentRejection> {
        if bytes.len() > MAX_REQUEST_FRAME_BYTES {
            return Err(AgentRejection::Malformed);
        }
        let envelope: Self =
            serde_json::from_slice(bytes).map_err(|_error| AgentRejection::Malformed)?;
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn sign(
        binding_id: String,
        nonce: [u8; 32],
        operation_id: String,
        expected_policy_revision: String,
        args: Vec<String>,
        signing_key: &SigningKey,
    ) -> Result<Self, AgentRejection> {
        let mut envelope = Self {
            protocol_version: PROTOCOL_VERSION,
            purpose: "submit".into(),
            binding_id,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            operation_id,
            expected_policy_revision,
            args,
            signature: URL_SAFE_NO_PAD.encode([0u8; 64]),
        };
        envelope.signature =
            URL_SAFE_NO_PAD.encode(signing_key.sign(&envelope.signing_bytes()?).to_bytes());
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<(), AgentRejection> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(AgentRejection::UnsupportedVersion);
        }
        if self.purpose != "submit"
            || !super::valid_operation_id(&self.operation_id)
            || !super::valid_sha256(&self.expected_policy_revision)
            || self.args.len() > MAX_ARGS
            || self
                .args
                .iter()
                .any(|arg| arg.len() > MAX_ARG_LEN || arg.contains('\0'))
        {
            return Err(AgentRejection::Malformed);
        }
        decode_fixed::<32>(&self.binding_id)?;
        decode_fixed::<32>(&self.nonce)?;
        decode_fixed::<64>(&self.signature)?;
        Ok(())
    }

    /// Domain including NUL, u8 encoding version, u8 protocol version; then u32
    /// big-endian byte lengths + purpose, binding bytes, nonce bytes, operation,
    /// revision bytes; finally u32 argument count and length-prefixed UTF-8 args.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, AgentRejection> {
        self.validate()?;
        let mut bytes = SIGNING_DOMAIN.to_vec();
        bytes.extend([ENCODING_VERSION, self.protocol_version]);
        append_field(&mut bytes, self.purpose.as_bytes());
        append_field(&mut bytes, &decode_fixed::<32>(&self.binding_id)?);
        append_field(&mut bytes, &decode_fixed::<32>(&self.nonce)?);
        append_field(&mut bytes, self.operation_id.as_bytes());
        let revision: Vec<u8> = self
            .expected_policy_revision
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect();
        append_field(&mut bytes, &revision);
        bytes.extend((self.args.len() as u32).to_be_bytes());
        for arg in &self.args {
            append_field(&mut bytes, arg.as_bytes());
        }
        Ok(bytes)
    }

    /// Only pass the current provider-owned binding key, never caller key material.
    pub fn verify(&self, stored_public_key: &str) -> Result<(), AgentRejection> {
        let bytes = self.signing_bytes()?;
        let key =
            decode_public_key(stored_public_key).map_err(|_error| AgentRejection::Unauthorized)?;
        let signature = Signature::from_bytes(&decode_fixed::<64>(&self.signature)?);
        key.verify_strict(&bytes, &signature)
            .map_err(|_error| AgentRejection::Unauthorized)
    }

    /// Durable binding-scoped replay marker, independent of operation or session.
    pub fn replay_digest(&self) -> Result<String, AgentRejection> {
        self.validate()?;
        let mut bytes = REPLAY_DOMAIN.to_vec();
        bytes.push(ENCODING_VERSION);
        append_field(&mut bytes, &decode_fixed::<32>(&self.binding_id)?);
        append_field(&mut bytes, &decode_fixed::<32>(&self.nonce)?);
        Ok(hex_sha256(&bytes))
    }
}

fn hex_nibble(byte: u8) -> u8 {
    if byte.is_ascii_digit() {
        byte - b'0'
    } else {
        byte - b'a' + 10
    }
}

fn append_field(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend((value.len() as u32).to_be_bytes());
    bytes.extend(value);
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], AgentRejection> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_error| AgentRejection::Malformed)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(AgentRejection::Malformed);
    }
    bytes.try_into().map_err(|_error| AgentRejection::Malformed)
}

/// Closed redacted categories, never arbitrary backend errors or reflected input.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum AgentRejection {
    #[error("unauthorized")]
    Unauthorized,
    #[error("malformed")]
    Malformed,
    #[error("unsupported_version")]
    UnsupportedVersion,
    #[error("replay")]
    Replay,
    #[error("stale_revision")]
    StaleRevision,
    #[error("invalid_arguments")]
    InvalidArguments,
    #[error("locked")]
    Locked,
    #[error("busy")]
    Busy,
    #[error("unavailable")]
    Unavailable,
}

/// Commit acknowledgment only; no review URL, polling state or execution output.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentResponse {
    Pending {
        protocol_version: u8,
        request_id: String,
    },
    Rejected {
        protocol_version: u8,
        category: AgentRejection,
    },
}

impl AgentResponse {
    pub fn pending(request_id: String) -> Self {
        Self::Pending {
            protocol_version: PROTOCOL_VERSION,
            request_id,
        }
    }

    pub fn rejected(category: AgentRejection) -> Self {
        Self::Rejected {
            protocol_version: PROTOCOL_VERSION,
            category,
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, AgentRejection> {
        if bytes.len() > MAX_RESPONSE_FRAME_BYTES {
            return Err(AgentRejection::Malformed);
        }
        let response: Self =
            serde_json::from_slice(bytes).map_err(|_error| AgentRejection::Malformed)?;
        match &response {
            Self::Pending {
                protocol_version,
                request_id,
            } => {
                if *protocol_version != PROTOCOL_VERSION
                    || !super::direct_request::valid_request_id(request_id)
                {
                    return Err(AgentRejection::Malformed);
                }
            }
            Self::Rejected {
                protocol_version, ..
            } => {
                if *protocol_version != PROTOCOL_VERSION {
                    return Err(AgentRejection::Malformed);
                }
            }
        }
        Ok(response)
    }
}
