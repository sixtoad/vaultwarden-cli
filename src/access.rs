//! Types and invariants for the human-approved access protocol.
//!
//! This module deliberately contains no Vaultwarden lookup or secret value.
//! An untrusted client may create an [`AccessRequest`], but it can select only
//! a named operation.  The provider owns the operation definition, secret
//! selection, approval UI, and process which receives injected environment
//! variables.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_OPERATION_ID_LEN: usize = 64;
pub const MAX_AGENT_ID_LEN: usize = 128;
pub const MAX_ARGS: usize = 64;
pub const MAX_ARG_LEN: usize = 4096;

/// An opaque, randomly generated request identifier. It contains no credential
/// name, operation arguments, or user information.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RequestId(String);

impl RequestId {
    pub fn new_random() -> Result<Self> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|err| anyhow::anyhow!("could not generate access request ID: {err}"))?;
        Ok(Self(URL_SAFE_NO_PAD.encode(bytes)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A request sent by an agent to the local human-controlled provider.
///
/// There is intentionally no `secret`, `field`, `environment`, or arbitrary
/// command field: only the provider's policy can choose secrets and commands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AccessRequest {
    pub protocol_version: u8,
    pub id: RequestId,
    pub agent_id: String,
    pub operation_id: String,
    pub operation_revision: String,
    pub args: Vec<String>,
    pub created_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

impl AccessRequest {
    pub fn new(
        agent_id: impl Into<String>,
        operation_id: impl Into<String>,
        operation_revision: impl Into<String>,
        args: Vec<String>,
        lifetime_seconds: u64,
    ) -> Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_secs();
        Self::new_at(
            agent_id,
            operation_id,
            operation_revision,
            args,
            now,
            lifetime_seconds,
        )
    }

    pub fn new_at(
        agent_id: impl Into<String>,
        operation_id: impl Into<String>,
        operation_revision: impl Into<String>,
        args: Vec<String>,
        created_at_unix_seconds: u64,
        lifetime_seconds: u64,
    ) -> Result<Self> {
        let request = Self {
            protocol_version: PROTOCOL_VERSION,
            id: RequestId::new_random()?,
            agent_id: agent_id.into(),
            operation_id: operation_id.into(),
            operation_revision: operation_revision.into(),
            args,
            created_at_unix_seconds,
            expires_at_unix_seconds: created_at_unix_seconds
                .checked_add(lifetime_seconds)
                .context("access request expiration overflowed")?,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            bail!("unsupported access protocol version")
        }
        if !valid_agent_id(&self.agent_id) {
            bail!("agent ID must be 1-128 printable non-whitespace characters")
        }
        if !valid_operation_id(&self.operation_id) {
            bail!("operation ID must use lowercase letters, digits, and hyphens")
        }
        if self.operation_revision.len() != 64
            || !self.operation_revision.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("operation revision must be a SHA-256 hex digest")
        }
        if self.args.len() > MAX_ARGS {
            bail!("access request has too many arguments")
        }
        if self
            .args
            .iter()
            .any(|arg| arg.len() > MAX_ARG_LEN || arg.contains('\0'))
        {
            bail!("access request arguments contain an invalid value")
        }
        if self.expires_at_unix_seconds <= self.created_at_unix_seconds {
            bail!("access request expiry must be after its creation time")
        }
        Ok(())
    }

    pub fn is_expired_at(&self, now_unix_seconds: u64) -> bool {
        now_unix_seconds >= self.expires_at_unix_seconds
    }

    /// The approval UI must show this digest. It binds the one-time decision to
    /// the exact paired agent, operation-policy revision, and supplied args.
    pub fn approval_digest(&self) -> String {
        #[derive(Serialize)]
        struct ApprovalBinding<'a> {
            protocol_version: u8,
            request_id: &'a RequestId,
            agent_id: &'a str,
            operation_id: &'a str,
            operation_revision: &'a str,
            args: &'a [String],
            expires_at_unix_seconds: u64,
        }

        let encoded = serde_json::to_vec(&ApprovalBinding {
            protocol_version: self.protocol_version,
            request_id: &self.id,
            agent_id: &self.agent_id,
            operation_id: &self.operation_id,
            operation_revision: &self.operation_revision,
            args: &self.args,
            expires_at_unix_seconds: self.expires_at_unix_seconds,
        })
        .expect("approval binding serialization cannot fail");
        hex_sha256(&encoded)
    }

    fn signing_payload(&self) -> Vec<u8> {
        // This is separate from the approval digest so the protocol can evolve
        // the human-facing digest without invalidating the signed wire format.
        serde_json::to_vec(self).expect("access request serialization cannot fail")
    }
}

/// A request authenticated by a paired agent's Ed25519 key. The daemon must
/// verify it against the public key stored in its human-owned pairing policy
/// before showing an approval prompt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SignedAccessRequest {
    pub request: AccessRequest,
    pub signature: String,
}

impl SignedAccessRequest {
    pub fn sign(request: AccessRequest, signing_key: &SigningKey) -> Self {
        let signature = signing_key.sign(&request.signing_payload());
        Self {
            request,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }
    }

    pub fn verify(&self, public_key: &VerifyingKey) -> Result<()> {
        self.request.validate()?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .context("access request signature is not valid base64url")?;
        let signature =
            Signature::from_slice(&bytes).context("access request signature is invalid")?;
        public_key
            .verify(&self.request.signing_payload(), &signature)
            .context("access request signature verification failed")
    }
}

pub fn encode_public_key(public_key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(public_key.as_bytes())
}

pub fn decode_public_key(encoded: &str) -> Result<VerifyingKey> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("agent public key is not valid base64url")?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("agent public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&key_bytes).context("agent public key is invalid")
}

/// The only terminal outcomes an agent may observe. The approved variant does
/// not contain a bearer token or secret material; it merely tells the agent
/// that the provider has started the protected operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RequestStatus {
    Pending,
    Approved { approval_digest: String },
    Denied,
    Expired,
    Completed { exit_code: i32 },
    Failed { message: String },
}

fn valid_agent_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AGENT_ID_LEN
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_operation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_OPERATION_ID_LEN
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (byte == b'-' && index != 0 && index + 1 != value.len())
        })
}

fn hex_sha256(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const REVISION: &str = "a3c4d2f1e9b07a5c83d4f1e8a2b7c6d5e4f3102948a7b6c5d4e3f29180a9b7c6";

    #[test]
    fn request_digest_binds_agent_operation_revision_and_args() {
        let base = AccessRequest::new_at(
            "codex-day-to-day",
            "deploy-homelab",
            REVISION,
            vec!["--dry-run".to_string()],
            100,
            60,
        )
        .unwrap();
        let mut changed = base.clone();
        changed.args.push("--production".to_string());

        assert_ne!(base.approval_digest(), changed.approval_digest());
    }

    #[test]
    fn rejects_arbitrary_command_shaped_operation_id() {
        let result = AccessRequest::new_at(
            "codex-day-to-day",
            "deploy; curl attacker",
            REVISION,
            Vec::new(),
            100,
            60,
        );

        assert!(result.is_err());
    }

    #[test]
    fn rejects_expired_or_nul_containing_requests() {
        let mut request = AccessRequest::new_at(
            "codex-day-to-day",
            "deploy-homelab",
            REVISION,
            Vec::new(),
            100,
            60,
        )
        .unwrap();
        request.args.push("ok\0not-ok".to_string());
        assert!(request.validate().is_err());
        assert!(request.is_expired_at(160));
    }

    #[test]
    fn signed_request_rejects_tampering() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let request = AccessRequest::new_at(
            "codex-day-to-day",
            "deploy-homelab",
            REVISION,
            Vec::new(),
            100,
            60,
        )
        .unwrap();
        let mut signed = SignedAccessRequest::sign(request, &key);
        signed.request.operation_id = "other-operation".to_string();

        assert!(signed.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn public_key_round_trip_preserves_verification_key() {
        let key = SigningKey::from_bytes(&[8; 32]).verifying_key();
        assert_eq!(decode_public_key(&encode_public_key(&key)).unwrap(), key);
    }
}
