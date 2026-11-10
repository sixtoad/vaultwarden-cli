//! Joining-endpoint half of the protocol: no I/O, no UI. The agent CLI uses
//! it over the agent socket; a companion app uses it over pinned mTLS.

use super::{
    Channel, ENROLLMENT_PROTOCOL_VERSION, EnrolleeKind, EnrollmentRejection, INVITATION_PREFIX,
    JoinerCancelReason, b64, decode_fixed,
    transcript::{self as t},
    unhex32,
    wire::{EnrollmentReply, EnrollmentRequest},
};
use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JoinerError {
    #[error("the invitation code is malformed")]
    MalformedInvitation,
    #[error("the provider rejected the enrollment: {0}")]
    Rejected(EnrollmentRejection),
    #[error("the provider did not prove knowledge of the invitation")]
    ProviderNotAuthenticated,
    #[error("the provider offered a different role than this endpoint can take")]
    WrongRole,
    #[error("unexpected provider reply")]
    UnexpectedReply,
}

/// `vwe1.<id>.<secret>`, both 32 bytes, unpadded base64url.
pub struct InvitationCode {
    id: [u8; 32],
    secret: Zeroizing<[u8; 32]>,
}

impl InvitationCode {
    pub fn parse(text: &str) -> Result<Self, JoinerError> {
        let mut parts = text.trim().split('.');
        let (Some(INVITATION_PREFIX), Some(id), Some(secret), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(JoinerError::MalformedInvitation);
        };
        Ok(Self {
            id: decode_fixed::<32>(id).ok_or(JoinerError::MalformedInvitation)?,
            secret: Zeroizing::new(
                decode_fixed::<32>(secret).ok_or(JoinerError::MalformedInvitation)?,
            ),
        })
    }
    pub fn id(&self) -> String {
        b64(&self.id)
    }
}

/// A sent join, awaiting the provider's half.
pub struct JoinAttempt {
    code: InvitationCode,
    channel: Channel,
    join_bytes: Vec<u8>,
    request: EnrollmentRequest,
}

impl JoinAttempt {
    /// A fresh agent key joins over the agent socket.
    pub fn agent(code: InvitationCode, key: &SigningKey, nonce: [u8; 32]) -> Self {
        let public = key.verifying_key().to_bytes();
        let join_bytes = t::join_transcript(Channel::AgentSocket, &code.id, &public, &nonce, &[]);
        let request = EnrollmentRequest::EnrollJoin {
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            invitation_id: code.id(),
            public_key: Some(b64(&public)),
            nonce: b64(&nonce),
            mac: b64(&t::mac(&code.secret, &code.id, t::JOIN, &join_bytes)),
        };
        Self {
            code,
            channel: Channel::AgentSocket,
            join_bytes,
            request,
        }
    }

    /// A companion joins with its mTLS client leaf, pinned to the provider's
    /// server certificate. Both are lowercase hex SHA-256 fingerprints.
    pub fn companion(
        code: InvitationCode,
        device_fingerprint: &str,
        provider_fingerprint: &str,
        nonce: [u8; 32],
    ) -> Result<Self, JoinerError> {
        let device = unhex32(device_fingerprint).ok_or(JoinerError::MalformedInvitation)?;
        let provider = unhex32(provider_fingerprint).ok_or(JoinerError::MalformedInvitation)?;
        let join_bytes =
            t::join_transcript(Channel::CompanionMtls, &code.id, &device, &nonce, &provider);
        let request = EnrollmentRequest::EnrollJoin {
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            invitation_id: code.id(),
            public_key: None,
            nonce: b64(&nonce),
            mac: b64(&t::mac(&code.secret, &code.id, t::JOIN, &join_bytes)),
        };
        Ok(Self {
            code,
            channel: Channel::CompanionMtls,
            join_bytes,
            request,
        })
    }

    /// Byte-identical on every retry, so a lost reply can be recovered.
    pub fn request(&self) -> &EnrollmentRequest {
        &self.request
    }

    /// Verify the provider's proof and derive the comparison code.
    pub fn accept(self, reply: &EnrollmentReply) -> Result<JoinedSession, JoinerError> {
        let EnrollmentReply::Joined {
            invitation_id,
            kind,
            provider_nonce,
            provider_mac,
            expires_in_seconds,
            ..
        } = reply
        else {
            return Err(match reply {
                EnrollmentReply::Rejected { reason, .. } => JoinerError::Rejected(*reason),
                _ => JoinerError::UnexpectedReply,
            });
        };
        let nonce = decode_fixed::<32>(provider_nonce).ok_or(JoinerError::UnexpectedReply)?;
        let tag = decode_fixed::<32>(provider_mac).ok_or(JoinerError::UnexpectedReply)?;
        if *invitation_id != self.code.id() {
            return Err(JoinerError::UnexpectedReply);
        }
        let full = t::full_transcript(&self.join_bytes, kind, &nonce);
        if !t::verify_mac(&self.code.secret, &self.code.id, t::PROVIDER, &full, &tag) {
            return Err(JoinerError::ProviderNotAuthenticated);
        }
        if kind.channel() != self.channel || !kind.valid() {
            return Err(JoinerError::WrongRole);
        }
        let transcript_hash = t::hash(&full);
        Ok(JoinedSession {
            comparison_code: t::comparison_code(&self.code.secret, &self.code.id, &transcript_hash),
            kind: kind.clone(),
            expires_in_seconds: *expires_in_seconds,
            code: self.code,
            transcript_hash,
        })
    }
}

/// After the handshake: show `comparison_code` and `kind` to the joining human.
pub struct JoinedSession {
    code: InvitationCode,
    transcript_hash: [u8; 32],
    pub kind: EnrolleeKind,
    pub comparison_code: String,
    pub expires_in_seconds: u64,
}

impl JoinedSession {
    fn control_mac(&self, action: &str) -> String {
        b64(&t::mac(
            &self.code.secret,
            &self.code.id,
            t::CONTROL,
            &t::control_message(action, &self.transcript_hash),
        ))
    }

    /// The joining human's approval; `key` is required for an agent.
    pub fn confirm(&self, key: Option<&SigningKey>) -> EnrollmentRequest {
        EnrollmentRequest::EnrollConfirm {
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            invitation_id: self.code.id(),
            mac: self.control_mac(t::CONFIRM),
            signature: key.map(|key| {
                b64(&key
                    .sign(&t::control_message(t::POSSESSION, &self.transcript_hash))
                    .to_bytes())
            }),
        }
    }

    pub fn status(&self) -> EnrollmentRequest {
        EnrollmentRequest::EnrollStatus {
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            invitation_id: self.code.id(),
            mac: self.control_mac(t::STATUS),
        }
    }

    pub fn cancel(&self, reason: JoinerCancelReason) -> EnrollmentRequest {
        EnrollmentRequest::EnrollCancel {
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            invitation_id: self.code.id(),
            reason,
            mac: self.control_mac(t::cancel_action(reason)),
        }
    }
}
