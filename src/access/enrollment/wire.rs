//! Closed joiner wire messages, shared by the agent socket and the companion
//! mTLS endpoint. JSON is transport; MACs and signatures cover canonical bytes.

use super::{
    ENROLLMENT_PROTOCOL_VERSION, EnrolleeKind, EnrollmentRejection, EnrollmentState,
    JoinerCancelReason, decode_fixed,
};
use serde::{Deserialize, Serialize};

/// Requests are small; replies fit the agent socket's 1 KiB response bound.
pub const MAX_ENROLLMENT_FRAME_BYTES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "purpose", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnrollmentRequest {
    EnrollJoin {
        protocol_version: u8,
        invitation_id: String,
        /// Agent channel only: the new Ed25519 public key. Companions are
        /// identified by their mTLS client leaf instead.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        public_key: Option<String>,
        nonce: String,
        mac: String,
    },
    /// The joining human's approval. Idempotent: re-sent until it commits.
    EnrollConfirm {
        protocol_version: u8,
        invitation_id: String,
        mac: String,
        /// Agent channel only: Ed25519 proof of possession of the new key.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    EnrollStatus {
        protocol_version: u8,
        invitation_id: String,
        mac: String,
    },
    EnrollCancel {
        protocol_version: u8,
        invitation_id: String,
        reason: JoinerCancelReason,
        mac: String,
    },
}

impl EnrollmentRequest {
    pub fn parse(bytes: &[u8]) -> Result<Self, EnrollmentRejection> {
        if bytes.len() > MAX_ENROLLMENT_FRAME_BYTES {
            return Err(EnrollmentRejection::Malformed);
        }
        let request: Self =
            serde_json::from_slice(bytes).map_err(|_error| EnrollmentRejection::Malformed)?;
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), EnrollmentRejection> {
        let (version, id, mac) = match self {
            Self::EnrollJoin {
                protocol_version,
                invitation_id,
                public_key,
                nonce,
                mac,
            } => {
                if public_key
                    .as_deref()
                    .is_some_and(|key| decode_fixed::<32>(key).is_none())
                    || decode_fixed::<32>(nonce).is_none()
                {
                    return Err(EnrollmentRejection::Malformed);
                }
                (protocol_version, invitation_id, mac)
            }
            Self::EnrollConfirm {
                protocol_version,
                invitation_id,
                mac,
                signature,
            } => {
                if signature
                    .as_deref()
                    .is_some_and(|sig| decode_fixed::<64>(sig).is_none())
                {
                    return Err(EnrollmentRejection::Malformed);
                }
                (protocol_version, invitation_id, mac)
            }
            Self::EnrollStatus {
                protocol_version,
                invitation_id,
                mac,
            }
            | Self::EnrollCancel {
                protocol_version,
                invitation_id,
                mac,
                ..
            } => (protocol_version, invitation_id, mac),
        };
        if *version != ENROLLMENT_PROTOCOL_VERSION {
            return Err(EnrollmentRejection::UnsupportedVersion);
        }
        if decode_fixed::<32>(id).is_none() || decode_fixed::<32>(mac).is_none() {
            return Err(EnrollmentRejection::Malformed);
        }
        Ok(())
    }

    pub fn invitation_id(&self) -> &str {
        match self {
            Self::EnrollJoin { invitation_id, .. }
            | Self::EnrollConfirm { invitation_id, .. }
            | Self::EnrollStatus { invitation_id, .. }
            | Self::EnrollCancel { invitation_id, .. } => invitation_id,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnrollmentReply {
    /// The provider's half of the handshake, authenticated by `provider_mac`.
    Joined {
        protocol_version: u8,
        invitation_id: String,
        kind: EnrolleeKind,
        provider_nonce: String,
        provider_mac: String,
        expires_in_seconds: u64,
    },
    State {
        protocol_version: u8,
        invitation_id: String,
        state: EnrollmentState,
    },
    Rejected {
        protocol_version: u8,
        reason: EnrollmentRejection,
    },
}

impl EnrollmentReply {
    pub fn rejected(reason: EnrollmentRejection) -> Self {
        Self::Rejected {
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            reason,
        }
    }
    pub fn state(invitation_id: &str, state: EnrollmentState) -> Self {
        Self::State {
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            invitation_id: invitation_id.into(),
            state,
        }
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, EnrollmentRejection> {
        if bytes.len() > MAX_ENROLLMENT_FRAME_BYTES {
            return Err(EnrollmentRejection::Malformed);
        }
        let reply: Self =
            serde_json::from_slice(bytes).map_err(|_error| EnrollmentRejection::Malformed)?;
        let version = match &reply {
            Self::Joined {
                protocol_version, ..
            }
            | Self::State {
                protocol_version, ..
            }
            | Self::Rejected {
                protocol_version, ..
            } => *protocol_version,
        };
        if version != ENROLLMENT_PROTOCOL_VERSION {
            return Err(EnrollmentRejection::UnsupportedVersion);
        }
        Ok(reply)
    }
}
