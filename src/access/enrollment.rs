//! Guided mutual enrollment (#59 phase 1). See `docs/guided-enrollment.md`.
//!
//! An already-authorized human issues an expiring, single-use invitation. Its
//! secret travels out of band to the joining endpoint, which proves knowledge
//! of it (HMAC-SHA256 under an HKDF-SHA256 key) and receives the provider's
//! proof in return. Both ends derive the same comparison code from the session
//! transcript. Enrollment commits only after the provider's human typed the
//! code shown on the joiner and the joiner's human confirmed it too.
//!
//! The joining endpoint never gains authority from this protocol: an agent
//! becomes a requester binding, a companion an approval client without the
//! administrator role. Neither can create, approve or cancel invitations on the
//! provider side.

use serde::{Deserialize, Serialize};
use std::time::Duration;

pub mod book;
pub mod joiner;
#[cfg(test)]
mod tests;
pub mod transcript;
pub mod wire;

pub const ENROLLMENT_PROTOCOL_VERSION: u8 = 1;
/// Prefix of the out-of-band invitation code: `vwe1.<id>.<secret>`.
pub const INVITATION_PREFIX: &str = "vwe1";
pub const DEFAULT_TTL_SECONDS: u64 = 600;
pub const MIN_TTL_SECONDS: u64 = 60;
pub const MAX_TTL_SECONDS: u64 = 1800;
/// Open or joined invitations at once.
pub const MAX_LIVE_INVITATIONS: usize = 8;
/// Live plus recently finished sessions kept in memory.
pub const MAX_RETAINED_SESSIONS: usize = 32;
/// Failed proofs of the invitation secret before the invitation is burned.
pub const MAX_PROOF_FAILURES: u8 = 3;
/// A finished session stays observable for this long, then is forgotten.
pub const FINAL_RETENTION: Duration = Duration::from_secs(600);
pub const MAX_LABEL_LEN: usize = 128;

/// What the joining endpoint becomes. Fixed by the inviting human.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnrolleeKind {
    /// A requester binding for one restricted OS identity. Never an approver.
    Agent { label: String, uid: u32, gid: u32 },
    /// An approval client. Never an administrator by enrollment.
    Companion { label: String },
}

impl EnrolleeKind {
    pub fn label(&self) -> &str {
        match self {
            Self::Agent { label, .. } | Self::Companion { label } => label,
        }
    }
    pub fn channel(&self) -> Channel {
        match self {
            Self::Agent { .. } => Channel::AgentSocket,
            Self::Companion { .. } => Channel::CompanionMtls,
        }
    }
    pub fn valid(&self) -> bool {
        let label = self.label();
        let label_ok = !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && label.trim() == label
            && !label.chars().any(char::is_control);
        match self {
            // Same rule as `agent_binding`: printable ASCII and spaces.
            Self::Agent { label, uid, gid } => {
                label_ok
                    && label.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
                    && ![0, u32::MAX].contains(uid)
                    && ![0, u32::MAX].contains(gid)
            }
            Self::Companion { .. } => label_ok,
        }
    }
}

/// The transport a joiner arrives on. Bound into every transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    AgentSocket,
    CompanionMtls,
}

/// Kernel or TLS identity of the joining peer, supplied by the transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Peer {
    Agent {
        uid: u32,
        groups: Vec<u32>,
    },
    /// SHA-256 fingerprint (lowercase hex) of the CA-valid mTLS client leaf.
    Companion {
        fingerprint: String,
    },
}

impl Peer {
    pub fn channel(&self) -> Channel {
        match self {
            Self::Agent { .. } => Channel::AgentSocket,
            Self::Companion { .. } => Channel::CompanionMtls,
        }
    }
    /// Whether this peer may act for a session of `kind`.
    pub fn matches(&self, kind: &EnrolleeKind) -> bool {
        match (self, kind) {
            (Self::Agent { uid, groups }, EnrolleeKind::Agent { uid: u, gid, .. }) => {
                uid == u && groups.contains(gid)
            }
            (Self::Companion { .. }, EnrolleeKind::Companion { .. }) => true,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InvitationRequest {
    pub kind: EnrolleeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

/// Returned once to the inviting human. The code contains the secret.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuedInvitation {
    pub id: String,
    pub invitation_code: String,
    pub kind: EnrolleeKind,
    pub expires_in_seconds: u64,
}

impl Drop for IssuedInvitation {
    /// The code carries the invitation secret: wipe it, including clones.
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.invitation_code);
    }
}

impl std::fmt::Debug for IssuedInvitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedInvitation")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("expires_in_seconds", &self.expires_in_seconds)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Party {
    Provider,
    Joiner,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AbortReason {
    /// The provider's human typed a code different from the provider's.
    CodeMismatch,
    /// The joiner's human said the codes differ.
    JoinerReportedMismatch,
    /// A second, different join proved the secret: it is no longer private.
    DuplicateJoin,
    TooManyFailures,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    /// Already enrolled, revoked, or otherwise refused by the identity store.
    IdentityRefused,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnrolledIdentity {
    Agent {
        binding_id: String,
        fingerprint: String,
    },
    Companion {
        fingerprint: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnrollmentState {
    AwaitingJoin {},
    AwaitingApprovals {
        provider_approved: bool,
        joiner_confirmed: bool,
    },
    Enrolled {
        identity: EnrolledIdentity,
    },
    Cancelled {
        by: Party,
    },
    Expired {},
    Aborted {
        reason: AbortReason,
    },
    Failed {
        reason: FailureReason,
    },
}

impl EnrollmentState {
    pub fn is_final(&self) -> bool {
        !matches!(self, Self::AwaitingJoin {} | Self::AwaitingApprovals { .. })
    }
}

/// Human-facing projection for the provider owner. It never carries the
/// invitation secret, and never the comparison code either: the owner must
/// read the code on the joining endpoint and type it into `approve`. A code
/// the provider displayed could be copied without looking at the joiner.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentView {
    pub id: String,
    pub kind: EnrolleeKind,
    pub state: EnrollmentState,
    pub expires_in_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joiner_fingerprint: Option<String>,
}

/// Closed failures for the provider's human.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum HumanEnrollmentError {
    #[error("unauthorized human")]
    Unauthorized,
    #[error("invalid enrollment request")]
    InvalidRequest,
    #[error("an equivalent invitation is already open")]
    Duplicate,
    #[error("too many open invitations")]
    LimitReached,
    #[error("enrollment unknown")]
    NotFound,
    #[error("invitation expired")]
    Expired,
    #[error("enrollment already finished")]
    Final,
    #[error("the joining endpoint has not joined yet")]
    AwaitingPeer,
    #[error("comparison code does not match; enrollment aborted")]
    CodeMismatch,
    #[error("enrollment unavailable")]
    Unavailable,
}

/// Closed failures for the joining endpoint. Unknown ids and wrong proofs
/// are indistinguishable.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentRejection {
    #[error("malformed")]
    Malformed,
    #[error("unsupported_version")]
    UnsupportedVersion,
    #[error("invalid_invitation")]
    InvalidInvitation,
    #[error("expired")]
    Expired,
    #[error("already_used")]
    AlreadyUsed,
    #[error("identity_refused")]
    IdentityRefused,
    #[error("busy")]
    Busy,
    #[error("unavailable")]
    Unavailable,
}

/// Kernel admission of an unpaired agent peer to the enrollment messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollmentAdmission {
    /// A session names this OS identity and can still matter to it.
    Admitted,
    Refused,
    /// The sessions are momentarily locked; the joiner retries.
    Busy,
}

/// The joining human's reason when declining.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JoinerCancelReason {
    Cancelled,
    CodeMismatch,
}

pub(crate) fn b64(bytes: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Canonical unpadded base64url of exactly `N` bytes.
pub(crate) fn decode_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return None;
    }
    bytes.try_into().ok()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Lowercase 64-digit hex to 32 bytes.
pub(crate) fn unhex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(pair).ok()?;
        out[index] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(out)
}
