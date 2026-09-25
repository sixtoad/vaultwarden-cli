//! Closed contracts for requests owned by an authenticated local human.
use super::{hex_sha256, valid_operation_id, valid_sha256};
use serde::{Deserialize, Serialize};

pub const DEFAULT_REQUEST_LIFETIME: std::time::Duration = std::time::Duration::from_secs(300);

/// Constructed only after the transport obtains the peer UID from the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedHuman {
    uid: u32,
}
impl AuthenticatedHuman {
    pub(crate) fn from_peer_uid(uid: u32) -> Self {
        Self { uid }
    }
    pub(crate) fn uid(self) -> u32 {
        self.uid
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectSubmission {
    pub operation: String,
    pub revision: Option<String>,
    pub values: Vec<String>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DirectRequestError {
    Unauthorized,
    Locked,
    InvalidRequest,
    StaleRevision,
    NotFound,
    Unavailable,
    ReviewUnavailable,
    AlreadyDecided,
    AuthenticationFailed,
}
impl std::fmt::Display for DirectRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unauthorized => "unauthorized human",
            Self::Locked => "provider locked",
            Self::InvalidRequest => "invalid request",
            Self::StaleRevision => "stale policy revision",
            Self::NotFound => "request unavailable",
            Self::Unavailable => "provider unavailable",
            Self::ReviewUnavailable => "review unavailable",
            Self::AlreadyDecided => "request already decided",
            Self::AuthenticationFailed => "authentication failed",
        })
    }
}
impl std::error::Error for DirectRequestError {}
impl From<super::ports::SessionError> for DirectRequestError {
    fn from(e: super::ports::SessionError) -> Self {
        match e {
            super::ports::SessionError::Locked => Self::Locked,
            _ => Self::Unavailable,
        }
    }
}
impl From<super::provider::ProviderError> for DirectRequestError {
    fn from(_: super::provider::ProviderError) -> Self {
        Self::Unavailable
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DirectFailure {
    ReviewUnavailable,
    ExecutionUnavailable,
    ExecutionRejected,
    ExecutionNonzero,
    ExecutionSignaled,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", from = "StrictDirectStatus")]
pub enum DirectStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Running,
    Completed { exit_code: i32 },
    Failed { reason: DirectFailure },
}
// Serde internally tagged unit variants ignore extra fields. Empty struct wire
// variants enforce the closed response contract without changing the public API.
#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum StrictDirectStatus {
    Pending {},
    Approved {},
    Denied {},
    Expired {},
    Running {},
    Completed { exit_code: u8 },
    Failed { reason: DirectFailure },
}
impl From<StrictDirectStatus> for DirectStatus {
    fn from(status: StrictDirectStatus) -> Self {
        match status {
            StrictDirectStatus::Pending {} => Self::Pending,
            StrictDirectStatus::Approved {} => Self::Approved,
            StrictDirectStatus::Denied {} => Self::Denied,
            StrictDirectStatus::Expired {} => Self::Expired,
            StrictDirectStatus::Running {} => Self::Running,
            StrictDirectStatus::Completed { exit_code } => Self::Completed {
                exit_code: i32::from(exit_code),
            },
            StrictDirectStatus::Failed { reason } => Self::Failed { reason },
        }
    }
}
impl DirectStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Denied | Self::Expired | Self::Completed { .. } | Self::Failed { .. }
        )
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubmissionReceipt {
    pub id: String,
    pub revision: String,
    pub arguments_digest: String,
    pub expires_at_unix_seconds: u64,
    pub status: DirectStatus,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewCredential {
    pub label: String,
    pub use_type: super::policy::CredentialUse,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectReview {
    pub id: String,
    pub requester: String,
    pub operation: String,
    pub effect: String,
    pub target: String,
    pub arguments: Vec<String>,
    pub credentials: Vec<ReviewCredential>,
    pub executable_digest: String,
    pub policy_digest: String,
    pub arguments_digest: String,
    pub expires_at_unix_seconds: u64,
    pub one_time: String,
    pub status: DirectStatus,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectRecord {
    pub owner_uid: u32,
    pub created_at_unix_seconds: u64,
    pub lifecycle_epoch: u64,
    pub review: DirectReview,
    pub binding_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalBinding>,
    #[serde(default)]
    pub execution_claimed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit: Vec<DecisionAudit>,
}
/// Internal durable authority; never projected into requester responses.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovalBinding {
    pub request_id: String,
    pub requester_uid: u32,
    pub policy_digest: String,
    pub arguments_digest: String,
    pub expires_at_unix_seconds: u64,
    pub lifecycle_epoch: u64,
    pub record_digest: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DecisionOutcome {
    Approved,
    Denied,
    Expired,
    ReviewUnavailable,
    ExecutionUnavailable,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DecisionAudit {
    pub binding: ApprovalBinding,
    pub at_unix_seconds: u64,
    pub outcome: DecisionOutcome,
}
/// Prepared under provider serialization and consumed exactly once in this process.
pub(crate) struct PreparedApproval {
    pub(crate) binding: ApprovalBinding,
    pub(crate) generation: u64,
}
pub(crate) struct AuthenticatedApproval(PreparedApproval);
impl PreparedApproval {
    pub(crate) fn authenticate(
        self,
        password: super::ports::SensitiveString,
        authenticator: &dyn super::ports::ApprovalAuthenticator,
    ) -> Result<AuthenticatedApproval, DirectRequestError> {
        if password.expose().is_empty() || password.expose().len() > 4096 {
            return Err(DirectRequestError::AuthenticationFailed);
        }
        authenticator
            .authenticate(password)
            .map_err(|_error| DirectRequestError::AuthenticationFailed)?;
        Ok(AuthenticatedApproval(self))
    }
}
impl AuthenticatedApproval {
    pub(crate) fn into_prepared(self) -> PreparedApproval {
        self.0
    }
}
pub(crate) fn arguments_digest(values: &[String]) -> String {
    hex_sha256(&serde_json::to_vec(&(1u8, values)).expect("string vector serialization"))
}
pub(crate) fn valid_request_id(id: &str) -> bool {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(id)
        .is_ok_and(|v| {
            v.len() == 32 && base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v) == id
        })
}
impl DirectRecord {
    pub(crate) fn approval_binding(&self) -> ApprovalBinding {
        ApprovalBinding {
            request_id: self.review.id.clone(),
            requester_uid: self.owner_uid,
            policy_digest: self.review.policy_digest.clone(),
            arguments_digest: self.review.arguments_digest.clone(),
            expires_at_unix_seconds: self.review.expires_at_unix_seconds,
            lifecycle_epoch: self.lifecycle_epoch,
            record_digest: self.binding_digest.clone(),
        }
    }
    pub(crate) fn seal(&mut self) {
        self.binding_digest = self.digest();
    }
    fn digest(&self) -> String {
        let mut review = self.review.clone();
        review.status = DirectStatus::Pending;
        hex_sha256(
            &serde_json::to_vec(&(
                1u8,
                self.owner_uid,
                self.created_at_unix_seconds,
                self.lifecycle_epoch,
                review,
            ))
            .expect("record projection serialization"),
        )
    }
    pub(crate) fn validate(&self, id: &str, epoch: u64) -> bool {
        let r = &self.review;
        let text = |s: &str| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control);
        self.binding_digest == self.digest()
            && self
                .approval
                .as_ref()
                .is_none_or(|binding| *binding == self.approval_binding())
            && (!matches!(r.status, DirectStatus::Approved | DirectStatus::Running)
                || self.approval.is_some()
                || r.one_time == LEGACY_ONE_TIME)
            && self
                .audit
                .iter()
                .all(|event| event.binding == self.approval_binding())
            && valid_request_id(id)
            && r.id == id
            && self.owner_uid != u32::MAX
            && self.lifecycle_epoch <= epoch
            && self.created_at_unix_seconds < r.expires_at_unix_seconds
            && r.requester == "local human terminal"
            && valid_operation_id(&r.operation)
            && text(&r.effect)
            && text(&r.target)
            && r.arguments.len() <= 32
            && r.arguments.iter().all(|v| text(v))
            && !r.credentials.is_empty()
            && r.credentials.len() <= 16
            && r.credentials.iter().all(|c| text(&c.label))
            && valid_sha256(&r.executable_digest)
            && valid_sha256(&r.policy_digest)
            && r.arguments_digest == arguments_digest(&r.arguments)
            && (r.one_time == ONE_TIME || r.one_time == LEGACY_ONE_TIME)
            && !matches!(r.status, DirectStatus::Completed { exit_code } if !(0..=255).contains(&exit_code))
    }
}

pub(crate) const LEGACY_ONE_TIME: &str = "Approving this request would authorize one execution only; approval is unavailable at this stage.";
pub(crate) const ONE_TIME: &str =
    "Approval authorizes this request once only. Execution is not available yet.";
