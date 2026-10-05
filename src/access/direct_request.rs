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
/// Immutable attribution, not authentication proof. Only a verified future
/// transport may authorize admission; a stored snapshot never grants it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentOwner {
    pub binding_id: String,
    pub label: String,
    pub fingerprint: String,
    pub uid: u32,
    pub gid: u32,
}
impl AgentOwner {
    pub(crate) fn from_binding(binding: &super::agent_binding::AgentBinding) -> Self {
        Self {
            binding_id: binding.id.clone(),
            label: binding.label.clone(),
            fingerprint: binding.fingerprint.clone(),
            uid: binding.uid,
            gid: binding.gid,
        }
    }
    pub(crate) fn review_requester(&self) -> String {
        format!("agent {} ({})", self.label, self.fingerprint)
    }
    pub(crate) fn matches(&self, binding: &super::agent_binding::AgentBinding) -> bool {
        *self == Self::from_binding(binding)
    }
    fn valid(&self) -> bool {
        valid_request_id(&self.binding_id)
            && super::valid_sha256(&self.fingerprint)
            && !self.label.is_empty()
            && self.label.len() <= 128
            && self
                .label
                .bytes()
                .all(|b| b.is_ascii_graphic() || b == b' ')
            && self.label.bytes().any(|b| b.is_ascii_graphic())
            && self.uid != 0
            && self.uid != u32::MAX
            && self.gid != 0
            && self.gid != u32::MAX
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RequestOwner {
    Human(u32),
    Agent(AgentOwner),
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(try_from = "DirectRecordWire")]
pub(crate) struct DirectRecord {
    pub owner_uid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_owner: Option<AgentOwner>,
    /// Binding-scoped nonce tombstone, retained through every terminal state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_digest: Option<String>,
    pub created_at_unix_seconds: u64,
    pub lifecycle_epoch: u64,
    pub review: DirectReview,
    pub binding_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalBinding>,
    #[serde(default)]
    pub execution_claimed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit: Vec<super::history::HistoryEvent>,
    pub history_version: u8,
}
/// Internal durable authority; never projected into requester responses.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovalBinding {
    pub request_id: String,
    pub requester_uid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_owner: Option<AgentOwner>,
    pub policy_digest: String,
    pub arguments_digest: String,
    pub expires_at_unix_seconds: u64,
    pub lifecycle_epoch: u64,
    pub record_digest: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DecisionOutcome {
    Invalidated,
    Recovered,
    Approved,
    Denied,
    Expired,
    ReviewUnavailable,
    ExecutionUnavailable,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyDecisionAudit {
    pub binding: ApprovalBinding,
    pub at_unix_seconds: u64,
    pub outcome: DecisionOutcome,
}
// Legacy authority-bearing audit is accepted only through this narrow migration.
#[derive(Deserialize)]
#[serde(untagged)]
enum StoredAudit {
    Current(super::history::HistoryEvent),
    Legacy(LegacyDecisionAudit),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectRecordWire {
    owner_uid: u32,
    #[serde(default)]
    agent_owner: Option<AgentOwner>,
    #[serde(default)]
    replay_digest: Option<String>,
    created_at_unix_seconds: u64,
    lifecycle_epoch: u64,
    review: DirectReview,
    binding_digest: String,
    #[serde(default)]
    approval: Option<ApprovalBinding>,
    #[serde(default)]
    execution_claimed: bool,
    #[serde(default)]
    audit: Vec<StoredAudit>,
    history_version: Option<u8>,
}
impl TryFrom<DirectRecordWire> for DirectRecord {
    type Error = &'static str;
    fn try_from(w: DirectRecordWire) -> Result<Self, Self::Error> {
        use super::history::{HISTORY_VERSION, HistoryEvent, HistoryOutcome};
        if w.agent_owner.is_some() && w.history_version != Some(HISTORY_VERSION) {
            return Err("invalid agent history format");
        }
        let mut record = Self {
            owner_uid: w.owner_uid,
            agent_owner: w.agent_owner,
            replay_digest: w.replay_digest,
            created_at_unix_seconds: w.created_at_unix_seconds,
            lifecycle_epoch: w.lifecycle_epoch,
            review: w.review,
            binding_digest: w.binding_digest,
            approval: w.approval,
            execution_claimed: w.execution_claimed,
            audit: Vec::new(),
            history_version: HISTORY_VERSION,
        };
        match w.history_version {
            Some(HISTORY_VERSION) => {
                for event in w.audit {
                    let StoredAudit::Current(event) = event else {
                        return Err("invalid history format");
                    };
                    record.audit.push(event);
                }
            }
            None => {
                // A submission time and attribution are proven by the sealed record.
                record.audit.push(HistoryEvent::snapshot(
                    &record,
                    0,
                    record.created_at_unix_seconds,
                    HistoryOutcome::Submitted,
                    Some(DirectStatus::Pending),
                ));
                let count = w.audit.len();
                if count > 3 {
                    return Err("invalid legacy history");
                }
                let mut previous = DirectStatus::Pending;
                for (index, event) in w.audit.into_iter().enumerate() {
                    let StoredAudit::Legacy(event) = event else {
                        return Err("invalid legacy history");
                    };
                    if event.binding != record.approval_binding() {
                        return Err("invalid legacy history");
                    }
                    let last = index + 1 == count;
                    let next = match event.outcome {
                        DecisionOutcome::Approved => match previous {
                            DirectStatus::Pending => DirectStatus::Approved,
                            DirectStatus::Approved => DirectStatus::Running,
                            DirectStatus::Running
                                if last
                                    && matches!(
                                        record.review.status,
                                        DirectStatus::Completed { .. }
                                    ) =>
                            {
                                record.review.status.clone()
                            }
                            _ => return Err("invalid legacy history"),
                        },
                        DecisionOutcome::Denied if previous == DirectStatus::Pending => {
                            DirectStatus::Denied
                        }
                        DecisionOutcome::Expired | DecisionOutcome::ReviewUnavailable
                            if matches!(
                                previous,
                                DirectStatus::Pending | DirectStatus::Approved
                            ) =>
                        {
                            DirectStatus::Expired
                        }
                        DecisionOutcome::ExecutionUnavailable
                            if last
                                && matches!(
                                    record.review.status,
                                    DirectStatus::Expired | DirectStatus::Failed { .. }
                                ) =>
                        {
                            record.review.status.clone()
                        }
                        _ => return Err("invalid legacy history"),
                    };
                    // Preserve the legacy ambiguity instead of claiming a precise historical cause.
                    record.audit.push(HistoryEvent::snapshot(
                        &record,
                        (index + 1) as u32,
                        event.at_unix_seconds,
                        HistoryOutcome::LegacyUnknown,
                        Some(next.clone()),
                    ));
                    previous = next;
                }
                // Earliest supported records had no audit. Only their final status is known;
                // do not invent a timestamp for it. An empty terminal audit is retained as
                // a legacy snapshot with no event timestamp, rather than inventing one.
                if count == 0 && record.review.status != DirectStatus::Pending {
                    // No event time was recorded: there is no truthful terminal event to add.
                    record.audit[0].outcome = HistoryOutcome::LegacyUnknown;
                    record.audit[0].at_unix_seconds = None;
                    record.audit[0].status = Some(record.review.status.clone());
                } else if previous != record.review.status {
                    return Err("inconsistent legacy history");
                }
            }
            _ => return Err("unsupported history version"),
        }
        if !record.validate_history() {
            return Err("invalid history");
        }
        Ok(record)
    }
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
    pub(crate) fn owner(&self) -> RequestOwner {
        self.agent_owner
            .clone()
            .map_or(RequestOwner::Human(self.owner_uid), RequestOwner::Agent)
    }
    pub(crate) fn human_visible(&self, human: AuthenticatedHuman, provider_uid: u32) -> bool {
        match self.owner() {
            RequestOwner::Human(uid) => uid == human.uid(),
            RequestOwner::Agent(_) => human.uid() == provider_uid,
        }
    }
    fn validate_history(&self) -> bool {
        use super::history::{HISTORY_VERSION, HistoryOutcome as O};
        if self.history_version != HISTORY_VERSION || self.audit.is_empty() || self.audit.len() > 4
        {
            return false;
        }
        let mut previous = None;
        for (ordinal, event) in self.audit.iter().enumerate() {
            if event.ordinal as usize != ordinal || !event.matches_record(self) {
                return false;
            }
            // A recorded start/completion cannot precede the one-time execution claim.
            // Legacy snapshots and recovery retain only facts the old format proves.
            if !self.execution_claimed
                && matches!(
                    event.status,
                    Some(
                        DirectStatus::Running
                            | DirectStatus::Completed { .. }
                            | DirectStatus::Failed { .. }
                    )
                )
                && !matches!(event.outcome, O::LegacyUnknown | O::Recovered)
            {
                return false;
            }
            if ordinal == 0 {
                if !((event.outcome == O::Submitted
                    && event.at_unix_seconds == Some(self.created_at_unix_seconds))
                    || (event.outcome == O::LegacyUnknown && event.at_unix_seconds.is_none()))
                {
                    return false;
                }
            } else if !matches!(
                (&previous, &event.status),
                (
                    Some(DirectStatus::Pending),
                    Some(DirectStatus::Approved | DirectStatus::Denied | DirectStatus::Expired)
                ) | (
                    Some(DirectStatus::Approved),
                    Some(
                        DirectStatus::Running | DirectStatus::Expired | DirectStatus::Failed { .. }
                    )
                ) | (
                    Some(DirectStatus::Running),
                    Some(DirectStatus::Completed { .. } | DirectStatus::Failed { .. })
                )
            ) {
                return false;
            }
            previous = event.status.clone();
        }
        previous.as_ref() == Some(&self.review.status)
    }
    pub(crate) fn approval_binding(&self) -> ApprovalBinding {
        ApprovalBinding {
            request_id: self.review.id.clone(),
            requester_uid: self.owner_uid,
            agent_owner: self.agent_owner.clone(),
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
        if let Some(replay_digest) = &self.replay_digest {
            return hex_sha256(
                &serde_json::to_vec(&(
                    3u8,
                    self.owner_uid,
                    &self.agent_owner,
                    replay_digest,
                    self.created_at_unix_seconds,
                    self.lifecycle_epoch,
                    review,
                ))
                .expect("signed agent record projection serialization"),
            );
        }
        if let Some(owner) = &self.agent_owner {
            return hex_sha256(
                &serde_json::to_vec(&(
                    2u8,
                    self.owner_uid,
                    owner,
                    self.created_at_unix_seconds,
                    self.lifecycle_epoch,
                    review,
                ))
                .expect("agent record projection serialization"),
            );
        }
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
                .replay_digest
                .as_ref()
                .is_none_or(|digest| self.agent_owner.is_some() && valid_sha256(digest))
            && self
                .approval
                .as_ref()
                .is_none_or(|binding| *binding == self.approval_binding())
            && (!matches!(r.status, DirectStatus::Approved | DirectStatus::Running)
                || self.approval.is_some()
                || r.one_time == LEGACY_ONE_TIME)
            && self.validate_history()
            && valid_request_id(id)
            && r.id == id
            && self.owner_uid != u32::MAX
            && self.lifecycle_epoch <= epoch
            && self.created_at_unix_seconds < r.expires_at_unix_seconds
            && match &self.agent_owner {
                Some(owner) => {
                    owner.valid()
                        && owner.uid == self.owner_uid
                        && r.requester == owner.review_requester()
                }
                None => r.requester == "local human terminal",
            }
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
            && (r.one_time == ONE_TIME
                || r.one_time == PREVIOUS_ONE_TIME
                || r.one_time == LEGACY_ONE_TIME)
            && !matches!(r.status, DirectStatus::Completed { exit_code } if !(0..=255).contains(&exit_code))
    }
}

pub(crate) const LEGACY_ONE_TIME: &str = "Approving this request would authorize one execution only; approval is unavailable at this stage.";
pub(crate) const PREVIOUS_ONE_TIME: &str =
    "Approval authorizes this request once only. Execution is not available yet.";
pub(crate) const ONE_TIME: &str =
    "Approval authorizes one protected execution. Lock or cancellation stops its descendants.";
