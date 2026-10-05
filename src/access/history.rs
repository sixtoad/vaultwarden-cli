//! Durable, explicitly allowlisted history. These records carry no authority.
use super::direct_request::{
    DirectFailure, DirectRecord, DirectRequestError, DirectStatus, ReviewCredential,
};
use serde::{Deserialize, Serialize};

pub const DEFAULT_HISTORY_LIMIT: u32 = 50;
pub const MAX_HISTORY_LIMIT: u32 = 200;
pub(crate) const HISTORY_VERSION: u8 = 1;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequesterSnapshot {
    Human { uid: u32, label: String },
    Agent { label: String, fingerprint: String },
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HistoryOutcome {
    Submitted,
    Approved,
    Denied,
    Expired,
    ReviewUnavailable,
    ExecutionStarted,
    Succeeded,
    ExecutionNonzero,
    ExecutionSignaled,
    ExecutionRejected,
    ExecutionUnavailable,
    Invalidated,
    Recovered,
    LegacyUnknown,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(try_from = "HistoryEventWire")]
pub struct HistoryEvent {
    pub version: u8,
    pub request_id: String,
    pub operation: String,
    pub requester: RequesterSnapshot,
    pub policy_revision: String,
    pub credentials: Vec<ReviewCredential>,
    pub created_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub at_unix_seconds: Option<u64>,
    pub ordinal: u32,
    pub outcome: HistoryOutcome,
    /// None only for migrated events whose precise lifecycle phase was not stored.
    pub status: Option<DirectStatus>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryEventWire {
    version: u8,
    request_id: String,
    operation: String,
    requester: RequesterSnapshot,
    policy_revision: String,
    credentials: Vec<ReviewCredential>,
    created_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    at_unix_seconds: Option<u64>,
    ordinal: u32,
    outcome: HistoryOutcome,
    status: Option<DirectStatus>,
}
impl TryFrom<HistoryEventWire> for HistoryEvent {
    type Error = &'static str;
    fn try_from(w: HistoryEventWire) -> Result<Self, Self::Error> {
        let event = Self {
            version: w.version,
            request_id: w.request_id,
            operation: w.operation,
            requester: w.requester,
            policy_revision: w.policy_revision,
            credentials: w.credentials,
            created_at_unix_seconds: w.created_at_unix_seconds,
            expires_at_unix_seconds: w.expires_at_unix_seconds,
            at_unix_seconds: w.at_unix_seconds,
            ordinal: w.ordinal,
            outcome: w.outcome,
            status: w.status,
        };
        if event.valid() {
            Ok(event)
        } else {
            Err("invalid history event")
        }
    }
}
impl HistoryEvent {
    pub(crate) fn snapshot(
        record: &DirectRecord,
        ordinal: u32,
        now: u64,
        outcome: HistoryOutcome,
        status: Option<DirectStatus>,
    ) -> Self {
        Self {
            version: HISTORY_VERSION,
            request_id: record.review.id.clone(),
            operation: record.review.operation.clone(),
            requester: match record.owner() {
                super::direct_request::RequestOwner::Human(uid) => RequesterSnapshot::Human {
                    uid,
                    label: record.review.requester.clone(),
                },
                super::direct_request::RequestOwner::Agent(owner) => RequesterSnapshot::Agent {
                    label: owner.label,
                    fingerprint: owner.fingerprint,
                },
            },
            policy_revision: record.review.policy_digest.clone(),
            credentials: record.review.credentials.clone(),
            created_at_unix_seconds: record.created_at_unix_seconds,
            expires_at_unix_seconds: record.review.expires_at_unix_seconds,
            at_unix_seconds: Some(now),
            ordinal,
            outcome,
            status,
        }
    }
    pub(crate) fn valid(&self) -> bool {
        let text = |s: &str| !s.is_empty() && s.len() <= 256;
        self.version == HISTORY_VERSION
            && super::direct_request::valid_request_id(&self.request_id)
            && super::valid_operation_id(&self.operation)
            && super::valid_sha256(&self.policy_revision)
            && self.created_at_unix_seconds < self.expires_at_unix_seconds
            && match &self.requester {
                RequesterSnapshot::Human { uid, label } => *uid != u32::MAX && text(label),
                RequesterSnapshot::Agent { label, fingerprint } => {
                    text(label) && super::valid_sha256(fingerprint)
                }
            }
            && !self.credentials.is_empty()
            && self.credentials.len() <= 16
            && self.credentials.iter().all(|c| text(&c.label))
            && (self.at_unix_seconds.is_some() || self.outcome == HistoryOutcome::LegacyUnknown)
            && self.consistent_outcome()
    }
    fn consistent_outcome(&self) -> bool {
        use DirectStatus as S;
        use HistoryOutcome as O;
        matches!(
            (&self.outcome, &self.status),
            (O::Submitted, Some(S::Pending))
                | (O::Approved, Some(S::Approved))
                | (O::Denied, Some(S::Denied))
                | (
                    O::Expired | O::ReviewUnavailable | O::Invalidated,
                    Some(S::Expired)
                )
                | (O::ExecutionStarted, Some(S::Running))
                | (O::Succeeded, Some(S::Completed { exit_code: 0 }))
                | (
                    O::ExecutionNonzero,
                    Some(S::Failed {
                        reason: DirectFailure::ExecutionNonzero
                    })
                )
                | (
                    O::ExecutionSignaled,
                    Some(S::Failed {
                        reason: DirectFailure::ExecutionSignaled
                    })
                )
                | (
                    O::ExecutionRejected,
                    Some(S::Failed {
                        reason: DirectFailure::ExecutionRejected
                    })
                )
                | (
                    O::ExecutionUnavailable,
                    Some(
                        S::Expired
                            | S::Failed {
                                reason: DirectFailure::ExecutionUnavailable
                            }
                    )
                )
                | (
                    O::ReviewUnavailable,
                    Some(S::Failed {
                        reason: DirectFailure::ReviewUnavailable
                    })
                )
                | (
                    O::Recovered,
                    Some(
                        S::Expired
                            | S::Failed {
                                reason: DirectFailure::ExecutionUnavailable
                            }
                    )
                )
                | (O::LegacyUnknown, _)
        ) || matches!((&self.outcome, &self.status), (O::ExecutionNonzero, Some(S::Completed { exit_code })) if (1..=255).contains(exit_code))
    }
    pub(crate) fn matches_record(&self, record: &DirectRecord) -> bool {
        let mut expected = Self::snapshot(
            record,
            self.ordinal,
            self.at_unix_seconds.unwrap_or(0),
            self.outcome,
            self.status.clone(),
        );
        expected.at_unix_seconds = self.at_unix_seconds;
        self.valid() && *self == expected
    }
}
pub(crate) fn limit(value: Option<u32>) -> Result<usize, DirectRequestError> {
    let limit = value.unwrap_or(DEFAULT_HISTORY_LIMIT);
    if (1..=MAX_HISTORY_LIMIT).contains(&limit) {
        Ok(limit as usize)
    } else {
        Err(DirectRequestError::InvalidRequest)
    }
}
pub(crate) fn newest(mut events: Vec<HistoryEvent>, limit: usize) -> Vec<HistoryEvent> {
    events.sort_by(|a, b| {
        (b.at_unix_seconds, &b.request_id, b.ordinal).cmp(&(
            a.at_unix_seconds,
            &a.request_id,
            a.ordinal,
        ))
    });
    events.truncate(limit);
    events
}
pub(crate) fn outcome(
    status: &DirectStatus,
    decision: super::direct_request::DecisionOutcome,
) -> HistoryOutcome {
    use super::direct_request::DecisionOutcome as D;
    use DirectStatus as S;
    use HistoryOutcome as O;
    match status {
        S::Pending => O::Submitted,
        S::Approved => O::Approved,
        S::Denied => O::Denied,
        S::Running => O::ExecutionStarted,
        S::Completed { exit_code: 0 } => O::Succeeded,
        S::Completed { .. } => O::ExecutionNonzero,
        S::Failed { reason } => match reason {
            DirectFailure::ReviewUnavailable => O::ReviewUnavailable,
            DirectFailure::ExecutionUnavailable if decision == D::Recovered => O::Recovered,
            DirectFailure::ExecutionUnavailable => O::ExecutionUnavailable,
            DirectFailure::ExecutionRejected => O::ExecutionRejected,
            DirectFailure::ExecutionNonzero => O::ExecutionNonzero,
            DirectFailure::ExecutionSignaled => O::ExecutionSignaled,
        },
        S::Expired => match decision {
            D::ReviewUnavailable => O::ReviewUnavailable,
            D::ExecutionUnavailable => O::ExecutionUnavailable,
            D::Invalidated => O::Invalidated,
            D::Recovered => O::Recovered,
            _ => O::Expired,
        },
    }
}
