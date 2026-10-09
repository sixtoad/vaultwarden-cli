//! Locked provider lifecycle and protected-operation admission.

use std::fmt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::AccessRequest;
use super::policy::{OperationPolicy, OperationPolicyDraft};
use super::ports::LoginEligibilityVerifier;
use super::provider_store::{ProviderState, ProviderStore};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderDiagnostic {
    UnsafeState,
    InvalidState,
    PersistenceFailure,
    InvalidOperationPolicy,
    CredentialIneligible,
    StaleOperationPolicyRevision,
    ExpiredAccessRequest,
    Conflict,
}

impl fmt::Display for ProviderDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafeState => "unsafe provider state",
            Self::InvalidState => "invalid provider state",
            Self::PersistenceFailure => "provider state persistence failed",
            Self::InvalidOperationPolicy => "invalid operation policy",
            Self::CredentialIneligible => "credential is not eligible",
            Self::StaleOperationPolicyRevision => "stale operation policy revision",
            Self::ExpiredAccessRequest => "access request expired",
            Self::Conflict => "record already exists",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderError {
    diagnostic: ProviderDiagnostic,
}
impl ProviderError {
    pub(crate) const fn new(diagnostic: ProviderDiagnostic) -> Self {
        Self { diagnostic }
    }
    pub const fn diagnostic(&self) -> ProviderDiagnostic {
        self.diagnostic
    }
}
impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.diagnostic.fmt(formatter)
    }
}
impl std::error::Error for ProviderError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderLockState {
    Locked,
}

/// The startup-only provider holds no secret-backend capability.
#[derive(Debug)]
pub struct Provider {
    store: ProviderStore,
    lock_state: ProviderLockState,
    state: ProviderState,
}

impl Provider {
    pub fn start(root: impl Into<PathBuf>) -> Result<Self, ProviderError> {
        Self::start_with_cleanup(root, || Ok(()))
    }
    /// Run composition-owned authority cleanup under exclusive ownership, before
    /// fallible durable-state validation. Never invoked for a competing writer.
    pub fn start_with_cleanup(
        root: impl Into<PathBuf>,
        cleanup: impl FnOnce() -> Result<(), ()>,
    ) -> Result<Self, ProviderError> {
        let mut store = ProviderStore::open_with_cleanup(root, cleanup)?;
        let state = store.invalidate_recovered()?;
        Ok(Self {
            store,
            lock_state: ProviderLockState::Locked,
            state,
        })
    }
    pub const fn lock_state(&self) -> ProviderLockState {
        self.lock_state
    }
    pub fn lock(&mut self) -> Result<(), ProviderError> {
        self.lock_state = ProviderLockState::Locked;
        self.state = self.store.invalidate_unexecuted()?;
        Ok(())
    }
    pub fn shutdown(&mut self) -> Result<(), ProviderError> {
        self.lock()
    }

    pub(crate) fn owner_uid(&self) -> u32 {
        self.store.owner_uid()
    }
    fn check_administrator(
        &self,
        human: super::direct_request::AuthenticatedHuman,
    ) -> Result<(), super::direct_request::DirectRequestError> {
        if human.uid() != self.owner_uid() {
            return Err(super::direct_request::DirectRequestError::Unauthorized);
        }
        Ok(())
    }
    pub(crate) fn list_agents(
        &self,
        human: super::direct_request::AuthenticatedHuman,
    ) -> Result<
        Vec<super::agent_binding::AgentBindingView>,
        super::direct_request::DirectRequestError,
    > {
        self.check_administrator(human)?;
        Ok(self
            .store
            .read_state()?
            .pairings
            .iter()
            .map(|b| b.view())
            .collect())
    }
    pub(crate) fn pair_agent(
        &mut self,
        human: super::direct_request::AuthenticatedHuman,
        input: super::agent_binding::AgentPairing,
        now: u64,
    ) -> Result<super::agent_binding::AgentBindingView, super::direct_request::DirectRequestError>
    {
        use super::{agent_binding::*, direct_request::DirectRequestError};
        self.check_administrator(human)?;
        let binding = AgentBinding::new(input, self.owner_uid())
            .map_err(|_error| DirectRequestError::InvalidRequest)?;
        let mut state = self.store.read_state()?;
        if state.pairings.iter().any(|b| {
            b.public_key == binding.public_key
                || (b.status == AgentBindingStatus::Enabled && b.label == binding.label)
        }) {
            return Err(DirectRequestError::InvalidRequest);
        }
        let view = binding.view();
        state
            .agent_audit
            .push(binding.audit(human.uid(), now, AgentAuditAction::Paired));
        state.pairings.push(binding);
        self.store.write_state(&state)?;
        self.state = state;
        Ok(view)
    }
    pub(crate) fn revoke_agent(
        &mut self,
        human: super::direct_request::AuthenticatedHuman,
        id: &str,
        now: u64,
    ) -> Result<super::agent_binding::AgentBindingView, super::direct_request::DirectRequestError>
    {
        use super::{agent_binding::*, direct_request::*};
        self.check_administrator(human)?;
        let mut state = self.store.read_state()?;
        let binding = state
            .pairings
            .iter_mut()
            .find(|b| b.id == id)
            .ok_or(DirectRequestError::NotFound)?;
        let changed = binding.status == AgentBindingStatus::Enabled;
        if changed {
            binding.status = AgentBindingStatus::Revoked;
            state
                .agent_audit
                .push(binding.audit(human.uid(), now, AgentAuditAction::Revoked));
        }
        let view = binding.view();
        if changed {
            for request in &mut state.requests {
                if request.direct.as_ref().is_some_and(|d| {
                    !d.execution_claimed
                        && d.agent_owner.as_ref().is_some_and(|a| a.binding_id == id)
                        && matches!(
                            d.review.status,
                            DirectStatus::Pending | DirectStatus::Approved
                        )
                }) {
                    request.transition(DirectStatus::Expired, DecisionOutcome::Invalidated, now)?;
                }
            }
            self.store.write_state(&state)?;
        }
        self.state = state;
        Ok(view)
    }
    /// OS-bound lookup is a prerequisite only; it never authenticates a signature.
    #[allow(dead_code)] // Shared with the later signed transport.
    pub(crate) fn agent_binding_for_peer(
        &self,
        id: &str,
        uid: u32,
        groups: &[u32],
    ) -> Result<super::direct_request::AgentOwner, super::direct_request::DirectRequestError> {
        use super::direct_request::*;
        self.store
            .read_state()?
            .pairings
            .iter()
            .find(|b| b.id == id && b.matches_os(uid, groups))
            .map(AgentOwner::from_binding)
            .ok_or(DirectRequestError::Unauthorized)
    }
    pub(crate) fn eligible_agent_ids(
        &self,
        uid: u32,
        groups: &[u32],
    ) -> Result<Vec<String>, super::protocol::AgentRejection> {
        use super::protocol::AgentRejection;
        if uid == self.owner_uid() {
            return Err(AgentRejection::Unauthorized);
        }
        Ok(self
            .store
            .read_state()
            .map_err(|_error| AgentRejection::Unavailable)?
            .pairings
            .iter()
            .filter(|binding| binding.matches_os(uid, groups))
            .map(|binding| binding.id.clone())
            .collect())
    }

    pub(crate) fn authenticate_agent(
        &self,
        uid: u32,
        groups: &[u32],
        input: &super::protocol::SignedSubmission,
    ) -> Result<super::direct_request::AgentOwner, super::protocol::AgentRejection> {
        use super::protocol::AgentRejection;
        if uid == self.owner_uid() {
            return Err(AgentRejection::Unauthorized);
        }
        let state = self
            .store
            .read_state()
            .map_err(|_error| AgentRejection::Unavailable)?;
        let binding = state
            .pairings
            .iter()
            .find(|binding| binding.id == input.binding_id && binding.matches_os(uid, groups))
            .ok_or(AgentRejection::Unauthorized)?;
        input.verify(&binding.public_key)?;
        Ok(super::direct_request::AgentOwner::from_binding(binding))
    }

    pub(crate) fn create_signed(
        &mut self,
        owner: super::direct_request::AgentOwner,
        input: super::protocol::SignedSubmission,
        now: u64,
        expires: u64,
        still_authorized: impl Fn() -> bool,
    ) -> Result<super::direct_request::DirectReview, super::protocol::AgentRejection> {
        use super::{direct_request::DirectSubmission, protocol::AgentRejection};
        if input.binding_id != owner.binding_id {
            return Err(AgentRejection::Unauthorized);
        }
        let marker = input.replay_digest()?;
        let state = self
            .store
            .read_state()
            .map_err(|_error| AgentRejection::Unavailable)?;
        if state.query_replay_markers.contains(&marker)
            || state.requests.iter().any(|request| {
                request
                    .direct
                    .as_ref()
                    .is_some_and(|record| record.replay_digest.as_ref() == Some(&marker))
            })
        {
            return Err(AgentRejection::Replay);
        }
        self.create_owned(
            owner.uid,
            Some(owner),
            Some(marker),
            DirectSubmission {
                operation: input.operation_id,
                revision: Some(input.expected_policy_revision),
                values: input.args,
            },
            now,
            expires,
            still_authorized,
        )
        .map_err(Into::into)
    }

    fn agent_current(
        state: &ProviderState,
        owner: &Option<super::direct_request::AgentOwner>,
    ) -> bool {
        owner.as_ref().is_none_or(|owner| {
            state.pairings.iter().any(|b| {
                owner.matches(b) && b.status == super::agent_binding::AgentBindingStatus::Enabled
            })
        })
    }
    pub(crate) fn authenticate_status_query(
        &self,
        uid: u32,
        groups: &[u32],
        query: &super::protocol::SignedStatusQuery,
    ) -> Result<super::direct_request::AgentOwner, super::protocol::AgentRejection> {
        use super::{direct_request::AgentOwner, protocol::AgentRejection};
        if uid == self.owner_uid() {
            return Err(AgentRejection::Unauthorized);
        }
        let state = self
            .store
            .read_state()
            .map_err(|_error| AgentRejection::Unavailable)?;
        let binding = state
            .pairings
            .iter()
            .find(|binding| binding.id == query.binding_id && binding.matches_os(uid, groups))
            .ok_or(AgentRejection::Unauthorized)?;
        query.verify(&binding.public_key)?;
        let owner = AgentOwner::from_binding(binding);
        // Check ownership before replay so inaccessible IDs have one rejection.
        Self::owned_agent_status(&state, &owner, &query.request_id)?;
        Ok(owner)
    }
    fn owned_agent_status(
        state: &ProviderState,
        owner: &super::direct_request::AgentOwner,
        id: &str,
    ) -> Result<super::direct_request::DirectStatus, super::protocol::AgentRejection> {
        state
            .requests
            .iter()
            .find(|request| request.id == id)
            .and_then(|request| request.direct.as_ref())
            .filter(|record| record.agent_owner.as_ref() == Some(owner))
            .map(|record| record.review.status.clone())
            .ok_or(super::protocol::AgentRejection::Unauthorized)
    }
    pub(crate) fn consume_status_query(
        &mut self,
        owner: &super::direct_request::AgentOwner,
        query: &super::protocol::SignedStatusQuery,
        still_authorized: impl Fn() -> bool,
    ) -> Result<(), super::protocol::AgentRejection> {
        use super::protocol::AgentRejection;
        let mut state = self
            .store
            .read_state()
            .map_err(|_error| AgentRejection::Unavailable)?;
        if query.binding_id != owner.binding_id
            || !Self::agent_current(&state, &Some(owner.clone()))
        {
            return Err(AgentRejection::Unauthorized);
        }
        Self::owned_agent_status(&state, owner, &query.request_id)?;
        let marker = query.replay_digest()?;
        if state.query_replay_markers.contains(&marker)
            || state.requests.iter().any(|request| {
                request
                    .direct
                    .as_ref()
                    .is_some_and(|record| record.replay_digest.as_ref() == Some(&marker))
            })
        {
            return Err(AgentRejection::Replay);
        }
        state.query_replay_markers.push(marker);
        self.store
            .write_state_guarded(&state, still_authorized)
            .map_err(|error| {
                if error.diagnostic() == ProviderDiagnostic::ExpiredAccessRequest {
                    AgentRejection::Unauthorized
                } else {
                    AgentRejection::Unavailable
                }
            })?;
        self.state = state;
        Ok(())
    }
    /// Exact immutable ownership, distinct from human administration authority.
    #[allow(dead_code)] // The polling transport will supply authenticated OS/signature evidence.
    pub(crate) fn agent_status(
        &self,
        owner: &super::direct_request::AgentOwner,
        uid: u32,
        groups: &[u32],
        id: &str,
    ) -> Result<super::direct_request::DirectStatus, super::direct_request::DirectRequestError>
    {
        use super::direct_request::*;
        let state = self.store.read_state()?;
        if !state
            .pairings
            .iter()
            .any(|b| owner.matches(b) && b.matches_os(uid, groups))
        {
            return Err(DirectRequestError::Unauthorized);
        }
        state
            .requests
            .iter()
            .find(|r| r.id == id)
            .and_then(|r| r.direct.as_ref())
            .filter(|d| d.agent_owner.as_ref() == Some(owner))
            .map(|d| d.review.status.clone())
            .ok_or(DirectRequestError::NotFound)
    }
    pub(crate) fn history(
        &self,
        owner: super::direct_request::AuthenticatedHuman,
        limit: Option<u32>,
    ) -> Result<Vec<super::history::HistoryEvent>, super::direct_request::DirectRequestError> {
        if owner.uid() != self.owner_uid() {
            return Err(super::direct_request::DirectRequestError::Unauthorized);
        }
        let limit = super::history::limit(limit)?;
        let state = self.store.read_state()?;
        Ok(super::history::newest(
            state
                .requests
                .into_iter()
                .filter_map(|r| r.direct)
                .filter(|d| d.human_visible(owner, self.owner_uid()))
                .flat_map(|d| d.audit)
                .collect(),
            limit,
        ))
    }
    pub(crate) fn create_direct(
        &mut self,
        owner: super::direct_request::AuthenticatedHuman,
        input: super::direct_request::DirectSubmission,
        now: u64,
        expires: u64,
        still_authorized: impl Fn() -> bool,
    ) -> Result<super::direct_request::DirectReview, super::direct_request::DirectRequestError>
    {
        self.create_owned(
            owner.uid(),
            None,
            None,
            input,
            now,
            expires,
            still_authorized,
        )
    }
    #[cfg(test)]
    pub(crate) fn create_agent_for_test(
        &mut self,
        owner: super::direct_request::AgentOwner,
        input: super::direct_request::DirectSubmission,
        now: u64,
        expires: u64,
        still_authorized: impl Fn() -> bool,
    ) -> Result<super::direct_request::DirectReview, super::direct_request::DirectRequestError>
    {
        self.create_owned(
            owner.uid,
            Some(owner),
            None,
            input,
            now,
            expires,
            still_authorized,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn create_owned(
        &mut self,
        uid: u32,
        agent_owner: Option<super::direct_request::AgentOwner>,
        replay_digest: Option<String>,
        input: super::direct_request::DirectSubmission,
        now: u64,
        expires: u64,
        still_authorized: impl Fn() -> bool,
    ) -> Result<super::direct_request::DirectReview, super::direct_request::DirectRequestError>
    {
        use super::direct_request::*;
        if !super::valid_operation_id(&input.operation)
            || input
                .revision
                .as_ref()
                .is_some_and(|v| !super::valid_sha256(v))
        {
            return Err(DirectRequestError::InvalidRequest);
        }
        let is_agent = agent_owner.is_some();
        let mut state = self.store.read_state()?;
        if !Self::agent_current(&state, &agent_owner) {
            return Err(DirectRequestError::Unauthorized);
        }
        let policy = state
            .operations
            .iter()
            .find(|p| p.id() == input.operation)
            .ok_or(DirectRequestError::InvalidRequest)?;
        if input
            .revision
            .as_ref()
            .is_some_and(|r| r != policy.revision())
        {
            return Err(DirectRequestError::StaleRevision);
        }
        let args = policy
            .normalize_args(&input.values)
            .map_err(|_error| DirectRequestError::InvalidRequest)?;
        if !still_authorized() {
            return Err(DirectRequestError::Locked);
        }
        let id = super::RequestId::new_random()
            .map_err(|_error| DirectRequestError::Unavailable)?
            .as_str()
            .to_owned();
        let mut review = policy.direct_review(id.clone(), args, expires);
        if let Some(owner) = &agent_owner {
            review.requester = owner.review_requester();
        }
        let mut direct = DirectRecord {
            owner_uid: uid,
            agent_owner,
            replay_digest,
            created_at_unix_seconds: now,
            lifecycle_epoch: state.lifecycle_epoch,
            review: review.clone(),
            binding_digest: String::new(),
            approval: None,
            execution_claimed: false,
            audit: Vec::new(),
            history_version: super::history::HISTORY_VERSION,
        };
        direct.seal();
        direct.audit.push(super::history::HistoryEvent::snapshot(
            &direct,
            0,
            now,
            super::history::HistoryOutcome::Submitted,
            Some(DirectStatus::Pending),
        ));
        state.requests.push(super::provider_store::RequestRecord {
            id,
            status: super::provider_store::RequestLifecycleStatus::Pending,
            direct: Some(direct),
        });
        if is_agent {
            self.store
                .write_state_guarded(&state, still_authorized)
                .map_err(|error| {
                    if error.diagnostic() == ProviderDiagnostic::ExpiredAccessRequest {
                        DirectRequestError::Locked
                    } else {
                        DirectRequestError::Unavailable
                    }
                })?;
        } else {
            self.store.write_state(&state)?;
        }
        self.state = state;
        Ok(review)
    }
    pub(crate) fn expire_direct(
        &mut self,
        now: std::time::Duration,
        wall: impl Fn() -> Result<u64, super::ports::SessionError>,
        deadlines: &std::collections::HashMap<String, std::time::Duration>,
    ) -> Result<(), ProviderError> {
        let mut state = self.store.read_state()?;
        let mut changed = false;
        for request in &mut state.requests {
            if request
                .direct
                .as_ref()
                .is_some_and(|d| !d.execution_claimed)
                && matches!(
                    request.status,
                    super::provider_store::RequestLifecycleStatus::Pending
                        | super::provider_store::RequestLifecycleStatus::Approved
                )
                && deadlines
                    .get(&request.id)
                    .is_none_or(|deadline| now >= *deadline)
            {
                request.transition(
                    super::direct_request::DirectStatus::Expired,
                    super::direct_request::DecisionOutcome::Expired,
                    wall()
                        .map_err(|_error| ProviderError::new(ProviderDiagnostic::InvalidState))?,
                )?;
                changed = true;
            }
        }
        if changed {
            self.store.write_state(&state)?;
        }
        self.state = state;
        Ok(())
    }
    pub(crate) fn pending_direct_ids(
        &self,
        owner: super::direct_request::AuthenticatedHuman,
    ) -> Result<Vec<String>, super::direct_request::DirectRequestError> {
        use super::direct_request::DirectStatus;
        Ok(self
            .store
            .read_state()?
            .requests
            .iter()
            .filter_map(|r| r.direct.as_ref())
            .filter(|d| {
                d.human_visible(owner, self.owner_uid()) && d.review.status == DirectStatus::Pending
            })
            .take(256)
            .map(|d| d.review.id.clone())
            .collect())
    }
    pub(crate) fn direct_review(
        &self,
        owner: super::direct_request::AuthenticatedHuman,
        id: &str,
    ) -> Result<super::direct_request::DirectReview, super::direct_request::DirectRequestError>
    {
        use super::direct_request::*;
        if !valid_request_id(id) {
            return Err(DirectRequestError::NotFound);
        }
        self.store
            .read_state()?
            .requests
            .iter()
            .find(|r| r.id == id)
            .and_then(|r| r.direct.as_ref())
            .filter(|d| d.human_visible(owner, self.owner_uid()))
            .map(|d| d.review.clone())
            .ok_or(DirectRequestError::NotFound)
    }
    pub(crate) fn fail_direct_launch(&mut self, id: &str) -> Result<(), ProviderError> {
        use super::{direct_request::*, provider_store::RequestLifecycleStatus};
        let mut state = self.store.read_state()?;
        if let Some(request) = state
            .requests
            .iter_mut()
            .find(|r| r.id == id && r.status == RequestLifecycleStatus::Pending)
        {
            request.transition(
                DirectStatus::Expired,
                DecisionOutcome::ReviewUnavailable,
                super::provider_store::provider_wall_time()?,
            )?;
            self.store.write_state(&state)?;
        }
        self.state = state;
        Ok(())
    }

    pub(crate) fn prepare_direct(
        &self,
        owner: super::direct_request::AuthenticatedHuman,
        id: &str,
    ) -> Result<super::direct_request::ApprovalBinding, super::direct_request::DirectRequestError>
    {
        use super::direct_request::*;
        let state = self.store.read_state()?;
        let direct = state
            .requests
            .iter()
            .find(|r| r.id == id)
            .and_then(|r| r.direct.as_ref())
            .filter(|d| d.human_visible(owner, self.owner_uid()))
            .ok_or(DirectRequestError::NotFound)?;
        if !Self::agent_current(&state, &direct.agent_owner) {
            return Err(DirectRequestError::Unauthorized);
        }
        if direct.review.status != DirectStatus::Pending {
            return Err(DirectRequestError::AlreadyDecided);
        }
        if direct.lifecycle_epoch != state.lifecycle_epoch {
            return Err(DirectRequestError::Unavailable);
        }
        let policy = state
            .operations
            .iter()
            .find(|p| p.id() == direct.review.operation)
            .ok_or(DirectRequestError::StaleRevision)?;
        if policy.revision() != direct.review.policy_digest {
            return Err(DirectRequestError::StaleRevision);
        }
        if !policy.validates_args(&direct.review.arguments) {
            return Err(DirectRequestError::InvalidRequest);
        }
        Ok(direct.approval_binding())
    }
    /// Rebuild approved authority from one durable snapshot. A returned image
    /// selection is only preparation input; it never consumes approval.
    #[allow(dead_code)] // Story 1.7 consumes preparation under live authority.
    pub(crate) fn approved_execution(
        &self,
        owner: super::direct_request::AuthenticatedHuman,
        id: &str,
    ) -> Result<
        (
            super::direct_request::ApprovalBinding,
            OperationPolicy,
            Vec<String>,
        ),
        super::direct_request::DirectRequestError,
    > {
        use super::direct_request::*;
        let state = self.store.read_state()?;
        let direct = state
            .requests
            .iter()
            .find(|r| r.id == id)
            .and_then(|r| r.direct.as_ref())
            .filter(|d| d.human_visible(owner, self.owner_uid()))
            .ok_or(DirectRequestError::NotFound)?;
        if !Self::agent_current(&state, &direct.agent_owner) {
            return Err(DirectRequestError::Unauthorized);
        }
        if direct.review.status != DirectStatus::Approved {
            return Err(DirectRequestError::AlreadyDecided);
        }
        let binding = direct.approval_binding();
        if direct.lifecycle_epoch != state.lifecycle_epoch
            || direct.approval.as_ref() != Some(&binding)
            || direct.review.one_time != ONE_TIME
        {
            return Err(DirectRequestError::Unavailable);
        }
        let policy = state
            .operations
            .iter()
            .find(|p| p.id() == direct.review.operation)
            .ok_or(DirectRequestError::StaleRevision)?;
        if policy.revision() != direct.review.policy_digest {
            return Err(DirectRequestError::StaleRevision);
        }
        let arguments = policy
            .normalize_args(&direct.review.arguments)
            .map_err(|_error| DirectRequestError::InvalidRequest)?;
        let mut expected = policy.direct_review(
            id.to_owned(),
            arguments.clone(),
            direct.review.expires_at_unix_seconds,
        );
        expected.status = DirectStatus::Approved;
        expected.requester = direct.review.requester.clone();
        if arguments != direct.review.arguments || expected != direct.review {
            return Err(DirectRequestError::InvalidRequest);
        }
        let mut argv = Vec::with_capacity(arguments.len() + 1);
        argv.push(policy.id().to_owned());
        argv.extend(arguments);
        Ok((binding, policy.clone(), argv))
    }

    /// Called under the application claim/release gates only when no active
    /// execution is registered. No process can exist for an unclaimed approval.
    pub(crate) fn cancel_unclaimed_execution(
        &mut self,
        owner: super::direct_request::AuthenticatedHuman,
        id: &str,
    ) -> Result<(), super::direct_request::DirectRequestError> {
        use super::direct_request::*;
        let mut state = self.store.read_state()?;
        let request = state
            .requests
            .iter_mut()
            .find(|request| request.id == id)
            .ok_or(DirectRequestError::NotFound)?;
        let direct = request
            .direct
            .as_ref()
            .filter(|direct| direct.human_visible(owner, self.owner_uid()))
            .ok_or(DirectRequestError::NotFound)?;
        if direct.review.status != DirectStatus::Approved || direct.execution_claimed {
            return Err(DirectRequestError::AlreadyDecided);
        }
        request.transition(
            DirectStatus::Expired,
            DecisionOutcome::ExecutionUnavailable,
            super::provider_store::provider_wall_time()?,
        )?;
        self.store.write_state(&state)?;
        self.state = state;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn claim_execution(
        &mut self,
        owner: super::direct_request::AuthenticatedHuman,
        id: &str,
        still_authorized: impl Fn() -> bool,
    ) -> Result<super::direct_request::ApprovalBinding, super::direct_request::DirectRequestError>
    {
        use super::direct_request::*;
        let mut state = self.store.read_state()?;
        let lifecycle_epoch = state.lifecycle_epoch;
        let owner_snapshot = state
            .requests
            .iter()
            .find(|r| r.id == id)
            .and_then(|r| r.direct.as_ref())
            .and_then(|d| d.agent_owner.clone());
        if !Self::agent_current(&state, &owner_snapshot) {
            return Err(DirectRequestError::Unauthorized);
        }
        let request = state
            .requests
            .iter_mut()
            .find(|request| request.id == id)
            .ok_or(DirectRequestError::NotFound)?;
        let request_status = request.status;
        let direct = request
            .direct
            .as_mut()
            .filter(|direct| direct.human_visible(owner, self.owner_uid()))
            .ok_or(DirectRequestError::NotFound)?;
        if request_status != super::provider_store::RequestLifecycleStatus::Approved
            || direct.review.status != DirectStatus::Approved
            || direct.execution_claimed
        {
            return Err(DirectRequestError::AlreadyDecided);
        }
        let binding = direct.approval_binding();
        if direct.lifecycle_epoch != lifecycle_epoch || direct.approval.as_ref() != Some(&binding) {
            return Err(DirectRequestError::Unavailable);
        }
        direct.execution_claimed = true;
        self.store.write_state_guarded(&state, still_authorized)?;
        self.state = state;
        Ok(binding)
    }

    pub(crate) fn execution_matches(
        &self,
        binding: &super::direct_request::ApprovalBinding,
    ) -> Result<bool, super::direct_request::DirectRequestError> {
        let state = self.store.read_state()?;
        Ok(Self::agent_current(&state, &binding.agent_owner)
            && state.lifecycle_epoch == binding.lifecycle_epoch
            && state
                .operations
                .iter()
                .any(|p| p.revision() == binding.policy_digest)
            && state
                .requests
                .iter()
                .filter_map(|r| r.direct.as_ref())
                .any(|d| {
                    d.execution_claimed
                        && d.approval.as_ref() == Some(binding)
                        && matches!(
                            d.review.status,
                            super::direct_request::DirectStatus::Approved
                                | super::direct_request::DirectStatus::Running
                        )
                }))
    }
    pub(crate) fn execution_started(
        &mut self,
        binding: &super::direct_request::ApprovalBinding,
    ) -> Result<(), super::direct_request::DirectRequestError> {
        use super::direct_request::*;
        let mut state = self.store.read_state()?;
        let request = state
            .requests
            .iter_mut()
            .find(|r| r.id == binding.request_id)
            .ok_or(DirectRequestError::NotFound)?;
        let direct = request
            .direct
            .as_ref()
            .ok_or(DirectRequestError::NotFound)?;
        if !direct.execution_claimed
            || direct.approval.as_ref() != Some(binding)
            || direct.review.status != DirectStatus::Approved
        {
            return Err(DirectRequestError::Unavailable);
        }
        request.transition(
            DirectStatus::Running,
            DecisionOutcome::Approved,
            super::provider_store::provider_wall_time()?,
        )?;
        self.store.write_state(&state)?;
        self.state = state;
        Ok(())
    }
    pub(crate) fn finish_execution(
        &mut self,
        binding: &super::direct_request::ApprovalBinding,
        status: super::direct_request::DirectStatus,
        cleanup: super::ports::CleanupEvidence,
    ) -> Result<(), super::direct_request::DirectRequestError> {
        use super::{direct_request::*, ports::CleanupEvidence};
        if cleanup == CleanupEvidence::Uncertain
            || !matches!(
                status,
                DirectStatus::Completed { .. } | DirectStatus::Failed { .. }
            )
        {
            return Err(DirectRequestError::Unavailable);
        }
        let mut state = self.store.read_state()?;
        let request = state
            .requests
            .iter_mut()
            .find(|r| r.id == binding.request_id)
            .ok_or(DirectRequestError::NotFound)?;
        let direct = request
            .direct
            .as_ref()
            .ok_or(DirectRequestError::NotFound)?;
        if !direct.execution_claimed
            || direct.approval.as_ref() != Some(binding)
            || !matches!(
                direct.review.status,
                DirectStatus::Approved | DirectStatus::Running
            )
            || (direct.review.status == DirectStatus::Running && cleanup != CleanupEvidence::Reaped)
            || (matches!(status, DirectStatus::Completed { .. })
                && (cleanup != CleanupEvidence::Reaped
                    || direct.review.status != DirectStatus::Running))
        {
            return Err(DirectRequestError::Unavailable);
        }
        let outcome = if matches!(status, DirectStatus::Completed { .. }) {
            DecisionOutcome::Approved
        } else {
            DecisionOutcome::ExecutionUnavailable
        };
        request.transition(
            status,
            outcome,
            super::provider_store::provider_wall_time()?,
        )?;
        // Cleanup authority survives revocation of launch authority.
        self.store.write_state(&state)?;
        self.state = state;
        Ok(())
    }
    pub(crate) fn decision_policy(
        &self,
        binding: &super::direct_request::ApprovalBinding,
    ) -> Result<OperationPolicy, super::direct_request::DirectRequestError> {
        use super::direct_request::*;
        let owner = AuthenticatedHuman::from_peer_uid(if binding.agent_owner.is_some() {
            self.owner_uid()
        } else {
            binding.requester_uid
        });
        if self.prepare_direct(owner, &binding.request_id)? != *binding {
            return Err(DirectRequestError::InvalidRequest);
        }
        self.store
            .read_state()?
            .operations
            .into_iter()
            .find(|p| p.revision() == binding.policy_digest)
            .ok_or(DirectRequestError::StaleRevision)
    }
    pub(crate) fn decide_direct(
        &mut self,
        binding: &super::direct_request::ApprovalBinding,
        approve: bool,
        now: u64,
        still_authorized: impl Fn() -> bool,
    ) -> Result<super::direct_request::DirectStatus, super::direct_request::DirectRequestError>
    {
        use super::direct_request::*;
        if self.prepare_direct(
            AuthenticatedHuman::from_peer_uid(if binding.agent_owner.is_some() {
                self.owner_uid()
            } else {
                binding.requester_uid
            }),
            &binding.request_id,
        )? != *binding
        {
            return Err(DirectRequestError::InvalidRequest);
        }
        let mut state = self.store.read_state()?;
        let request = state
            .requests
            .iter_mut()
            .find(|r| r.id == binding.request_id)
            .ok_or(DirectRequestError::NotFound)?;
        let (next, outcome) = if approve {
            (DirectStatus::Approved, DecisionOutcome::Approved)
        } else {
            (DirectStatus::Denied, DecisionOutcome::Denied)
        };
        request.transition(next.clone(), outcome, now)?;
        self.store.write_state_guarded(&state, still_authorized)?;
        self.state = state;
        Ok(next)
    }

    /// Checks the registry-owned image before the backend eligibility port and
    /// only advances in-memory authority after durable replacement succeeds.
    #[cfg(test)]
    pub(crate) fn activate_operation<V: LoginEligibilityVerifier>(
        &mut self,
        draft: OperationPolicyDraft,
        verifier: &V,
    ) -> Result<String, ProviderError> {
        self.activate_operation_checked(draft, verifier, || true)
    }

    #[cfg(test)]
    pub(crate) fn activate_operation_checked<V: LoginEligibilityVerifier>(
        &mut self,
        draft: OperationPolicyDraft,
        verifier: &V,
        still_authorized: impl Fn() -> bool,
    ) -> Result<String, ProviderError> {
        self.provision_operation(draft, verifier, false, still_authorized)
    }

    pub(crate) fn provision_operation<V: LoginEligibilityVerifier>(
        &mut self,
        draft: OperationPolicyDraft,
        verifier: &V,
        create_only: bool,
        still_authorized: impl Fn() -> bool,
    ) -> Result<String, ProviderError> {
        let state = self.store.read_state()?;
        if create_only
            && state
                .operations
                .iter()
                .any(|policy| policy.id() == draft.id)
        {
            return Err(ProviderError::new(ProviderDiagnostic::Conflict));
        }
        let Some(image) = state
            .approved_images
            .iter()
            .find(|image| image.id() == draft.image_id)
        else {
            return Err(ProviderError::new(
                ProviderDiagnostic::InvalidOperationPolicy,
            ));
        };
        let policy = OperationPolicy::from_draft(draft, image)
            .map_err(|_error| ProviderError::new(ProviderDiagnostic::InvalidOperationPolicy))?;
        if let Some(ssh) = policy.ssh()
            && !verifier
                .is_ssh_eligible(&ssh.credential.item_id)
                .unwrap_or(false)
        {
            return Err(ProviderError::new(ProviderDiagnostic::CredentialIneligible));
        }
        let marker = format!("vw-access={}", policy.id());
        for binding in policy.login_bindings() {
            if !verifier
                .is_login_eligible(binding.item_id, &binding.required_fields, &marker)
                .unwrap_or(false)
            {
                return Err(ProviderError::new(ProviderDiagnostic::CredentialIneligible));
            }
        }
        if !still_authorized() {
            return Err(ProviderError::new(ProviderDiagnostic::CredentialIneligible));
        }
        let revision = policy.revision().to_owned();
        let updated = self
            .store
            .upsert_operation_guarded(&state, policy, still_authorized)?;
        self.state = updated;
        Ok(revision)
    }

    pub(crate) fn register_image(
        &mut self,
        input: super::policy::ImageRegistration,
        verifier: &dyn super::ports::ImageVerifier,
        still_authorized: impl Fn() -> bool,
    ) -> Result<super::policy::ImageRegistration, ProviderError> {
        let mut state = self.store.read_state()?;
        if state
            .approved_images
            .iter()
            .any(|image| image.id() == input.id)
        {
            return Err(ProviderError::new(ProviderDiagnostic::Conflict));
        }
        let image = super::policy::ApprovedImage::from_registration(input)
            .map_err(|_error| ProviderError::new(ProviderDiagnostic::InvalidOperationPolicy))?;
        verifier.verify(image.execution_image()).map_err(|error| {
            ProviderError::new(match error {
                // An unavailable preparation environment cannot establish safe authority.
                super::ports::ExecutionError::Unavailable => ProviderDiagnostic::UnsafeState,
                _ => ProviderDiagnostic::InvalidOperationPolicy,
            })
        })?;
        let metadata = image.metadata();
        state.approved_images.push(image);
        self.store.write_state_guarded(&state, still_authorized)?;
        self.state = state;
        Ok(metadata)
    }

    pub(crate) fn images(&self) -> Result<Vec<super::policy::ImageRegistration>, ProviderError> {
        Ok(self
            .store
            .read_state()?
            .approved_images
            .iter()
            .map(|image| image.metadata())
            .collect())
    }
    pub(crate) fn operations(&self) -> Result<Vec<super::policy::OperationSummary>, ProviderError> {
        Ok(self
            .store
            .read_state()?
            .operations
            .iter()
            .map(|policy| policy.summary())
            .collect())
    }
    pub(crate) fn operation(
        &self,
        id: &str,
    ) -> Result<Option<super::policy::OperationMetadata>, ProviderError> {
        Ok(self
            .store
            .read_state()?
            .operations
            .iter()
            .find(|policy| policy.id() == id)
            .map(|policy| policy.metadata()))
    }

    /// This preflight is deliberately side-effect free and must run before an
    /// approval prompt or secret-resolution capability is reachable.
    pub fn preflight_request(&self, request: &AccessRequest) -> Result<(), ProviderError> {
        request
            .validate()
            .map_err(|_error| ProviderError::new(ProviderDiagnostic::InvalidOperationPolicy))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_error| ProviderError::new(ProviderDiagnostic::InvalidState))?
            .as_secs();
        if request.is_expired_at(now) {
            return Err(ProviderError::new(ProviderDiagnostic::ExpiredAccessRequest));
        }
        // Reload under the stable writer lock so a changed/deleted image,
        // registry mismatch, or on-disk tampering cannot be admitted from a
        // stale in-memory policy.
        let state = self.store.read_state()?;
        let Some(policy) = state
            .operations
            .iter()
            .find(|policy| policy.id() == request.operation_id)
        else {
            return Err(ProviderError::new(
                ProviderDiagnostic::InvalidOperationPolicy,
            ));
        };
        if policy.revision() != request.operation_revision {
            return Err(ProviderError::new(
                ProviderDiagnostic::StaleOperationPolicyRevision,
            ));
        }
        if !policy.validates_args(&request.args) {
            return Err(ProviderError::new(
                ProviderDiagnostic::InvalidOperationPolicy,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::policy::{
        ArgumentSpec, CredentialUse, LoginCredentialDraft, LoginField, LoginFieldMapping,
        test_approved_image,
    };
    use crate::access::ports::LoginEligibilityError;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    const ITEM: &str = "11111111-1111-1111-1111-111111111111";
    fn temp() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }
    fn draft() -> OperationPolicyDraft {
        OperationPolicyDraft {
            ssh: None,
            id: "deploy-homelab".into(),
            description: "Deploy".into(),
            image_id: "deploy-image".into(),
            targets: vec!["staging".into()],
            arguments: vec![ArgumentSpec::Target],
            credentials: vec![LoginCredentialDraft {
                item_id: ITEM.into(),
                label: "login".into(),
                use_type: CredentialUse::Login,
                field_mappings: vec![LoginFieldMapping {
                    field: LoginField::Password,
                    environment: "DEPLOY_PASSWORD".into(),
                }],
            }],
        }
    }
    struct Eligible;
    impl LoginEligibilityVerifier for Eligible {
        fn is_login_eligible(
            &self,
            item: &str,
            fields: &[LoginField],
            marker: &str,
        ) -> Result<bool, LoginEligibilityError> {
            Ok(item == ITEM
                && fields == [LoginField::Password]
                && marker == "vw-access=deploy-homelab")
        }
    }
    fn provision_for_test(provider: &mut Provider, image: crate::access::policy::ApprovedImage) {
        provider.state.approved_images.push(image);
        provider.store.write_state(&provider.state).unwrap();
    }
    #[test]
    fn startup_cleanup_precedes_registered_image_integrity_validation() {
        let temp = temp();
        let root = temp.path().join("provider");
        let provider = Provider::start(&root).unwrap();
        let image = test_approved_image(temp.path(), "deploy-image");
        let path = root.join("provider-state.json");
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        state["approved_images"] = serde_json::json!([image]);
        fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        drop(provider);
        fs::set_permissions(
            temp.path().join("approved-image"),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        fs::write(temp.path().join("approved-image"), b"modified executable").unwrap();
        let cleared = std::cell::Cell::new(false);
        let result = Provider::start_with_cleanup(&root, || {
            cleared.set(true);
            Ok(())
        });
        assert_eq!(
            result.unwrap_err().diagnostic(),
            ProviderDiagnostic::InvalidState
        );
        assert!(cleared.get());
    }

    #[test]
    fn activation_requires_registry_id_and_exact_login_binding() {
        let temp = temp();
        let root = temp.path().join("provider");
        let mut provider = Provider::start(&root).unwrap();
        assert_eq!(
            provider
                .activate_operation(draft(), &Eligible)
                .unwrap_err()
                .diagnostic(),
            ProviderDiagnostic::InvalidOperationPolicy
        );
        provision_for_test(
            &mut provider,
            test_approved_image(temp.path(), "deploy-image"),
        );
        let revision = provider.activate_operation(draft(), &Eligible).unwrap();
        let request = AccessRequest::new(
            "agent",
            "deploy-homelab",
            revision,
            vec!["staging".into()],
            60,
        )
        .unwrap();
        assert!(provider.preflight_request(&request).is_ok());
        drop(provider);
        let reopened = Provider::start(&root).unwrap();
        assert_eq!(reopened.state.operations.len(), 1);
        assert!(reopened.preflight_request(&request).is_ok());
    }
    #[test]
    fn stale_revision_precedes_argument_processing_and_mutates_nothing() {
        let temp = temp();
        let root = temp.path().join("provider");
        let mut provider = Provider::start(&root).unwrap();
        provision_for_test(
            &mut provider,
            test_approved_image(temp.path(), "deploy-image"),
        );
        provider.activate_operation(draft(), &Eligible).unwrap();
        let stale = AccessRequest::new(
            "agent",
            "deploy-homelab",
            "a".repeat(64),
            vec!["bad".into()],
            60,
        )
        .unwrap();
        assert_eq!(
            provider.preflight_request(&stale).unwrap_err().diagnostic(),
            ProviderDiagnostic::StaleOperationPolicyRevision
        );
        assert!(provider.state.requests.is_empty());
    }
    #[test]
    fn poisoned_store_blocks_preflight_before_stale_memory_is_admitted() {
        let temp = temp();
        let root = temp.path().join("provider");
        let mut provider = Provider::start(&root).unwrap();
        provision_for_test(
            &mut provider,
            test_approved_image(temp.path(), "deploy-image"),
        );
        let revision = provider.activate_operation(draft(), &Eligible).unwrap();
        let request = AccessRequest::new(
            "agent",
            "deploy-homelab",
            revision,
            vec!["staging".into()],
            60,
        )
        .unwrap();
        provider.store.poison_for_test();
        assert_eq!(
            provider
                .preflight_request(&request)
                .unwrap_err()
                .diagnostic(),
            ProviderDiagnostic::UnsafeState
        );
    }
    #[test]
    fn preflight_uses_revalidated_durable_state_not_a_stale_cache() {
        let temp = temp();
        let root = temp.path().join("provider");
        let mut provider = Provider::start(&root).unwrap();
        provision_for_test(
            &mut provider,
            test_approved_image(temp.path(), "deploy-image"),
        );
        let revision = provider.activate_operation(draft(), &Eligible).unwrap();
        let request = AccessRequest::new(
            "agent",
            "deploy-homelab",
            revision,
            vec!["staging".into()],
            60,
        )
        .unwrap();
        let mut altered = provider.store.read_state().unwrap();
        altered.operations.clear();
        provider.store.write_state(&altered).unwrap();
        assert_eq!(
            provider
                .preflight_request(&request)
                .unwrap_err()
                .diagnostic(),
            ProviderDiagnostic::InvalidOperationPolicy
        );
    }
    #[test]
    fn stable_diagnostics_are_redacted() {
        assert_eq!(
            ProviderDiagnostic::CredentialIneligible.to_string(),
            "credential is not eligible"
        );
        assert_eq!(
            ProviderDiagnostic::StaleOperationPolicyRevision.to_string(),
            "stale operation policy revision"
        );
    }
}
