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
        let state = store.invalidate_unexecuted()?;
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
    pub(crate) fn create_direct(
        &mut self,
        owner: super::direct_request::AuthenticatedHuman,
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
        let mut state = self.store.read_state()?;
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
        let review = policy.direct_review(id.clone(), args, expires);
        let mut direct = DirectRecord {
            owner_uid: owner.uid(),
            created_at_unix_seconds: now,
            lifecycle_epoch: state.lifecycle_epoch,
            review: review.clone(),
            binding_digest: String::new(),
            approval: None,
            audit: Vec::new(),
        };
        direct.seal();
        state.requests.push(super::provider_store::RequestRecord {
            id,
            status: super::provider_store::RequestLifecycleStatus::Pending,
            direct: Some(direct),
        });
        self.store.write_state(&state)?;
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
            if request.direct.is_some()
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
            .filter(|d| d.owner_uid == owner.uid())
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
            .filter(|d| d.owner_uid == owner.uid())
            .ok_or(DirectRequestError::NotFound)?;
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
            .filter(|d| d.owner_uid == owner.uid())
            .ok_or(DirectRequestError::NotFound)?;
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
        if arguments != direct.review.arguments || expected != direct.review {
            return Err(DirectRequestError::InvalidRequest);
        }
        let mut argv = Vec::with_capacity(arguments.len() + 1);
        argv.push(policy.id().to_owned());
        argv.extend(arguments);
        Ok((binding, policy.clone(), argv))
    }
    pub(crate) fn decision_policy(
        &self,
        binding: &super::direct_request::ApprovalBinding,
    ) -> Result<OperationPolicy, super::direct_request::DirectRequestError> {
        use super::direct_request::*;
        let owner = AuthenticatedHuman::from_peer_uid(binding.requester_uid);
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
            AuthenticatedHuman::from_peer_uid(binding.requester_uid),
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

    pub(crate) fn activate_operation_checked<V: LoginEligibilityVerifier>(
        &mut self,
        draft: OperationPolicyDraft,
        verifier: &V,
        still_authorized: impl Fn() -> bool,
    ) -> Result<String, ProviderError> {
        let state = self.store.read_state()?;
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
        let updated = self.store.upsert_operation(&state, policy)?;
        self.state = updated;
        Ok(revision)
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
