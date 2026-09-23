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
        let mut store = ProviderStore::open(root)?;
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
        self.state = self.store.invalidate_unexecuted()?;
        self.lock_state = ProviderLockState::Locked;
        Ok(())
    }
    pub fn shutdown(&mut self) -> Result<(), ProviderError> {
        self.lock()
    }

    /// Checks the registry-owned image before the backend eligibility port and
    /// only advances in-memory authority after durable replacement succeeds.
    pub fn activate_operation<V: LoginEligibilityVerifier>(
        &mut self,
        draft: OperationPolicyDraft,
        verifier: &V,
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
            .map_err(|_| ProviderError::new(ProviderDiagnostic::InvalidOperationPolicy))?;
        let marker = format!("vw-access={}", policy.id());
        for binding in policy.login_bindings() {
            if !verifier
                .is_login_eligible(binding.item_id, &binding.required_fields, &marker)
                .unwrap_or(false)
            {
                return Err(ProviderError::new(ProviderDiagnostic::CredentialIneligible));
            }
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
            .map_err(|_| ProviderError::new(ProviderDiagnostic::InvalidOperationPolicy))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProviderError::new(ProviderDiagnostic::InvalidState))?
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
