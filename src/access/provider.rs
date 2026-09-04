//! Locked provider lifecycle foundation.
//!
//! This module intentionally has no secret-backend field or constructor. A
//! future unlocked provider must be a separate, human-approved capability.

use std::fmt;
use std::path::PathBuf;

use super::provider_store::{ProviderState, ProviderStore};

/// Stable, redacted categories suitable for daemon diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderDiagnostic {
    UnsafeState,
    InvalidState,
    PersistenceFailure,
}

impl fmt::Display for ProviderDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsafeState => "unsafe provider state",
            Self::InvalidState => "invalid provider state",
            Self::PersistenceFailure => "provider state persistence failed",
        };
        formatter.write_str(message)
    }
}

/// An error which deliberately retains no filesystem, serialized-state, or
/// backend detail for callers to render.
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

/// The startup-only provider. Its fields prove this foundation stores neither
/// a Vaultwarden backend nor an unlocked session.
#[derive(Debug)]
pub struct Provider {
    store: ProviderStore,
    lock_state: ProviderLockState,
    state: ProviderState,
}

impl Provider {
    /// Start in the locked state. Startup is itself a crash-recovery boundary,
    /// so stale unexecuted records are durably invalidated first.
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

    /// Locking never preserves an approved or running operation in memory or
    /// on disk. A write failure is returned and callers must fail closed.
    pub fn lock(&mut self) -> Result<(), ProviderError> {
        self.state = self.store.invalidate_unexecuted()?;
        self.lock_state = ProviderLockState::Locked;
        Ok(())
    }

    /// Shutdown has the same durable invalidation semantics as lock and
    /// restart. It is explicit because `Drop` cannot report durability errors.
    pub fn shutdown(&mut self) -> Result<(), ProviderError> {
        self.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::provider_store::{RequestLifecycleStatus, RequestRecord};
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::tempdir;

    fn state_path(root: &std::path::Path) -> std::path::PathBuf {
        root.join("provider-state.json")
    }

    #[test]
    fn redacted_diagnostics_have_stable_operator_rendering() {
        assert_eq!(
            ProviderDiagnostic::UnsafeState.to_string(),
            "unsafe provider state"
        );
        assert_eq!(
            ProviderDiagnostic::InvalidState.to_string(),
            "invalid provider state"
        );
        assert_eq!(
            ProviderDiagnostic::PersistenceFailure.to_string(),
            "provider state persistence failed"
        );
        assert_eq!(
            ProviderError::new(ProviderDiagnostic::UnsafeState).to_string(),
            "unsafe provider state"
        );
    }

    #[test]
    fn safe_initialization_is_locked_and_has_no_authority() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("provider");
        let provider = Provider::start(&root).unwrap();

        assert_eq!(provider.lock_state(), ProviderLockState::Locked);
        assert!(provider.state.pairings.is_empty());
        assert!(provider.state.operations.is_empty());
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(state_path(&root))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn lifecycle_boundaries_durably_invalidate_unexecuted_records() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("provider");
        let mut store = ProviderStore::open(&root).unwrap();
        let mut state = store.read_state().unwrap();
        state.requests = vec![
            RequestRecord {
                id: "pending".into(),
                status: RequestLifecycleStatus::Pending,
            },
            RequestRecord {
                id: "approved".into(),
                status: RequestLifecycleStatus::Approved,
            },
            RequestRecord {
                id: "running".into(),
                status: RequestLifecycleStatus::Running,
            },
            RequestRecord {
                id: "done".into(),
                status: RequestLifecycleStatus::Completed,
            },
        ];
        store.write_state(&state).unwrap();
        drop(store);

        let mut provider = Provider::start(&root).unwrap();
        assert_eq!(provider.state.lifecycle_epoch, 1);
        provider.lock().unwrap();
        provider.shutdown().unwrap();
        drop(provider);
        let saved = ProviderStore::open(&root).unwrap().read_state().unwrap();
        assert_eq!(saved.lifecycle_epoch, 3);
        assert_eq!(
            saved.requests[0].status,
            RequestLifecycleStatus::Invalidated
        );
        assert_eq!(
            saved.requests[1].status,
            RequestLifecycleStatus::Invalidated
        );
        assert_eq!(
            saved.requests[2].status,
            RequestLifecycleStatus::Invalidated
        );
        assert_eq!(saved.requests[3].status, RequestLifecycleStatus::Completed);
    }

    #[test]
    fn malformed_or_missing_state_fails_closed() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("provider");
        Provider::start(&root).unwrap();
        fs::write(state_path(&root), b"not json").unwrap();
        assert_eq!(
            Provider::start(&root).unwrap_err().diagnostic(),
            ProviderDiagnostic::InvalidState
        );
        fs::remove_file(state_path(&root)).unwrap();
        assert_eq!(
            Provider::start(&root).unwrap_err().diagnostic(),
            ProviderDiagnostic::InvalidState
        );
    }

    #[test]
    fn symlinked_or_permissive_state_fails_closed() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("provider");
        Provider::start(&root).unwrap();
        let outside = temp.path().join("outside");
        fs::write(&outside, b"{}").unwrap();
        fs::remove_file(state_path(&root)).unwrap();
        symlink(&outside, state_path(&root)).unwrap();
        assert_eq!(
            Provider::start(&root).unwrap_err().diagnostic(),
            ProviderDiagnostic::UnsafeState
        );

        fs::remove_file(state_path(&root)).unwrap();
        let store = ProviderStore::open(&root);
        assert_eq!(
            store.unwrap_err().diagnostic(),
            ProviderDiagnostic::InvalidState
        );
        // A separately initialized root demonstrates mode rejection without
        // replacing a required state file after initialization.
        let permissive_root = temp.path().join("permissive");
        Provider::start(&permissive_root).unwrap();
        fs::set_permissions(
            state_path(&permissive_root),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        assert_eq!(
            Provider::start(&permissive_root).unwrap_err().diagnostic(),
            ProviderDiagnostic::UnsafeState
        );
    }
}
