//! Serialized session authority. No adapter or caller can obtain resolved values.
use super::{policy::OperationPolicyDraft, ports::*, provider::Provider};
use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub const MAX_SESSION: Duration = Duration::from_secs(15 * 60);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    Locked,
    Unlocked,
}
struct Authority {
    provider: Provider,
    backend: Box<dyn SecretBackend>,
    deadline: Option<Duration>,
    cleanup_failed: bool,
}
pub struct ProviderApplication {
    gate: Mutex<Authority>,
    clock: Box<dyn SessionClock>,
    closing: AtomicBool,
}
impl ProviderApplication {
    pub fn new(
        provider: Provider,
        backend: Box<dyn SecretBackend>,
        clock: Box<dyn SessionClock>,
    ) -> Result<Self, SessionError> {
        let app = Self {
            gate: Mutex::new(Authority {
                provider,
                backend,
                deadline: None,
                cleanup_failed: true,
            }),
            clock,
            closing: AtomicBool::new(false),
        };
        app.lock()?;
        Ok(app)
    }
    fn revoke(authority: &mut Authority) -> Result<(), SessionError> {
        authority.deadline = None;
        authority.cleanup_failed = true;
        // Attempt both cleanups even if either fails. Revocation precedes fallible I/O.
        let backend = authority.backend.clear();
        let store = authority.provider.lock();
        if backend.is_err() || store.is_err() {
            return Err(SessionError::CleanupFailed);
        }
        authority.cleanup_failed = false;
        Ok(())
    }
    fn admit(&self, authority: &mut Authority) -> Result<(), SessionError> {
        if self.closing.load(Ordering::Acquire) {
            Self::revoke(authority)?;
            return Err(SessionError::Locked);
        }
        match authority.deadline {
            Some(deadline) if self.clock.now() < deadline && !authority.cleanup_failed => Ok(()),
            Some(_) => {
                Self::revoke(authority)?;
                Err(SessionError::Locked)
            }
            None => Err(SessionError::Locked),
        }
    }
    pub fn lock(&self) -> Result<(), SessionError> {
        let mut authority = self.gate.lock().map_err(|_| SessionError::CleanupFailed)?;
        Self::revoke(&mut authority)
    }
    /// Irreversible admission closure for transport failure and process shutdown.
    pub fn shutdown(&self) -> Result<(), SessionError> {
        self.close_admission();
        self.lock()
    }
    /// Publish irreversible closure without waiting for an in-flight backend call.
    pub fn close_admission(&self) {
        self.closing.store(true, Ordering::Release);
    }
    pub fn status(&self) -> Result<SessionStatus, SessionError> {
        let mut authority = self.gate.lock().map_err(|_| SessionError::CleanupFailed)?;
        match self.admit(&mut authority) {
            Ok(()) => Ok(SessionStatus::Unlocked),
            Err(SessionError::Locked) => Ok(SessionStatus::Locked),
            Err(e) => Err(e),
        }
    }
    /// Registry validation still precedes eligibility; the backend is held behind
    /// the same gate as unlock, expiry, lock and future scoped consumption.
    pub fn activate_operation(&self, draft: OperationPolicyDraft) -> Result<String, SessionError> {
        let mut authority = self.gate.lock().map_err(|_| SessionError::CleanupFailed)?;
        self.admit(&mut authority)?;
        let probe = authority.backend.probe_compatibility();
        self.admit(&mut authority)?;
        probe?;
        let deadline = authority.deadline.ok_or(SessionError::Locked)?;
        struct Verifier<'a> {
            backend: std::cell::RefCell<&'a mut dyn SecretBackend>,
            clock: &'a dyn SessionClock,
            deadline: Duration,
            closing: &'a AtomicBool,
        }
        impl LoginEligibilityVerifier for Verifier<'_> {
            fn is_login_eligible(
                &self,
                id: &str,
                fields: &[super::policy::LoginField],
                marker: &str,
            ) -> Result<bool, LoginEligibilityError> {
                if self.closing.load(Ordering::Acquire) || self.clock.now() >= self.deadline {
                    return Err(LoginEligibilityError);
                }
                let result = self
                    .backend
                    .borrow_mut()
                    .eligible(&CredentialBinding {
                        immutable_item_id: id,
                        fields,
                        marker,
                    })
                    .map_err(|_| LoginEligibilityError);
                if self.closing.load(Ordering::Acquire) || self.clock.now() >= self.deadline {
                    return Err(LoginEligibilityError);
                }
                result
            }
        }
        let Authority {
            provider, backend, ..
        } = &mut *authority;
        let result = provider
            .activate_operation_checked(
                draft,
                &Verifier {
                    backend: std::cell::RefCell::new(backend.as_mut()),
                    clock: self.clock.as_ref(),
                    deadline,
                    closing: &self.closing,
                },
                || !self.closing.load(Ordering::Acquire) && self.clock.now() < deadline,
            )
            .map_err(|_| SessionError::InvalidRequest);
        // Failed/slow eligibility revokes the session before returning to callers.
        self.admit(&mut authority)?;
        result
    }
    // No public resolver exists until execution can consume values inside this gate.
    #[allow(dead_code)] // Execution adapter will consume within this private scope in Story 1.7.
    fn consume_scoped(
        &self,
        binding: &CredentialBinding<'_>,
        consume: impl FnOnce(&[SensitiveString]),
    ) -> Result<(), SessionError> {
        let mut authority = self.gate.lock().map_err(|_| SessionError::CleanupFailed)?;
        self.admit(&mut authority)?;
        let probe = authority.backend.probe_compatibility();
        self.admit(&mut authority)?;
        probe?;
        let values = authority.backend.resolve(binding);
        self.admit(&mut authority)?;
        consume(&values?);
        Ok(())
    }
}
impl ApprovalAuthenticator for ProviderApplication {
    fn authenticate(&self, password: SensitiveString) -> Result<(), SessionError> {
        let mut authority = self.gate.lock().map_err(|_| SessionError::CleanupFailed)?;
        if self.closing.load(Ordering::Acquire) {
            return Err(SessionError::Locked);
        }
        if authority.cleanup_failed {
            return Err(SessionError::CleanupFailed);
        }
        Self::revoke(&mut authority)?;
        let started = self.clock.now();
        let attempt = authority
            .backend
            .probe_compatibility()
            .and_then(|()| authority.backend.unlock(password));
        match attempt {
            Ok(lifetime) if !lifetime.is_zero() => {
                let Some(deadline) = started.checked_add(lifetime.min(MAX_SESSION)) else {
                    Self::revoke(&mut authority)?;
                    return Err(SessionError::AuthenticationFailed);
                };
                if self.closing.load(Ordering::Acquire) || self.clock.now() >= deadline {
                    Self::revoke(&mut authority)?;
                    return Err(SessionError::Locked);
                }
                authority.deadline = Some(deadline);
                Ok(())
            }
            result => {
                Self::revoke(&mut authority)?;
                Err(result.err().unwrap_or(SessionError::AuthenticationFailed))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::policy::LoginField;
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    };
    struct Clock(Arc<AtomicU64>);
    impl SessionClock for Clock {
        fn now(&self) -> Duration {
            Duration::from_secs(self.0.load(Ordering::SeqCst))
        }
    }
    #[derive(Default)]
    struct Observed {
        resolutions: AtomicUsize,
        unlocks: AtomicUsize,
        clears: AtomicUsize,
        incompatible: AtomicBool,
        cleanup_error: AtomicBool,
        authority: AtomicBool,
        expire_probe: AtomicBool,
        eligibility_time: AtomicU64,
        resolution_error: AtomicBool,
    }
    struct Backend {
        observed: Arc<Observed>,
        barrier: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
        advance: Option<Arc<AtomicU64>>,
        lifetime: Duration,
        block_unlock: bool,
    }
    impl ProviderSession for Backend {
        fn probe_compatibility(&mut self) -> Result<(), SessionError> {
            if self.observed.expire_probe.load(Ordering::SeqCst) {
                self.advance.as_ref().unwrap().store(900, Ordering::SeqCst);
            }
            if self.observed.incompatible.load(Ordering::SeqCst) {
                Err(SessionError::Incompatible)
            } else {
                Ok(())
            }
        }
        fn unlock(&mut self, password: SensitiveString) -> Result<Duration, SessionError> {
            self.observed.unlocks.fetch_add(1, Ordering::SeqCst);
            if self.block_unlock {
                let (entered, resume) = self.barrier.take().unwrap();
                entered.send(()).unwrap();
                resume.recv().unwrap();
            }
            if password.expose() != "password-sentinel" {
                return Err(SessionError::AuthenticationFailed);
            }
            self.observed.authority.store(true, Ordering::SeqCst);
            Ok(self.lifetime)
        }
        fn clear(&mut self) -> Result<(), SessionError> {
            self.observed.authority.store(false, Ordering::SeqCst);
            self.observed.clears.fetch_add(1, Ordering::SeqCst);
            if self.observed.cleanup_error.load(Ordering::SeqCst) {
                Err(SessionError::CleanupFailed)
            } else {
                Ok(())
            }
        }
    }
    impl SecretBackend for Backend {
        fn eligible(&mut self, _: &CredentialBinding<'_>) -> Result<bool, SessionError> {
            self.observed.resolutions.fetch_add(1, Ordering::SeqCst);
            let time = self.observed.eligibility_time.load(Ordering::SeqCst);
            if time != 0 {
                self.advance.as_ref().unwrap().store(time, Ordering::SeqCst);
            }
            Ok(true)
        }
        fn resolve(
            &mut self,
            _: &CredentialBinding<'_>,
        ) -> Result<Vec<SensitiveString>, SessionError> {
            assert!(self.observed.authority.load(Ordering::SeqCst));
            self.observed.resolutions.fetch_add(1, Ordering::SeqCst);
            if let Some((entered, resume)) = self.barrier.take() {
                entered.send(()).unwrap();
                resume.recv().unwrap();
            }
            if let Some(clock) = &self.advance {
                clock.store(900, Ordering::SeqCst);
            }
            if self.observed.resolution_error.load(Ordering::SeqCst) {
                return Err(SessionError::BackendUnavailable);
            }
            Ok(vec![SensitiveString::new("secret-sentinel".into())])
        }
    }
    fn binding() -> CredentialBinding<'static> {
        CredentialBinding {
            immutable_item_id: "11111111-1111-1111-1111-111111111111",
            fields: &[LoginField::Password],
            marker: "vw-access=test",
        }
    }
    fn fixture_with(
        backend: Backend,
        clock: Arc<AtomicU64>,
    ) -> (tempfile::TempDir, Arc<ProviderApplication>) {
        let dir = tempfile::tempdir().unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let provider = Provider::start(dir.path().join("provider")).unwrap();
        let app =
            ProviderApplication::new(provider, Box::new(backend), Box::new(Clock(clock))).unwrap();
        (dir, Arc::new(app))
    }
    fn backend(observed: Arc<Observed>) -> Backend {
        Backend {
            observed,
            barrier: None,
            advance: None,
            lifetime: Duration::from_secs(3600),
            block_unlock: false,
        }
    }
    fn unlock(app: &ProviderApplication) {
        app.authenticate(SensitiveString::new("password-sentinel".into()))
            .unwrap();
    }
    #[test]
    fn slow_backend_errors_revoke_before_propagation() {
        for operation in ["consume_probe", "activate_probe", "resolve"] {
            let clock = Arc::new(AtomicU64::new(0));
            let observed = Arc::new(Observed::default());
            let mut backend = backend(observed.clone());
            backend.advance = Some(clock.clone());
            let (_dir, app) = fixture_with(backend, clock);
            unlock(&app);
            let before = observed.clears.load(Ordering::SeqCst);
            if operation == "resolve" {
                observed.resolution_error.store(true, Ordering::SeqCst);
            } else {
                observed.expire_probe.store(true, Ordering::SeqCst);
                observed.incompatible.store(true, Ordering::SeqCst);
            }
            let result = if operation == "activate_probe" {
                app.activate_operation(super::super::policy::OperationPolicyDraft {
                    id: "deploy".into(),
                    description: "Deploy".into(),
                    image_id: "absent".into(),
                    targets: vec![],
                    arguments: vec![],
                    credentials: vec![],
                })
                .map(|_| ())
            } else {
                app.consume_scoped(&binding(), |_| panic!("error must not release values"))
            };
            assert_eq!(result, Err(SessionError::Locked));
            // Inspect immediately: status() must not be what performs cleanup.
            assert!(!observed.authority.load(Ordering::SeqCst));
            assert_eq!(observed.clears.load(Ordering::SeqCst), before + 1);
            assert_eq!(
                observed.resolutions.load(Ordering::SeqCst),
                usize::from(operation == "resolve")
            );
        }
    }

    #[test]
    fn closing_between_eligibility_checks_prevents_next_binding_and_final_persistence() {
        use super::super::policy::{
            ArgumentSpec, CredentialUse, LoginCredentialDraft, LoginFieldMapping,
            test_approved_image,
        };
        struct ClosingClock {
            observed: Arc<Observed>,
            app: Arc<Mutex<std::sync::Weak<ProviderApplication>>>,
        }
        impl SessionClock for ClosingClock {
            fn now(&self) -> Duration {
                if self.observed.resolutions.load(Ordering::SeqCst) > 0 {
                    self.app
                        .lock()
                        .unwrap()
                        .upgrade()
                        .unwrap()
                        .close_admission();
                }
                Duration::ZERO
            }
        }
        for count in [1, 2] {
            let observed = Arc::new(Observed::default());
            let weak = Arc::new(Mutex::new(std::sync::Weak::new()));
            let dir = tempfile::tempdir().unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let app = Arc::new(
                ProviderApplication::new(
                    Provider::start(dir.path().join("provider")).unwrap(),
                    Box::new(backend(observed.clone())),
                    Box::new(ClosingClock {
                        observed: observed.clone(),
                        app: weak.clone(),
                    }),
                )
                .unwrap(),
            );
            *weak.lock().unwrap() = Arc::downgrade(&app);
            unlock(&app);
            let path = dir.path().join("provider/provider-state.json");
            let mut state: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            state["approved_images"] =
                serde_json::json!([test_approved_image(dir.path(), "deploy-image")]);
            std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
            let draft = OperationPolicyDraft {
                id: "deploy".into(),
                description: "Deploy".into(),
                image_id: "deploy-image".into(),
                targets: vec!["test".into()],
                arguments: vec![ArgumentSpec::Target],
                credentials: (0..count)
                    .map(|i| LoginCredentialDraft {
                        item_id: if i == 0 {
                            binding().immutable_item_id.into()
                        } else {
                            "22222222-2222-2222-2222-222222222222".into()
                        },
                        label: format!("Login {i}"),
                        use_type: CredentialUse::Login,
                        field_mappings: vec![LoginFieldMapping {
                            field: LoginField::Password,
                            environment: format!("PASSWORD_{i}"),
                        }],
                    })
                    .collect(),
            };
            assert_eq!(app.activate_operation(draft), Err(SessionError::Locked));
            assert_eq!(observed.resolutions.load(Ordering::SeqCst), 1);
            assert!(!observed.authority.load(Ordering::SeqCst));
            let state: serde_json::Value =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert!(state["operations"].as_array().unwrap().is_empty());
        }
    }

    #[test]
    fn locked_and_incompatible_never_use_items_or_leak_sentinels() {
        let observed = Arc::new(Observed::default());
        let (dir, app) = fixture_with(backend(observed.clone()), Arc::new(AtomicU64::new(0)));
        assert_eq!(
            app.consume_scoped(&binding(), |_| panic!("must not consume")),
            Err(SessionError::Locked)
        );
        observed.incompatible.store(true, Ordering::SeqCst);
        assert_eq!(
            app.authenticate(SensitiveString::new("password-sentinel".into())),
            Err(SessionError::Incompatible)
        );
        assert_eq!(observed.unlocks.load(Ordering::SeqCst), 0);
        assert_eq!(observed.resolutions.load(Ordering::SeqCst), 0);
        observed.incompatible.store(false, Ordering::SeqCst);
        unlock(&app);
        observed.incompatible.store(true, Ordering::SeqCst);
        assert_eq!(
            app.consume_scoped(&binding(), |_| panic!("must not consume")),
            Err(SessionError::Incompatible)
        );
        assert_eq!(observed.resolutions.load(Ordering::SeqCst), 0);
        let persisted =
            std::fs::read_to_string(dir.path().join("provider/provider-state.json")).unwrap();
        let exposed = format!(
            "{persisted} {:?} {:?} {}",
            app.status(),
            SensitiveString::new("secret-sentinel".into()),
            SessionError::AuthenticationFailed
        );
        for secret in ["password-sentinel", "session-sentinel", "secret-sentinel"] {
            assert!(!exposed.contains(secret));
        }
    }
    #[test]
    fn expiry_exact_boundary_clears_authority_and_token_lifetime_bounds_session() {
        for (lifetime, limit) in [
            (Duration::from_secs(30), 30),
            (Duration::from_secs(3600), 900),
        ] {
            let observed = Arc::new(Observed::default());
            let clock = Arc::new(AtomicU64::new(0));
            let mut backend = backend(observed.clone());
            backend.lifetime = lifetime;
            let (_dir, app) = fixture_with(backend, clock.clone());
            unlock(&app);
            // Expected deadlines are independent of the production cap constant.
            clock.store(limit - 1, Ordering::SeqCst);
            assert_eq!(app.status(), Ok(SessionStatus::Unlocked));
            app.consume_scoped(&binding(), |values| {
                assert_eq!(values[0].expose(), "secret-sentinel")
            })
            .unwrap();
            clock.store(limit, Ordering::SeqCst);
            assert_eq!(app.status(), Ok(SessionStatus::Locked));
            assert!(!observed.authority.load(Ordering::SeqCst));
            assert_eq!(
                app.consume_scoped(&binding(), |_| panic!("expired")),
                Err(SessionError::Locked)
            );
            assert_eq!(observed.resolutions.load(Ordering::SeqCst), 1);
        }
    }
    #[test]
    fn unusable_deadlines_clear_newly_created_authority() {
        for (start, lifetime) in [(0, Duration::ZERO), (u64::MAX, Duration::from_secs(60))] {
            let observed = Arc::new(Observed::default());
            let mut backend = backend(observed.clone());
            backend.lifetime = lifetime;
            let (_dir, app) = fixture_with(backend, Arc::new(AtomicU64::new(start)));
            assert_eq!(
                app.authenticate(SensitiveString::new("password-sentinel".into())),
                Err(SessionError::AuthenticationFailed)
            );
            assert!(!observed.authority.load(Ordering::SeqCst));
            assert_eq!(app.status(), Ok(SessionStatus::Locked));
        }
    }
    #[test]
    fn expiry_during_compatibility_probe_prevents_item_resolution() {
        let clock = Arc::new(AtomicU64::new(0));
        let observed = Arc::new(Observed::default());
        let mut backend = backend(observed.clone());
        backend.advance = Some(clock.clone());
        let (_dir, app) = fixture_with(backend, clock);
        unlock(&app);
        observed.expire_probe.store(true, Ordering::SeqCst);
        assert_eq!(
            app.consume_scoped(&binding(), |_| panic!("expired probe")),
            Err(SessionError::Locked)
        );
        assert_eq!(observed.resolutions.load(Ordering::SeqCst), 0);
        assert!(!observed.authority.load(Ordering::SeqCst));
    }
    #[test]
    fn expires_during_resolution_discards_values() {
        let clock = Arc::new(AtomicU64::new(0));
        let observed = Arc::new(Observed::default());
        let mut backend = backend(observed.clone());
        backend.advance = Some(clock.clone());
        let (_dir, app) = fixture_with(backend, clock);
        unlock(&app);
        assert_eq!(
            app.consume_scoped(&binding(), |_| panic!("late value")),
            Err(SessionError::Locked)
        );
        assert!(!observed.authority.load(Ordering::SeqCst));
    }
    #[test]
    fn cleanup_failure_poison_cannot_be_bypassed_by_unlock() {
        let observed = Arc::new(Observed::default());
        let (_dir, app) = fixture_with(backend(observed.clone()), Arc::new(AtomicU64::new(0)));
        unlock(&app);
        observed.cleanup_error.store(true, Ordering::SeqCst);
        assert_eq!(app.lock(), Err(SessionError::CleanupFailed));
        assert_eq!(app.status(), Ok(SessionStatus::Locked));
        assert_eq!(
            app.authenticate(SensitiveString::new("password-sentinel".into())),
            Err(SessionError::CleanupFailed)
        );
        assert_eq!(
            app.consume_scoped(&binding(), |_| panic!("poisoned")),
            Err(SessionError::Locked)
        );
        observed.cleanup_error.store(false, Ordering::SeqCst);
        app.lock().unwrap();
        unlock(&app);
        assert_eq!(app.status(), Ok(SessionStatus::Unlocked));
    }
    #[test]
    fn lock_serializes_resolution_and_delayed_unlock() {
        for block_unlock in [false, true] {
            let observed = Arc::new(Observed::default());
            let (entered_tx, entered_rx) = mpsc::channel();
            let (resume_tx, resume_rx) = mpsc::channel();
            let mut backend = backend(observed.clone());
            backend.barrier = Some((entered_tx, resume_rx));
            backend.block_unlock = block_unlock;
            let (_dir, app) = fixture_with(backend, Arc::new(AtomicU64::new(0)));
            if !block_unlock {
                unlock(&app);
            }
            let consuming = Arc::new(AtomicBool::new(false));
            let first = {
                let app = app.clone();
                let consuming = consuming.clone();
                std::thread::spawn(move || {
                    if block_unlock {
                        unlock(&app);
                    } else {
                        app.consume_scoped(&binding(), |_| {
                            consuming.store(true, Ordering::SeqCst);
                        })
                        .unwrap();
                    }
                })
            };
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            let (locked_tx, locked_rx) = mpsc::channel();
            let locking = {
                let app = app.clone();
                std::thread::spawn(move || {
                    app.lock().unwrap();
                    locked_tx.send(()).unwrap();
                })
            };
            assert!(locked_rx.recv_timeout(Duration::from_millis(30)).is_err());
            resume_tx.send(()).unwrap();
            first.join().unwrap();
            locking.join().unwrap();
            assert_eq!(app.status(), Ok(SessionStatus::Locked));
            assert_eq!(consuming.load(Ordering::SeqCst), !block_unlock);
            assert!(!observed.authority.load(Ordering::SeqCst));
            assert_eq!(
                app.consume_scoped(&binding(), |_| panic!("late result")),
                Err(SessionError::Locked)
            );
        }
    }
    #[test]
    fn lock_restart_and_expiry_invalidate_durable_work() {
        for action in ["lock", "restart", "expiry"] {
            let observed = Arc::new(Observed::default());
            let clock = Arc::new(AtomicU64::new(0));
            let (dir, app) = fixture_with(backend(observed.clone()), clock.clone());
            unlock(&app);
            let path = dir.path().join("provider/provider-state.json");
            let mut state: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            let epoch = state["lifecycle_epoch"].as_u64().unwrap();
            state["requests"] = serde_json::json!([{"id":"pending", "status":"pending"},{"id":"approved","status":"approved"},{"id":"done","status":"completed"}]);
            std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
            if action == "restart" {
                drop(app);
                let provider = Provider::start(dir.path().join("provider")).unwrap();
                let app = ProviderApplication::new(
                    provider,
                    Box::new(backend(observed.clone())),
                    Box::new(Clock(clock)),
                )
                .unwrap();
                assert_eq!(app.status(), Ok(SessionStatus::Locked));
            } else if action == "expiry" {
                clock.store(900, Ordering::SeqCst);
                assert_eq!(app.status(), Ok(SessionStatus::Locked));
                unlock(&app);
            } else {
                app.lock().unwrap();
                unlock(&app);
            }
            let state: serde_json::Value =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert!(state["lifecycle_epoch"].as_u64().unwrap() > epoch);
            assert_eq!(state["requests"][0]["status"], "invalidated");
            assert_eq!(state["requests"][1]["status"], "invalidated");
            assert_eq!(state["requests"][2]["status"], "completed");
        }
    }
    #[test]
    fn persistence_failure_still_clears_backend_and_blocks_renewal() {
        let observed = Arc::new(Observed::default());
        let (dir, app) = fixture_with(backend(observed.clone()), Arc::new(AtomicU64::new(0)));
        unlock(&app);
        std::fs::remove_file(dir.path().join("provider/provider-state.json")).unwrap();
        assert_eq!(app.lock(), Err(SessionError::CleanupFailed));
        assert!(!observed.authority.load(Ordering::SeqCst));
        assert_eq!(
            app.authenticate(SensitiveString::new("password-sentinel".into())),
            Err(SessionError::CleanupFailed)
        );
    }
    #[test]
    fn shutdown_discards_delayed_unlock_and_permanently_closes_admission() {
        let observed = Arc::new(Observed::default());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let mut backend = backend(observed.clone());
        backend.barrier = Some((entered_tx, resume_rx));
        backend.block_unlock = true;
        let (_dir, app) = fixture_with(backend, Arc::new(AtomicU64::new(0)));
        let pending = {
            let app = app.clone();
            std::thread::spawn(move || {
                app.authenticate(SensitiveString::new("password-sentinel".into()))
            })
        };
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let shutdown = {
            let app = app.clone();
            std::thread::spawn(move || app.shutdown())
        };
        let wait_until = std::time::Instant::now() + Duration::from_secs(2);
        while !app.closing.load(Ordering::Acquire) && std::time::Instant::now() < wait_until {
            std::thread::yield_now();
        }
        let closed = app.closing.load(Ordering::Acquire);
        resume_tx.send(()).unwrap();
        let pending_result = pending.join().unwrap();
        shutdown.join().unwrap().unwrap();
        assert!(
            closed,
            "shutdown did not close admission within the deadline"
        );
        assert_eq!(pending_result, Err(SessionError::Locked));
        assert_eq!(app.status(), Ok(SessionStatus::Locked));
        assert!(!observed.authority.load(Ordering::SeqCst));
        assert_eq!(
            app.authenticate(SensitiveString::new("password-sentinel".into())),
            Err(SessionError::Locked)
        );
        assert_eq!(observed.unlocks.load(Ordering::SeqCst), 1);
        assert_eq!(
            app.consume_scoped(&binding(), |_| panic!("shut down")),
            Err(SessionError::Locked)
        );
    }

    #[test]
    fn expiry_across_bindings_and_before_policy_commit_revokes_without_persistence() {
        use super::super::policy::{
            ArgumentSpec, CredentialUse, LoginCredentialDraft, LoginFieldMapping,
            test_approved_image,
        };
        struct StepClock(Arc<AtomicU64>);
        impl SessionClock for StepClock {
            fn now(&self) -> Duration {
                let now = self.0.load(Ordering::SeqCst);
                Duration::from_secs(if now >= 899 {
                    self.0.fetch_add(1, Ordering::SeqCst)
                } else {
                    now
                })
            }
        }
        for expire_at in [899, 900] {
            let dir = tempfile::tempdir().unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let clock = Arc::new(AtomicU64::new(0));
            let observed = Arc::new(Observed::default());
            observed.eligibility_time.store(expire_at, Ordering::SeqCst);
            let mut backend = backend(observed.clone());
            backend.advance = Some(clock.clone());
            let app = ProviderApplication::new(
                Provider::start(dir.path().join("provider")).unwrap(),
                Box::new(backend),
                Box::new(StepClock(clock)),
            )
            .unwrap();
            unlock(&app);
            let path = dir.path().join("provider/provider-state.json");
            let mut state: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            state["approved_images"] =
                serde_json::json!([test_approved_image(dir.path(), "deploy-image")]);
            std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
            let credentials = (0..if expire_at == 899 { 1 } else { 2 })
                .map(|i| LoginCredentialDraft {
                    item_id: if i == 0 {
                        binding().immutable_item_id.into()
                    } else {
                        "22222222-2222-2222-2222-222222222222".into()
                    },
                    label: format!("Login {i}"),
                    use_type: CredentialUse::Login,
                    field_mappings: vec![LoginFieldMapping {
                        field: LoginField::Password,
                        environment: format!("DEPLOY_PASSWORD_{i}"),
                    }],
                })
                .collect();
            let draft = OperationPolicyDraft {
                id: "deploy".into(),
                description: "Deploy".into(),
                image_id: "deploy-image".into(),
                targets: vec!["test".into()],
                arguments: vec![ArgumentSpec::Target],
                credentials,
            };
            assert_eq!(app.activate_operation(draft), Err(SessionError::Locked));
            assert_eq!(observed.resolutions.load(Ordering::SeqCst), 1);
            assert!(!observed.authority.load(Ordering::SeqCst));
            let state: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert!(state["operations"].as_array().unwrap().is_empty());
        }
    }
    #[test]
    fn production_policy_activation_uses_only_owned_unlocked_backend() {
        use super::super::policy::{
            ArgumentSpec, CredentialUse, LoginCredentialDraft, LoginFieldMapping,
            test_approved_image,
        };
        let observed = Arc::new(Observed::default());
        let (dir, app) = fixture_with(backend(observed.clone()), Arc::new(AtomicU64::new(0)));
        let draft = || OperationPolicyDraft {
            id: "deploy".into(),
            description: "Deploy".into(),
            image_id: "deploy-image".into(),
            targets: vec!["test".into()],
            arguments: vec![ArgumentSpec::Target],
            credentials: vec![LoginCredentialDraft {
                item_id: binding().immutable_item_id.into(),
                label: "Login".into(),
                use_type: CredentialUse::Login,
                field_mappings: vec![LoginFieldMapping {
                    field: LoginField::Password,
                    environment: "DEPLOY_PASSWORD".into(),
                }],
            }],
        };
        assert_eq!(app.activate_operation(draft()), Err(SessionError::Locked));
        unlock(&app);
        assert_eq!(
            app.activate_operation(draft()),
            Err(SessionError::InvalidRequest)
        );
        assert_eq!(observed.resolutions.load(Ordering::SeqCst), 0);
        let path = dir.path().join("provider/provider-state.json");
        let mut state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        state["approved_images"] =
            serde_json::json!([test_approved_image(dir.path(), "deploy-image")]);
        std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        observed.incompatible.store(true, Ordering::SeqCst);
        assert_eq!(
            app.activate_operation(draft()),
            Err(SessionError::Incompatible)
        );
        assert_eq!(observed.resolutions.load(Ordering::SeqCst), 0);
        observed.incompatible.store(false, Ordering::SeqCst);
        assert_eq!(app.activate_operation(draft()).unwrap().len(), 64);
        assert_eq!(observed.resolutions.load(Ordering::SeqCst), 1);
    }
}
