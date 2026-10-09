use super::{
    application::*, direct_request::AuthenticatedHuman, policy::*, ports::*, provider::Provider,
    provisioning::*,
};
use crate::adapters::execution::LinuxExecutablePreparer;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

struct Clock(Arc<AtomicU64>);
impl SessionClock for Clock {
    fn now(&self) -> Duration {
        Duration::from_secs(self.0.load(Ordering::SeqCst))
    }
}
struct Backend(bool);
impl ProviderSession for Backend {
    fn probe_compatibility(&mut self) -> Result<(), SessionError> {
        Ok(())
    }
    fn unlock(&mut self, _: SensitiveString) -> Result<Duration, SessionError> {
        Ok(Duration::from_secs(60))
    }
    fn clear(&mut self) -> Result<(), SessionError> {
        Ok(())
    }
}
impl SecretBackend for Backend {
    fn eligible(&mut self, binding: &CredentialBinding<'_>) -> Result<bool, SessionError> {
        let marker = match binding.immutable_item_id {
            "11111111-1111-1111-1111-111111111111" => "vw-access=deploy",
            "22222222-2222-2222-2222-222222222222" => "vw-access=unrelated",
            "33333333-3333-3333-3333-333333333333" => "vw-access=deploy",
            _ => panic!("unexpected immutable Login item ID"),
        };
        assert_eq!(binding.fields, &[LoginField::Password]);
        assert_eq!(binding.marker, marker);
        Ok(self.0 && binding.immutable_item_id != "33333333-3333-3333-3333-333333333333")
    }
    fn ssh_eligible(&mut self, item_id: &str) -> Result<bool, SessionError> {
        assert_eq!(item_id, "11111111-1111-1111-1111-111111111111");
        Ok(self.0)
    }
    fn resolve_ssh(&mut self, _: &str) -> Result<SensitiveString, SessionError> {
        panic!("provisioning cannot resolve SSH secrets")
    }
    fn resolve(&mut self, _: &CredentialBinding<'_>) -> Result<Vec<SensitiveString>, SessionError> {
        panic!("provisioning cannot resolve secrets")
    }
}
fn owner() -> AuthenticatedHuman {
    AuthenticatedHuman::from_peer_uid(unsafe { libc::geteuid() })
}
fn fixture(
    eligible: bool,
) -> (
    tempfile::TempDir,
    Arc<ProviderApplication>,
    Arc<AtomicU64>,
    ImageRegistration,
) {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(AtomicU64::new(0));
    let app = Arc::new(
        ProviderApplication::new(
            Provider::start(dir.path().join("state")).unwrap(),
            Box::new(Backend(eligible)),
            Box::new(Clock(clock.clone())),
        )
        .unwrap(),
    );
    let image = test_approved_image(dir.path(), "deploy-image").metadata();
    (dir, app, clock, image)
}
fn unlock(app: &ProviderApplication) {
    app.authenticate(SensitiveString::new("synthetic".into()))
        .unwrap();
}
fn draft() -> OperationPolicyDraft {
    super::direct_request_tests::operation_draft()
}
fn register(app: &ProviderApplication, image: ImageRegistration) {
    app.register_image(owner(), image, &LinuxExecutablePreparer)
        .unwrap();
}

#[test]
fn provisioning_owner_locked_inspection_and_create_only_restart() {
    let (dir, app, clock, image) = fixture(true);
    let other = AuthenticatedHuman::from_peer_uid(owner().uid().wrapping_add(1));
    assert_eq!(app.list_images(other), Err(ProvisioningError::Unauthorized));
    assert_eq!(
        app.list_operations(other),
        Err(ProvisioningError::Unauthorized)
    );
    assert_eq!(
        app.show_image(other, "deploy-image"),
        Err(ProvisioningError::Unauthorized)
    );
    assert_eq!(
        app.show_operation(other, "deploy"),
        Err(ProvisioningError::Unauthorized)
    );
    assert_eq!(
        app.create_operation(other, draft()),
        Err(ProvisioningError::Unauthorized)
    );
    assert_eq!(
        app.register_image(other, image.clone(), &LinuxExecutablePreparer),
        Err(ProvisioningError::Unauthorized)
    );
    assert_eq!(
        app.register_image(owner(), image.clone(), &LinuxExecutablePreparer),
        Err(ProvisioningError::Locked)
    );
    assert_eq!(
        app.create_operation(owner(), draft()),
        Err(ProvisioningError::Locked)
    );
    assert!(app.list_images(owner()).unwrap().is_empty());
    unlock(&app);
    register(&app, image.clone());
    let created = app.create_operation(owner(), draft()).unwrap();
    assert_eq!(
        app.create_operation(owner(), draft()),
        Err(ProvisioningError::Conflict)
    );
    assert_eq!(
        app.register_image(owner(), image.clone(), &LinuxExecutablePreparer),
        Err(ProvisioningError::Conflict)
    );
    assert_eq!(
        app.show_operation(owner(), "deploy").unwrap().revision,
        created.revision
    );
    app.lock().unwrap();
    assert_eq!(app.show_image(owner(), "deploy-image").unwrap(), image);
    drop(app);
    let restarted = ProviderApplication::new(
        Provider::start(dir.path().join("state")).unwrap(),
        Box::new(Backend(true)),
        Box::new(Clock(clock)),
    )
    .unwrap();
    assert_eq!(restarted.list_operations(owner()).unwrap(), vec![created]);
    assert_eq!(restarted.status().unwrap(), SessionStatus::Locked);
}

#[test]
fn provisioning_duplicate_races_preserve_unrelated_policy() {
    let (_dir, app, _, image) = fixture(true);
    unlock(&app);
    register(&app, image.clone());
    let mut unrelated = draft();
    unrelated.id = "unrelated".into();
    unrelated.credentials[0].item_id = "22222222-2222-2222-2222-222222222222".into();
    let before = app.create_operation(owner(), unrelated).unwrap();
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let app = app.clone();
            std::thread::spawn(move || app.create_operation(owner(), draft()))
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Err(ProvisioningError::Conflict))
            .count(),
        7
    );
    assert_eq!(
        app.show_operation(owner(), "unrelated").unwrap().revision,
        before.revision
    );
    let mut second = image;
    second.id = "another-image".into();
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let app = app.clone();
            let image = second.clone();
            std::thread::spawn(move || app.register_image(owner(), image, &LinuxExecutablePreparer))
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Err(ProvisioningError::Conflict))
            .count(),
        7
    );
}

#[test]
fn provisioning_login_and_ssh_eligibility_fail_without_partial_policy() {
    let (_dir, app, _, image) = fixture(false);
    unlock(&app);
    register(&app, image);
    assert_eq!(
        app.create_operation(owner(), draft()),
        Err(ProvisioningError::CredentialIneligible)
    );
    let mut ssh = test_ssh_draft();
    ssh.image_id = "deploy-image".into();
    assert_eq!(
        app.create_operation(owner(), ssh),
        Err(ProvisioningError::CredentialIneligible)
    );
    assert!(app.list_operations(owner()).unwrap().is_empty());
    let (_ssh_dir, ssh_app, _, image) = fixture(true);
    unlock(&ssh_app);
    register(&ssh_app, image);
    let mut later_ineligible = draft();
    let mut second = later_ineligible.credentials[0].clone();
    second.item_id = "33333333-3333-3333-3333-333333333333".into();
    second.field_mappings[0].environment = "SECOND_PASSWORD".into();
    later_ineligible.credentials.push(second);
    assert_eq!(
        ssh_app.create_operation(owner(), later_ineligible),
        Err(ProvisioningError::CredentialIneligible)
    );
    assert!(ssh_app.list_operations(owner()).unwrap().is_empty());
    let mut ssh = test_ssh_draft();
    ssh.image_id = "deploy-image".into();
    ssh_app.create_operation(owner(), ssh).unwrap();
}

#[test]
fn provisioning_verification_rejects_digest_symlink_unsafe_and_unsupported_elf() {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    for case in ["digest", "symlink", "writable", "unsupported"] {
        let (dir, app, _, mut image) = fixture(true);
        unlock(&app);
        match case {
            "digest" => image.sha256 = "a".repeat(64),
            "symlink" => {
                let link = dir.path().join("link");
                std::os::unix::fs::symlink(&image.path, &link).unwrap();
                image.path = link.to_str().unwrap().into();
            }
            "writable" => {
                std::fs::set_permissions(&image.path, std::fs::Permissions::from_mode(0o700))
                    .unwrap()
            }
            _ => {
                let mut bytes = std::fs::read(&image.path).unwrap();
                bytes[64..68].copy_from_slice(&3u32.to_le_bytes());
                std::fs::set_permissions(&image.path, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
                std::fs::write(&image.path, &bytes).unwrap();
                std::fs::set_permissions(&image.path, std::fs::Permissions::from_mode(0o500))
                    .unwrap();
                image.sha256 = Sha256::digest(&bytes)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
            }
        }
        assert_eq!(
            app.register_image(owner(), image, &LinuxExecutablePreparer),
            Err(ProvisioningError::InvalidInput),
            "{case}"
        );
        assert!(app.list_images(owner()).unwrap().is_empty());
    }
}

#[test]
fn provisioning_expiry_and_closure_at_commit_prevent_creation() {
    for action in ["expiry", "closure", "lock-intent"] {
        for image_write in [true, false] {
            let (_dir, app, clock, mut image) = fixture(true);
            unlock(&app);
            register(&app, image.clone());
            image.id = "second-image".into();
            let hooked = app.clone();
            let lockers = Arc::new(std::sync::Mutex::new(Vec::new()));
            let hook_lockers = lockers.clone();
            let mut fired = false;
            super::provider_store::WRITE_TEST_HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |stage| {
                    if stage == 0 && !fired {
                        fired = true;
                        match action {
                            "expiry" => clock.store(60, Ordering::SeqCst),
                            "closure" => hooked.close_admission(),
                            _ => {
                                // Publish real lock intent on another thread while this transaction owns the gate.
                                let locking = hooked.clone();
                                let epoch = hooked.revocation_epoch_for_test();
                                hook_lockers
                                    .lock()
                                    .unwrap()
                                    .push(std::thread::spawn(move || locking.lock().unwrap()));
                                let timeout = std::time::Instant::now() + Duration::from_secs(5);
                                while hooked.revocation_epoch_for_test() == epoch {
                                    assert!(std::time::Instant::now() < timeout);
                                    std::thread::yield_now();
                                }
                            }
                        }
                    }
                    false
                }))
            });
            let result = if image_write {
                app.register_image(owner(), image, &LinuxExecutablePreparer)
                    .map(|_| ())
            } else {
                app.create_operation(owner(), draft()).map(|_| ())
            };
            super::provider_store::WRITE_TEST_HOOK.with(|hook| *hook.borrow_mut() = None);
            for locker in lockers.lock().unwrap().drain(..) {
                locker.join().unwrap();
            }
            assert!(result.is_err(), "{action}");
            assert_eq!(app.list_images(owner()).unwrap().len(), 1);
            assert!(app.list_operations(owner()).unwrap().is_empty());
        }
    }
}

#[test]
fn provisioning_persistence_faults_close_admission() {
    for stage in [0, 1] {
        for image_write in [true, false] {
            let (dir, app, clock, mut image) = fixture(true);
            unlock(&app);
            register(&app, image.clone());
            let expected_operation = OperationPolicy::from_draft(
                draft(),
                &ApprovedImage::from_registration(image.clone()).unwrap(),
            )
            .unwrap()
            .metadata();
            image.id = "second-image".into();
            let expected_image = image.clone();
            super::provider_store::WRITE_TEST_HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |observed| observed == stage))
            });
            let result = if image_write {
                app.register_image(owner(), image, &LinuxExecutablePreparer)
                    .map(|_| ())
            } else {
                app.create_operation(owner(), draft()).map(|_| ())
            };
            super::provider_store::WRITE_TEST_HOOK.with(|hook| *hook.borrow_mut() = None);
            assert_eq!(result, Err(ProvisioningError::Unavailable));
            assert!(app.admission_closed());
            assert!(app.create_operation(owner(), draft()).is_err());
            if stage == 1 {
                assert_eq!(
                    app.list_images(owner()),
                    Err(ProvisioningError::Unavailable)
                );
                drop(app);
                let reopened = ProviderApplication::new(
                    Provider::start(dir.path().join("state")).unwrap(),
                    Box::new(Backend(true)),
                    Box::new(Clock(clock)),
                )
                .unwrap();
                assert_eq!(reopened.status().unwrap(), SessionStatus::Locked);
                if image_write {
                    assert_eq!(
                        reopened.show_image(owner(), "second-image").unwrap(),
                        expected_image
                    );
                    unlock(&reopened);
                    assert_eq!(
                        reopened.register_image(owner(), expected_image, &LinuxExecutablePreparer),
                        Err(ProvisioningError::Conflict)
                    );
                } else {
                    assert_eq!(
                        reopened.show_operation(owner(), "deploy").unwrap(),
                        expected_operation
                    );
                    unlock(&reopened);
                    assert_eq!(
                        reopened.create_operation(owner(), draft()),
                        Err(ProvisioningError::Conflict)
                    );
                }
            }
        }
    }
}

#[test]
fn provisioning_inspection_bound_is_explicit_and_input_is_closed() {
    let mut value = serde_json::to_value(draft()).unwrap();
    value["password"] = "sentinel-secret".into();
    assert!(serde_json::from_value::<OperationPolicyDraft>(value).is_err());
    for kind in [
        "image_register",
        "image_list",
        "operation_create",
        "operation_show",
    ] {
        assert!(
            super::protocol::SignedSubmission::parse(format!("{{\"kind\":\"{kind}\"}}").as_bytes())
                .is_err()
        );
    }
}

#[test]
fn provisioning_preparation_unavailable_is_not_invalid_input() {
    struct Unavailable;
    impl ImageVerifier for Unavailable {
        fn verify(&self, _: ExecutionImage<'_>) -> Result<(), ExecutionError> {
            Err(ExecutionError::Unavailable)
        }
    }
    let (_dir, app, _, image) = fixture(true);
    unlock(&app);
    assert_eq!(
        app.register_image(owner(), image, &Unavailable),
        Err(ProvisioningError::Unavailable)
    );
    assert!(app.admission_closed());
    assert!(app.list_images(owner()).unwrap().is_empty());
}

#[test]
fn provisioning_actual_lists_reject_oversized_valid_metadata() {
    let (dir, app, _, image) = fixture(true);
    unlock(&app);
    register(&app, image);
    app.create_operation(owner(), draft()).unwrap();
    app.lock().unwrap();
    let path = dir.path().join("state/provider-state.json");
    let mut state: super::provider_store::ProviderState =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    // Inspection-only size fixture: seed through provisioning, then construct a
    // bulk snapshot with strict factories. No production test accessor or fake
    // limit is used; each real list must enforce the actual one-MiB bound.
    let base_image = state.approved_images[0].metadata();
    for index in 0..6000 {
        let mut registration = base_image.clone();
        registration.id = format!("image-{index:06}-{}", "i".repeat(48));
        let approved = ApprovedImage::from_registration(registration).unwrap();
        let mut policy = draft();
        policy.id = format!("operation-{index:06}-{}", "o".repeat(44));
        policy.image_id = approved.id().into();
        state
            .operations
            .push(OperationPolicy::from_draft(policy, &approved).unwrap());
        state.approved_images.push(approved);
    }
    state.validate().unwrap();
    assert!(
        serde_json::to_vec(
            &state
                .approved_images
                .iter()
                .map(ApprovedImage::metadata)
                .collect::<Vec<_>>()
        )
        .unwrap()
        .len()
            > MAX_INSPECTION_BYTES
    );
    assert!(
        serde_json::to_vec(
            &state
                .operations
                .iter()
                .map(OperationPolicy::summary)
                .collect::<Vec<_>>()
        )
        .unwrap()
        .len()
            > MAX_INSPECTION_BYTES
    );
    std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    assert_eq!(
        app.list_images(owner()),
        Err(ProvisioningError::OversizedResult)
    );
    assert_eq!(
        app.list_operations(owner()),
        Err(ProvisioningError::OversizedResult)
    );
}

#[test]
fn provisioning_post_rename_expiry_poison_and_shared_activation_guard() {
    for legacy in [false, true] {
        for stage in [0, 1] {
            let (_dir, app, clock, image) = fixture(true);
            unlock(&app);
            register(&app, image);
            super::provider_store::WRITE_TEST_HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |observed| {
                    if observed == stage {
                        clock.store(60, Ordering::SeqCst);
                    }
                    false
                }))
            });
            let result = if legacy {
                app.activate_operation(draft())
                    .map(|_| ())
                    .map_err(ProvisioningError::from)
            } else {
                app.create_operation(owner(), draft()).map(|_| ())
            };
            super::provider_store::WRITE_TEST_HOOK.with(|hook| *hook.borrow_mut() = None);
            assert!(result.is_err());
            if stage == 0 {
                assert!(app.list_operations(owner()).unwrap().is_empty());
            } else {
                assert!(app.admission_closed());
                assert_eq!(
                    app.list_operations(owner()),
                    Err(ProvisioningError::Unavailable)
                );
            }
        }
    }
}
