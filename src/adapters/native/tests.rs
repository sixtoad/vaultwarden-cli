//! Disposable native qualification. Synthetic identity/backend are explicit test seams;
//! installed cross-account/Keychain/service behavior is not established by these tests.
use super::*;
use crate::access::{
    agent_binding::AgentPairing,
    direct_request::{DirectRequestError, DirectStatus, DirectSubmission},
    policy::*,
    ports::*,
    protocol::{AgentRejection, SignedSubmission},
    provider::Provider,
};
use std::{
    cell::Cell,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};
fn digest(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(std::fs::read(path).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn image_registration() -> ImageRegistration {
    ImageRegistration {
        id: "native-ssh".into(),
        execution_root: "/usr/bin".into(),
        path: "/usr/bin/ssh".into(),
        sha256: digest(Path::new("/usr/bin/ssh")),
        profile: ExecutionProfile::ReviewedNativeMachOArm64V1,
    }
}
struct Clock(Arc<AtomicU64>);
impl SessionClock for Clock {
    fn now(&self) -> Duration {
        Duration::from_secs(self.0.load(Ordering::SeqCst))
    }
    fn unix_seconds(&self) -> Result<u64, SessionError> {
        Ok(1700000000)
    }
}
struct Backend(Arc<AtomicUsize>);
impl ProviderSession for Backend {
    fn probe_compatibility(&mut self) -> Result<(), SessionError> {
        Ok(())
    }
    fn unlock(&mut self, password: SensitiveString) -> Result<Duration, SessionError> {
        if password.expose() == "synthetic-password" {
            Ok(Duration::from_secs(900))
        } else {
            Err(SessionError::AuthenticationFailed)
        }
    }
    fn clear(&mut self) -> Result<(), SessionError> {
        Ok(())
    }
}
impl SecretBackend for Backend {
    fn eligible(&mut self, _: &CredentialBinding<'_>) -> Result<bool, SessionError> {
        Ok(true)
    }
    fn resolve(&mut self, _: &CredentialBinding<'_>) -> Result<Vec<SensitiveString>, SessionError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(vec![SensitiveString::new("native-synthetic-value".into())])
    }
    fn create_eligible(&mut self, _: &CreateEffect) -> Result<(), SessionError> {
        Ok(())
    }
    fn create_secret(
        &mut self,
        _: &CreateEffect,
        input: &crate::secret_storage::SecretImport,
        live: &dyn Fn() -> bool,
    ) -> Result<String, crate::secret_storage::WriteStatus> {
        assert!(live());
        NATIVE_CREATED.with(|created| {
            created
                .borrow_mut()
                .push(input.password.clone().unwrap_or_default());
        });
        Ok("33333333-3333-3333-3333-333333333333".into())
    }
    fn verify_secret(
        &mut self,
        _: &CreateEffect,
        _: &str,
        _: &crate::secret_storage::SecretImport,
    ) -> Result<(), SessionError> {
        Ok(())
    }
}
thread_local! {
    /// Passwords received by the synthetic create backend on this test thread.
    static NATIVE_CREATED: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}
struct Auth;
impl ApprovalAuthenticator for Auth {
    fn authenticate(&self, password: SensitiveString) -> Result<(), SessionError> {
        if password.expose() == "synthetic-password" {
            Ok(())
        } else {
            Err(SessionError::AuthenticationFailed)
        }
    }
}
pub(crate) fn operation_draft() -> OperationPolicyDraft {
    OperationPolicyDraft {
        require_password: false,
        id: "native-version".into(),
        description: "Native synthetic approved launch".into(),
        image_id: "native-ssh".into(),
        targets: vec!["-V".into()],
        arguments: vec![ArgumentSpec::Target],
        credentials: vec![LoginCredentialDraft {
            namespace: None,
            item_id: "11111111-1111-1111-1111-111111111111".into(),
            label: "Synthetic".into(),
            use_type: CredentialUse::Login,
            field_mappings: vec![LoginFieldMapping {
                field: LoginField::Password,
                environment: "NATIVE_TEST_VALUE".into(),
            }],
        }],
        ssh: None,
        create: None,
    }
}
pub(crate) fn submission(operation: &str) -> DirectSubmission {
    DirectSubmission {
        operation: operation.into(),
        revision: None,
        values: vec!["-V".into()],
    }
}
struct Launcher;
impl DirectReviewLauncher for Launcher {
    fn launch(&self, _: &str) -> Result<(), DirectRequestError> {
        Ok(())
    }
}
pub(crate) struct Fixture {
    pub(crate) root: tempfile::TempDir,
    app: Option<ProviderApplication>,
    pub(crate) clock: Arc<AtomicU64>,
    resolved: Arc<AtomicUsize>,
    revision: String,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        identity::TEST_IDENTITIES.with(|v| v.borrow_mut().take());
        identity::TEST_ACCOUNT_UUID.with(|v| v.borrow_mut().take());
    }
}
impl Fixture {
    pub(crate) fn app(&self) -> &ProviderApplication {
        self.app.as_ref().unwrap()
    }
    pub(crate) fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        identity::TEST_IDENTITIES.with(|v| {
            *v.borrow_mut() = Some(identity::Identities {
                provider_uid: unsafe { libc::geteuid() },
                provider_uuid: "synthetic-provider".into(),
                operator_uid: 42001,
                operator_uuid: "synthetic-operator".into(),
                human_gid: 20,
                agent_gid: 1,
                human_socket_dir: root.path().join("human"),
                ssh_runtime_dir: root.path().into(),
            })
        });
        let provider = Provider::start(root.path().join("provider")).unwrap();
        let clock = Arc::new(AtomicU64::new(10));
        let resolved = Arc::new(AtomicUsize::new(0));
        let app = ProviderApplication::new(
            provider,
            Box::new(Backend(resolved.clone())),
            Box::new(Clock(clock.clone())),
        )
        .unwrap();
        app.authenticate(SensitiveString::new("synthetic-password".into()))
            .unwrap();
        app.register_image(
            app.human_owner(),
            image_registration(),
            &NativeExecutablePreparer,
        )
        .unwrap();
        let operation = operation_draft();
        let revision = app
            .create_operation(app.human_owner(), operation)
            .unwrap()
            .revision;
        Self {
            root,
            app: Some(app),
            clock,
            resolved,
            revision,
        }
    }
    fn request(&self) -> String {
        self.app()
            .submit_direct(
                self.app().human_owner(),
                DirectSubmission {
                    operation: "native-version".into(),
                    revision: None,
                    values: vec!["-V".into()],
                },
                &Launcher,
            )
            .unwrap()
            .id
    }
    fn approve(&self, id: &str) {
        let approval = self
            .app()
            .prepare_approval(self.app().human_owner(), id)
            .unwrap()
            .authenticate(SensitiveString::new("synthetic-password".into()), &Auth)
            .unwrap();
        assert_eq!(
            self.app().commit_approval(approval).unwrap(),
            DirectStatus::Approved
        );
    }
    fn execute(&self, id: &str) -> Result<DirectStatus, DirectRequestError> {
        self.app().run_execution(
            self.app().human_owner(),
            id,
            &NativeExecutablePreparer,
            &NativeProcessSupervisor {
                material: self.root.path().join("unused"),
            },
        )
    }
}
#[test]
fn native_approved_launch_consumes_one_authority_and_redacts_results() {
    let f = Fixture::new();
    let id = f.request();
    f.approve(&id);
    let status = f.execute(&id).unwrap();
    assert!(
        matches!(status, DirectStatus::Completed { .. }),
        "{status:?}"
    );
    assert_eq!(f.resolved.load(Ordering::SeqCst), 1);
    assert!(f.execute(&id).is_err());
    assert_eq!(f.resolved.load(Ordering::SeqCst), 1);
    let state =
        std::fs::read_to_string(f.root.path().join("provider/provider-state.json")).unwrap();
    assert!(!state.contains("native-synthetic-value"));
    assert!(!state.contains("synthetic-password"));
}
#[test]
fn native_withdrawal_expiry_denial_and_lock_prevent_later_resolution() {
    for scenario in ["cancel", "expiry", "deny", "lock"] {
        let f = Fixture::new();
        let id = f.request();
        if scenario != "deny" {
            f.approve(&id);
        }
        match scenario {
            "cancel" => f
                .app()
                .cancel_execution(f.app().human_owner(), &id)
                .unwrap(),
            "expiry" => f.clock.store(1000, Ordering::SeqCst),
            "deny" => {
                f.app().deny_direct(f.app().human_owner(), &id).unwrap();
            }
            _ => f.app().lock().unwrap(),
        }
        assert!(f.execute(&id).is_err(), "{scenario}");
        assert_eq!(f.resolved.load(Ordering::SeqCst), 0, "{scenario}");
    }
}
#[test]
fn native_signed_request_replay_wrong_identity_revocation_and_locked_restart() {
    let mut f = Fixture::new();
    let key = ed25519_dalek::SigningKey::from_bytes(&[73; 32]);
    let binding = f
        .app()
        .pair_agent(
            f.app().human_owner(),
            AgentPairing {
                label: "Synthetic kernel identity fixture".into(),
                public_key: crate::access::encode_public_key(&key.verifying_key()),
                uid: 1,
                gid: 1,
            },
        )
        .unwrap();
    // Pairing audit belongs to the operator, while filesystem ownership stays provider.
    let mut operation:OperationPolicyDraft=serde_json::from_value(serde_json::json!({
        "id":"after-pair","description":"Revalidate administrator audit after pairing","image_id":"native-ssh",
        "targets":["-V"],"arguments":[{"type":"target"}],"credentials":[{"namespace":null,"item_id":"11111111-1111-1111-1111-111111111111","label":"Synthetic","use_type":"login","field_mappings":[{"field":"password","environment":"NATIVE_TEST_VALUE"}]}]
    })).unwrap();
    operation.id = "after-pair".into();
    f.app()
        .create_operation(f.app().human_owner(), operation)
        .unwrap();
    let request = SignedSubmission::sign(
        binding.id.clone(),
        [23; 32],
        "native-version".into(),
        f.revision.clone(),
        vec!["-V".into()],
        &key,
    )
    .unwrap();
    assert!(
        f.app()
            .submit_signed(2, &[1], request.clone(), &Launcher)
            .is_err()
    );
    assert!(
        f.app()
            .submit_signed(1, &[2], request.clone(), &Launcher)
            .is_err()
    );
    let mut wrong = request.clone();
    wrong.signature = "A".repeat(86);
    assert!(f.app().submit_signed(1, &[1], wrong, &Launcher).is_err());
    let id = f
        .app()
        .submit_signed(1, &[1], request.clone(), &Launcher)
        .unwrap();
    f.approve(&id);
    assert!(matches!(
        f.execute(&id).unwrap(),
        DirectStatus::Completed { .. }
    ));
    assert!(
        f.app()
            .submit_signed(1, &[1], request.clone(), &Launcher)
            .is_err()
    );
    let root = f.root.path().join("provider");
    drop(f.app.take());
    let restarted = ProviderApplication::new(
        Provider::start(root).unwrap(),
        Box::new(Backend(f.resolved.clone())),
        Box::new(Clock(f.clock.clone())),
    )
    .unwrap();
    assert_eq!(
        restarted.submit_signed(1, &[1], request.clone(), &Launcher),
        Err(AgentRejection::Locked)
    );
    restarted
        .authenticate(SensitiveString::new("synthetic-password".into()))
        .unwrap();
    assert_eq!(
        restarted.submit_signed(1, &[1], request.clone(), &Launcher),
        Err(AgentRejection::Replay)
    );
    restarted
        .revoke_agent(restarted.human_owner(), &binding.id)
        .unwrap();
    let next = SignedSubmission::sign(
        binding.id,
        [24; 32],
        "native-version".into(),
        f.revision.clone(),
        vec!["-V".into()],
        &key,
    )
    .unwrap();
    assert!(restarted.submit_signed(1, &[1], next, &Launcher).is_err());
}

#[test]
fn native_preparer_rejects_digest_mutation_writable_copy_symlink_and_foreign_profile() {
    let reg = image_registration();
    let image = || ExecutionImage {
        root: Path::new(&reg.execution_root),
        path: Path::new(&reg.path),
        sha256: &reg.sha256,
        profile: reg.profile,
    };
    assert!(
        NativeExecutablePreparer
            .prepare(image(), vec!["ssh".into(), "-V".into()])
            .is_ok()
    );
    let mut bad = image();
    bad.sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
    assert!(
        NativeExecutablePreparer
            .prepare(bad, vec!["ssh".into()])
            .is_err()
    );
    let mut foreign = image();
    foreign.profile = ExecutionProfile::ReviewedSelfContainedElf64V1;
    assert!(
        NativeExecutablePreparer
            .prepare(foreign, vec!["ssh".into()])
            .is_err()
    );
    let root = tempfile::tempdir().unwrap();
    let copy = root.path().join("ssh");
    std::fs::copy(&reg.path, &copy).unwrap();
    assert!(
        NativeExecutablePreparer
            .prepare(
                ExecutionImage {
                    root: root.path(),
                    path: &copy,
                    sha256: &reg.sha256,
                    profile: reg.profile
                },
                vec!["ssh".into()]
            )
            .is_err()
    );
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&reg.path, &link).unwrap();
    assert!(
        NativeExecutablePreparer
            .prepare(
                ExecutionImage {
                    root: root.path(),
                    path: &link,
                    sha256: &reg.sha256,
                    profile: reg.profile
                },
                vec!["ssh".into()]
            )
            .is_err()
    );
    let mut macho = std::fs::read(&reg.path).unwrap();
    macho[0] = 0;
    assert!(image::macho(&macho).is_err());
}
struct Control {
    live: Cell<bool>,
    release_allowed: bool,
    started: Cell<bool>,
}
impl ExecutionControl for Control {
    fn live(&self) -> bool {
        self.live.get()
    }
    fn remaining(&self) -> Duration {
        Duration::from_secs(5)
    }
    fn release(
        &self,
        action: &mut dyn FnMut() -> Result<(), ExecutionError>,
    ) -> Result<(), ExecutionError> {
        if !self.release_allowed {
            Err(ExecutionError::Cancelled)
        } else {
            action()
        }
    }
    fn started(&self) -> Result<(), ExecutionError> {
        self.started.set(true);
        self.live.set(false);
        Ok(())
    }
}
#[test]
fn native_release_denial_does_not_launch_and_withdrawal_does_not_signal_consumer() {
    use std::net::TcpListener;
    let root = tempfile::tempdir().unwrap();
    let reg = image_registration();
    let supervisor = NativeProcessSupervisor {
        material: root.path().into(),
    };
    let denied = Control {
        live: Cell::new(true),
        release_allowed: false,
        started: Cell::new(false),
    };
    let prepared = NativeExecutablePreparer
        .prepare(
            ExecutionImage {
                root: Path::new(&reg.execution_root),
                path: Path::new(&reg.path),
                sha256: &reg.sha256,
                profile: reg.profile,
            },
            vec!["ssh".into(), "-V".into()],
        )
        .unwrap();
    let result = supervisor.supervise_controlled(
        prepared,
        ChildEnvironment::from_mappings([]).unwrap(),
        &denied,
    );
    assert_eq!(result.cleanup, CleanupEvidence::NotStarted);
    assert!(!denied.started.get());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let prepared = NativeExecutablePreparer
        .prepare(
            ExecutionImage {
                root: Path::new(&reg.execution_root),
                path: Path::new(&reg.path),
                sha256: &reg.sha256,
                profile: reg.profile,
            },
            vec![
                "ssh".into(),
                "-F".into(),
                "/dev/null".into(),
                "-oConnectTimeout=2".into(),
                "-oBatchMode=yes".into(),
                "-p".into(),
                port.to_string(),
                "127.0.0.1".into(),
            ],
        )
        .unwrap();
    let cancel = Control {
        live: Cell::new(true),
        release_allowed: true,
        started: Cell::new(false),
    };
    let result = supervisor.supervise_controlled(
        prepared,
        ChildEnvironment::from_mappings([]).unwrap(),
        &cancel,
    );
    assert_eq!(result.outcome, Err(ExecutionError::ObservationLost));
    assert_eq!(result.cleanup, CleanupEvidence::Detached);
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(error) => panic!("consumer did not survive withdrawal: {error}"),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    use std::io::Read;
    let mut stream = stream;
    let mut bytes = [0u8; 256];
    assert!(
        stream.read(&mut bytes).unwrap() > 0,
        "SSH consumer survives and sends its banner after authority closes"
    );
    // Closing the fixture-owned server lets the consumer exit naturally; never send a signal.
    drop(stream);
}

#[test]
fn native_acl_grants_cannot_modify_durable_authority_or_credentials() {
    let mut f = Fixture::new();
    let state = f.root.path().join("provider/provider-state.json");
    let grant = |path: &Path| {
        assert!(
            std::process::Command::new("/bin/chmod")
                .args(["+a", "everyone allow write"])
                .arg(path)
                .status()
                .unwrap()
                .success()
        );
    };
    let clear = |path: &Path| {
        assert!(
            std::process::Command::new("/bin/chmod")
                .arg("-N")
                .arg(path)
                .status()
                .unwrap()
                .success()
        );
    };
    grant(&state);
    assert!(
        f.app().lock().is_err(),
        "an ACL must not bypass private mode bits"
    );
    clear(&state);
    drop(f.app.take());
    let directory = f.root.path().join("provider");
    grant(&directory);
    assert!(Provider::start(&directory).is_err());
    clear(&directory);
    let file = f.root.path().join("setup.json");
    std::fs::write(&file, b"{}").unwrap();
    grant(&file);
    assert!(super::super::session::load_setup(&file).is_err());
    clear(&file);
}

#[test]
fn native_account_reuse_denies_admission_and_revoked_history_survives_account_removal() {
    let mut f = Fixture::new();
    let key = ed25519_dalek::SigningKey::from_bytes(&[74; 32]);
    let binding = f
        .app()
        .pair_agent(
            f.app().human_owner(),
            AgentPairing {
                label: "Synthetic removed account".into(),
                public_key: crate::access::encode_public_key(&key.verifying_key()),
                uid: 1,
                gid: 1,
            },
        )
        .unwrap();
    let request = SignedSubmission::sign(
        binding.id.clone(),
        [25; 32],
        "native-version".into(),
        f.revision.clone(),
        vec!["-V".into()],
        &key,
    )
    .unwrap();
    let queued = f
        .app()
        .submit_signed(1, &[1], request.clone(), &Launcher)
        .unwrap();
    f.approve(&queued);
    let original = identity::uuid(1).unwrap();
    let replacement = if original == "0".repeat(32) {
        "1".repeat(32)
    } else {
        "0".repeat(32)
    };
    identity::TEST_ACCOUNT_UUID.with(|v| *v.borrow_mut() = Some((1, Some(replacement))));
    assert_eq!(
        f.app().submit_signed(1, &[1], request.clone(), &Launcher),
        Err(AgentRejection::Unauthorized)
    );
    assert!(
        f.execute(&queued).is_err(),
        "queued old-account authority cannot release"
    );
    assert_eq!(f.resolved.load(Ordering::SeqCst), 0);
    f.app()
        .revoke_agent(f.app().human_owner(), &binding.id)
        .unwrap();
    identity::TEST_ACCOUNT_UUID.with(|v| *v.borrow_mut() = Some((1, None)));
    drop(f.app.take());
    let restarted = ProviderApplication::new(
        Provider::start(f.root.path().join("provider")).unwrap(),
        Box::new(Backend(f.resolved.clone())),
        Box::new(Clock(f.clock.clone())),
    )
    .unwrap();
    restarted
        .authenticate(SensitiveString::new("synthetic-password".into()))
        .unwrap();
    let entries = restarted.list_agents(restarted.human_owner()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].status,
        crate::access::agent_binding::AgentBindingStatus::Revoked
    );
    assert_eq!(
        restarted.submit_signed(1, &[1], request, &Launcher),
        Err(AgentRejection::Unauthorized)
    );
    let state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(f.root.path().join("provider/provider-state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(state["agent_audit"].as_array().unwrap().len(), 2);
}

#[test]
fn native_spawn_delivers_resolved_mapping_without_parent_environment_or_descriptors() {
    struct SyntheticSpawn(PathBuf);
    impl ProcessSupervisor<NativeExecutablePreparer> for SyntheticSpawn {
        fn available(&self) -> bool {
            true
        }
        fn supervise(
            &self,
            _: PreparedExecutable,
            _: ChildEnvironment,
        ) -> Result<ExecutionOutcome, ExecutionError> {
            Err(ExecutionError::Unavailable)
        }
        fn supervise_controlled(
            &self,
            mut prepared: PreparedExecutable,
            environment: ChildEnvironment,
            control: &dyn ExecutionControl,
        ) -> Supervision {
            // Test-only direct preparation substitutes a disposable observer after the
            // application resolves its normal mapping. Production image admission is unchanged.
            prepared.path = self.0.clone();
            prepared.argv = arguments(vec!["synthetic-environment-observer".into()]).unwrap();
            let mut launch = Spawn::new(&mut prepared, &environment).unwrap();
            let mut pid = 0;
            control
                .release(&mut || {
                    pid = launch.start()?;
                    Ok(())
                })
                .unwrap();
            drop(launch);
            control.started().unwrap();
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status));
            let success = libc::WEXITSTATUS(status) == 0;
            Supervision {
                outcome: Ok(if success {
                    ExecutionOutcome::ExitedZero
                } else {
                    ExecutionOutcome::ExitedNonZero
                }),
                cleanup: CleanupEvidence::Reaped,
                helper_reaped: false,
            }
        }
    }
    let f = Fixture::new();
    let source = f.root.path().join("environment-observer.c");
    let binary = f.root.path().join("environment-observer");
    std::fs::write(&source,br#"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
extern char **environ;
int main(void) {
    const char *value=getenv("NATIVE_TEST_VALUE");
    if (!value || strcmp(value,"native-synthetic-value")) return 1;
    int count=0;
    for (char **entry=environ; *entry; ++entry) {
        if (strcmp(*entry,"LANG=C") && strcmp(*entry,"LC_ALL=C") && strcmp(*entry,"NATIVE_TEST_VALUE=native-synthetic-value")) return 1;
        ++count;
    }
    if (count!=3) return 1;
    for (int fd=3; fd<getdtablesize(); ++fd) {
        errno=0;
        if (fcntl(fd,F_GETFD)!=-1 || errno!=EBADF) return 1;
    }
    return 0;
}
"#).unwrap();
    assert!(
        std::process::Command::new("/usr/bin/clang")
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()
            .unwrap()
            .success()
    );
    let extra = File::open(&source).unwrap();
    assert!(extra.as_raw_fd() > 2);
    // Deliberately inheritable descriptor owned solely by this fixture.
    assert_eq!(
        unsafe { libc::fcntl(extra.as_raw_fd(), libc::F_SETFD, 0) },
        0
    );
    assert!(
        std::env::vars_os()
            .any(|(name, _)| name != "LANG" && name != "LC_ALL" && name != "NATIVE_TEST_VALUE")
    );
    let id = f.request();
    f.approve(&id);
    let status = f
        .app()
        .run_execution(
            f.app().human_owner(),
            &id,
            &NativeExecutablePreparer,
            &SyntheticSpawn(binary),
        )
        .unwrap();
    assert!(
        matches!(status, DirectStatus::Completed { exit_code: 0 }),
        "{status:?}"
    );
    assert_eq!(f.resolved.load(Ordering::SeqCst), 1);
}

#[test]
fn native_reaper_capacity_denies_execution_before_backend_resolution() {
    let f = Fixture::new();
    let id = f.request();
    f.approve(&id);
    let mut reservations = Vec::new();
    while let Ok(reservation) = super::reaper::reserve() {
        reservations.push(reservation);
    }
    assert!(!reservations.is_empty());
    assert!(f.execute(&id).is_err());
    assert_eq!(f.resolved.load(Ordering::SeqCst), 0);
    drop(reservations);
    assert!(super::reaper::reserve().is_ok());
}

/// Real kernel listing: the caller is excluded, and a copied system binary
/// running under the provider file name is observed until it exits.
#[test]
fn native_stopped_provider_proof_observes_other_provider_processes() {
    use std::ffi::OsStr;
    let uid = unsafe { libc::geteuid() };
    let name = OsStr::new(PROVIDER_EXECUTABLE);
    assert!(!platform::other_process_named(uid, name).unwrap());
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join(PROVIDER_EXECUTABLE);
    std::fs::copy("/bin/sleep", &copy).unwrap();
    let mut running = std::process::Command::new(&copy).arg("30").spawn().unwrap();
    let observed = platform::other_process_named(uid, name);
    let elsewhere = platform::other_process_named(uid.wrapping_add(1), name);
    let state_root = tempfile::tempdir().unwrap();
    identity::TEST_IDENTITIES.with(|v| {
        *v.borrow_mut() = Some(identity::Identities {
            provider_uid: uid,
            provider_uuid: "synthetic-provider".into(),
            operator_uid: 42001,
            operator_uuid: "synthetic-operator".into(),
            human_gid: 20,
            agent_gid: 1,
            human_socket_dir: state_root.path().join("human"),
            ssh_runtime_dir: state_root.path().into(),
        })
    });
    let mut cleared = false;
    let refused = NativeProcessSupervisor::recover_stopped(state_root.path(), || {
        cleared = true;
        Ok(())
    });
    identity::TEST_IDENTITIES.with(|v| v.borrow_mut().take());
    running.kill().unwrap();
    running.wait().unwrap();
    assert!(observed.unwrap());
    assert!(!elsewhere.unwrap());
    assert!(matches!(refused, Err(ExecutionError::ManagerUnavailable)));
    assert!(!cleared);
    assert!(!platform::other_process_named(uid, name).unwrap());
}

/// Disposable producer image; modes are selected by argv[1]. Every mode ignores SIGPIPE
/// and exits zero unless stated, so frame validation alone decides acceptance.
const PRODUCER_SOURCE: &[u8] = br#"
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
static void put(const void *data, size_t len) {
    const char *p = data;
    while (len) { ssize_t n = write(3, p, len); if (n <= 0) return; p += n; len -= (size_t)n; }
}
static void header(uint32_t n) {
    unsigned char h[4] = { n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff };
    put(h, 4);
}
/* Writes the header then {"password":"<fill>"} of exactly total JSON bytes. */
static void password(uint32_t total, char fill) {
    size_t k = total - 15;
    char *json = malloc(total);
    memcpy(json, "{\"password\":\"", 13);
    memset(json + 13, fill, k);
    memcpy(json + 13 + k, "\"}", 2);
    header(total);
    put(json, total);
    free(json);
}
int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    const char *m = argc > 1 ? argv[1] : "";
    if (!strcmp(m, "small")) { const char *j = "{\"password\":\"native-producer-sentinel\"}"; header((uint32_t)strlen(j)); put(j, strlen(j)); }
    else if (!strcmp(m, "descriptors")) {
        /* fd 3 is the write-only pipe end; the read end and every other descriptor are closed. */
        struct stat st;
        int flags = fcntl(3, F_GETFL);
        if (flags < 0 || (flags & O_ACCMODE) != O_WRONLY || fstat(3, &st) || !S_ISFIFO(st.st_mode)) return 1;
        for (int fd = 4; fd < getdtablesize(); ++fd) { errno = 0; if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) return 1; }
        const char *j = "{\"password\":\"native-producer-sentinel\"}"; header((uint32_t)strlen(j)); put(j, strlen(j));
    }
    else if (!strcmp(m, "maximum")) password(65536, 'm');
    else if (!strcmp(m, "overflow")) { password(65536, 'o'); char extra[70000]; memset(extra, 'x', sizeof extra); put(extra, sizeof extra); }
    else if (!strcmp(m, "short")) { header(100); put("{\"password\":\"x\"", 15); }
    else if (!strcmp(m, "zero")) header(0);
    else if (!strcmp(m, "oversized")) { header(65537); put("{}", 2); }
    else if (!strcmp(m, "trailing")) { password(40, 't'); put(" ", 1); }
    else if (!strcmp(m, "malformed")) { header(8); put("not json", 8); }
    else if (!strcmp(m, "nonzero")) { const char *j = "{\"password\":\"native-producer-sentinel\"}"; header((uint32_t)strlen(j)); put(j, strlen(j)); return 1; }
    else if (!strcmp(m, "detached")) {
        pid_t child = fork();
        if (child < 0) return 1;
        if (child == 0) { sleep(3); put("late-bytes", 10); _exit(0); }
        const char *j = "{\"password\":\"native-producer-sentinel\"}"; header((uint32_t)strlen(j)); put(j, strlen(j));
    }
    else return 2;
    return 0;
}
"#;
fn producer_image() -> &'static Path {
    static IMAGE: std::sync::OnceLock<(tempfile::TempDir, PathBuf)> = std::sync::OnceLock::new();
    &IMAGE
        .get_or_init(|| {
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("producer.c");
            let binary = dir.path().join("producer");
            std::fs::write(&source, PRODUCER_SOURCE).unwrap();
            assert!(
                std::process::Command::new("/usr/bin/clang")
                    .arg(&source)
                    .arg("-o")
                    .arg(&binary)
                    .status()
                    .unwrap()
                    .success()
            );
            (dir, binary)
        })
        .1
}
fn prepared_ssh() -> PreparedExecutable {
    let reg = image_registration();
    NativeExecutablePreparer
        .prepare(
            ExecutionImage {
                root: Path::new(&reg.execution_root),
                path: Path::new(&reg.path),
                sha256: &reg.sha256,
                profile: reg.profile,
            },
            vec!["ssh".into()],
        )
        .unwrap()
}
/// Spawns the disposable producer through the production `Spawn` with a test-only
/// image substitution after admission, then reaps it. Returns whether it exited zero.
fn spawn_and_reap(mut prepared: PreparedExecutable, mode: &str) -> bool {
    prepared.path = producer_image().into();
    prepared.argv = arguments(vec!["synthetic-producer".into(), mode.into()]).unwrap();
    let environment = ChildEnvironment::from_mappings([]).unwrap();
    let mut launch = Spawn::new(&mut prepared, &environment).unwrap();
    let pid = launch.start().unwrap();
    drop(launch);
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}
fn produce(mode: &str) -> Result<crate::secret_storage::SecretImport, ExecutionError> {
    let mut prepared = prepared_ssh();
    let mut output = NativeExecutablePreparer
        .prepare_producer(&mut prepared)
        .unwrap();
    assert!(spawn_and_reap(prepared, mode), "{mode}");
    output.read(CleanupEvidence::Reaped)
}

#[test]
fn native_producer_frame_round_trips_through_fd_three() {
    let input = produce("small").unwrap();
    assert_eq!(input.password.as_deref(), Some("native-producer-sentinel"));
    assert_eq!(input.selectors(), ["password"]);
    let input = produce("descriptors").unwrap();
    assert_eq!(input.password.as_deref(), Some("native-producer-sentinel"));
}

#[test]
fn native_producer_maximum_frame_exceeds_pipe_buffer_and_succeeds() {
    let input = produce("maximum").unwrap();
    let password = input.password.as_deref().unwrap();
    assert_eq!(password.len(), crate::secret_storage::MAX_IMPORT_BYTES - 15);
    assert!(password.bytes().all(|b| b == b'm'));
}

#[test]
fn native_producer_rejects_overflow_and_malformed_frames() {
    for mode in [
        "overflow",
        "short",
        "zero",
        "oversized",
        "trailing",
        "malformed",
    ] {
        assert_eq!(
            produce(mode).err(),
            Some(ExecutionError::ExecutionFailed),
            "{mode}"
        );
    }
}

#[test]
fn native_producer_output_requires_confirmed_reaping() {
    for evidence in [
        CleanupEvidence::NotStarted,
        CleanupEvidence::Detached,
        CleanupEvidence::Uncertain,
    ] {
        let mut prepared = prepared_ssh();
        let mut output = NativeExecutablePreparer
            .prepare_producer(&mut prepared)
            .unwrap();
        assert!(spawn_and_reap(prepared, "small"));
        assert_eq!(
            output.read(evidence).err(),
            Some(ExecutionError::CleanupUncertain),
            "{evidence:?}"
        );
        // One-shot: a refused read consumed the channel.
        assert!(output.read(CleanupEvidence::Reaped).is_err());
    }
}

#[test]
fn native_producer_abandoned_launch_accepts_nothing() {
    let mut prepared = prepared_ssh();
    let mut output = NativeExecutablePreparer
        .prepare_producer(&mut prepared)
        .unwrap();
    assert!(
        NativeExecutablePreparer
            .prepare_producer(&mut prepared)
            .is_err(),
        "one channel per prepared execution"
    );
    drop(prepared);
    let started = std::time::Instant::now();
    assert_eq!(
        output.read(CleanupEvidence::Reaped).err(),
        Some(ExecutionError::ExecutionFailed)
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn native_producer_detached_descendant_neither_hangs_nor_appends() {
    let mut prepared = prepared_ssh();
    let mut output = NativeExecutablePreparer
        .prepare_producer(&mut prepared)
        .unwrap();
    assert!(spawn_and_reap(prepared, "detached"));
    // The descendant still holds fd 3 and writes only after three seconds.
    let started = std::time::Instant::now();
    let input = output.read(CleanupEvidence::Reaped).unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(input.password.as_deref(), Some("native-producer-sentinel"));
}

/// Application wiring: native create reaches the adapter's producer channel, and only a
/// zero exit with confirmed reaping posts. The fixture never signals the producer.
#[test]
fn native_create_reaches_producer_and_posts_only_after_successful_reaped_exit() {
    struct ProducerSpawn(&'static str);
    impl ProcessSupervisor<NativeExecutablePreparer> for ProducerSpawn {
        fn available(&self) -> bool {
            true
        }
        fn supervise(
            &self,
            _: PreparedExecutable,
            _: ChildEnvironment,
        ) -> Result<ExecutionOutcome, ExecutionError> {
            Err(ExecutionError::Unavailable)
        }
        fn supervise_controlled(
            &self,
            mut prepared: PreparedExecutable,
            environment: ChildEnvironment,
            control: &dyn ExecutionControl,
        ) -> Supervision {
            assert!(prepared.producer.is_some(), "create prepares fd 3");
            prepared.path = producer_image().into();
            prepared.argv = arguments(vec!["synthetic-producer".into(), self.0.into()]).unwrap();
            let mut launch = Spawn::new(&mut prepared, &environment).unwrap();
            let mut pid = 0;
            control
                .release(&mut || {
                    pid = launch.start()?;
                    Ok(())
                })
                .unwrap();
            drop(launch);
            control.started().unwrap();
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status));
            Supervision {
                outcome: Ok(if libc::WEXITSTATUS(status) == 0 {
                    ExecutionOutcome::ExitedZero
                } else {
                    ExecutionOutcome::ExitedNonZero
                }),
                cleanup: CleanupEvidence::Reaped,
                helper_reaped: false,
            }
        }
    }
    for (mode, posts) in [("small", true), ("nonzero", false), ("malformed", false)] {
        NATIVE_CREATED.with(|created| created.borrow_mut().clear());
        let f = Fixture::new();
        f.app()
            .create_operation(
                f.app().human_owner(),
                OperationPolicyDraft {
                    require_password: false,
                    id: "native-create".into(),
                    description: "Native synthetic create".into(),
                    image_id: "native-ssh".into(),
                    targets: vec![],
                    arguments: vec![],
                    credentials: vec![],
                    ssh: None,
                    create: Some(CreateEffect {
                        server: "https://vault.example".into(),
                        destination: crate::secret_storage::Destination {
                            account_id: "11111111-1111-1111-1111-111111111111".into(),
                            folder: "homelab/production".into(),
                            folder_id: "22222222-2222-2222-2222-222222222222".into(),
                            reference: "homelab/production/github/token".into(),
                        },
                        fields: vec!["password".into()],
                        eligibility_marker: "deploy".into(),
                    }),
                },
            )
            .unwrap();
        let id = f
            .app()
            .submit_direct(
                f.app().human_owner(),
                DirectSubmission {
                    operation: "native-create".into(),
                    revision: None,
                    values: vec![],
                },
                &Launcher,
            )
            .unwrap()
            .id;
        f.approve(&id);
        let result = f.app().run_execution(
            f.app().human_owner(),
            &id,
            &NativeExecutablePreparer,
            &ProducerSpawn(mode),
        );
        let created = NATIVE_CREATED.with(|created| created.borrow().clone());
        if posts {
            assert!(
                matches!(result, Ok(DirectStatus::Completed { exit_code: 0 })),
                "{mode}: {result:?}"
            );
            assert_eq!(created, ["native-producer-sentinel"], "{mode}");
        } else {
            assert!(created.is_empty(), "{mode}: {result:?}");
        }
        assert_eq!(f.resolved.load(Ordering::SeqCst), 0, "{mode}");
        let state =
            std::fs::read_to_string(f.root.path().join("provider/provider-state.json")).unwrap();
        assert!(!state.contains("native-producer-sentinel"), "{mode}");
    }
}
