//! Invoked only inside an isolated systemd provider harness by the integration suite.
use super::*;
use crate::access::{
    policy::ExecutionProfile,
    ports::{ExecutionImage, SensitiveString},
};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
// Record before StartTransientUnit, including worker-thread launches and instant exits.
pub(super) fn record_identity(lease: &manager::Lease) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(root) = std::env::var_os("VW18_ROOT") {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(PathBuf::from(root).join("identities.jsonl"))
            .unwrap();
        serde_json::to_writer(&mut file, lease).unwrap();
        writeln!(file).unwrap();
        file.sync_all().unwrap();
    }
}
// Per-unit synthetic test input; never mutates the shared manager environment.
pub(super) fn apply_environment_fixture(
    properties: &mut manager::PropertiesList,
    values: &[String],
) {
    if let Some(root) = std::env::var_os("VW18_ROOT") {
        use std::os::unix::fs::DirBuilderExt;
        // A bypassed SSH fchdir must leave markers inside disposable fixture storage.
        let ambient = PathBuf::from(root).join("ambient-working-directory");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&ambient)
            .unwrap();
        properties.push((
            "WorkingDirectory".into(),
            dbus::arg::Variant(Box::new(ambient.to_str().unwrap().to_owned())),
        ));
    }
    if !values.is_empty() {
        properties.push((
            "Environment".into(),
            dbus::arg::Variant(Box::new(values.to_vec())),
        ));
    }
}
struct Control {
    root: PathBuf,
}
impl ExecutionControl for Control {
    fn live(&self) -> bool {
        !self.root.join("cancel").exists()
    }
    fn remaining(&self) -> Duration {
        Duration::from_secs(30)
    }
    fn release(
        &self,
        action: &mut dyn FnMut() -> Result<(), ExecutionError>,
    ) -> Result<(), ExecutionError> {
        if self.live() {
            action()
        } else {
            Err(ExecutionError::Cancelled)
        }
    }
    fn started(&self) -> Result<(), ExecutionError> {
        if self.root.join("stop-after-exec").exists() {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !self.root.join("tree-ready").exists() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
            std::fs::write(self.root.join("cancel"), b"cancel").unwrap();
        }
        journal_barrier("started");
        std::fs::write(self.root.join("started"), b"started")
            .map_err(|_error| ExecutionError::ExecutionFailed)
    }
}
#[test]
#[ignore = "internal real-manager harness; invoked by scripts/test-systemd-supervisor.sh"]
fn provider_harness() {
    let root = PathBuf::from(std::env::var_os("VW18_ROOT").expect("harness root"));
    let stage = |value: &str| std::fs::write(root.join("stage"), value).unwrap();
    stage("configuration");
    let provider = std::env::var("VW18_PROVIDER").expect("harness provider");
    let mode = if root.join("recover").exists() {
        "recover".into()
    } else {
        std::env::var("VW18_MODE").expect("harness mode")
    };
    let runtime = PathBuf::from(format!("/run/user/{}", unsafe { libc::geteuid() }));
    let mut config =
        Config::new(provider, root.join("helper"), &runtime).expect("safe helper installation");
    std::fs::write(
        root.join("runtime"),
        config.runtime.as_os_str().as_encoded_bytes(),
    )
    .unwrap();
    let manager_environment = if mode == "helper-environment" {
        config.test_environment = vec![
            "LD_PRELOAD=/synthetic-must-never-load.so".into(),
            "GLIBC_TUNABLES=glibc.malloc.check=3".into(),
            "RUST_BACKTRACE=1".into(),
            "VW18_ARBITRARY_SECRET=synthetic-helper-environment-input".into(),
        ];
        let before = manager_environment_snapshot();
        let observation_config = config.clone();
        let observation_root = root.clone();
        let names = before
            .iter()
            .chain(&config.test_environment)
            .map(|entry| entry.split_once('=').unwrap().0.to_owned())
            .collect::<Vec<_>>();
        PHASE_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |phase| {
                if phase == LaunchPhase::JobAccepted {
                    observe_helper_environment(&observation_config, &names);
                    std::fs::write(
                        observation_root.join("helper-environment-observed"),
                        b"observed",
                    )
                    .unwrap();
                }
            }));
        });
        Some(before)
    } else {
        None
    };
    let supervisor = SystemdProcessSupervisor {
        config,
        healthy: AtomicBool::new(true),
        material_root: if mode.starts_with("ssh-")
            || mode.starts_with("app-ssh-")
            || root.join("ssh").exists()
        {
            Some(crate::adapters::ssh_material::initialize(&root).unwrap())
        } else {
            None
        },
    };
    // This observer is itself the manager-recognized MainPID, never an arbitrary shell child.
    Manager::connect()
        .unwrap()
        .provider(&supervisor.config)
        .unwrap();
    stage("recovery");
    supervisor.recover().unwrap();
    stage("recovered");
    if mode == "recover" {
        finish(&root, b"recovered");
        return;
    }
    if mode.starts_with("ssh-") {
        ssh_scenario(&root, &mode, &supervisor);
        return;
    }
    if mode == "failed-launch-recovery" {
        let manager = Manager::connect().unwrap();
        let lease = manager.lease(supervisor.config.name().unwrap());
        let _listener = BridgeListener::bind(&supervisor.config.socket(&lease.name)).unwrap();
        supervisor.config.record(&lease).unwrap();
        assert!(
            manager
                .start(&supervisor.config, &lease, Duration::from_secs(30))
                .is_err()
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while manager.unit(&lease.name).unwrap().is_some() {
            assert!(
                Instant::now() < deadline,
                "failed launch must be collected without reset-failed"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let retained = supervisor.config.leases().unwrap();
        assert_eq!(
            retained.len(),
            1,
            "unloading must retain independent cleanup identity"
        );
        assert_eq!(retained[0].name, lease.name);
        supervisor.recover().unwrap();
        assert!(supervisor.config.leases().unwrap().is_empty());
        finish(&root, b"failed-unit-collected-and-lease-recovered");
        return;
    }
    if mode == "collision" {
        let manager = Manager::connect().unwrap();
        let lease = manager.lease(supervisor.config.name().unwrap());
        let _listener = BridgeListener::bind(&supervisor.config.socket(&lease.name)).unwrap();
        supervisor.config.record(&lease).unwrap();
        manager
            .start(&supervisor.config, &lease, Duration::from_secs(30))
            .unwrap();
        let first = manager.owned(&supervisor.config, &lease).unwrap().unwrap();
        assert_eq!(
            manager.start(&supervisor.config, &lease, Duration::from_secs(30)),
            Err(ExecutionError::UnitCollision)
        );
        let second = manager.owned(&supervisor.config, &lease).unwrap().unwrap();
        assert_eq!(first.pid, second.pid);
        assert_eq!(first.invocation, second.invocation);
        drop(_listener);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !matches!(manager.unused(&supervisor.config, &lease), Ok(true)) {
            assert!(
                Instant::now() < deadline,
                "unreleased helper should finish without termination"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        supervisor.config.forget(&lease).unwrap();
        finish(&root, b"collision-refused-and-reaped");
        return;
    }
    if mode.starts_with("app-ssh-") {
        ssh_application_scenario(&root, &mode, Arc::new(supervisor));
        return;
    }
    if mode.starts_with("app-") {
        application_scenario(&root, &mode, Arc::new(supervisor));
        return;
    }
    if mode.starts_with("phase-") {
        let target = match mode.as_str() {
            "phase-job" => LaunchPhase::JobAccepted,
            "phase-helper" => LaunchPhase::HelperConnected,
            "phase-transfer" => LaunchPhase::CredentialsTransferred,
            "phase-release" => LaunchPhase::Release,
            "phase-exit" => LaunchPhase::NaturalExit,
            _ => panic!("unknown phase"),
        };
        let cancelled = root.join("cancel");
        PHASE_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |observed| {
                if observed == target {
                    std::fs::write(&cancelled, b"cancel").unwrap();
                }
            }))
        });
    }
    if mode.starts_with("fault-") {
        use manager::{FAULT, Fault};
        match mode.as_str() {
            "fault-missing" => FAULT.with(|f| f.set(Fault::Missing)),
            "fault-job" => FAULT.with(|f| f.set(Fault::Job)),
            "fault-exec" => FAULT.with(|f| f.set(Fault::Exec)),
            "fault-monitor" | "fault-observe" => {
                let fault = if mode == "fault-monitor" {
                    Fault::Monitor
                } else {
                    Fault::Observe
                };
                PHASE_HOOK.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move |phase| {
                        if phase == LaunchPhase::Release {
                            FAULT.with(|f| f.set(fault));
                        }
                    }))
                });
            }
            _ => panic!("unknown fault"),
        }
    }
    if mode == "fault-observe" {
        std::fs::write(root.join("stop-after-exec"), b"stop").unwrap();
    }
    let image = root.join("image");
    let digest = Sha256::digest(std::fs::read(&image).unwrap())
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect::<String>();
    let argv = vec![
        "fixture".into(),
        if mode == "orphan" {
            "orphan"
        } else if mode == "exit"
            || mode == "helper-environment"
            || mode.starts_with("phase-")
            || (mode.starts_with("fault-") && mode != "fault-observe")
        {
            "exit"
        } else {
            "tree"
        }
        .into(),
        root.join("tree-ready").to_str().unwrap().to_owned(),
    ];
    let prepared = LinuxExecutablePreparer
        .prepare(
            ExecutionImage {
                root: &root,
                path: &image,
                sha256: &digest,
                profile: ExecutionProfile::ReviewedSelfContainedElf64V1,
            },
            argv,
        )
        .unwrap();
    // A replaced source pathname cannot change the sealed capability.
    std::fs::rename(&image, root.join("original-image")).unwrap();
    std::fs::write(&image, b"replacement is not an executable").unwrap();
    let environment = ChildEnvironment::from_mappings([(
        "LOGIN_TOKEN".into(),
        SensitiveString::new("story18-synthetic-secret".into()),
    )])
    .unwrap();
    let inherited = std::env::vars_os().collect::<std::collections::BTreeMap<_, _>>();
    let result =
        supervisor.supervise_controlled(prepared, environment, &Control { root: root.clone() });
    assert!(
        std::env::vars_os().collect::<std::collections::BTreeMap<_, _>>() == inherited,
        "supervision must not mutate the provider environment"
    );
    if let Some(before) = manager_environment {
        assert!(
            manager_environment_snapshot() == before,
            "shared manager environment changed"
        );
        assert!(root.join("helper-environment-observed").exists());
    }
    stage(&format!(
        "outcome={:?}, cleanup={:?}",
        result.outcome, result.cleanup
    ));
    if mode.starts_with("fault-") {
        use manager::{FAULT, Fault};
        let (error, cleanup) = match mode.as_str() {
            "fault-missing" => (
                ExecutionError::ManagerUnavailable,
                CleanupEvidence::NotStarted,
            ),
            "fault-job" => (ExecutionError::ExecutionFailed, CleanupEvidence::Reaped),
            "fault-exec" | "fault-monitor" => {
                (ExecutionError::ObservationLost, CleanupEvidence::Reaped)
            }
            "fault-observe" => (ExecutionError::ObservationLost, CleanupEvidence::Detached),
            _ => panic!("unknown fault scenario"),
        };
        assert_eq!(result.outcome, Err(error));
        assert_eq!(result.cleanup, cleanup);
        if mode == "fault-monitor" {
            assert!(!supervisor.available());
        }
        if mode == "fault-exec" {
            assert!(!root.join("started").exists());
        }
        if mode == "fault-observe" {
            let leases = supervisor.config.leases().unwrap();
            assert_eq!(leases.len(), 1);
            assert!(
                !manager::proc_empty(std::path::Path::new("/proc"), &leases[0].cgroup).unwrap()
            );
            std::fs::write(root.join("cgroup"), &leases[0].cgroup).unwrap();
        }
        FAULT.with(|f| f.set(Fault::None));
        supervisor.recover().unwrap();
        assert_eq!(
            supervisor.config.leases().unwrap().len(),
            usize::from(mode == "fault-observe")
        );
        finish(&root, b"failed-closed-and-recovered");
        return;
    }
    assert_eq!(
        result.cleanup,
        if matches!(mode.as_str(), "cancel" | "orphan" | "helper-crash") {
            CleanupEvidence::Detached
        } else {
            CleanupEvidence::Reaped
        }
    );
    if mode == "exit" {
        assert!(
            result.helper_reaped,
            "normal completion carries helper ECHILD evidence"
        );
    }
    if matches!(
        mode.as_str(),
        "exit" | "orphan" | "helper-environment" | "phase-exit"
    ) {
        assert_eq!(result.outcome, Ok(ExecutionOutcome::ExitedZero));
    } else if mode == "helper-failure" {
        assert_eq!(result.outcome, Err(ExecutionError::ExecutionFailed));
    } else {
        assert_eq!(
            result.outcome,
            Err(if matches!(mode.as_str(), "cancel" | "helper-crash") {
                ExecutionError::ObservationLost
            } else {
                ExecutionError::Cancelled
            })
        );
    }
    if mode.starts_with("phase-") && mode != "phase-exit" {
        assert!(
            !root.join("started").exists(),
            "revoked phase never releases execution"
        );
    }
    finish(&root, b"reaped");
}

fn application_scenario(
    root: &std::path::Path,
    mode: &str,
    supervisor: Arc<SystemdProcessSupervisor>,
) {
    use crate::access::{
        direct_request::*,
        direct_request_tests::{Launcher, fixture},
        policy::*,
        ports::*,
    };
    use std::os::unix::fs::PermissionsExt;
    struct Permit;
    impl ApprovalAuthenticator for Permit {
        fn authenticate(&self, _: SensitiveString) -> Result<(), SessionError> {
            Ok(())
        }
    }
    let f = fixture();
    let image_path = f.dir.path().join("approved-image");
    std::fs::set_permissions(&image_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::copy(root.join("image"), &image_path).unwrap();
    std::fs::set_permissions(&image_path, std::fs::Permissions::from_mode(0o500)).unwrap();
    let digest = Sha256::digest(std::fs::read(&image_path).unwrap())
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect::<String>();
    let image = ApprovedImage::new(
        "deploy-image".into(),
        f.dir.path().to_str().unwrap().into(),
        image_path.to_str().unwrap().into(),
        digest,
        ExecutionProfile::ReviewedSelfContainedElf64V1,
    )
    .unwrap();
    let state_path = f.dir.path().join("provider/provider-state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    state["approved_images"] = serde_json::json!([image]);
    state["operations"] = serde_json::json!([]);
    std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let target = match mode {
        "app-exit" | "app-worker-exit" => "exit",
        "app-nonzero" => "nonzero",
        "app-signal" => "signal",
        "app-agent-revoke" => "multi-tree",
        _ => "tree",
    };
    let marker = root.join("app-tree-ready").to_str().unwrap().to_owned();
    let mut credentials = vec![LoginCredentialDraft {
        namespace: None,
        item_id: "11111111-1111-1111-1111-111111111111".into(),
        label: "Synthetic login".into(),
        use_type: CredentialUse::Login,
        field_mappings: vec![LoginFieldMapping {
            field: LoginField::Password,
            environment: "LOGIN_TOKEN".into(),
        }],
    }];
    if mode == "app-agent-revoke" {
        credentials.push(LoginCredentialDraft {
            namespace: None,
            item_id: "22222222-2222-2222-2222-222222222222".into(),
            label: "Second synthetic login".into(),
            use_type: CredentialUse::Login,
            field_mappings: vec![LoginFieldMapping {
                field: LoginField::Password,
                environment: "LOGIN_TOKEN_TWO".into(),
            }],
        });
    }
    f.app
        .activate_operation(OperationPolicyDraft {
            create: None,
            ssh: None,
            id: "deploy".into(),
            description: "Synthetic protected execution".into(),
            image_id: "deploy-image".into(),
            targets: vec![target.into()],
            arguments: vec![
                ArgumentSpec::Target,
                ArgumentSpec::Choice {
                    choices: if mode == "app-agent-revoke" {
                        vec![
                            marker.clone(),
                            root.join("other-tree-ready").to_str().unwrap().into(),
                        ]
                    } else {
                        vec![marker.clone()]
                    },
                },
            ],
            credentials,
        })
        .unwrap();
    let owner = f.app.human_owner();
    if mode == "app-agent-revoke" {
        scoped_agent_revocation(root, &f, supervisor);
        return;
    }
    let id = f
        .app
        .submit_direct(
            owner,
            DirectSubmission {
                operation: "deploy".into(),
                revision: None,
                values: vec![target.into(), marker],
            },
            &Launcher::default(),
        )
        .unwrap()
        .id;
    let approval = f
        .app
        .prepare_approval(owner, &id)
        .unwrap()
        .authenticate(SensitiveString::new("synthetic".into()), &Permit)
        .unwrap();
    f.app.commit_approval(approval).unwrap();
    if mode.starts_with("app-worker-") {
        let worker = ExecutionWorker::start(f.app.clone(), supervisor.clone()).unwrap();
        let dispatcher = worker.dispatcher();
        dispatcher.dispatch(&id).unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let status = f.app.direct_status(owner, &id).unwrap();
            if mode == "app-worker-exit" && status == (DirectStatus::Completed { exit_code: 0 }) {
                break;
            }
            if mode == "app-worker-shutdown"
                && status == DirectStatus::Running
                && root.join("app-tree-ready").exists()
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "approved-ID worker failed to execute synthetic workload"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(dispatcher);
        let app = f.app.clone();
        let (done, completed) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            app.shutdown().unwrap();
            worker.join().unwrap();
            done.send(()).unwrap();
        });
        completed
            .recv_timeout(Duration::from_secs(15))
            .expect("worker shutdown must be bounded");
        let expected = f.app.direct_status(owner, &id).unwrap();
        assert!(expected.is_terminal());
        if mode == "app-worker-exit" {
            assert_eq!(expected, DirectStatus::Completed { exit_code: 0 });
        }
        let state_bytes = std::fs::read(&state_path).unwrap();
        let state: serde_json::Value = serde_json::from_slice(&state_bytes).unwrap();
        let persisted: DirectStatus =
            serde_json::from_value(state["requests"][0]["direct"]["review"]["status"].clone())
                .unwrap();
        assert_eq!(persisted, expected, "worker outcome must be durable");
        let text = String::from_utf8(state_bytes).unwrap();
        assert!(!text.contains("synthetic-password-sentinel"));
        finish(root, b"worker-dispatched-durable-and-joined");
        return;
    }
    let (app, request, runner) = (f.app.clone(), id.clone(), supervisor.clone());
    let fail_persistence = mode == "app-persistence";
    let work = std::thread::spawn(move || {
        app.run_execution(
            owner,
            &request,
            &LinuxExecutablePreparer,
            &FaultSupervisor {
                supervisor: runner,
                fail_persistence,
            },
        )
    });
    if !matches!(mode, "app-exit" | "app-nonzero" | "app-signal") {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !root.join("app-tree-ready").exists()
            || f.app.direct_status(owner, &id).unwrap() != DirectStatus::Running
        {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(20));
        }
        let lease = supervisor.config.leases().unwrap().pop().unwrap();
        std::fs::write(root.join("cgroup"), &lease.cgroup).unwrap();
        match mode {
            "app-lock" => f.app.lock().unwrap(),
            "app-cancel" | "app-persistence" => f.app.cancel_execution(owner, &id).unwrap(),
            "app-revoke" => f.app.revoke_requester(owner).unwrap(),
            "app-shutdown" => f.app.shutdown().unwrap(),
            "app-deadline" => f.monotonic.store(310, Ordering::Release),
            _ => panic!("unknown application scenario"),
        }
    }
    let result = work.join().unwrap();
    let expected = match mode {
        "app-exit" => Some(DirectStatus::Completed { exit_code: 0 }),
        "app-nonzero" => Some(DirectStatus::Failed {
            reason: DirectFailure::ExecutionNonzero,
        }),
        "app-signal" => Some(DirectStatus::Failed {
            reason: DirectFailure::ExecutionSignaled,
        }),
        _ => None,
    };
    if let Some(expected) = expected {
        assert_eq!(f.app.direct_status(owner, &id).unwrap(), expected);
        if mode == "app-exit" {
            assert_eq!(result, Ok(expected.clone()));
        } else {
            assert_eq!(result, Err(DirectRequestError::Unavailable));
        }
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        let persisted: DirectStatus =
            serde_json::from_value(state["requests"][0]["direct"]["review"]["status"].clone())
                .unwrap();
        assert_eq!(
            persisted, expected,
            "exact execution failure must be durable"
        );
    } else {
        assert_eq!(result, Err(DirectRequestError::Unavailable));
    }
    let state = std::fs::read_to_string(&state_path).unwrap();
    assert!(!state.contains("synthetic-password-sentinel"));
    assert!(!state.contains("story18-synthetic-secret"));
    if mode == "app-persistence" {
        assert!(f.app.admission_closed());
        let state: serde_json::Value = serde_json::from_str(&state).unwrap();
        assert_eq!(state["requests"][0]["status"], "running");
    } else {
        assert!(f.app.direct_status(owner, &id).unwrap().is_terminal());
        let review = serde_json::to_string(&f.app.review_direct(owner, &id).unwrap()).unwrap();
        assert!(!review.contains("synthetic-password-sentinel"));
    }
    finish(root, b"application-verified");
}

fn scoped_agent_revocation(
    root: &std::path::Path,
    f: &crate::access::direct_request_tests::Fixture,
    supervisor: Arc<SystemdProcessSupervisor>,
) {
    use crate::access::{
        agent_binding::{AgentBindingStatus, AgentPairing},
        direct_request::*,
        direct_request_tests::Launcher,
        ports::*,
    };
    struct Permit;
    impl ApprovalAuthenticator for Permit {
        fn authenticate(&self, _: SensitiveString) -> Result<(), SessionError> {
            Ok(())
        }
    }
    let human = f.app.human_owner();
    let mut prepared = Vec::new();
    let mut work = Vec::new();
    let mut leases = Vec::new();
    for (seed, label, marker) in [
        (91, "revoked-agent", "app-tree-ready"),
        (92, "surviving-agent", "other-tree-ready"),
    ] {
        let binding = f
            .app
            .pair_agent(
                human,
                AgentPairing {
                    label: label.into(),
                    public_key: crate::access::encode_public_key(
                        &ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key(),
                    ),
                    uid: 41000 + u32::from(seed),
                    gid: 42000 + u32::from(seed),
                },
            )
            .unwrap();
        let id = f
            .app
            .submit_agent_for_test(
                &binding.id,
                binding.uid,
                &[binding.gid],
                DirectSubmission {
                    operation: "deploy".into(),
                    revision: None,
                    values: vec![
                        "multi-tree".into(),
                        root.join(marker).to_str().unwrap().into(),
                    ],
                },
                &Launcher::default(),
            )
            .unwrap()
            .id;
        let approval = f
            .app
            .prepare_approval(human, &id)
            .unwrap()
            .authenticate(SensitiveString::new("synthetic".into()), &Permit)
            .unwrap();
        f.app.commit_approval(approval).unwrap();
        prepared.push((binding, id, marker));
    }
    // Prepare both requests before the first supervisor starts polling authority.
    // Admission deliberately uses try_lock and rejects incidental busy state.
    for (binding, id, marker) in prepared {
        let app = f.app.clone();
        let request = id.clone();
        let runner = supervisor.clone();
        let worker = std::thread::spawn(move || {
            app.run_execution(human, &request, &LinuxExecutablePreparer, runner.as_ref())
        });
        let deadline = Instant::now() + Duration::from_secs(15);
        while !root.join(marker).exists()
            || f.app.direct_status(human, &id).unwrap() != DirectStatus::Running
        {
            assert!(
                Instant::now() < deadline,
                "agent workload did not become running"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let current = supervisor.config.leases().unwrap();
        assert_eq!(current.len(), work.len() + 1);
        let lease = current
            .into_iter()
            .find(|candidate| {
                !leases
                    .iter()
                    .any(|prior: &manager::Lease| prior.name == candidate.name)
            })
            .unwrap();
        leases.push(lease);
        work.push((binding, id, worker));
    }
    let (a, a_id, a_worker) = work.remove(0);
    let (b, b_id, b_worker) = work.remove(0);
    assert_eq!(
        f.app.revoke_agent(human, &a.id).unwrap().status,
        AgentBindingStatus::Revoked
    );
    assert_eq!(
        a_worker.join().unwrap(),
        Err(DirectRequestError::Unavailable)
    );
    assert_eq!(
        f.app.direct_status(human, &a_id).unwrap(),
        DirectStatus::Failed {
            reason: DirectFailure::ObservationLost,
        }
    );
    assert_eq!(
        f.app.direct_status(human, &b_id).unwrap(),
        DirectStatus::Running
    );
    assert!(!f.app.admission_closed());
    std::fs::write(
        root.join("scoped-identities.json"),
        serde_json::to_vec(&leases).unwrap(),
    )
    .unwrap();
    std::fs::write(root.join("agent-revoked"), b"future-access-revoked").unwrap();
    // The independent integration process must observe both released consumers alive
    // before ending its fixture. Neither scoped revocation can terminate a consumer.
    let deadline = Instant::now() + Duration::from_secs(15);
    while !root.join("scoped-observation-complete").exists() {
        assert!(
            Instant::now() < deadline,
            "independent scoped observation missing"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        f.app.revoke_agent(human, &a.id).unwrap().status,
        AgentBindingStatus::Revoked
    );
    assert_eq!(
        f.app.direct_status(human, &b_id).unwrap(),
        DirectStatus::Running
    );
    f.app.revoke_agent(human, &b.id).unwrap();
    assert_eq!(
        b_worker.join().unwrap(),
        Err(DirectRequestError::Unavailable)
    );
    assert!(!f.app.admission_closed());
    finish(root, b"scoped-agent-revocation-independently-observed");
}
struct FaultSupervisor {
    supervisor: Arc<SystemdProcessSupervisor>,
    fail_persistence: bool,
}
impl ProcessSupervisor<LinuxExecutablePreparer> for FaultSupervisor {
    fn available(&self) -> bool {
        self.supervisor.available()
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
        prepared: PreparedExecutable,
        environment: ChildEnvironment,
        control: &dyn ExecutionControl,
    ) -> Supervision {
        struct FaultControl<'a> {
            delegate: &'a dyn ExecutionControl,
            enabled: bool,
        }
        impl ExecutionControl for FaultControl<'_> {
            fn live(&self) -> bool {
                self.delegate.live()
            }
            fn remaining(&self) -> Duration {
                self.delegate.remaining()
            }
            fn release(
                &self,
                action: &mut dyn FnMut() -> Result<(), ExecutionError>,
            ) -> Result<(), ExecutionError> {
                self.delegate.release(action)
            }
            fn started(&self) -> Result<(), ExecutionError> {
                self.delegate.started()?;
                if self.enabled {
                    crate::access::provider_store::WRITE_TEST_HOOK
                        .with(|hook| *hook.borrow_mut() = Some(Box::new(|stage| stage == 0)));
                }
                Ok(())
            }
        }
        self.supervisor.supervise_controlled(
            prepared,
            environment,
            &FaultControl {
                delegate: control,
                enabled: self.fail_persistence,
            },
        )
    }
}

fn manager_environment_snapshot() -> Vec<String> {
    use dbus::blocking::stdintf::org_freedesktop_dbus::Properties;
    dbus::blocking::Connection::new_session()
        .unwrap()
        .with_proxy(
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            Duration::from_secs(2),
        )
        .get("org.freedesktop.systemd1.Manager", "Environment")
        .unwrap()
}
fn observe_helper_environment(config: &Config, names: &[String]) {
    use dbus::blocking::stdintf::org_freedesktop_dbus::Properties;
    let leases = config.leases().unwrap();
    assert_eq!(leases.len(), 1);
    let manager = Manager::connect().unwrap();
    let helper = manager.owned(config, &leases[0]).unwrap().unwrap();
    // The test entrypoint pauses before production PR_SET_DUMPABLE=0; inspect
    // this same exec/loader environment, then enter the unchanged helper code.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let status = std::fs::read_to_string(format!("/proc/{}/status", helper.pid)).unwrap();
        if status.lines().any(|line| line.starts_with("State:\tT")) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "helper inspection barrier was not reached"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // Observe the actual helper before any credential transfer or workload release.
    let environment = std::fs::read(format!("/proc/{}/environ", helper.pid)).unwrap();
    for entry in environment
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let name = entry.split(|byte| *byte == b'=').next().unwrap();
        assert!(
            !names.iter().any(|candidate| candidate.as_bytes() == name),
            "helper inherited a forbidden environment name"
        );
    }
    let connection = dbus::blocking::Connection::new_session().unwrap();
    let (path,): (dbus::Path<'static>,) = connection
        .with_proxy(
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            Duration::from_secs(2),
        )
        .method_call(
            "org.freedesktop.systemd1.Manager",
            "GetUnit",
            (&leases[0].name,),
        )
        .unwrap();
    let unset: Vec<String> = connection
        .with_proxy("org.freedesktop.systemd1", path, Duration::from_secs(2))
        .get("org.freedesktop.systemd1.Service", "UnsetEnvironment")
        .unwrap();
    assert!(
        unset.iter().all(|name| !name.contains('=')),
        "typed unset policy contains values"
    );
    assert!(
        names.iter().all(|name| unset.contains(name)),
        "typed unset policy omits tested names"
    );
    assert_eq!(unsafe { libc::kill(helper.pid as i32, libc::SIGCONT) }, 0);
}

fn journal_barrier(phase: &str) {
    use std::io::Write;
    let provider = std::env::var("VW18_PROVIDER").unwrap();
    println!("VW18-JOURNAL-BARRIER:{provider}:{phase}:stdout");
    std::io::stdout().flush().unwrap();
    eprintln!("VW18-JOURNAL-BARRIER:{provider}:{phase}:stderr");
    std::io::stderr().flush().unwrap();
}
fn finish(root: &std::path::Path, value: &[u8]) {
    journal_barrier("finished");
    std::fs::write(root.join("finished"), value).unwrap();
}

fn ssh_scenario(root: &std::path::Path, mode: &str, supervisor: &SystemdProcessSupervisor) {
    let (mut ssh, key) = crate::adapters::ssh_material::fixture(root);
    ssh.destination.resource_path = format!("/srv/{mode}");
    let image = root.join("image");
    let digest = Sha256::digest(std::fs::read(&image).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let mut prepared = LinuxExecutablePreparer
        .prepare(
            ExecutionImage {
                root,
                path: &image,
                sha256: &digest,
                profile: ExecutionProfile::ReviewedSelfContainedElf64V1,
            },
            vec!["fixture".into()],
        )
        .unwrap();
    let mut material = LinuxExecutablePreparer
        .prepare_ssh(&mut prepared, &root.join("ssh"), &ssh)
        .unwrap();
    material.install_key(SensitiveString::new(key)).unwrap();
    let socket = prepared
        .descriptor_and_arguments()
        .1
        .iter()
        .find_map(|arg| {
            arg.to_str()
                .ok()?
                .strip_prefix("IdentityAgent=\"")?
                .strip_suffix('"')
        })
        .map(std::path::PathBuf::from)
        .unwrap();
    std::fs::write(
        root.join("agent-path"),
        socket.as_os_str().as_encoded_bytes(),
    )
    .unwrap();
    let request = std::fs::read_dir(root.join("ssh/agents"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::write(
        root.join("material-path"),
        request.as_os_str().as_encoded_bytes(),
    )
    .unwrap();
    material.mark_in_use().unwrap();
    let report = supervisor.supervise_controlled(
        prepared,
        ChildEnvironment::from_mappings([]).unwrap(),
        &Control { root: root.into() },
    );
    assert!(
        root.join("ssh-output-sinks-verified").exists(),
        "native child must verify stdout and stderr both resolve to /dev/null"
    );
    assert!(
        root.join("ssh-agent-ready").exists(),
        "approved main process must obtain its public identity through the agent"
    );
    if mode == "ssh-detached-recovery" {
        assert_eq!(report.cleanup, CleanupEvidence::Detached);
        material.finalize(report.cleanup).unwrap();
        assert!(!request.exists());
        let (mut next, _, _) =
            crate::adapters::ssh_material::prepare(&root.join("ssh"), &ssh).unwrap();
        use crate::access::ports::SshMaterial;
        // Cleanup fault injection may retain public files, but never blocks admission.
        let _public_cleanup = next.finalize(CleanupEvidence::NotStarted);
        let leases = supervisor.config.leases().unwrap();
        assert_eq!(leases.len(), 1);
        let restarted = SystemdProcessSupervisor {
            config: supervisor.config.clone(),
            healthy: AtomicBool::new(true),
            material_root: Some(root.join("ssh")),
        };
        let recovered = crate::access::provider::Provider::start_with_cleanup(
            root.join("recovery-provider"),
            || restarted.recover().map_err(|_error| ()),
        )
        .unwrap();
        assert!(!manager::proc_empty(std::path::Path::new("/proc"), &leases[0].cgroup).unwrap());
        assert!(
            std::os::unix::net::UnixStream::connect(&socket).is_err(),
            "detachment must close signing authority"
        );
        assert!(
            !request.exists(),
            "public resources can be removed without stopping consumers"
        );
        assert_eq!(restarted.config.leases().unwrap().len(), 1);
        assert!(
            restarted.available(),
            "retained public SSH resources must not disable delivery"
        );
        drop(recovered);
    } else if mode == "ssh-cleanup-failure" {
        assert_eq!(report.cleanup, CleanupEvidence::Reaped);
        crate::adapters::ssh_material::TEST_FAIL_REMOVE.with(|fail| fail.set(true));
        assert!(material.finalize(report.cleanup).is_err());
        assert!(!request.join("identity").exists());
        let (mut next, _, _) =
            crate::adapters::ssh_material::prepare(&root.join("ssh"), &ssh).unwrap();
        use crate::access::ports::SshMaterial;
        // Cleanup fault injection may retain public files, but never blocks admission.
        let _public_cleanup = next.finalize(CleanupEvidence::NotStarted);
        supervisor.recover().unwrap();
        assert!(!request.join("identity").exists());
        crate::adapters::ssh_material::TEST_FAIL_REMOVE.with(|fail| fail.set(false));
        material.finalize(report.cleanup).unwrap();
        assert!(!request.exists());
    } else {
        assert_eq!(
            report.cleanup,
            if mode == "ssh-clean-exit" {
                CleanupEvidence::Reaped
            } else {
                CleanupEvidence::Detached
            }
        );
        material.finalize(report.cleanup).unwrap();
        assert!(!request.exists());
        assert_eq!(
            report.outcome,
            if matches!(mode, "ssh-exit" | "ssh-clean-exit") {
                Ok(ExecutionOutcome::ExitedZero)
            } else {
                Err(ExecutionError::ObservationLost)
            }
        );
    }
    assert!(std::os::unix::net::UnixStream::connect(&socket).is_err());
    finish(root, b"ssh-agent-authority-ended-consumers-independent");
}

/// Public synthetic server proof and userauth request; no private key enters these files.
fn prepare_agent_exchange(root: &std::path::Path, key: &str) -> Vec<u8> {
    use signature::Signer;
    use ssh_key::encoding::Encode;
    fn field(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    fn packet(value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        field(&mut out, value);
        out
    }
    let key = ssh_key::PrivateKey::from_openssh(key).unwrap();
    let public = key.public_key().to_bytes().unwrap();
    let session = [17u8; 32];
    let signature: ssh_key::Signature = key.try_sign(&session).unwrap();
    let mut encoded = Vec::new();
    signature.encode(&mut encoded).unwrap();
    let mut binding = vec![27];
    field(&mut binding, b"session-bind@openssh.com");
    field(&mut binding, &public);
    field(&mut binding, &session);
    field(&mut binding, &encoded);
    binding.push(0);
    std::fs::write(root.join("ssh-bind-request"), packet(&binding)).unwrap();
    let mut data = Vec::new();
    field(&mut data, &session);
    data.push(50);
    field(&mut data, b"backup");
    field(&mut data, b"ssh-connection");
    field(&mut data, b"publickey");
    data.push(1);
    field(&mut data, b"ssh-ed25519");
    field(&mut data, &public);
    let mut request = vec![13];
    field(&mut request, &public);
    field(&mut request, &data);
    request.extend_from_slice(&0u32.to_be_bytes());
    std::fs::write(root.join("ssh-sign-request"), packet(&request)).unwrap();
    data
}

fn ssh_application_scenario(
    root: &std::path::Path,
    mode: &str,
    supervisor: Arc<SystemdProcessSupervisor>,
) {
    use crate::access::{
        direct_request::*,
        direct_request_tests::{Launcher, RESOLUTION_ACTION, fixture},
        policy::*,
        ports::*,
    };
    use std::os::unix::fs::PermissionsExt;
    struct Permit;
    impl ApprovalAuthenticator for Permit {
        fn authenticate(&self, _: SensitiveString) -> Result<(), SessionError> {
            Ok(())
        }
    }
    let f = fixture();
    let image_path = f.dir.path().join("approved-image");
    std::fs::set_permissions(&image_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::copy(root.join("image"), &image_path).unwrap();
    std::fs::set_permissions(&image_path, std::fs::Permissions::from_mode(0o500)).unwrap();
    let digest = Sha256::digest(std::fs::read(&image_path).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let image = ApprovedImage::new(
        "deploy-image".into(),
        f.dir.path().to_str().unwrap().into(),
        image_path.to_str().unwrap().into(),
        digest,
        ExecutionProfile::ReviewedSelfContainedElf64V1,
    )
    .unwrap();
    let state_path = f.dir.path().join("provider/provider-state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    state["approved_images"] = serde_json::json!([image]);
    state["operations"] = serde_json::json!([]);
    std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let (mut ssh, key) = crate::adapters::ssh_material::fixture(root);
    ssh.destination.resource_path = format!("/srv/{}", mode.strip_prefix("app-").unwrap());
    let signing_data = if mode == "app-ssh-nonzero" {
        Some(prepare_agent_exchange(root, &key))
    } else {
        None
    };
    let mut draft = test_ssh_draft();
    draft.ssh = Some(ssh);
    let revision = f.app.activate_operation(draft).unwrap();
    let owner = f.app.human_owner();
    let id = f
        .app
        .submit_direct(
            owner,
            DirectSubmission {
                operation: "ssh-backup".into(),
                revision: Some(revision),
                values: vec![],
            },
            &Launcher::default(),
        )
        .unwrap()
        .id;
    let approval = f
        .app
        .prepare_approval(owner, &id)
        .unwrap()
        .authenticate(SensitiveString::new("synthetic".into()), &Permit)
        .unwrap();
    f.app.commit_approval(approval).unwrap();
    let app = f.app.clone();
    let execution_id = id.clone();
    let runner = supervisor.clone();
    let backend_key = key.clone();
    let work = std::thread::spawn(move || {
        RESOLUTION_ACTION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                Ok(vec![SensitiveString::new(backend_key.clone())])
            }))
        });
        let result = app.run_execution(
            owner,
            &execution_id,
            &LinuxExecutablePreparer,
            runner.as_ref(),
        );
        RESOLUTION_ACTION.with(|hook| *hook.borrow_mut() = None);
        result
    });
    if matches!(mode, "app-ssh-lock" | "app-ssh-cancel") {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !root.join("ssh-agent-ready").exists()
            || f.app.direct_status(owner, &id).unwrap() != DirectStatus::Running
        {
            assert!(
                Instant::now() < deadline,
                "SSH application must discover its public identity and remain running"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let leases = supervisor.config.leases().unwrap();
        assert_eq!(leases.len(), 1);
        assert!(!manager::proc_empty(std::path::Path::new("/proc"), &leases[0].cgroup).unwrap());
        let material = std::fs::read_dir(root.join("ssh/agents"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert!(!material.join("identity").exists());
        let socket =
            std::path::PathBuf::from(std::fs::read_to_string(root.join("agent-path")).unwrap());
        assert!(socket.exists());
        if mode == "app-ssh-lock" {
            f.app.lock().unwrap();
        } else {
            f.app.cancel_execution(owner, &id).unwrap();
        }
        assert!(
            !manager::proc_empty(std::path::Path::new("/proc"), &leases[0].cgroup).unwrap(),
            "authority-loss acknowledgment must preserve released descendants"
        );
        assert!(std::os::unix::net::UnixStream::connect(&socket).is_err());
        assert!(
            !material.join("identity").exists(),
            "managed agent must never create a private-key file"
        );
        if mode == "app-ssh-cancel" {
            supervisor.recover().unwrap();
            assert!(
                !manager::proc_empty(std::path::Path::new("/proc"), &leases[0].cgroup).unwrap()
            );
            assert!(!material.join("identity").exists());
        }
    }
    assert_eq!(work.join().unwrap(), Err(DirectRequestError::Unavailable));
    for entry in std::fs::read_dir(root.join("ssh/agents")).unwrap() {
        let path = entry.unwrap().path();
        assert!(!path.join("identity").exists());
    }
    assert!(
        root.join("ssh-output-sinks-verified").exists(),
        "native child must verify stdout and stderr both resolve to /dev/null"
    );
    assert!(root.join("ssh-agent-ready").exists());
    if let Some(data) = signing_data {
        use signature::Verifier;
        use ssh_key::encoding::Decode;
        let response = std::fs::read(root.join("ssh-sign-response")).unwrap();
        assert_eq!(
            u32::from_be_bytes(response[..4].try_into().unwrap()) as usize,
            response.len() - 4
        );
        assert_eq!(response[4], 14);
        let length = u32::from_be_bytes(response[5..9].try_into().unwrap()) as usize;
        assert_eq!(length, response.len() - 9);
        let mut encoded = &response[9..];
        let signature = ssh_key::Signature::decode(&mut encoded).unwrap();
        assert!(encoded.is_empty());
        let parsed = ssh_key::PrivateKey::from_openssh(&key).unwrap();
        Verifier::verify(parsed.public_key(), &data, &signature).unwrap();
    }
    assert_eq!(
        std::fs::read_dir(root.join("ssh/agents")).unwrap().count(),
        0
    );
    let status = f.app.direct_status(owner, &id).unwrap();
    match mode {
        "app-ssh-nonzero" => assert_eq!(
            status,
            DirectStatus::Failed {
                reason: DirectFailure::ExecutionNonzero
            }
        ),
        "app-ssh-signal" => assert_eq!(
            status,
            DirectStatus::Failed {
                reason: DirectFailure::ExecutionSignaled
            }
        ),
        _ => assert!(status.is_terminal()),
    }
    let text = std::fs::read_to_string(&state_path).unwrap();
    let state: serde_json::Value = serde_json::from_str(&text).unwrap();
    let persisted: DirectStatus =
        serde_json::from_value(state["requests"][0]["direct"]["review"]["status"].clone()).unwrap();
    assert_eq!(persisted, status);
    assert!(!text.contains(&key));
    assert!(!text.contains("BEGIN OPENSSH PRIVATE KEY"));
    let encoded_key_payload = key
        .lines()
        .find(|line| !line.is_empty() && !line.starts_with("-----"))
        .unwrap();
    assert!(
        !text.contains(encoded_key_payload),
        "JSON escaping must not hide persisted private-key payloads from the disclosure oracle"
    );
    assert!(!text.contains("ssh-raw-output-sentinel"));
    assert!(!text.contains("SSH_AUTH_SOCK"));
    finish(root, b"ssh-application-lifecycle-verified");
}
