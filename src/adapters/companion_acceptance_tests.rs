//! Explicitly invoked, bounded real-Mac/Linux acceptance fixture. No production vault.
use super::*;
use crate::{
    access::{
        agent_binding::{AgentBindingView, AgentPairing},
        policy::*,
        ports::{CredentialBinding, ProviderSession, SecretBackend},
        provider::Provider,
    },
    adapters::{
        session::MonotonicClock,
        supervisor::{ExecutionWorker, SystemdProcessSupervisor},
        unix_socket::AgentSocket,
    },
};
use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

const SYNTHETIC_PASSWORD: &str = "synthetic-companion-password";
struct SyntheticBackend;
impl ProviderSession for SyntheticBackend {
    fn probe_compatibility(&mut self) -> Result<(), SessionError> {
        Ok(())
    }
    fn unlock(&mut self, password: SensitiveString) -> Result<Duration, SessionError> {
        SyntheticApproval.authenticate(password)?;
        Ok(Duration::from_secs(900))
    }
    fn clear(&mut self) -> Result<(), SessionError> {
        Ok(())
    }
}
impl SecretBackend for SyntheticBackend {
    fn eligible(&mut self, _: &CredentialBinding<'_>) -> Result<bool, SessionError> {
        Ok(true)
    }
    fn resolve(&mut self, _: &CredentialBinding<'_>) -> Result<Vec<SensitiveString>, SessionError> {
        Ok(vec![SensitiveString::new(
            "synthetic-password-sentinel".into(),
        )])
    }
}
struct SyntheticApproval;
impl ApprovalAuthenticator for SyntheticApproval {
    fn authenticate(&self, password: SensitiveString) -> Result<(), SessionError> {
        if password.expose() == SYNTHETIC_PASSWORD {
            Ok(())
        } else {
            Err(SessionError::AuthenticationFailed)
        }
    }
}
fn setting(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing fixture setting {name}"))
}
fn file_setting(name: &str) -> PathBuf {
    PathBuf::from(setting(name))
}
fn save(path: &Path, value: &serde_json::Value) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .unwrap();
    serde_json::to_writer(&mut file, value).unwrap();
    file.sync_all().unwrap();
}

#[test]
#[ignore = "manual real-Mac acceptance: isolated systemd service and explicit VW_COMPANION_* fixture settings required"]
fn companion_acceptance_fixture() {
    let control = file_setting("VW_COMPANION_CONTROL");
    identity::private_directory(&control).unwrap();
    let root = control.join("provider");
    let resumed = std::env::var("VW_COMPANION_RESUME").as_deref() == Ok("1");
    assert_eq!(
        root.exists(),
        resumed,
        "fresh and resumed fixtures must be explicit"
    );
    let previous_ready: Option<serde_json::Value> = resumed.then(|| {
        serde_json::from_slice(&std::fs::read(control.join("resume-ready.json")).unwrap()).unwrap()
    });
    let server = file_setting("VW_COMPANION_SERVER_CERT");
    let server_key = file_setting("VW_COMPANION_SERVER_KEY");
    let server_ca = file_setting("VW_COMPANION_SERVER_CA");
    let public_endpoint = setting("VW_COMPANION_PUBLIC_ENDPOINT");
    assert!(public_endpoint.starts_with("https://"));
    let client_identity = std::env::var("VW_COMPANION_CLIENT_IDENTITY").ok();
    let client_ca = file_setting("VW_COMPANION_CLIENT_CA");
    let client_cert = file_setting("VW_COMPANION_CLIENT_CERT");
    let socket_root = file_setting("VW_COMPANION_AGENT_SOCKET_DIR");
    let address: SocketAddr = setting("VW_COMPANION_LISTEN").parse().unwrap();
    let agent_uid: u32 = setting("VW_COMPANION_AGENT_UID").parse().unwrap();
    let agent_gid: u32 = setting("VW_COMPANION_AGENT_GID").parse().unwrap();
    let public_key = setting("VW_COMPANION_AGENT_PUBLIC_KEY");
    let lifetime = std::env::var("VW_COMPANION_LIFETIME_SECONDS")
        .map(|s| s.parse::<u64>().unwrap())
        .unwrap_or(900);
    assert!((30..=1200).contains(&lifetime));
    let request_lifetime = std::env::var("VW_COMPANION_REQUEST_SECONDS")
        .map(|s| s.parse::<u64>().unwrap())
        .unwrap_or(120);
    assert!((5..=300).contains(&request_lifetime));
    let unit = setting("VW_COMPANION_SYSTEMD_UNIT");
    assert!(
        unit.starts_with("vw-companion-acceptance-") && unit.ends_with(".service"),
        "fixture must use an isolated service name"
    );
    let supervisor = Arc::new(
        SystemdProcessSupervisor::companion_fixture(unit, file_setting("VW_COMPANION_HELPER"))
            .unwrap(),
    );
    let image_path = control.join("protected-image");
    if !resumed {
        std::fs::copy(file_setting("VW_COMPANION_IMAGE"), &image_path).unwrap();
        std::fs::set_permissions(&image_path, std::fs::Permissions::from_mode(0o500)).unwrap();
    }
    let image = ApprovedImage::new(
        "synthetic-image".into(),
        control.to_str().unwrap().into(),
        image_path.to_str().unwrap().into(),
        identity::fingerprint(&std::fs::read(&image_path).unwrap()),
        ExecutionProfile::ReviewedSelfContainedElf64V1,
    )
    .unwrap();
    // Initialize only this newly created synthetic fixture, then enroll through
    // the real stopped-provider path before reopening its authority store.
    let client_fingerprint = if resumed {
        let fingerprint = identity::certificate_fingerprint(&client_cert).unwrap();
        assert_eq!(
            previous_ready.as_ref().unwrap()["client_fingerprint"],
            fingerprint
        );
        fingerprint
    } else {
        let mut initial = Provider::start(&root).unwrap();
        initial.shutdown().unwrap();
        drop(initial);
        identity::enroll(&root, &client_cert, &client_ca, "Synthetic acceptance Mac").unwrap()
    };
    if std::env::var("VW_COMPANION_START_CLIENT_REVOKED").as_deref() == Ok("1") {
        identity::revoke(&root, &client_fingerprint).unwrap();
        assert!(identity::list(&root).unwrap().is_empty());
    }
    let client_revoked = !identity::list(&root)
        .unwrap()
        .iter()
        .any(|identity| identity.fingerprint == client_fingerprint);
    let state_path = root.join("provider-state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    if resumed {
        assert_eq!(state["approved_images"], serde_json::json!([image]));
    } else {
        state["approved_images"] = serde_json::json!([image]);
        save(&state_path, &state);
    }
    let provider =
        Provider::start_with_cleanup(&root, || supervisor.recover().map_err(|_error| ())).unwrap();
    let app = Arc::new(
        ProviderApplication::new_with_request_lifetime(
            provider,
            Box::new(SyntheticBackend),
            Box::<MonotonicClock>::default(),
            Duration::from_secs(request_lifetime),
        )
        .unwrap(),
    );
    let (revision, binding) = if let Some(previous) = &previous_ready {
        let binding: AgentBindingView =
            serde_json::from_value(previous["binding"].clone()).unwrap();
        let revision = previous["revision"].as_str().unwrap().to_owned();
        assert!(
            app.list_agents(app.human_owner())
                .unwrap()
                .contains(&binding)
        );
        let reloaded: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        assert_eq!(reloaded["pairings"], state["pairings"]);
        assert_eq!(reloaded["operations"], state["operations"]);
        assert_eq!(reloaded["requests"], state["requests"]);
        assert!(
            reloaded["operations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|policy| {
                    policy["id"] == "synthetic-deploy" && policy["revision"] == revision
                })
        );
        assert_eq!(app.status().unwrap(), SessionStatus::Locked);
        (revision, binding)
    } else {
        app.authenticate(SensitiveString::new(SYNTHETIC_PASSWORD.into()))
            .unwrap();
        let revision = app
            .activate_operation(OperationPolicyDraft {
                ssh: None,
                id: "synthetic-deploy".into(),
                description: "Run synthetic protected Linux execution once".into(),
                image_id: "synthetic-image".into(),
                targets: vec!["exit".into()],
                arguments: vec![
                    ArgumentSpec::Target,
                    ArgumentSpec::Choice {
                        choices: vec!["synthetic".into()],
                    },
                ],
                credentials: vec![LoginCredentialDraft {
                    item_id: "11111111-1111-1111-1111-111111111111".into(),
                    label: "Synthetic acceptance login".into(),
                    use_type: CredentialUse::Login,
                    field_mappings: vec![LoginFieldMapping {
                        field: LoginField::Password,
                        environment: "LOGIN_TOKEN".into(),
                    }],
                }],
            })
            .unwrap();
        let binding = app
            .pair_agent(
                app.human_owner(),
                AgentPairing {
                    label: "Synthetic non-TTY agent".into(),
                    public_key,
                    uid: agent_uid,
                    gid: agent_gid,
                },
            )
            .unwrap();
        (revision, binding)
    };
    if std::env::var_os("VW_COMPANION_START_LOCKED").is_some() {
        app.lock().unwrap();
    }
    let worker = ExecutionWorker::start(app.clone(), supervisor).unwrap();
    let mut service = Companion::bind(
        address,
        &server,
        &server_key,
        &client_ca,
        &root.join(identity::STORE_FILE),
    )
    .unwrap()
    .with_approval_authenticator(Arc::new(SyntheticApproval))
    .with_execution_dispatcher(worker.dispatcher());
    let lost_reply = std::env::var("VW_COMPANION_DROP_APPROVAL_REPLY").as_deref() == Ok("1");
    let traffic = lost_reply.then(|| Arc::new(FixtureTraffic::armed()));
    service.fixture_traffic = traffic.clone();
    let actual = service.listener.local_addr().unwrap();
    let launcher = service.request_launcher();
    let socket = AgentSocket::bind(&socket_root, agent_gid).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let agent_task = runtime.spawn(socket.serve(app.clone(), launcher, stop.clone()));
    let server_task = {
        let app = app.clone();
        let stop = stop.clone();
        std::thread::spawn(move || service.serve(app, stop))
    };
    save(
        &control.join("ready.json"),
        &serde_json::json!({"version":1,"address":actual.to_string(),"endpoint":public_endpoint,"server_ca_path":server_ca,"client_ca_path":client_ca,"client_certificate_path":client_cert,"client_identity_path":client_identity,"client_revoked":client_revoked,"drop_approval_reply":lost_reply,"resumed":resumed,"controls":{"lock":control.join("lock"),"revoke_agent":control.join("revoke-agent"),"stop":control.join("stop")},"agent_cli_args":["submit","synthetic-deploy","--socket",socket_root.join("agent.sock"),"--key-file","<agent-owned-32-byte-seed>","--binding-id",binding.id,"--revision",revision,"--wait","--timeout-seconds","300","--","exit","synthetic"],"provider_fingerprint":identity::certificate_fingerprint(&server).unwrap(),"client_fingerprint":client_fingerprint,"binding":binding,"revision":revision,"operation":"synthetic-deploy","arguments":["exit","synthetic"],"socket":socket_root.join("agent.sock"),"request_lifetime_seconds":request_lifetime,"lifetime_seconds":lifetime}),
    );
    let deadline = Instant::now() + Duration::from_secs(lifetime);
    let mut observed: BTreeSet<String> = if resumed {
        state["requests"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|record| record.get("direct").is_some_and(|direct| !direct.is_null()))
            .map(|record| record["id"].as_str().unwrap().to_owned())
            .collect()
    } else {
        BTreeSet::new()
    };
    let mut previous = serde_json::Value::Null;
    let mut previous_traffic = serde_json::Value::Null;
    while Instant::now() < deadline
        && !control.join("stop").exists()
        && !stop.load(Ordering::Acquire)
    {
        if control.join("lock").exists() {
            app.lock().unwrap();
            std::fs::remove_file(control.join("lock")).unwrap();
        }
        if control.join("revoke-agent").exists() {
            app.revoke_agent(app.human_owner(), &binding.id).unwrap();
            std::fs::remove_file(control.join("revoke-agent")).unwrap();
        }
        observed.extend(app.companion_pending().unwrap());
        let statuses=observed.iter().map(|id|serde_json::json!({"request_id":id,"status":app.direct_status(app.human_owner(),id).unwrap()})).collect::<Vec<_>>();
        let snapshot = serde_json::json!({"requests":statuses,"session":if app.status().unwrap()==SessionStatus::Locked{"locked"}else{"unlocked"}});
        if snapshot != previous {
            save(&control.join("observed.json"), &snapshot);
            previous = snapshot;
        }
        if let Some(traffic) = &traffic {
            let snapshot = traffic.snapshot();
            if snapshot != previous_traffic {
                save(&control.join("transport-observation.json"), &snapshot);
                previous_traffic = snapshot;
            }
        }
        assert!(!worker.is_finished(), "protected execution worker exited");
        // These observations revalidate durable state under the authority gate.
        // Keep test-only polling modest so it does not crowd signed admission.
        std::thread::sleep(Duration::from_secs(1));
    }
    stop.store(true, Ordering::Release);
    app.shutdown().unwrap();
    runtime.block_on(agent_task).unwrap().unwrap();
    server_task.join().unwrap().unwrap();
    worker.join().unwrap();
    save(
        &control.join("finished.json"),
        &serde_json::json!({"shutdown":"complete","observed_requests":observed.len()}),
    );
}
