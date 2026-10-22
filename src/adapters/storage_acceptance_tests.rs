//! Opt-in composed storage fixture. All controls live in the operator-only directory.
use super::acceptance_tests::{file_setting, save, setting};
use super::*;
use crate::access::{
    agent_binding::{AgentBindingView, AgentPairing},
    policy::*,
    provider::Provider,
};
use crate::adapters::{
    session::MonotonicClock,
    supervisor::{ExecutionWorker, SystemdProcessSupervisor},
    unix_socket::AgentSocket,
    vaultwarden::VaultwardenBackend,
};
use std::os::unix::fs::PermissionsExt;

#[test]
#[ignore = "explicit isolated storage acceptance runner required"]
fn storage_acceptance_fixture() {
    let control = file_setting("VW_COMPANION_CONTROL");
    identity::private_directory(&control).unwrap();
    let root = control.join("provider");
    let resumed = std::env::var("VW_COMPANION_RESUME").as_deref() == Ok("1");
    assert_eq!(root.exists(), resumed);
    let settings: serde_json::Value =
        serde_json::from_slice(&std::fs::read(control.join("storage.json")).unwrap()).unwrap();
    let effect: CreateEffect = serde_json::from_value(settings["effect"].clone()).unwrap();
    assert!(effect.valid());
    assert_eq!(effect.eligibility_marker, "storage-consume");
    assert_eq!(effect.destination.folder, "storage-acceptance");
    assert_eq!(effect.fields, vec!["password"]);
    let unit = setting("VW_COMPANION_SYSTEMD_UNIT");
    assert!(unit.starts_with("vw-companion-acceptance-") && unit.ends_with(".service"));
    let supervisor = Arc::new(
        SystemdProcessSupervisor::companion_fixture(unit, file_setting("VW_COMPANION_HELPER"))
            .unwrap(),
    );
    let client_cert = file_setting("VW_COMPANION_CLIENT_CERT");
    let client_ca = file_setting("VW_COMPANION_CLIENT_CA");
    let server = file_setting("VW_COMPANION_SERVER_CERT");
    let images = ["producer", "consumer"]
        .into_iter()
        .map(|name| {
            let path = control.join(format!("{name}-image"));
            if !resumed {
                std::fs::copy(control.join("bin").join(format!("{name}-image")), &path).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
            }
            ApprovedImage::new(
                format!("storage-{name}"),
                control.to_str().unwrap().into(),
                path.to_str().unwrap().into(),
                identity::fingerprint(&std::fs::read(path).unwrap()),
                ExecutionProfile::ReviewedSelfContainedElf64V1,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    if !resumed {
        let mut provider = Provider::start(&root).unwrap();
        provider.shutdown().unwrap();
        drop(provider);
        identity::enroll(
            &root,
            &client_cert,
            &client_ca,
            "Synthetic storage acceptance Mac",
        )
        .unwrap();
    }
    let state_path = root.join("provider-state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    if resumed {
        assert_eq!(state["approved_images"], serde_json::json!(images));
    } else {
        state["approved_images"] = serde_json::json!(images);
        save(&state_path, &state);
    }
    // cfg(test) intentionally disables automatic native-store installation.
    // This composed fixture explicitly installs the production Secret Service store.
    keyring_core::set_default_store(dbus_secret_service_keyring_store::Store::new().unwrap());
    let backend = VaultwardenBackend::from_setup(&control.join("private/setup.json")).unwrap();
    let approval = Arc::new(backend.approval_authenticator());
    let provider =
        Provider::start_with_cleanup(&root, || supervisor.recover().map_err(|_error| ())).unwrap();
    let app = Arc::new(
        ProviderApplication::new_with_request_lifetime(
            provider,
            Box::new(backend),
            Box::<MonotonicClock>::default(),
            Duration::from_secs(300),
        )
        .unwrap(),
    );
    let binding: AgentBindingView = if resumed {
        let ready: serde_json::Value =
            serde_json::from_slice(&std::fs::read(control.join("resume-ready.json")).unwrap())
                .unwrap();
        let binding = serde_json::from_value(ready["binding"].clone()).unwrap();
        assert!(
            app.list_agents(app.human_owner())
                .unwrap()
                .contains(&binding)
        );
        binding
    } else {
        // Provisioning authentication uses the identical disposable setup snapshot.
        let password = std::fs::read_to_string(control.join("private/password")).unwrap();
        app.authenticate(SensitiveString::new(password)).unwrap();
        for scenario in ["create", "deny", "interrupt"] {
            let mut create = effect.clone();
            create.destination.reference = format!("storage-acceptance/{scenario}");
            app.activate_operation(OperationPolicyDraft {
                id: format!("storage-{scenario}"),
                description: format!("Synthetic storage acceptance {scenario}"),
                image_id: "storage-producer".into(),
                targets: vec![],
                arguments: vec![],
                credentials: vec![],
                ssh: None,
                create: Some(create),
            })
            .unwrap();
        }
        let binding = app
            .pair_agent(
                app.human_owner(),
                AgentPairing {
                    label: "Synthetic storage agent".into(),
                    public_key: setting("VW_COMPANION_AGENT_PUBLIC_KEY"),
                    uid: setting("VW_COMPANION_AGENT_UID").parse().unwrap(),
                    gid: setting("VW_COMPANION_AGENT_GID").parse().unwrap(),
                },
            )
            .unwrap();
        app.lock().unwrap();
        binding
    };
    assert_eq!(app.status().unwrap(), SessionStatus::Locked);
    let worker = ExecutionWorker::start(app.clone(), supervisor).unwrap();
    let service = Companion::bind(
        setting("VW_COMPANION_LISTEN").parse().unwrap(),
        &server,
        &file_setting("VW_COMPANION_SERVER_KEY"),
        &client_ca,
        &root.join(identity::STORE_FILE),
    )
    .unwrap()
    .with_approval_authenticator(approval)
    .with_execution_dispatcher(worker.dispatcher());
    let launcher = service.request_launcher();
    let socket_root = file_setting("VW_COMPANION_AGENT_SOCKET_DIR");
    let socket = AgentSocket::bind(
        &socket_root,
        setting("VW_COMPANION_AGENT_GID").parse().unwrap(),
    )
    .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let agent_task = runtime.spawn(socket.serve(app.clone(), launcher, stop.clone()));
    let server_task = {
        let app = app.clone();
        let stop = stop.clone();
        std::thread::spawn(move || service.serve(app, stop))
    };
    let write_ready = || {
        let operations = app
            .list_operations(app.human_owner())
            .unwrap()
            .into_iter()
            .map(|op| {
                let arguments = if op.id == "storage-consume" {
                    vec!["storage.invalid"]
                } else {
                    vec![]
                };
                (
                    op.id,
                    serde_json::json!({"revision":op.revision,"arguments":arguments}),
                )
            })
            .collect::<serde_json::Map<String, serde_json::Value>>();
        save(
            &control.join("ready.json"),
            &serde_json::json!({"version":1,"endpoint":setting("VW_COMPANION_PUBLIC_ENDPOINT"),"provider_fingerprint":identity::certificate_fingerprint(&server).unwrap(),"client_fingerprint":identity::certificate_fingerprint(&client_cert).unwrap(),"binding":binding,"socket":socket_root.join("agent.sock"),"operations":operations,"effect":effect,"resumed":resumed}),
        );
    };
    write_ready();
    let deadline = Instant::now() + Duration::from_secs(1200);
    let mut previous = serde_json::Value::Null;
    while Instant::now() < deadline
        && !control.join("stop").exists()
        && !stop.load(Ordering::Acquire)
    {
        // Only the provider-owner directory can submit these human-only controls.
        let command_path = control.join("operator-command.json");
        if command_path.exists() {
            let meta = std::fs::symlink_metadata(&command_path).unwrap();
            use std::os::unix::fs::MetadataExt;
            assert!(
                meta.is_file()
                    && meta.uid() == unsafe { libc::geteuid() }
                    && meta.mode() & 0o077 == 0
                    && meta.nlink() == 1
            );
            let command: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&command_path).unwrap()).unwrap();
            let result = match command["action"].as_str().unwrap() {
                "provision-consumer" => {
                    let id = command["item_id"].as_str().unwrap();
                    assert!(crate::secret_storage::valid_id(id));
                    let mut namespace = effect.destination.clone();
                    namespace.reference = "storage-acceptance/create".into();
                    let draft = OperationPolicyDraft {
                        id: "storage-consume".into(),
                        description:
                            "Consume exactly the separately selected synthetic stored item".into(),
                        image_id: "storage-consumer".into(),
                        targets: vec!["storage.invalid".into()],
                        arguments: vec![ArgumentSpec::Target],
                        credentials: vec![LoginCredentialDraft {
                            namespace: Some(namespace),
                            item_id: id.into(),
                            label: "Synthetic created login".into(),
                            use_type: CredentialUse::Login,
                            field_mappings: vec![LoginFieldMapping {
                                field: LoginField::Password,
                                environment: "STORAGE_CREDENTIAL".into(),
                            }],
                        }],
                        ssh: None,
                        create: None,
                    };
                    match app.create_operation(app.human_owner(), draft) {
                        Ok(revision) => {
                            write_ready();
                            serde_json::json!({"success":true,"revision":revision})
                        }
                        Err(_) => serde_json::json!({"success":false}),
                    }
                }
                "reconcile" => match app.reconcile_write(
                    app.human_owner(),
                    command["request_id"].as_str().unwrap(),
                    command["item_id"].as_str().unwrap(),
                ) {
                    Ok(receipt) => serde_json::json!({"success":true,"receipt":receipt}),
                    Err(_) => serde_json::json!({"success":false}),
                },
                _ => panic!("unknown operator fixture control"),
            };
            save(&control.join("operator-result.json"), &result);
            std::fs::remove_file(command_path).unwrap();
        }
        // Read-only durable receipts contain no plaintext, session or approval material.
        let durable: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        let requests = durable["requests"].as_array().unwrap().iter().filter(|r| !r["direct"].is_null()).map(|r| {
            let id = r["id"].as_str().unwrap();
            serde_json::json!({"request_id":id,"status":app.direct_status(app.human_owner(),id).unwrap(),"write_receipt":r["direct"]["write_receipt"]})
        }).collect::<Vec<_>>();
        let history = app.history(app.human_owner(), Some(200)).unwrap();
        let started = history.iter().filter(|event| event.outcome == crate::access::history::HistoryOutcome::ExecutionStarted).map(|event| serde_json::json!({"request_id":event.request_id,"operation":event.operation})).collect::<Vec<_>>();
        let snapshot = serde_json::json!({"execution_started":started,"requests":requests,"session":if app.status().unwrap()==SessionStatus::Locked{"locked"}else{"unlocked"}});
        if snapshot != previous {
            save(&control.join("observed.json"), &snapshot);
            previous = snapshot;
        }
        assert!(!worker.is_finished());
        std::thread::sleep(Duration::from_millis(500));
    }
    stop.store(true, Ordering::Release);
    app.shutdown().unwrap();
    runtime.block_on(agent_task).unwrap().unwrap();
    server_task.join().unwrap().unwrap();
    worker.join().unwrap();
    save(
        &control.join("finished.json"),
        &serde_json::json!({"shutdown":"complete"}),
    );
}
