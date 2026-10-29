fn grant_fixture_admin(service: &Companion) {
    let mut registry: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&service.identity_store).unwrap()).unwrap();
    registry["version"] = 2.into();
    registry["administrators"] = serde_json::json!([leaf_fingerprint(CLIENT)]);
    std::fs::write(
        &service.identity_store,
        serde_json::to_vec(&registry).unwrap(),
    )
    .unwrap();
}
fn management_exchange(
    service: &Companion,
    f: &Fixture,
    command: serde_json::Value,
) -> (u16, serde_json::Value) {
    let response = exchange_body(
        service,
        &f.app,
        client_config(Some((CLIENT, CLIENT_KEY))),
        &command.to_string(),
    );
    let status = response.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    (status, body)
}
fn management_prepare(
    service: &Companion,
    f: &Fixture,
    target: &serde_json::Value,
) -> serde_json::Value {
    let (status, prepared) = management_exchange(
        service,
        f,
        serde_json::json!({"version":2,"command":"identity_prepare","target":target}),
    );
    assert_eq!(status, 200, "{prepared}");
    prepared
}
fn management_revoke(
    target: &serde_json::Value,
    prepared: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({"version":2,"command":"identity_revoke","target":target,"action_id":prepared["action_id"],"ticket":prepared["ticket"],"password":"synthetic-password"})
}
#[test]
fn management_mtls_requires_explicit_admin_and_closed_bounded_inventory() {
    let f = fixture();
    let (service, _, _) = service(&f);
    let command = serde_json::json!({"version":2,"command":"identity_list","limit":1,"after":null});
    assert_eq!(management_exchange(&service, &f, command.clone()).0, 403);
    grant_fixture_admin(&service);
    let (status, first) = management_exchange(&service, &f, command.clone());
    assert_eq!(status, 200);
    assert_eq!(first["identities"].as_array().unwrap().len(), 1);
    assert!(!first["next_cursor"].is_null());
    let mut next = command.clone();
    next["after"] = first["next_cursor"].clone();
    let (status, second) = management_exchange(&service, &f, next);
    assert_eq!(status, 200);
    assert!(second["next_cursor"].is_null());
    assert_ne!(first["identities"][0]["id"], second["identities"][0]["id"]);
    let encoded = format!("{first}{second}");
    for forbidden in [
        "private_key",
        "password",
        "uid",
        "gid",
        "public_key",
        "token",
    ] {
        assert!(!encoded.contains(forbidden));
    }
    for (field, value) in [
        ("limit", serde_json::json!(65)),
        ("after", serde_json::json!("forged")),
        ("version", serde_json::json!(1)),
        ("extra", serde_json::json!(true)),
    ] {
        let mut bad = command.clone();
        bad[field] = value;
        assert_eq!(management_exchange(&service, &f, bad).0, 400);
    }
    assert!(
        !exchange_body(&service, &f.app, client_config(None), &command.to_string())
            .contains("identities")
    );
}
#[test]
fn management_mtls_certificate_revocation_retires_session_and_is_exact_single_use_durable() {
    let f = fixture();
    let (service, check, _) = service(&f);
    grant_fixture_admin(&service);
    let pending = request(&f, &service);
    let target = serde_json::json!({"kind":"approval_client","id":"b".repeat(64)});
    let prepared = management_prepare(&service, &f, &target);
    let command = management_revoke(&target, &prepared);
    let mut forged = command.clone();
    forged["target"]["id"] = leaf_fingerprint(CLIENT).into();
    assert_eq!(management_exchange(&service, &f, forged).0, 409);
    assert_eq!(check.calls.load(Ordering::SeqCst), 0);
    let mut wrong_action = command.clone();
    wrong_action["action_id"] = crate::access::RequestId::new_random()
        .unwrap()
        .as_str()
        .into();
    assert_eq!(management_exchange(&service, &f, wrong_action).0, 409);
    let (status, completed) = management_exchange(&service, &f, command.clone());
    assert_eq!(status, 200);
    assert_eq!(completed["revocation"], "recorded");
    assert_eq!(completed["cleanup"], "complete");
    assert_eq!(f.app.status().unwrap(), SessionStatus::Locked);
    assert_eq!(
        f.app.direct_status(f.app.human_owner(), &pending).unwrap(),
        DirectStatus::Expired
    );
    assert_eq!(management_exchange(&service, &f, command).0, 409);
    let query = serde_json::json!({"version":2,"command":"identity_status","target":target,"action_id":prepared["action_id"]});
    let mut wrong_status = query.clone();
    wrong_status["target"]["id"] = leaf_fingerprint(CLIENT).into();
    assert_eq!(management_exchange(&service, &f, wrong_status).0, 403);
    let (_, reconciled) = management_exchange(&service, &f, query.clone());
    assert_eq!(completed, reconciled);
    *service.management.lock().unwrap() = management::State::default();
    assert_eq!(management_exchange(&service, &f, query).1, completed);
    assert_eq!(check.calls.load(Ordering::SeqCst), 1);
    assert!(!service.authorized(&"b".repeat(64)));
    let audit = std::fs::read_to_string(
        service
            .identity_store
            .parent()
            .unwrap()
            .join("companion-management-actions.json"),
    )
    .unwrap();
    assert!(audit.contains(&leaf_fingerprint(CLIENT)));
    assert!(audit.contains(prepared["action_id"].as_str().unwrap()));
    assert!(!audit.contains("synthetic-password"));
    assert!(!audit.contains(prepared["ticket"].as_str().unwrap()));
}
#[test]
fn management_authentication_lock_change_retires_ticket_without_revoking_target() {
    let f = fixture();
    let (service, check, _) = service(&f);
    grant_fixture_admin(&service);
    let target = serde_json::json!({"kind":"approval_client","id":"b".repeat(64)});
    let prepared = management_prepare(&service, &f, &target);
    let app = f.app.clone();
    *check.action.lock().unwrap() = Some(Box::new(move || {
        app.lock().unwrap();
    }));
    assert_eq!(
        management_exchange(&service, &f, management_revoke(&target, &prepared)).0,
        409
    );
    assert!(service.authorized(&"b".repeat(64)));
    assert_eq!(
        management_exchange(&service, &f, management_revoke(&target, &prepared)).0,
        409
    );
}
#[test]
fn management_self_revocation_reports_loss_of_access_and_never_replays() {
    let f = fixture();
    let (service, _, _) = service(&f);
    grant_fixture_admin(&service);
    let target = serde_json::json!({"kind":"approval_client","id":leaf_fingerprint(CLIENT)});
    let prepared = management_prepare(&service, &f, &target);
    assert_eq!(
        management_exchange(&service, &f, management_revoke(&target, &prepared)).1["revocation"],
        "recorded"
    );
    assert_eq!(management_exchange(&service, &f, serde_json::json!({"version":2,"command":"identity_status","target":target,"action_id":prepared["action_id"]})).0, 200);
    assert!(!identity::administrator(
        &service.identity_store,
        &leaf_fingerprint(CLIENT)
    ));
    assert_eq!(
        management_exchange(
            &service,
            &f,
            serde_json::json!({"version":2,"command":"identity_list","limit":1,"after":null})
        )
        .0,
        403
    );
    let mut wrong_target = target.clone();
    wrong_target["id"] = "b".repeat(64).into();
    assert_eq!(management_exchange(&service, &f, serde_json::json!({"version":2,"command":"identity_status","target":wrong_target,"action_id":prepared["action_id"]})).0, 403);
}
#[test]
fn management_origin_does_not_infer_local_human_device_and_v1_remains_closed() {
    let f = fixture();
    let (service, _, _) = service(&f);
    let id = request(&f, &service);
    let (status, origin) = management_exchange(
        &service,
        &f,
        serde_json::json!({"version":2,"command":"request_origin","request_id":id}),
    );
    assert_eq!(status, 200);
    assert!(origin["origin"].is_null());
    let (_, review) = management_exchange(
        &service,
        &f,
        serde_json::json!({"version":1,"command":"review","request_id":id}),
    );
    assert!(review.get("origin").is_none());
    assert!(review["review"].get("origin").is_none());
}
#[test]
fn management_mtls_agent_revocation_preserves_signed_origin_and_invalidates_pending_work() {
    use crate::access::{agent_binding::AgentPairing, protocol::SignedSubmission};
    let f = fixture();
    let (service, _, _) = service(&f);
    grant_fixture_admin(&service);
    let key = ed25519_dalek::SigningKey::from_bytes(&[211; 32]);
    let agent = f
        .app
        .pair_agent(
            f.app.human_owner(),
            AgentPairing {
                label: "Synthetic Mac".into(),
                public_key: crate::access::encode_public_key(&key.verifying_key()),
                uid: 41001,
                gid: 42001,
            },
        )
        .unwrap();
    let revision = crate::access::direct_request_tests::records(&f)["operations"][0]["revision"]
        .as_str()
        .unwrap()
        .to_owned();
    let message = SignedSubmission::sign(
        agent.id.clone(),
        [17; 32],
        "deploy".into(),
        revision,
        input().values,
        &key,
    )
    .unwrap();
    let mut forged = message.clone();
    forged.binding_id = crate::access::RequestId::new_random()
        .unwrap()
        .as_str()
        .into();
    assert!(
        f.app
            .submit_signed(
                agent.uid,
                &[agent.gid],
                forged,
                service.request_launcher().as_ref()
            )
            .is_err()
    );
    let id = f
        .app
        .submit_signed(
            agent.uid,
            &[agent.gid],
            message,
            service.request_launcher().as_ref(),
        )
        .unwrap();
    let (_, original) = management_exchange(
        &service,
        &f,
        serde_json::json!({"version":2,"command":"request_origin","request_id":id}),
    );
    assert_eq!(original["origin"]["binding_id"], agent.id);
    assert_eq!(original["origin"]["fingerprint"], agent.fingerprint);
    assert_eq!(original["origin"]["evidence"], "signed_os_binding");
    let target = serde_json::json!({"kind":"requester_agent","id":agent.id});
    let prepared = management_prepare(&service, &f, &target);
    let (status, result) = management_exchange(&service, &f, management_revoke(&target, &prepared));
    assert_eq!(status, 200);
    assert_eq!(result["revocation"], "recorded");
    assert_eq!(result["cleanup"], "complete");
    assert_eq!(
        f.app.direct_status(f.app.human_owner(), &id).unwrap(),
        DirectStatus::Expired
    );
    assert_eq!(
        management_exchange(
            &service,
            &f,
            serde_json::json!({"version":2,"command":"request_origin","request_id":id})
        )
        .1,
        original
    );
    assert!(service.authorized(&leaf_fingerprint(CLIENT)));
    let (_, detail) = management_exchange(
        &service,
        &f,
        serde_json::json!({"version":2,"command":"identity_detail","target":target}),
    );
    assert_eq!(detail["identity"]["trust"], "revoked");
    assert_eq!(detail["identity"]["roles"], serde_json::json!([]));
}
#[test]
fn management_preparation_expiry_and_wrong_password_never_create_durable_intent() {
    let f = fixture();
    let (service, check, _) = service(&f);
    grant_fixture_admin(&service);
    let target = serde_json::json!({"kind":"approval_client","id":"b".repeat(64)});
    let prepared = management_prepare(&service, &f, &target);
    f.monotonic.fetch_add(55, Ordering::SeqCst);
    assert_eq!(
        management_exchange(&service, &f, management_revoke(&target, &prepared)).0,
        409
    );
    assert_eq!(check.calls.load(Ordering::SeqCst), 0);
    let prepared = management_prepare(&service, &f, &target);
    let mut wrong = management_revoke(&target, &prepared);
    wrong["password"] = "wrong".into();
    assert_eq!(management_exchange(&service, &f, wrong).0, 422);
    assert!(
        !service
            .identity_store
            .parent()
            .unwrap()
            .join("companion-management-actions.json")
            .exists()
    );
    assert_eq!(
        management_exchange(&service, &f, management_revoke(&target, &prepared)).0,
        409
    );
    assert!(service.authorized(&"b".repeat(64)));
}
#[test]
fn management_unresolved_durable_intent_fences_startup_but_status_remains_readable() {
    let f = fixture();
    let (service, _, _) = service(&f);
    grant_fixture_admin(&service);
    let target = serde_json::json!({"kind":"approval_client","id":"b".repeat(64)});
    let prepared = management_prepare(&service, &f, &target);
    let root = service.identity_store.parent().unwrap();
    write_private(root, "companion-management-actions.json", serde_json::json!({"version":2,"actions":[{
        "action_id":prepared["action_id"],"actor":leaf_fingerprint(CLIENT),"target":target,"revocation":"pending","cleanup":"pending"
    }]}).to_string().as_bytes());
    Companion::enforce_management_recovery(root, &f.app);
    assert!(f.app.admission_closed());
    let (status, action) = management_exchange(
        &service,
        &f,
        serde_json::json!({"version":2,"command":"identity_status","target":target,"action_id":prepared["action_id"]}),
    );
    assert_eq!(status, 200);
    assert_eq!(action["revocation"], "pending");
    assert_eq!(action["cleanup"], "pending");
    assert!(service.authorized(&"b".repeat(64))); // Pending does not fabricate a tombstone.
}

#[test]
fn management_recorded_revocation_with_unknown_cleanup_remains_readable_behind_fence() {
    let f = fixture();
    let (service, _, _) = service(&f);
    grant_fixture_admin(&service);
    let action_id = crate::access::RequestId::new_random()
        .unwrap()
        .as_str()
        .to_owned();
    let target = serde_json::json!({"kind":"approval_client","id":"b".repeat(64)});
    let root = service.identity_store.parent().unwrap();
    write_private(root, "companion-management-actions.json", serde_json::json!({"version":2,"actions":[{
        "action_id":action_id,"actor":leaf_fingerprint(CLIENT),"target":target,"revocation":"recorded","cleanup":"unknown"
    }]}).to_string().as_bytes());
    Companion::enforce_management_recovery(root, &f.app);
    assert!(f.app.admission_closed());
    let (status, action) = management_exchange(
        &service,
        &f,
        serde_json::json!({"version":2,"command":"identity_status","target":target,"action_id":action_id}),
    );
    assert_eq!(status, 200);
    assert_eq!(action["revocation"], "recorded");
    assert_eq!(action["cleanup"], "unknown");
}

#[test]
fn management_busy_before_mutation_records_definite_refusal_without_restart_fence() {
    let f = fixture();
    let (service, _, _) = service(&f);
    grant_fixture_admin(&service);
    let target = serde_json::json!({"kind":"approval_client","id":"b".repeat(64)});
    let prepared = management_prepare(&service, &f, &target);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let app = f.app.clone();
    service.management.lock().unwrap().before_mutation = Some(Box::new(move || {
        std::thread::spawn(move || {
            app.management_hold_gate_for_test(|| {
                entered_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
            })
        });
        entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    }));
    let result = management_exchange(&service, &f, management_revoke(&target, &prepared));
    resume_tx.send(()).unwrap();
    assert_eq!(result.0, 200);
    assert_eq!(result.1["revocation"], "not_recorded");
    assert_eq!(result.1["cleanup"], "not_applicable");
    assert_eq!(result.1["owner_reconciled"], false);
    assert!(service.authorized(&"b".repeat(64)));
    Companion::enforce_management_recovery(service.identity_store.parent().unwrap(), &f.app);
    assert!(!f.app.admission_closed());
}
#[test]
fn management_owner_recovery_is_exact_stopped_only_and_preserves_original_uncertainty() {
    let f = fixture();
    let (service, _, _) = service(&f);
    grant_fixture_admin(&service);
    let root = service.identity_store.parent().unwrap();
    let target = serde_json::json!({"kind":"approval_client","id":"b".repeat(64)});
    let action_id = crate::access::RequestId::new_random()
        .unwrap()
        .as_str()
        .to_owned();
    write_private(root, "companion-management-actions.json", serde_json::json!({"version":2,"actions":[{
        "action_id":action_id,"actor":leaf_fingerprint(CLIENT),"target":target,"revocation":"pending","cleanup":"unknown"
    }]}).to_string().as_bytes());
    let called = AtomicBool::new(false);
    assert!(
        management::reconcile_stopped(
            root,
            &action_id,
            "approval_client",
            &"b".repeat(64),
            None,
            || {
                called.store(true, Ordering::SeqCst);
                Ok(())
            }
        )
        .is_err()
    );
    assert!(!called.load(Ordering::SeqCst)); // competing daemon: no cleanup before writer lock.
    drop(f.app);
    assert!(
        management::reconcile_stopped(
            root,
            &action_id,
            "approval_client",
            &leaf_fingerprint(CLIENT),
            None,
            || {
                called.store(true, Ordering::SeqCst);
                Ok(())
            }
        )
        .is_err()
    );
    assert!(!called.load(Ordering::SeqCst)); // mismatched exact target never starts cleanup.
    assert!(
        management::reconcile_stopped(
            root,
            &action_id,
            "approval_client",
            &"b".repeat(64),
            None,
            || Err(())
        )
        .is_err()
    );
    assert!(service.authorized(&"b".repeat(64))); // failed cleanup never acknowledges or mutates target.
    let receipt = management::reconcile_stopped(
        root,
        &action_id,
        "approval_client",
        &"b".repeat(64),
        None,
        || {
            called.store(true, Ordering::SeqCst);
            Ok(())
        },
    )
    .unwrap();
    assert!(called.load(Ordering::SeqCst));
    assert_eq!(receipt["revocation"], "pending");
    assert_eq!(receipt["cleanup"], "unknown");
    assert_eq!(receipt["owner_reconciled"], true);
    assert!(!service.authorized(&"b".repeat(64)));
    let audit: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("companion-management-actions.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(audit["actions"][0]["actor"], leaf_fingerprint(CLIENT));
    assert_eq!(audit["actions"][0]["reconciled_by_uid"], unsafe {
        libc::geteuid()
    });
}

#[test]
fn management_inventory_distinguishes_configured_unlocked_from_runtime_available() {
    struct NoRuntime;
    impl ExecutionDispatcher for NoRuntime {
        fn dispatch(&self, _: &str) -> Result<(), SessionError> {
            panic!("inventory must not dispatch")
        }
        // default-false readiness: presence of this adapter is not runtime proof.
    }
    let f = fixture();
    let (mut service, _, _) = service(&f);
    grant_fixture_admin(&service);
    let query = serde_json::json!({"version":2,"command":"identity_list","limit":1,"after":null});
    let (status, available) = management_exchange(&service, &f, query.clone());
    assert_eq!(status, 200);
    assert_eq!(available["provider"]["execution_available"], true);
    service.execution_dispatcher = Some(Arc::new(NoRuntime));
    assert_eq!(f.app.status().unwrap(), SessionStatus::Unlocked);
    let (status, unavailable) = management_exchange(&service, &f, query.clone());
    assert_eq!(status, 200);
    assert_eq!(unavailable["provider"]["execution_configured"], true);
    assert_eq!(unavailable["provider"]["execution_available"], false);
    service.execution_dispatcher = None;
    let (_, absent) = management_exchange(&service, &f, query);
    assert_eq!(absent["provider"]["execution_configured"], false);
    assert_eq!(absent["provider"]["execution_available"], false);
}

#[test]
fn management_missing_receipt_owner_recovery_requires_exact_known_actor_and_preserves_unknown() {
    let f = fixture();
    let (service, _, _) = service(&f);
    grant_fixture_admin(&service);
    let root = service.identity_store.parent().unwrap();
    let action_id = crate::access::RequestId::new_random()
        .unwrap()
        .as_str()
        .to_owned();
    let called = AtomicBool::new(false);
    drop(f.app);
    assert!(
        management::reconcile_stopped(
            root,
            &action_id,
            "approval_client",
            &"b".repeat(64),
            None,
            || {
                called.store(true, Ordering::SeqCst);
                Ok(())
            }
        )
        .is_err()
    );
    assert!(
        management::reconcile_stopped(
            root,
            &action_id,
            "approval_client",
            &"b".repeat(64),
            Some(&"f".repeat(64)),
            || {
                called.store(true, Ordering::SeqCst);
                Ok(())
            }
        )
        .is_err()
    );
    assert!(!called.load(Ordering::SeqCst));
    let actor = leaf_fingerprint(CLIENT);
    let receipt = management::reconcile_stopped(
        root,
        &action_id,
        "approval_client",
        &"b".repeat(64),
        Some(&actor),
        || {
            called.store(true, Ordering::SeqCst);
            Ok(())
        },
    )
    .unwrap();
    assert!(called.load(Ordering::SeqCst));
    assert_eq!(receipt["revocation"], "unknown");
    assert_eq!(receipt["cleanup"], "unknown");
    assert_eq!(receipt["owner_reconciled"], true);
    assert!(!service.authorized(&"b".repeat(64)));
    let query: Command = serde_json::from_value(serde_json::json!({"version":2,"command":"identity_status","target":receipt["target"],"action_id":action_id})).unwrap();
    assert!(management::receipt_authorized(&service, &actor, &query));
    assert!(!management::receipt_authorized(
        &service,
        &"b".repeat(64),
        &query
    ));
    assert!(
        management::reconcile_stopped(
            root,
            &action_id,
            "approval_client",
            &"b".repeat(64),
            Some(&"b".repeat(64)),
            || Ok(())
        )
        .is_err()
    );
}
