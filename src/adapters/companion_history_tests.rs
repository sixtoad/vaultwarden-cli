// Included inside the companion transport tests to exercise their actual TLS
// service, synthetic enrollment and durable application fixtures.

#[test]
fn companion_history_real_mtls_requires_current_enrollment_and_returns_only_display_data() {
    let f = fixture();
    let (service, check, execution) = service(&f);
    let id = request(&f, &service);
    let command = r#"{"version":1,"command":"history"}"#;
    let response = exchange_body(
        &service,
        &f.app,
        client_config(Some((CLIENT, CLIENT_KEY))),
        command,
    );
    assert!(response.starts_with("HTTP/1.1 200"));
    let body: serde_json::Value =
        serde_json::from_str(response.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "version":1,"history_version":1,"events":[{
                "request_id":id,"operation":"deploy","at_unix_seconds":1700000000u64,
                "ordinal":0,"outcome":"submitted"
            }]
        })
    );
    for config in [
        client_config(None),
        client_config(Some((
            include_bytes!("../../tests/companion-tls/other.pem"),
            include_bytes!("../../tests/companion-tls/other-key.pem"),
        ))),
    ] {
        let refused = exchange_body(&service, &f.app, config, command);
        assert!(!refused.contains("200 Response"));
        assert!(!refused.contains(&id));
    }
    std::fs::write(&service.identity_store, br#"{"version":1,"identities":[]}"#).unwrap();
    let revoked = exchange_body(
        &service,
        &f.app,
        client_config(Some((CLIENT, CLIENT_KEY))),
        command,
    );
    assert!(revoked.starts_with("HTTP/1.1 403"));
    assert!(!revoked.contains(&id));
    assert!(service.state.lock().unwrap().tickets.is_empty());
    assert_eq!(check.calls.load(Ordering::SeqCst), 0);
    assert_eq!(execution.0.load(Ordering::SeqCst), 0);
}

#[test]
fn companion_history_revocation_during_store_read_does_not_release_events() {
    let f = fixture();
    let (service, _, _) = service(&f);
    let id = request(&f, &service);
    let path = service.identity_store.clone();
    crate::access::provider_store::READ_TEST_HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            std::fs::write(&path, br#"{"version":1,"identities":[]}"#).unwrap();
            false
        }));
    });
    let result = service.dispatch(
        &leaf_fingerprint(CLIENT),
        Command::History {
            version: 1,
            limit: None,
        },
        &f.app,
    );
    crate::access::provider_store::READ_TEST_HOOK.with(|hook| *hook.borrow_mut() = None);
    assert_eq!(result.status, 403);
    assert!(!result.body.contains(&id));
}

#[test]
fn companion_history_command_is_closed_and_limits_are_exact() {
    for body in [
        r#"{"version":1,"command":"history"}"#,
        r#"{"version":1,"command":"history","limit":1}"#,
        r#"{"version":1,"command":"history","limit":50}"#,
        r#"{"version":1,"command":"history","limit":200}"#,
    ] {
        assert!(read_command(&mut wire(body).as_bytes()).is_ok(), "{body}");
    }
    for field in [
        "\"limit\":0",
        "\"limit\":201",
        "\"limit\":4294967295",
        "\"limit\":-1",
        "\"limit\":1.5",
        "\"limit\":null",
        "\"limit\":\"50\"",
        "\"limit\":50,\"limit\":1",
        "\"uid\":0",
        "\"ticket\":\"secret\"",
    ] {
        let body = format!("{{\"version\":1,\"command\":\"history\",{field}}}");
        assert!(read_command(&mut wire(&body).as_bytes()).is_err(), "{body}");
    }
    assert!(read_command(&mut wire(r#"{"version":2,"command":"history"}"#).as_bytes()).is_err());
}

#[test]
fn companion_history_bounds_and_owner_filter_preserve_canonical_order() {
    use crate::access::direct_request::DirectRecord;
    use base64::Engine;
    let f = fixture();
    let (service, _, _) = service(&f);
    request(&f, &service);
    let mut state = crate::access::direct_request_tests::records(&f);
    let template: DirectRecord =
        serde_json::from_value(state["requests"][0]["direct"].clone()).unwrap();
    let mut ids = Vec::new();
    let mut rows = Vec::new();
    for n in 0..206u32 {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&n.to_be_bytes());
        let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let mut record = template.clone();
        record.review.id = id.clone();
        if n == 205 {
            record.owner_uid += 1;
            record.audit[0].requester = crate::access::history::RequesterSnapshot::Human {
                uid: record.owner_uid,
                label: record.review.requester.clone(),
            };
        } else {
            ids.push(id.clone());
        }
        record.audit[0].request_id = id.clone();
        // Terminal legacy records need no live request deadline. Cloning pending
        // IDs would correctly expire them and append another canonical event.
        record.review.status = DirectStatus::Denied;
        record.audit[0].status = Some(DirectStatus::Denied);
        record.audit[0].outcome = crate::access::history::HistoryOutcome::LegacyUnknown;
        record.audit[0].at_unix_seconds = None;
        record.seal();
        rows.push(serde_json::json!({"id":id,"status":"denied","direct":record}));
    }
    state["requests"] = rows.into();
    std::fs::write(
        f.dir.path().join("provider/provider-state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    ids.sort_by(|a, b| b.cmp(a));
    for (limit, count) in [(None, 50), (Some(1), 1), (Some(200), 200)] {
        let response = service.dispatch(
            &leaf_fingerprint(CLIENT),
            Command::History { version: 1, limit },
            &f.app,
        );
        assert_eq!(response.status, 200);
        let value: serde_json::Value = serde_json::from_str(&response.body).unwrap();
        let actual = value["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["request_id"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            ids[..count].iter().map(String::as_str).collect::<Vec<_>>()
        );
    }
    // Lock does not erase durable history or turn it into decision authority.
    f.app.lock().unwrap();
    let locked = service.dispatch(
        &leaf_fingerprint(CLIENT),
        Command::History {
            version: 1,
            limit: Some(1),
        },
        &f.app,
    );
    assert_eq!(locked.status, 200);
    assert!(service.state.lock().unwrap().tickets.is_empty());
}

#[test]
fn companion_history_projection_omits_internal_fields_preserves_unknown_time_and_fails_on_overflow()
{
    let f = fixture();
    let (service, _, _) = service(&f);
    let id = request(&f, &service);
    let mut event = f.app.companion_history(None).unwrap().remove(0);
    event.at_unix_seconds = None;
    event.outcome = crate::access::history::HistoryOutcome::LegacyUnknown;
    event.policy_revision = "POLICY-PRIVATE-SENTINEL".into();
    event.requester = crate::access::history::RequesterSnapshot::Agent {
        label: "REQUESTER-PRIVATE-SENTINEL".into(),
        fingerprint: "FINGERPRINT-PRIVATE-SENTINEL".into(),
    };
    event.credentials[0].label = "CREDENTIAL-PRIVATE-SENTINEL".into();
    let response = Response::history(std::slice::from_ref(&event));
    assert_eq!(response.status, 200);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&response.body).unwrap(),
        serde_json::json!({
            "version":1,"history_version":1,"events":[{"request_id":id,"operation":"deploy",
            "at_unix_seconds":null,"ordinal":0,"outcome":"legacy_unknown"}]
        })
    );
    assert!(!response.body.contains("SENTINEL"));
    assert_eq!(Response::history(&vec![event.clone(); 201]).status, 503);
    // Defense in depth in the shared serializer, independent of canonical field
    // validation. Never send a partial list if the byte budget is exceeded.
    event.operation = "x".repeat(1_048_576);
    let oversized = Response::history(&[event]);
    assert_eq!(oversized.status, 503);
    assert_eq!(oversized.body, r#"{"error":"unavailable","version":1}"#);
}
