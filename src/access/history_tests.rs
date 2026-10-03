use super::{
    direct_request::*,
    direct_request_tests::{approval, fixture, operation_draft, pending, records},
    history::*,
    provider::Provider,
};
use std::{
    os::unix::fs::{PermissionsExt, symlink},
    sync::atomic::Ordering,
};

fn save(f: &super::direct_request_tests::Fixture, value: &serde_json::Value) {
    std::fs::write(
        f.dir.path().join("provider/provider-state.json"),
        serde_json::to_vec(value).unwrap(),
    )
    .unwrap();
}
#[test]
fn history_submission_and_decision_have_exact_allowlisted_snapshots() {
    let f = fixture();
    let id = pending(&f);
    let owner = f.app.human_owner();
    let review = f.app.review_direct(owner, &id).unwrap();
    let events = f.app.history(owner, None).unwrap();
    assert_eq!(
        serde_json::to_value(&events).unwrap(),
        serde_json::json!([{
            "version":1,"request_id":id,"operation":"deploy",
            "requester":{"kind":"human","uid":owner.uid(),"label":"local human terminal"},
            "policy_revision":review.policy_digest,"credentials":review.credentials,
            "created_at_unix_seconds":1700000000u64,"expires_at_unix_seconds":1700000300u64,
            "at_unix_seconds":1700000000u64,"ordinal":0,"outcome":"submitted","status":{"status":"pending"}
        }])
    );
    f.wall.store(1700000001, Ordering::SeqCst);
    f.app.commit_approval(approval(&f, &id)).unwrap();
    let events = f.app.history(owner, None).unwrap();
    let mut expected = events[1].clone();
    expected.at_unix_seconds = Some(1700000001);
    expected.ordinal = 1;
    expected.outcome = HistoryOutcome::Approved;
    expected.status = Some(DirectStatus::Approved);
    assert_eq!(events[0], expected);
    let audit = serde_json::to_string(&events).unwrap();
    for forbidden in [
        "binding",
        "arguments",
        "target",
        "record_digest",
        "environment",
        "executable",
        "one_time",
        "session",
        "synthetic-password",
        "approval-password-sentinel",
    ] {
        assert!(!audit.contains(forbidden), "{forbidden}");
    }
}
#[test]
fn history_limits_empty_equal_timestamps_and_all_tiebreakers_are_deterministic() {
    let f = fixture();
    let owner = f.app.human_owner();
    assert!(f.app.history(owner, None).unwrap().is_empty());
    for value in [0, 201, u32::MAX] {
        assert_eq!(
            f.app.history(owner, Some(value)),
            Err(DirectRequestError::InvalidRequest)
        );
    }
    let a = pending(&f);
    let b = pending(&f);
    f.app.deny_direct(owner, &a).unwrap();
    f.app.deny_direct(owner, &b).unwrap();
    let all = f.app.history(owner, Some(200)).unwrap();
    assert_eq!(all.len(), 4);
    let mut ids = [a, b];
    ids.sort_by(|a, b| b.cmp(a));
    assert_eq!(
        all.iter()
            .map(|e| (e.request_id.as_str(), e.ordinal))
            .collect::<Vec<_>>(),
        vec![
            (ids[0].as_str(), 1),
            (ids[0].as_str(), 0),
            (ids[1].as_str(), 1),
            (ids[1].as_str(), 0)
        ]
    );
    assert_eq!(f.app.history(owner, Some(1)).unwrap(), all[..1]);
    assert_eq!(f.app.history(owner, None).unwrap(), all);
}
#[test]
fn history_default_and_maximum_limits_count_events() {
    let f = fixture();
    let id = pending(&f);
    let event = f.app.history(f.app.human_owner(), None).unwrap().remove(0);
    let events = (0..250)
        .map(|n| {
            let mut e = event.clone();
            e.ordinal = n;
            e.at_unix_seconds = Some(n as u64);
            e
        })
        .collect::<Vec<_>>();
    for (input, expected) in [(None, 50), (Some(1), 1), (Some(200), 200)] {
        let recent = super::history::newest(events.clone(), super::history::limit(input).unwrap());
        assert_eq!(recent.len(), expected);
        assert_eq!(recent[0].ordinal, 249);
        assert_eq!(recent.last().unwrap().ordinal, 250 - expected as u32);
    }
    assert!(!id.is_empty());
}
#[test]
fn history_owner_and_browser_generation_guards_work_while_locked() {
    let f = fixture();
    pending(&f);
    let owner = f.app.human_owner();
    let wrong = AuthenticatedHuman::from_peer_uid(owner.uid() + 1);
    assert_eq!(
        f.app.history(wrong, None),
        Err(DirectRequestError::Unauthorized)
    );
    let generation = f.app.decision_generation().unwrap();
    assert!(f.app.browser_history(generation, None).is_ok());
    f.app.lock().unwrap();
    assert_eq!(
        f.app.browser_history(generation, None),
        Err(DirectRequestError::Unauthorized)
    );
    let current = f.app.decision_generation().unwrap();
    assert!(f.app.browser_history(current, None).is_ok());
    let events = f.app.history(owner, None).unwrap();
    assert_eq!(events[0].outcome, HistoryOutcome::Invalidated);
    assert_eq!(events.len(), 2);
}
#[test]
fn history_policy_and_credential_labels_are_event_time_snapshots() {
    let f = fixture();
    let id = pending(&f);
    let owner = f.app.human_owner();
    f.app.deny_direct(owner, &id).unwrap();
    let before = f.app.history(owner, None).unwrap();
    let mut draft = operation_draft();
    draft.credentials[0].label = "changed credential".into();
    draft.description = "changed operation".into();
    f.app.activate_operation(draft).unwrap();
    assert_eq!(f.app.history(owner, None).unwrap(), before);
}
#[test]
fn history_terminal_restart_is_idempotent_and_pending_never_regains_authority() {
    let f = fixture();
    let denied = pending(&f);
    let pending = pending(&f);
    let owner = f.app.human_owner();
    f.app.deny_direct(owner, &denied).unwrap();
    let before = f
        .app
        .history(owner, None)
        .unwrap()
        .into_iter()
        .filter(|e| e.request_id == denied)
        .collect::<Vec<_>>();
    let root = f.dir.path().join("provider");
    drop(f.app);
    let provider = Provider::start(&root).unwrap();
    let events = provider.history(owner, None).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|e| e.request_id == denied)
            .cloned()
            .collect::<Vec<_>>(),
        before
    );
    assert!(
        events
            .iter()
            .any(|e| e.request_id == pending && e.outcome == HistoryOutcome::Recovered)
    );
    assert_eq!(
        provider.direct_review(owner, &pending).unwrap().status,
        DirectStatus::Expired
    );
    drop(provider);
    let again = Provider::start(&root).unwrap();
    assert_eq!(again.history(owner, None).unwrap(), events);
}
#[test]
fn history_legacy_binding_migration_is_narrow_and_removes_audit_authority() {
    let f = fixture();
    let id = pending(&f);
    f.app.commit_approval(approval(&f, &id)).unwrap();
    let owner = f.app.human_owner();
    let mut state = records(&f);
    let record: DirectRecord =
        serde_json::from_value(state["requests"][0]["direct"].clone()).unwrap();
    state["requests"][0]["direct"]
        .as_object_mut()
        .unwrap()
        .remove("history_version");
    state["requests"][0]["direct"]["audit"] = serde_json::json!([{"binding":record.approval_binding(),"at_unix_seconds":1700000001u64,"outcome":"approved"}]);
    save(&f, &state);
    let root = f.dir.path().join("provider");
    drop(f.app);
    let provider = Provider::start(&root).unwrap();
    let history = provider.history(owner, None).unwrap();
    assert!(
        history
            .iter()
            .any(|e| e.outcome == HistoryOutcome::LegacyUnknown)
    );
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("provider-state.json")).unwrap()).unwrap();
    assert_eq!(saved["requests"][0]["direct"]["history_version"], 1);
    assert!(
        !saved["requests"][0]["direct"]["audit"]
            .to_string()
            .contains("binding")
    );
    drop(provider);
    let again = Provider::start(&root).unwrap();
    assert_eq!(again.history(owner, None).unwrap(), history);
}
#[test]
fn history_old_records_without_audits_recover_without_inventing_event_times() {
    for status in [
        DirectStatus::Pending,
        DirectStatus::Approved,
        DirectStatus::Running,
        DirectStatus::Denied,
    ] {
        let f = fixture();
        let id = pending(&f);
        let owner = f.app.human_owner();
        let mut state = records(&f);
        let mut record: DirectRecord =
            serde_json::from_value(state["requests"][0]["direct"].clone()).unwrap();
        record.review.status = status.clone();
        record.review.one_time = LEGACY_ONE_TIME.into();
        record.seal();
        let mut old = serde_json::to_value(record).unwrap();
        old.as_object_mut().unwrap().remove("history_version");
        old.as_object_mut().unwrap().remove("audit");
        state["requests"][0]["direct"] = old;
        state["requests"][0]["status"] = serde_json::json!(match status {
            DirectStatus::Pending => "pending",
            DirectStatus::Approved => "approved",
            DirectStatus::Running => "running",
            _ => "denied",
        });
        save(&f, &state);
        let root = f.dir.path().join("provider");
        drop(f.app);
        let provider = Provider::start(&root).unwrap();
        let history = provider.history(owner, None).unwrap();
        if status != DirectStatus::Pending {
            let legacy = history
                .iter()
                .find(|e| e.outcome == HistoryOutcome::LegacyUnknown)
                .unwrap();
            assert_eq!(legacy.at_unix_seconds, None);
        }
        assert!(
            provider
                .direct_review(owner, &id)
                .unwrap()
                .status
                .is_terminal()
        );
        drop(provider);
        let again = Provider::start(&root).unwrap();
        assert_eq!(again.history(owner, None).unwrap(), history);
    }
}
#[test]
fn history_malformed_storage_unknown_versions_duplicates_and_state_mismatch_fail_closed() {
    for case in [
        "version",
        "event_version",
        "ordinal",
        "duplicate",
        "unknown",
        "outcome",
        "snapshot",
        "legacy_binding",
        "final_status",
    ] {
        let f = fixture();
        let id = pending(&f);
        let owner = f.app.human_owner();
        if matches!(case, "legacy_binding" | "final_status") {
            f.app.deny_direct(owner, &id).unwrap();
        }
        let mut state = records(&f);
        if case == "final_status" {
            state["requests"][0]["status"] = "invalidated".into();
        }
        let direct = &mut state["requests"][0]["direct"];
        match case {
            "final_status" => direct["review"]["status"] = serde_json::json!({"status":"expired"}),
            "version" => direct["history_version"] = 99.into(),
            "event_version" => direct["audit"][0]["version"] = 99.into(),
            "ordinal" => direct["audit"][0]["ordinal"] = 1.into(),
            "duplicate" => {
                let event = direct["audit"][0].clone();
                direct["audit"].as_array_mut().unwrap().push(event);
            }
            "unknown" => direct["audit"][0]["secret"] = "SENTINEL".into(),
            "outcome" => direct["audit"][0]["outcome"] = "denied".into(),
            "snapshot" => direct["audit"][0]["policy_revision"] = "a".repeat(64).into(),
            "legacy_binding" => {
                let r: DirectRecord = serde_json::from_value(direct.clone()).unwrap();
                let mut b = r.approval_binding();
                b.requester_uid += 1;
                direct.as_object_mut().unwrap().remove("history_version");
                direct["audit"] = serde_json::json!([{"binding":b,"at_unix_seconds":1700000000u64,"outcome":"denied"}]);
            }
            _ => panic!("unknown fixture case"),
        }
        save(&f, &state);
        assert_eq!(
            f.app.history(owner, None),
            Err(DirectRequestError::Unavailable),
            "{case}"
        );
        assert_eq!(
            f.app.direct_status(owner, &id),
            Err(DirectRequestError::Unavailable)
        );
    }
}
#[test]
fn history_durable_read_and_private_file_guards_are_independent() {
    for case in ["mode", "symlink", "malformed", "missing", "read_hook"] {
        let f = fixture();
        pending(&f);
        let path = f.dir.path().join("provider/provider-state.json");
        match case {
            "mode" => {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap()
            }
            "symlink" => {
                let copy = f.dir.path().join("copy");
                std::fs::rename(&path, &copy).unwrap();
                symlink(copy, &path).unwrap();
            }
            "malformed" => std::fs::write(&path, b"SYNTHETIC-SECRET-NOT-JSON").unwrap(),
            "missing" => std::fs::remove_file(&path).unwrap(),
            "read_hook" => super::provider_store::READ_TEST_HOOK
                .with(|h| *h.borrow_mut() = Some(Box::new(|| true))),
            _ => panic!("unknown fixture case"),
        }
        let result = f.app.history(f.app.human_owner(), None);
        super::provider_store::READ_TEST_HOOK.with(|h| *h.borrow_mut() = None);
        assert_eq!(result, Err(DirectRequestError::Unavailable), "{case}");
        assert!(!format!("{result:?}").contains("SYNTHETIC"));
    }
}
#[test]
fn history_transition_failure_cannot_split_audit_and_lifecycle() {
    for stage in [0, 1] {
        let f = fixture();
        let id = pending(&f);
        let before = records(&f);
        super::provider_store::WRITE_TEST_HOOK
            .with(|h| *h.borrow_mut() = Some(Box::new(move |s| s == stage)));
        let result = f.app.deny_direct(f.app.human_owner(), &id);
        super::provider_store::WRITE_TEST_HOOK.with(|h| *h.borrow_mut() = None);
        assert_eq!(result, Err(DirectRequestError::Unavailable));
        let saved = records(&f);
        if stage == 0 {
            assert_eq!(saved, before);
        } else {
            assert_eq!(saved["requests"][0]["status"], "denied");
            assert_eq!(
                saved["requests"][0]["direct"]["audit"]
                    .as_array()
                    .unwrap()
                    .len(),
                2
            );
            assert_eq!(
                f.app.history(f.app.human_owner(), None),
                Err(DirectRequestError::Unavailable)
            );
        }
    }
}
#[test]
fn history_agent_snapshot_fixture_is_closed_and_stable_without_agent_authority() {
    let f = fixture();
    pending(&f);
    let mut e = f.app.history(f.app.human_owner(), None).unwrap().remove(0);
    let label = "fixture agent <script>\u{1b}]0;title\u{7}\u{202e}".to_string();
    e.requester = RequesterSnapshot::Agent {
        label: label.clone(),
        fingerprint: "a".repeat(64),
    };
    let wire = serde_json::to_vec(&e).unwrap();
    let mut identity = label;
    identity.push_str(" changed");
    let loaded: HistoryEvent = serde_json::from_slice(&wire).unwrap();
    assert_eq!(loaded, e);
    assert!(!wire.is_empty());
    let mut invalid = serde_json::to_value(e).unwrap();
    invalid["requester"]["uid"] = 1.into();
    assert!(serde_json::from_value::<HistoryEvent>(invalid).is_err());
    assert_eq!(
        f.app.history(
            AuthenticatedHuman::from_peer_uid(f.app.human_owner().uid() + 1),
            None
        ),
        Err(DirectRequestError::Unauthorized)
    );
}

#[test]
fn history_every_lifecycle_projection_has_exact_fields_and_distinct_outcomes() {
    use super::provider_store::{RequestLifecycleStatus, RequestRecord};
    for (status, decision, outcome) in [
        (
            DirectStatus::Approved,
            DecisionOutcome::Approved,
            HistoryOutcome::Approved,
        ),
        (
            DirectStatus::Denied,
            DecisionOutcome::Denied,
            HistoryOutcome::Denied,
        ),
        (
            DirectStatus::Expired,
            DecisionOutcome::Expired,
            HistoryOutcome::Expired,
        ),
        (
            DirectStatus::Expired,
            DecisionOutcome::ReviewUnavailable,
            HistoryOutcome::ReviewUnavailable,
        ),
        (
            DirectStatus::Expired,
            DecisionOutcome::Invalidated,
            HistoryOutcome::Invalidated,
        ),
        (
            DirectStatus::Expired,
            DecisionOutcome::Recovered,
            HistoryOutcome::Recovered,
        ),
        (
            DirectStatus::Expired,
            DecisionOutcome::ExecutionUnavailable,
            HistoryOutcome::ExecutionUnavailable,
        ),
        (
            DirectStatus::Running,
            DecisionOutcome::Approved,
            HistoryOutcome::ExecutionStarted,
        ),
        (
            DirectStatus::Completed { exit_code: 0 },
            DecisionOutcome::Approved,
            HistoryOutcome::Succeeded,
        ),
        (
            DirectStatus::Completed { exit_code: 17 },
            DecisionOutcome::Approved,
            HistoryOutcome::ExecutionNonzero,
        ),
        (
            DirectStatus::Failed {
                reason: DirectFailure::ExecutionNonzero,
            },
            DecisionOutcome::ExecutionUnavailable,
            HistoryOutcome::ExecutionNonzero,
        ),
        (
            DirectStatus::Failed {
                reason: DirectFailure::ExecutionSignaled,
            },
            DecisionOutcome::ExecutionUnavailable,
            HistoryOutcome::ExecutionSignaled,
        ),
        (
            DirectStatus::Failed {
                reason: DirectFailure::ExecutionRejected,
            },
            DecisionOutcome::ExecutionUnavailable,
            HistoryOutcome::ExecutionRejected,
        ),
        (
            DirectStatus::Failed {
                reason: DirectFailure::ExecutionUnavailable,
            },
            DecisionOutcome::ExecutionUnavailable,
            HistoryOutcome::ExecutionUnavailable,
        ),
        (
            DirectStatus::Failed {
                reason: DirectFailure::ReviewUnavailable,
            },
            DecisionOutcome::ExecutionUnavailable,
            HistoryOutcome::ReviewUnavailable,
        ),
        (
            DirectStatus::Failed {
                reason: DirectFailure::ExecutionUnavailable,
            },
            DecisionOutcome::Recovered,
            HistoryOutcome::Recovered,
        ),
    ] {
        let f = fixture();
        let id = pending(&f);
        let state = records(&f);
        let direct: DirectRecord =
            serde_json::from_value(state["requests"][0]["direct"].clone()).unwrap();
        let revision = direct.review.policy_digest.clone();
        let credentials = direct.review.credentials.clone();
        let uid = direct.owner_uid;
        let mut request = RequestRecord {
            id: id.clone(),
            status: RequestLifecycleStatus::Pending,
            direct: Some(direct),
        };
        if matches!(
            status,
            DirectStatus::Running | DirectStatus::Completed { .. } | DirectStatus::Failed { .. }
        ) {
            request
                .transition(
                    DirectStatus::Approved,
                    DecisionOutcome::Approved,
                    1700000001,
                )
                .unwrap();
        }
        if matches!(
            status,
            DirectStatus::Completed { .. } | DirectStatus::Failed { .. }
        ) {
            request.direct.as_mut().unwrap().execution_claimed = true;
            request
                .transition(DirectStatus::Running, DecisionOutcome::Approved, 1700000002)
                .unwrap();
        }
        if matches!(status, DirectStatus::Running) {
            request.direct.as_mut().unwrap().execution_claimed = true;
        }
        request
            .transition(status.clone(), decision, 1700000003)
            .unwrap();
        let record = request.direct.unwrap();
        let ordinal = record.audit.len() - 1;
        assert!(record.validate(&id, state["lifecycle_epoch"].as_u64().unwrap()));
        let expected = serde_json::json!({
            "version":1,"request_id":id,"operation":"deploy",
            "requester":{"kind":"human","uid":uid,"label":"local human terminal"},
            "policy_revision":revision,"credentials":credentials,
            "created_at_unix_seconds":1700000000u64,"expires_at_unix_seconds":1700000300u64,
            "at_unix_seconds":1700000003u64,"ordinal":ordinal,"outcome":outcome,"status":status
        });
        assert_eq!(
            serde_json::to_value(record.audit.last().unwrap()).unwrap(),
            expected
        );
        assert_eq!(
            record
                .audit
                .iter()
                .filter(|e| e.at_unix_seconds == Some(1700000003))
                .count(),
            1
        );
    }
}
#[test]
fn history_provider_owner_guard_is_independent_of_application_authentication() {
    let f = fixture();
    pending(&f);
    let owner = f.app.human_owner();
    let root = f.dir.path().join("provider");
    drop(f.app);
    let provider = Provider::start(root).unwrap();
    assert!(!provider.history(owner, None).unwrap().is_empty());
    assert_eq!(
        provider.history(AuthenticatedHuman::from_peer_uid(owner.uid() + 1), None),
        Err(DirectRequestError::Unauthorized)
    );
}

#[test]
fn history_time_precedes_identity_and_ordinal_and_unknown_time_sorts_last() {
    use base64::Engine;
    let f = fixture();
    pending(&f);
    let base = f.app.history(f.app.human_owner(), None).unwrap().remove(0);
    let low = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32]);
    let high = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([255u8; 32]);
    assert!(high > low);
    let event = |time, id: &str, ordinal| {
        let mut event = base.clone();
        event.at_unix_seconds = time;
        event.request_id = id.into();
        event.ordinal = ordinal;
        if time.is_none() {
            event.outcome = HistoryOutcome::LegacyUnknown;
        }
        event
    };
    let expected = vec![
        event(Some(200), &low, 0),
        event(Some(100), &high, 0),
        event(Some(100), &low, 3),
        event(Some(100), &low, 1),
        event(None, &high, 3),
    ];
    for indexes in [[4, 3, 0, 2, 1], [1, 0, 4, 3, 2], [2, 4, 1, 0, 3]] {
        let shuffled = indexes.map(|index| expected[index].clone()).to_vec();
        assert_eq!(super::history::newest(shuffled, 200), expected);
    }
}
#[test]
fn history_recorded_execution_requires_a_claim_independently_of_other_guards() {
    use super::provider_store::RequestRecord;
    for completed in [false, true] {
        let f = fixture();
        let id = pending(&f);
        let owner = f.app.human_owner();
        f.app.commit_approval(approval(&f, &id)).unwrap();
        let mut state = records(&f);
        let mut request: RequestRecord =
            serde_json::from_value(state["requests"][0].clone()).unwrap();
        request.direct.as_mut().unwrap().execution_claimed = true;
        request
            .transition(DirectStatus::Running, DecisionOutcome::Approved, 1700000001)
            .unwrap();
        if completed {
            request
                .transition(
                    DirectStatus::Completed { exit_code: 0 },
                    DecisionOutcome::Approved,
                    1700000002,
                )
                .unwrap();
        }
        state["requests"][0] = serde_json::to_value(request).unwrap();
        save(&f, &state);
        assert!(f.app.history(owner, None).is_ok());
        state["requests"][0]["direct"]["execution_claimed"] = false.into();
        save(&f, &state);
        assert_eq!(
            f.app.history(owner, None),
            Err(DirectRequestError::Unavailable)
        );
    }
}

#[test]
fn history_wire_validation_guards_are_independently_observable() {
    let f = fixture();
    pending(&f);
    let event = f.app.history(f.app.human_owner(), None).unwrap().remove(0);
    let original = serde_json::to_value(event).unwrap();
    for case in [
        "version",
        "request_id",
        "operation",
        "policy",
        "expiry",
        "human_uid",
        "human_label_empty",
        "human_label_long",
        "agent_fingerprint",
        "credentials_empty",
        "credentials_count",
        "credential_label_empty",
        "credential_label_long",
        "event_time",
        "outcome",
        "unknown_field",
    ] {
        assert!(serde_json::from_value::<HistoryEvent>(original.clone()).is_ok());
        let mut bad = original.clone();
        match case {
            "version" => bad["version"] = 2.into(),
            "request_id" => bad["request_id"] = "invalid".into(),
            "operation" => bad["operation"] = "INVALID OPERATION".into(),
            "policy" => bad["policy_revision"] = "INVALID".into(),
            "expiry" => bad["expires_at_unix_seconds"] = bad["created_at_unix_seconds"].clone(),
            "human_uid" => bad["requester"]["uid"] = u32::MAX.into(),
            "human_label_empty" => bad["requester"]["label"] = "".into(),
            "human_label_long" => bad["requester"]["label"] = "x".repeat(257).into(),
            "agent_fingerprint" => {
                let valid = serde_json::json!({"kind":"agent","label":"fixture agent","fingerprint":"a".repeat(64)});
                bad["requester"] = valid;
                assert!(serde_json::from_value::<HistoryEvent>(bad.clone()).is_ok());
                bad["requester"]["fingerprint"] = "INVALID".into();
            }
            "credentials_empty" => bad["credentials"] = serde_json::json!([]),
            "credentials_count" => {
                bad["credentials"] = serde_json::json!(vec![bad["credentials"][0].clone(); 17])
            }
            "credential_label_empty" => bad["credentials"][0]["label"] = "".into(),
            "credential_label_long" => bad["credentials"][0]["label"] = "x".repeat(257).into(),
            "event_time" => bad["at_unix_seconds"] = serde_json::Value::Null,
            "outcome" => bad["outcome"] = "approved".into(),
            "unknown_field" => bad["raw_output"] = "SYNTHETIC-FORBIDDEN-OUTPUT".into(),
            _ => panic!("unknown fixture case"),
        }
        assert!(
            serde_json::from_value::<HistoryEvent>(bad).is_err(),
            "{case}"
        );
    }
}

#[test]
fn history_all_current_terminal_records_and_attribution_survive_two_restarts() {
    use super::provider_store::RequestRecord;
    let f = fixture();
    let owner = f.app.human_owner();
    for status in [
        DirectStatus::Denied,
        DirectStatus::Expired,
        DirectStatus::Completed { exit_code: 0 },
        DirectStatus::Failed {
            reason: DirectFailure::ExecutionNonzero,
        },
    ] {
        let id = pending(&f);
        let mut state = records(&f);
        let index = state["requests"]
            .as_array()
            .unwrap()
            .iter()
            .position(|r| r["id"] == id)
            .unwrap();
        let mut request: RequestRecord =
            serde_json::from_value(state["requests"][index].clone()).unwrap();
        if matches!(
            status,
            DirectStatus::Completed { .. } | DirectStatus::Failed { .. }
        ) {
            request
                .transition(
                    DirectStatus::Approved,
                    DecisionOutcome::Approved,
                    1700000001,
                )
                .unwrap();
            request.direct.as_mut().unwrap().execution_claimed = true;
            request
                .transition(DirectStatus::Running, DecisionOutcome::Approved, 1700000002)
                .unwrap();
        }
        let reason = if status == DirectStatus::Denied {
            DecisionOutcome::Denied
        } else {
            DecisionOutcome::Expired
        };
        request.transition(status, reason, 1700000003).unwrap();
        state["requests"][index] = serde_json::to_value(request).unwrap();
        save(&f, &state);
    }
    let before = f.app.history(owner, Some(200)).unwrap();
    assert_eq!(before.len(), 12);
    let root = f.dir.path().join("provider");
    drop(f.app);
    for _ in 0..2 {
        let provider = Provider::start(&root).unwrap();
        assert_eq!(provider.history(owner, Some(200)).unwrap(), before);
        for event in &before {
            assert!(
                provider
                    .direct_review(owner, &event.request_id)
                    .unwrap()
                    .status
                    .is_terminal()
            );
        }
        drop(provider);
    }
}

#[test]
fn history_completed_legacy_three_approvals_reconstruct_exact_phases_and_restart_stably() {
    let f = fixture();
    let id = pending(&f);
    let owner = f.app.human_owner();
    let mut state = records(&f);
    let mut record: DirectRecord =
        serde_json::from_value(state["requests"][0]["direct"].clone()).unwrap();
    let original = record.audit[0].clone();
    record.review.status = DirectStatus::Completed { exit_code: 0 };
    record.execution_claimed = true;
    let binding = record.approval_binding();
    let mut legacy = serde_json::to_value(&record).unwrap();
    legacy.as_object_mut().unwrap().remove("history_version");
    legacy["audit"] = serde_json::json!([1700000001u64, 1700000002, 1700000003].map(
        |at| serde_json::json!({"binding":binding,"at_unix_seconds":at,"outcome":"approved"})
    ));
    state["requests"][0]["status"] = "completed".into();
    state["requests"][0]["direct"] = legacy;
    save(&f, &state);
    let root = f.dir.path().join("provider");
    drop(f.app);
    let provider = Provider::start(&root).unwrap();
    let actual = provider.history(owner, None).unwrap();
    let mut expected = vec![original.clone()];
    for (offset, status) in [
        DirectStatus::Approved,
        DirectStatus::Running,
        DirectStatus::Completed { exit_code: 0 },
    ]
    .into_iter()
    .enumerate()
    {
        let mut event = original.clone();
        event.ordinal = offset as u32 + 1;
        event.at_unix_seconds = Some(1700000001 + offset as u64);
        event.outcome = HistoryOutcome::LegacyUnknown;
        event.status = Some(status);
        expected.push(event);
    }
    expected.reverse();
    assert_eq!(actual, expected);
    assert_eq!(
        provider.direct_review(owner, &id).unwrap().status,
        DirectStatus::Completed { exit_code: 0 }
    );
    drop(provider);
    let again = Provider::start(root).unwrap();
    assert_eq!(again.history(owner, None).unwrap(), expected);
}

#[test]
fn history_first_read_at_request_deadline_expires_pending_and_approved_once() {
    for approve in [false, true] {
        let f = fixture();
        let id = pending(&f);
        let owner = f.app.human_owner();
        if approve {
            f.app.commit_approval(approval(&f, &id)).unwrap();
        }
        f.monotonic.store(310, Ordering::SeqCst);
        f.wall.store(1700000300, Ordering::SeqCst);
        // History is the first operation after the request deadline; the session expires at 910.
        let events = f.app.history(owner, None).unwrap();
        assert_eq!(events.len(), if approve { 3 } else { 2 });
        assert_eq!(events[0].outcome, HistoryOutcome::Expired);
        assert_eq!(events[0].at_unix_seconds, Some(1700000300));
        let saved = records(&f);
        assert_eq!(saved["requests"][0]["status"], "invalidated");
        assert_eq!(
            events
                .iter()
                .filter(|e| e.outcome == HistoryOutcome::Expired)
                .count(),
            1
        );
        assert_eq!(f.app.history(owner, None).unwrap(), events);
        assert_eq!(records(&f), saved);
        assert_eq!(
            f.app.status().unwrap(),
            super::application::SessionStatus::Unlocked
        );
    }
}
