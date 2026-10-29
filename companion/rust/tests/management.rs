use companion_core::{api::management::*, provider::management::ManagementSession};
use serde_json::{json, Value};
fn id() -> String {
    "A".repeat(43)
}
fn target() -> Value {
    json!({"kind":"requester_agent","id":id()})
}
fn row() -> Value {
    json!({"kind":"requester_agent","id":id(),"label":"Same label","fingerprint":"b".repeat(64),"roles":["request"],"trust":"enabled","this_client":false})
}
fn new() -> ManagementSession {
    let mut s = ManagementSession::default();
    s.configure("").unwrap();
    s
}
fn start(
    s: &mut ManagementSession,
    c: ManagementCommand,
) -> companion_core::api::provider::ProviderWork {
    s.begin(c, IdentityKind::RequesterAgent, id(), "synthetic".into())
        .unwrap()
}
fn reply(s: &mut ManagementSession, c: ManagementCommand, v: Value) {
    let w = start(s, c);
    s.finish(w.token, &serde_json::to_vec(&v).unwrap());
}
fn prepared() -> Value {
    json!({"version":2,"identity":row(),"generation":1,"action_id":"C".repeat(43),"ticket":"d".repeat(64),"valid_for_seconds":55})
}
fn prepare(s: &mut ManagementSession) {
    reply(s, ManagementCommand::Prepare, prepared());
    assert!(s.snapshot().can_revoke);
}
fn action(revocation: &str, cleanup: &str) -> Value {
    json!({"version":2,"owner_reconciled":false,"target":target(),"action_id":"C".repeat(43),"revocation":revocation,"cleanup":cleanup})
}
fn inventory(rows: Value) -> Value {
    json!({"version":2,"identities":rows,"generation":1,"next_cursor":null,"provider":{"fingerprint":"e".repeat(64),"execution_configured":true,"execution_available":false}})
}
#[test]
fn inventory_is_closed_bounded_sorted_and_never_grants_revocation() {
    let mut s = new();
    reply(&mut s, ManagementCommand::List, inventory(json!([row()])));
    assert_eq!(s.snapshot().state, InventoryState::Ready);
    assert!(!s.snapshot().can_revoke);
    assert_eq!(s.snapshot().identities[0].label, "\"Same label\"");
    for bad in [
        inventory(json!([row(), row()])),
        inventory(json!((0..65).map(|_| row()).collect::<Vec<_>>())),
        {
            let mut v = inventory(json!([row()]));
            v["secret"] = "must-reject".into();
            v
        },
        {
            let mut v = inventory(json!([row()]));
            v["identities"][0]["roles"] = json!(["admin"]);
            v
        },
        {
            let mut v = inventory(json!([row()]));
            v["identities"][0]["this_client"] = true.into();
            v
        },
    ] {
        reply(&mut s, ManagementCommand::List, bad);
        assert_eq!(s.snapshot().outcome, ManagementOutcome::Invalid);
        assert!(s.snapshot().identities.is_empty());
    }
}
#[test]
fn target_binding_and_single_consumption_prevent_selection_substitution() {
    let mut s = new();
    prepare(&mut s);
    assert!(s
        .begin(
            ManagementCommand::Revoke,
            IdentityKind::RequesterAgent,
            "B".repeat(43),
            "synthetic".into()
        )
        .is_err());
    let w = start(&mut s, ManagementCommand::Revoke);
    let sent: Value = serde_json::from_slice(&w.body).unwrap();
    assert_eq!(sent["target"], target());
    assert!(!s.snapshot().can_revoke);
    assert!(!s.snapshot().recovery.contains("synthetic"));
    assert!(!s.snapshot().recovery.contains("ticket"));
    assert!(s
        .begin(
            ManagementCommand::Revoke,
            IdentityKind::RequesterAgent,
            id(),
            "synthetic".into()
        )
        .is_err());
    s.finish(w.token, b"");
    assert!(!s.snapshot().recovery.is_empty());
    assert!(s
        .begin(
            ManagementCommand::List,
            IdentityKind::RequesterAgent,
            id(),
            String::new()
        )
        .is_err());
    let status = start(&mut s, ManagementCommand::Status);
    let body: Value = serde_json::from_slice(&status.body).unwrap();
    assert_eq!(body["command"], "identity_status");
    assert_eq!(body["target"], target());
    assert!(body.get("password").is_none());
}
#[test]
fn invalidation_rejects_late_preparation_and_clears_all_trust() {
    let mut s = new();
    let w = start(&mut s, ManagementCommand::Prepare);
    s.invalidate();
    s.finish(w.token, &serde_json::to_vec(&prepared()).unwrap());
    assert_eq!(s.snapshot().outcome, ManagementOutcome::Stale);
    assert!(!s.snapshot().can_revoke);
    assert!(s.snapshot().detail.is_none());
    prepare(&mut s);
    s.invalidate();
    assert!(s
        .begin(
            ManagementCommand::Revoke,
            IdentityKind::RequesterAgent,
            id(),
            "synthetic".into()
        )
        .is_err());
}
#[test]
fn lost_reply_relaunch_and_cleanup_unknown_stay_original_action_only() {
    let mut s = new();
    prepare(&mut s);
    let w = start(&mut s, ManagementCommand::Revoke);
    s.finish(w.token, b"");
    let marker = s.snapshot().recovery;
    let mut restored = new();
    restored.configure(&marker).unwrap();
    assert!(restored
        .begin(
            ManagementCommand::Prepare,
            IdentityKind::RequesterAgent,
            id(),
            String::new()
        )
        .is_err());
    reply(
        &mut restored,
        ManagementCommand::Status,
        action("recorded", "unknown"),
    );
    assert_eq!(restored.snapshot().revocation, "recorded");
    assert!(!restored.snapshot().recovery.is_empty());
    reply(
        &mut restored,
        ManagementCommand::Status,
        action("recorded", "complete"),
    );
    assert!(restored.snapshot().recovery.is_empty());
    assert_eq!(
        restored.snapshot().action_target,
        format!("requester_agent:{}", id())
    );
}
#[test]
fn wrong_action_unknown_fields_and_impossible_cleanup_never_settle() {
    for scenario in 0..3 {
        let mut v = if scenario == 2 {
            action("unknown", "complete")
        } else {
            action("recorded", "complete")
        };
        let mut s = new();
        prepare(&mut s);
        let w = start(&mut s, ManagementCommand::Revoke);
        s.finish(w.token, b"");
        if scenario == 0 {
            v["action_id"] = "Z".repeat(43).into();
        }
        if scenario == 1 {
            v["target"]["id"] = "Z".repeat(43).into();
        }
        reply(&mut s, ManagementCommand::Status, v);
        assert_eq!(s.snapshot().outcome, ManagementOutcome::Invalid);
        assert!(!s.snapshot().recovery.is_empty());
    }
    let mut s = new();
    prepare(&mut s);
    let w = start(&mut s, ManagementCommand::Revoke);
    let mut v = action("recorded", "complete");
    v["future_authority"] = true.into();
    s.finish(w.token, &serde_json::to_vec(&v).unwrap());
    assert_eq!(s.snapshot().outcome, ManagementOutcome::Invalid);
    assert!(!s.snapshot().recovery.is_empty());
}
#[test]
fn definite_rejection_clears_action_but_lost_or_stale_reply_never_does() {
    for (error, retained) in [
        ("authentication_failed", false),
        ("unauthorized", false),
        ("stale", true),
        ("unavailable", true),
    ] {
        let mut s = new();
        prepare(&mut s);
        let w = start(&mut s, ManagementCommand::Revoke);
        s.finish(
            w.token,
            &serde_json::to_vec(&json!({"version":1,"error":error})).unwrap(),
        );
        assert_eq!(!s.snapshot().recovery.is_empty(), retained);
        assert!(!s.snapshot().can_revoke);
    }
}
#[test]
fn late_mutation_reply_is_attributed_to_original_target_without_restoring_authority() {
    let mut s = new();
    prepare(&mut s);
    let w = start(&mut s, ManagementCommand::Revoke);
    s.invalidate();
    s.finish(
        w.token,
        &serde_json::to_vec(&action("recorded", "complete")).unwrap(),
    );
    assert!(s.snapshot().recovery.is_empty());
    assert_eq!(s.snapshot().action_id, "C".repeat(43));
    assert!(s.snapshot().detail.is_none());
    assert!(!s.snapshot().can_revoke);
    s.finish(
        w.token,
        &serde_json::to_vec(&action("unknown", "unknown")).unwrap(),
    );
    assert_eq!(s.snapshot().revocation, "recorded");
}
#[test]
fn origin_is_exact_request_bound_and_never_inferred_from_label() {
    let mut s = new();
    reply(
        &mut s,
        ManagementCommand::Origin,
        json!({"version":2,"request_id":id(),"origin":null}),
    );
    assert!(s.snapshot().origin_text.starts_with("Unavailable"));
    let origin = json!({"kind":"requester_agent","binding_id":"B".repeat(43),"label":"<claimed device>","fingerprint":"f".repeat(64),"evidence":"signed_os_binding"});
    reply(
        &mut s,
        ManagementCommand::Origin,
        json!({"version":2,"request_id":id(),"origin":origin}),
    );
    assert!(s
        .snapshot()
        .origin_text
        .contains("does not establish a physical device"));
    reply(
        &mut s,
        ManagementCommand::Origin,
        json!({"version":2,"request_id":"B".repeat(43),"origin":null}),
    );
    assert!(s.snapshot().origin_text.is_empty());
    assert_eq!(s.snapshot().outcome, ManagementOutcome::Invalid);
    reply(
        &mut s,
        ManagementCommand::Origin,
        json!({"version":1,"error":"invalid_request"}),
    );
    assert_eq!(s.snapshot().outcome, ManagementOutcome::Unsupported);
}
#[test]
fn malformed_recovery_and_excessive_password_fail_before_send() {
    for r in [
        json!({"target":target(),"action_id":id(),"ticket":"secret"}),
        json!({"target":{"kind":"device","id":id()},"action_id":id()}),
    ] {
        assert!(new().configure(&r.to_string()).is_err());
    }
    let mut s = new();
    prepare(&mut s);
    assert!(s
        .begin(
            ManagementCommand::Revoke,
            IdentityKind::RequesterAgent,
            id(),
            "x".repeat(4097)
        )
        .is_err());
    assert!(s.snapshot().recovery.is_empty());
}

#[test]
fn owner_reconciliation_and_proven_noop_settle_without_claiming_original_success() {
    for (revocation, cleanup, owner) in [
        ("unknown", "unknown", true),
        ("not_recorded", "not_applicable", false),
    ] {
        let mut s = new();
        prepare(&mut s);
        let w = start(&mut s, ManagementCommand::Revoke);
        s.finish(w.token, b"");
        let mut v = action(revocation, cleanup);
        v["owner_reconciled"] = owner.into();
        reply(&mut s, ManagementCommand::Status, v);
        assert_eq!(s.snapshot().outcome, ManagementOutcome::Accepted);
        assert!(s.snapshot().recovery.is_empty());
        assert_eq!(s.snapshot().revocation, revocation);
        s.configure("").unwrap();
        assert!(s.snapshot().action_id.is_empty());
        assert!(!s.snapshot().message.contains("confirmed"));
        assert_eq!(s.snapshot().outcome, ManagementOutcome::None);
    }
}

#[test]
fn action_fact_matrix_is_closed_even_with_owner_reconciliation() {
    for revocation in ["not_recorded", "pending", "recorded", "unknown"] {
        for cleanup in ["pending", "complete", "unknown", "not_applicable"] {
            for owner in [false, true] {
                let valid = matches!(
                    (revocation, cleanup),
                    ("not_recorded", "not_applicable")
                        | ("pending", "pending" | "unknown")
                        | ("recorded", "complete" | "unknown")
                        | ("unknown", "unknown")
                );
                let mut s = new();
                prepare(&mut s);
                let w = start(&mut s, ManagementCommand::Revoke);
                s.finish(w.token, b"");
                let mut v = action(revocation, cleanup);
                v["owner_reconciled"] = owner.into();
                reply(&mut s, ManagementCommand::Status, v);
                let snapshot = s.snapshot();
                assert_eq!(
                    snapshot.outcome,
                    if valid {
                        ManagementOutcome::Accepted
                    } else {
                        ManagementOutcome::Invalid
                    },
                    "{revocation}/{cleanup}/{owner}"
                );
                let settled = valid
                    && (owner
                        || (revocation == "recorded" && cleanup == "complete")
                        || (revocation == "not_recorded" && cleanup == "not_applicable"));
                assert_eq!(
                    snapshot.recovery.is_empty(),
                    settled,
                    "{revocation}/{cleanup}/{owner}"
                );
            }
        }
    }
}
