use super::*;
use std::time::{Duration, Instant};

const ID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const ACTION: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

fn client() -> String {
    "c".repeat(64)
}
fn ticket() -> String {
    "d".repeat(64)
}
fn revoke() -> String {
    format!(
        r#"{{"version":2,"command":"identity_revoke","target":{{"kind":"approval_client","id":"{}"}},"action_id":"{ACTION}","ticket":"{}","password":"pw"}}"#,
        client(),
        ticket()
    )
}

#[test]
fn a_decision_stays_uncertain_until_settled() {
    let start = Recovery::default();
    assert_eq!(
        start.before_send(br#"{"version":1,"command":"status"}"#),
        Some(start.clone())
    );
    let pending = start
        .before_send(
            format!(
                r#"{{"version":1,"command":"decision","request_id":"{ID}","decision":"deny"}}"#
            )
            .as_bytes(),
        )
        .unwrap();
    assert_eq!(pending.pending_id.as_deref(), Some(ID));
    assert!(pending.has_pending());
    assert!(pending
        .before_send(br#"{"version":1,"command":"list"}"#)
        .is_none());
    assert!(pending
        .before_send(
            format!(r#"{{"version":1,"command":"status","request_id":"{ACTION}"}}"#).as_bytes()
        )
        .is_none());
    assert_eq!(
        pending.before_send(
            format!(r#"{{"version":1,"command":"status","request_id":"{ID}"}}"#).as_bytes()
        ),
        Some(pending.clone())
    );
    assert!(pending.settle(ACTION).is_none());
    assert_eq!(pending.settle(ID), Some(Recovery::default()));
    assert!(start
        .before_send(br#"{"version":1,"command":"decision","request_id":"short"}"#)
        .is_none());
    assert!(start.before_send(b"not json").is_none());
}

#[test]
fn an_administrative_revocation_is_recorded_without_its_secrets() {
    let marked = Recovery::default()
        .before_send(revoke().as_bytes())
        .unwrap();
    assert_eq!(marked.management.as_ref().unwrap().action_id, ACTION);
    assert!(!marked.management_json().contains("pw"));
    assert!(!marked.management_json().contains(&ticket()));
    assert!(marked
        .before_send(
            format!(r#"{{"version":1,"command":"status","request_id":"{ID}"}}"#).as_bytes()
        )
        .is_none());
    let status = format!(
        r#"{{"version":2,"command":"identity_status","target":{{"kind":"approval_client","id":"{}"}},"action_id":"{ACTION}"}}"#,
        client()
    );
    assert_eq!(marked.before_send(status.as_bytes()), Some(marked.clone()));
    assert!(marked.settle(ID).is_none());
    assert_eq!(marked.settle(ACTION), Some(Recovery::default()));
    assert!(Recovery::default()
        .before_send(revoke().replace("\"pw\"", "\"\"").as_bytes())
        .is_none());
    assert!(Recovery::default()
        .before_send(
            revoke()
                .replace("approval_client", "requester_agent")
                .as_bytes()
        )
        .is_none());
    assert!(
        marked.before_send(revoke().as_bytes()).is_none(),
        "one at a time"
    );
    let json: serde_json::Value = serde_json::from_str(&marked.management_json()).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"target":{"kind":"approval_client","id":client()},"action_id":ACTION})
    );
}

#[test]
fn prepared_tickets_die_with_the_foreground() {
    let now = Instant::now();
    let mut gate = ManagementGate::default();
    let prepare = format!(
        r#"{{"version":2,"command":"identity_prepare","target":{{"kind":"approval_client","id":"{}"}}}}"#,
        client()
    );
    let reply = format!(
        r#"{{"version":2,"identity":{{"kind":"approval_client","id":"{}"}},"action_id":"{ACTION}","ticket":"{}"}}"#,
        client(),
        ticket()
    );
    let (prepare, reply, revoke) = (prepare.as_bytes(), reply.as_bytes(), revoke());
    let revoke = revoke.as_bytes();
    assert!(
        gate.begin(prepare, false, now).is_none(),
        "background prepare"
    );
    let epoch = gate.begin(prepare, true, now).unwrap();
    assert!(gate.finish(prepare, reply, epoch, true, now));
    assert!(gate.begin(revoke, true, now).is_some());
    assert!(gate.begin(revoke, true, now).is_none(), "one attempt");

    let epoch = gate.begin(prepare, true, now).unwrap();
    assert!(gate.finish(prepare, reply, epoch, true, now));
    gate.invalidate();
    assert!(gate.begin(revoke, true, now).is_none());

    let epoch = gate.begin(prepare, true, now).unwrap();
    gate.invalidate();
    assert!(
        !gate.finish(prepare, reply, epoch, true, now),
        "after invalidation"
    );

    let epoch = gate.begin(prepare, true, now).unwrap();
    assert!(gate.finish(prepare, reply, epoch, true, now));
    assert!(
        gate.begin(revoke, true, now + Duration::from_secs(55))
            .is_none(),
        "expired"
    );

    let epoch = gate.begin(prepare, true, now).unwrap();
    assert!(
        !gate.finish(prepare, reply, epoch, false, now),
        "background reply"
    );
    // Other commands pass through untouched.
    assert!(gate
        .begin(br#"{"version":1,"command":"list"}"#, false, now)
        .is_some());
}
