use companion_core::api::provider::{
    ProviderCommand as Command, ProviderOutcome, ProviderStatusProgress,
};
use companion_core::provider::{protocol::*, session::ProviderSession};
use serde_json::{json, Value};

const ID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/companion/review.json"
    ))
    .unwrap()
}
fn reply(session: &mut ProviderSession, command: Command, id: &str, value: Value) {
    let work = session.begin(command, id.into(), String::new()).unwrap();
    session.finish(work.token, &serde_json::to_vec(&value).unwrap());
}
fn connected() -> ProviderSession {
    let mut session = ProviderSession::default();
    session.configure("").unwrap();
    reply(
        &mut session,
        Command::Session,
        "",
        json!({"version":1,"state":"unlocked","generation":1}),
    );
    session
}
fn reviewed() -> ProviderSession {
    let mut session = connected();
    reply(&mut session, Command::Review, ID, fixture());
    assert!(session.snapshot().can_decide);
    session
}

#[test]
fn canonical_review_renders_every_field_and_argument_boundary() {
    let mut session = connected();
    let mut value = fixture();
    value["review"]["arguments"] = json!([
        "",
        " a b ",
        "a\nb",
        "\u{202e}hidden",
        "literal\\u{202e}",
        "\"quoted\""
    ]);
    reply(&mut session, Command::Review, ID, value);
    let state = session.snapshot();
    for fragment in [
        ID,
        "agent synthetic",
        "deploy",
        "Deploy synthetic",
        "staging",
        "Synthetic login",
        "login",
        "2000000000",
        "Approve this operation once",
        "pending",
        &"a".repeat(64),
        &"b".repeat(64),
        &"c".repeat(64),
        "[0] \"\"",
        "[1] \" a b \"",
        "[2] \"a\\u{000a}b\"",
        "[3] \"\\u{202e}hidden\"",
        "[4] \"literal\\\\u{202e}\"",
        "[5] \"\\\"quoted\\\"\"",
    ] {
        assert!(state.review_text.contains(fragment), "missing {fragment}");
    }
    assert!(!state.review_text.contains('\u{202e}'));
    assert_eq!(
        visible("\u{00ad}\u{200b}\u{2066}\u{2028}\u{007f}"),
        "\"\\u{00ad}\\u{200b}\\u{2066}\\u{2028}\\u{007f}\""
    );
}

#[test]
fn closed_schema_rejects_unknown_missing_duplicate_and_invalid_variants() {
    for path in [
        vec!["extra"],
        vec!["review", "extra"],
        vec!["review", "status", "extra"],
        vec!["review", "credentials", "0", "extra"],
    ] {
        let mut value = fixture();
        let mut node = &mut value;
        for key in &path[..path.len() - 1] {
            node = if *key == "0" {
                &mut node[0]
            } else {
                &mut node[*key]
            };
        }
        node[path[path.len() - 1]] = true.into();
        assert!(decode::<ReviewResponse>(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut missing = fixture();
    missing.as_object_mut().unwrap().remove("ticket");
    assert!(decode::<ReviewResponse>(&serde_json::to_vec(&missing).unwrap()).is_err());
    for value in [
        json!({"status":"completed"}),
        json!({"status":"completed","exit_code":256}),
        json!({"status":"failed","reason":"backend_secret"}),
        json!({"status":"running","reason":"execution_nonzero"}),
        json!({"status":"unknown"}),
        json!({"status":"pending","exit_code":null}),
    ] {
        assert!(decode::<Status>(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    assert!(decode::<SessionResponse>(
        br#"{"version":1,"state":"unlocked","generation":1,"generation":2}"#
    )
    .is_err());
    assert!(
        decode::<SessionResponse>(br#"{"version":1,"state":"unlocked","generation":-1}"#).is_err()
    );
    assert!(decode::<SessionResponse>(&vec![b' '; RESPONSE_LIMIT + 1]).is_err());
}

#[test]
fn list_has_visible_bounded_unique_valid_ids() {
    let mut session = connected();
    for ids in [json!([ID, ID]), json!(["bad"]), json!(vec![ID; 257])] {
        reply(
            &mut session,
            Command::List,
            "",
            json!({"version":1,"requests":ids}),
        );
        assert!(session.snapshot().requests.is_empty());
    }
    let ids: Vec<String> = (0..256).map(|i| format!("{i:043}")).collect();
    reply(
        &mut session,
        Command::List,
        "",
        json!({"version":1,"requests":ids}),
    );
    assert_eq!(session.snapshot().requests.len(), 256);
}

#[test]
fn review_rejects_wrong_id_generation_digest_ticket_status_version_and_deadline() {
    for (field, value) in [
        ("version", json!(2)),
        ("generation", json!(2)),
        ("ticket", json!("D".repeat(64))),
        ("review.id", json!("B".repeat(43))),
        ("review.policy_digest", json!("B".repeat(64))),
        ("review.status", json!({"status":"completed","exit_code":0})),
        ("review.expires_at_unix_seconds", json!(1)),
    ] {
        let mut session = connected();
        let mut value2 = fixture();
        if let Some(name) = field.strip_prefix("review.") {
            value2["review"][name] = value;
        } else {
            value2[field] = value;
        }
        reply(&mut session, Command::Review, ID, value2);
        assert!(!session.snapshot().can_decide, "accepted {field}");
    }
}

#[test]
fn consumes_ticket_before_send_wrong_password_requires_explicit_new_review() {
    let mut session = reviewed();
    let work = session
        .begin(Command::Approve, "ignored".into(), "fresh-password".into())
        .unwrap();
    let request: Value = serde_json::from_slice(&work.body).unwrap();
    assert_eq!(request["request_id"], ID);
    assert_eq!(request["password"], "fresh-password");
    assert_eq!(request["ticket"], "d".repeat(64));
    assert!(session.snapshot().review_text.is_empty());
    assert_eq!(session.snapshot().uncertain_id, ID);
    assert!(session
        .begin(Command::Approve, ID.into(), "fresh".into())
        .is_err());
    session.finish(
        work.token,
        br#"{"version":1,"error":"authentication_failed"}"#,
    );
    assert!(session.snapshot().uncertain_id.is_empty());
    assert!(session
        .begin(Command::Approve, ID.into(), "fresh".into())
        .is_err());
    reply(
        &mut session,
        Command::Session,
        "",
        json!({"version":1,"state":"unlocked","generation":1}),
    );
    reply(&mut session, Command::Review, ID, fixture());
    assert!(session.snapshot().can_decide);
}

#[test]
fn deny_omits_password_and_approval_never_reuses_it() {
    let mut session = reviewed();
    let deny = session
        .begin(Command::Deny, ID.into(), "discard-this".into())
        .unwrap();
    let body: Value = serde_json::from_slice(&deny.body).unwrap();
    assert_eq!(body["decision"], "deny");
    assert!(body.get("password").is_none());
    session.finish(deny.token, br#"{"version":1,"status":{"status":"denied"}}"#);
    reply(&mut session, Command::Review, ID, fixture());
    for password in [String::new(), "é".repeat(2049)] {
        assert!(session
            .begin(Command::Approve, ID.into(), password)
            .is_err());
    }
}

#[test]
fn oversized_escaped_password_never_sends_or_creates_false_uncertainty() {
    let mut session = reviewed();
    assert!(session
        .begin(Command::Approve, ID.into(), "\0".repeat(4096))
        .is_err());
    assert!(session.snapshot().uncertain_id.is_empty());
    assert!(!session.snapshot().busy);
    assert!(!session.snapshot().can_decide);
}

#[test]
fn uncertain_recovery_is_request_scoped_status_only_and_never_resends() {
    for response in [
        b"".as_slice(),
        br#"{"version":1,"error":"stale"}"#,
        br#"{"version":1,"error":"unavailable"}"#,
        br#"{"version":2,"status":{"status":"approved"}}"#,
        br#"{"version":1,"error":"authentication_failed","secret":true}"#,
    ] {
        let mut session = reviewed();
        let work = session
            .begin(Command::Approve, ID.into(), "fresh".into())
            .unwrap();
        session.invalidate(); // close/sleep/config selection cannot erase commit uncertainty
        session.finish(work.token, response);
        assert_eq!(session.snapshot().uncertain_id, ID);
        assert!(session.configure("").is_err());
        for command in [
            Command::Approve,
            Command::Deny,
            Command::Unlock,
            Command::Review,
            Command::Session,
            Command::List,
        ] {
            assert!(session.begin(command, ID.into(), "fresh".into()).is_err());
        }
        assert!(session
            .begin(Command::Status, "B".repeat(43), String::new())
            .is_err());
        reply(
            &mut session,
            Command::Status,
            ID,
            json!({"version":1,"status":{"status":"pending"}}),
        );
        assert_eq!(session.snapshot().uncertain_id, ID);
        reply(
            &mut session,
            Command::Status,
            ID,
            json!({"version":1,"status":{"status":"completed","exit_code":0}}),
        );
        assert!(session.snapshot().uncertain_id.is_empty());
        assert_eq!(session.snapshot().status_id, ID);
        assert!(!session.snapshot().can_decide);
    }
}

#[test]
fn generation_invalidation_and_late_reads_never_restore_review() {
    let mut session = reviewed();
    reply(
        &mut session,
        Command::Session,
        "",
        json!({"version":1,"state":"unlocked","generation":2}),
    );
    assert!(!session.snapshot().can_decide);
    let work = session
        .begin(Command::Review, ID.into(), String::new())
        .unwrap();
    session.invalidate();
    assert!(session.snapshot().busy);
    session.finish(work.token + 1, &serde_json::to_vec(&fixture()).unwrap());
    assert!(session.snapshot().busy);
    session.finish(work.token, &serde_json::to_vec(&fixture()).unwrap());
    assert!(!session.snapshot().busy);
    assert!(session.snapshot().review_text.is_empty());
    session.finish(work.token, &serde_json::to_vec(&fixture()).unwrap());
    assert!(session.snapshot().review_text.is_empty());
}

#[test]
fn same_generation_late_review_cannot_restore_after_sleep_selection_or_close() {
    let mut session = connected();
    let work = session
        .begin(Command::Review, ID.into(), String::new())
        .unwrap();
    session.invalidate();
    session.finish(work.token, &serde_json::to_vec(&fixture()).unwrap());
    assert!(session.snapshot().review_text.is_empty());
    assert!(!session.snapshot().can_decide);
}

#[test]
fn decision_completion_survives_invalidation_but_duplicate_cannot_change_outcome() {
    let mut session = reviewed();
    let work = session
        .begin(Command::Deny, ID.into(), String::new())
        .unwrap();
    session.invalidate();
    session.finish(work.token, br#"{"version":1,"status":{"status":"denied"}}"#);
    let state = session.snapshot();
    assert!(state.uncertain_id.is_empty());
    assert!(state.message.contains("denied"));
    session.finish(
        work.token,
        br#"{"version":1,"status":{"status":"approved"}}"#,
    );
    assert_eq!(session.snapshot().message, state.message);
}

#[test]
fn unlock_is_separate_consumes_review_and_is_not_retried() {
    let mut session = reviewed();
    let work = session
        .begin(Command::Unlock, String::new(), "fresh".into())
        .unwrap();
    assert!(session.snapshot().review_text.is_empty());
    session.finish(work.token, b"");
    assert!(session.snapshot().locked);
    assert!(session.snapshot().uncertain_id.is_empty());
    assert!(session
        .begin(Command::Approve, ID.into(), "fresh".into())
        .is_err());
}

#[test]
fn restored_marker_only_allows_original_status() {
    let mut session = ProviderSession::default();
    session.configure(ID).unwrap();
    assert_eq!(session.snapshot().uncertain_id, ID);
    assert!(session
        .begin(Command::Session, String::new(), String::new())
        .is_err());
    reply(
        &mut session,
        Command::Status,
        ID,
        json!({"version":1,"error":"unavailable"}),
    );
    assert_eq!(session.snapshot().uncertain_id, ID);
}

#[test]
fn failed_authority_replies_retire_cached_authority_and_inbox_with_typed_outcomes() {
    for body in [
        br#"{"version":1,"error":"rate_limited"}"#.as_slice(),
        br#"{"version":1,"error":"unavailable"}"#,
        br#"{"version":1,"error":"unauthorized"}"#,
        br#"{"version":1,"error":"stale"}"#,
        b"malformed",
    ] {
        let mut session = reviewed();
        reply(
            &mut session,
            Command::List,
            "",
            json!({"version":1,"requests":[ID]}),
        );
        let work = session
            .begin(Command::Session, "".into(), "".into())
            .unwrap();
        session.finish(work.token, body);
        let state = session.snapshot();
        assert!(state.locked && state.requests.is_empty() && !state.can_decide);
        assert!(matches!(
            state.outcome,
            ProviderOutcome::Rejected | ProviderOutcome::Invalid
        ));
    }
    let mut session = connected();
    reply(
        &mut session,
        Command::Session,
        "",
        json!({"version":1,"state":"locked","generation":2}),
    );
    assert_eq!(session.snapshot().outcome, ProviderOutcome::Accepted);
    let work = session
        .begin(Command::Session, "".into(), "".into())
        .unwrap();
    session.invalidate();
    session.finish(
        work.token,
        br#"{"version":1,"state":"unlocked","generation":2}"#,
    );
    assert_eq!(session.snapshot().outcome, ProviderOutcome::Stale);
    assert!(session.snapshot().locked);
}

#[test]
fn commitment_is_distinct_from_terminal_status_and_configuration_clears_tracking() {
    let mut session = reviewed();
    let work = session
        .begin(Command::Approve, "".into(), "fresh".into())
        .unwrap();
    session.finish(
        work.token,
        br#"{"version":1,"status":{"status":"approved"}}"#,
    );
    assert_eq!(
        session.snapshot().status_progress,
        ProviderStatusProgress::Committed
    );
    assert!(session.snapshot().uncertain_id.is_empty());
    reply(
        &mut session,
        Command::Status,
        ID,
        json!({"version":1,"status":{"status":"running"}}),
    );
    assert_eq!(
        session.snapshot().status_progress,
        ProviderStatusProgress::Committed
    );
    reply(
        &mut session,
        Command::Status,
        ID,
        json!({"version":1,"status":{"status":"completed","exit_code":0}}),
    );
    assert_eq!(
        session.snapshot().status_progress,
        ProviderStatusProgress::Terminal
    );
    assert_eq!(session.snapshot().status_id, ID);
    session.configure("").unwrap();
    assert_eq!(
        session.snapshot().status_progress,
        ProviderStatusProgress::None
    );
    assert!(session.snapshot().status_id.is_empty());
}
