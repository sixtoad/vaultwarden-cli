//! Guided enrollment (#59 phase 2): the joiner half reproduces the provider
//! crate's frozen vector byte for byte, and both journeys map every closed
//! outcome (mismatch, expiry, revoked identity, forged provider, loss).
use companion_core::api::enrollment::{
    AdminCommand, AdminOutcome, AdminRefusal, AdminSessionState, AdminState, EnrolleeRole,
    EnrollmentAdminRequest, JoinerCommand, JoinerEnd, JoinerPhase,
};
use companion_core::provider::enrollment::JoinerSession;
use companion_core::provider::enrollment_admin::AdminSession;
use serde_json::{json, Value};

const DEVICE: &str = "bb00000000000000000000000000000000000000000000000000000000000002";
const PIN: &str = "aa00000000000000000000000000000000000000000000000000000000000001";
fn vector() -> Value {
    serde_json::from_str(include_str!("../../fixtures/enrollment-v1.json")).unwrap()
}
fn nonce() -> [u8; 32] {
    [5; 32]
}
fn body(work: &[u8]) -> Value {
    serde_json::from_slice(work).unwrap()
}
fn reply(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn joined_session() -> JoinerSession {
    let v = vector();
    let mut s = JoinerSession::default();
    let work = s
        .join(
            v["invitation_code"].as_str().unwrap(),
            v["device_fingerprint"].as_str().unwrap(),
            v["provider_fingerprint"].as_str().unwrap(),
            nonce(),
        )
        .unwrap();
    s.finish(work.token, &reply(&v["joined"]));
    s
}
fn state(value: Value) -> Vec<u8> {
    let v = vector();
    reply(
        &json!({"result":"state","protocol_version":1,"invitation_id":v["join"]["invitation_id"],"state":value}),
    )
}
fn rejected(reason: &str) -> Vec<u8> {
    reply(&json!({"result":"rejected","protocol_version":1,"reason":reason}))
}

#[test]
fn the_joiner_reproduces_the_provider_vector() {
    let v = vector();
    let mut s = JoinerSession::default();
    let work = s
        .join(
            &format!("  {}\n", v["invitation_code"].as_str().unwrap()),
            v["device_fingerprint"].as_str().unwrap(),
            v["provider_fingerprint"].as_str().unwrap(),
            nonce(),
        )
        .unwrap();
    assert_eq!(
        body(&work.body),
        json!({"command":"enroll","version":1,"message":v["join"]})
    );
    assert_eq!(s.snapshot().phase, JoinerPhase::Joining);
    assert!(s.snapshot().comparison_code.is_empty());
    s.finish(work.token, &reply(&v["joined"]));
    let snap = s.snapshot();
    assert_eq!(snap.phase, JoinerPhase::Compare);
    assert_eq!(snap.comparison_code, v["comparison_code"].as_str().unwrap());
    assert_eq!(snap.role, EnrolleeRole::Companion);
    assert_eq!(snap.label, "Studio Mac");
    assert!(snap.seconds_remaining > 590 && snap.seconds_remaining <= 599);
    for (command, key) in [
        (JoinerCommand::Status, "status"),
        (JoinerCommand::Confirm, "confirm"),
    ] {
        let work = s.begin(command, DEVICE, PIN).unwrap();
        assert_eq!(
            body(&work.body),
            json!({"command":"enroll","version":1,"message":v[key]})
        );
        s.finish(work.token, &[]);
    }
    let mut s = joined_session();
    let work = s.begin(JoinerCommand::Cancel, DEVICE, PIN).unwrap();
    assert_eq!(body(&work.body)["message"], v["cancel"]);
    let mut s = joined_session();
    let work = s.begin(JoinerCommand::Decline, DEVICE, PIN).unwrap();
    assert_eq!(body(&work.body)["message"], v["decline"]);
}

#[test]
fn a_provider_without_the_secret_never_gets_a_code_shown() {
    let v = vector();
    let mut forged = v["joined"].clone();
    forged["provider_nonce"] = json!("CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo");
    let mut s = JoinerSession::default();
    let work = s
        .join(
            v["invitation_code"].as_str().unwrap(),
            v["device_fingerprint"].as_str().unwrap(),
            v["provider_fingerprint"].as_str().unwrap(),
            nonce(),
        )
        .unwrap();
    s.finish(work.token, &reply(&forged));
    let snap = s.snapshot();
    assert_eq!(snap.phase, JoinerPhase::Ended);
    assert_eq!(snap.end, JoinerEnd::ProviderNotAuthenticated);
    assert!(snap.comparison_code.is_empty());
    // A different provider pin is a different transcript: same failure.
    let mut s = JoinerSession::default();
    let work = s
        .join(
            v["invitation_code"].as_str().unwrap(),
            v["device_fingerprint"].as_str().unwrap(),
            &"c".repeat(64),
            nonce(),
        )
        .unwrap();
    s.finish(work.token, &reply(&v["joined"]));
    assert_eq!(s.snapshot().end, JoinerEnd::ProviderNotAuthenticated);
}

#[test]
fn mismatch_at_either_end_ends_without_enrolling() {
    let mut s = joined_session();
    let work = s.begin(JoinerCommand::Decline, DEVICE, PIN).unwrap();
    s.finish(
        work.token,
        &state(json!({"state":"aborted","reason":"joiner_reported_mismatch"})),
    );
    let snap = s.snapshot();
    assert_eq!(
        (snap.phase, snap.end),
        (JoinerPhase::Ended, JoinerEnd::Declined)
    );
    assert!(snap.comparison_code.is_empty());
    assert!(s.begin(JoinerCommand::Confirm, DEVICE, PIN).is_err());
    // The owner typed a different code at the provider.
    let mut s = joined_session();
    let work = s.begin(JoinerCommand::Confirm, DEVICE, PIN).unwrap();
    s.finish(
        work.token,
        &state(
            json!({"state":"awaiting_approvals","provider_approved":false,"joiner_confirmed":true}),
        ),
    );
    assert_eq!(s.snapshot().phase, JoinerPhase::Waiting);
    let work = s.begin(JoinerCommand::Confirm, DEVICE, PIN).unwrap();
    s.finish(
        work.token,
        &state(json!({"state":"aborted","reason":"code_mismatch"})),
    );
    assert_eq!(s.snapshot().end, JoinerEnd::CodeMismatch);
}

#[test]
fn expiry_cancellation_and_revoked_identities_are_final() {
    for (answer, end) in [
        (state(json!({"state":"expired"})), JoinerEnd::Expired),
        (
            state(json!({"state":"cancelled","by":"provider"})),
            JoinerEnd::CancelledByProvider,
        ),
        (
            state(json!({"state":"failed","reason":"identity_refused"})),
            JoinerEnd::IdentityRefused,
        ),
        (
            state(json!({"state":"aborted","reason":"duplicate_join"})),
            JoinerEnd::DuplicateJoin,
        ),
        (rejected("expired"), JoinerEnd::Expired),
    ] {
        let mut s = joined_session();
        let work = s.begin(JoinerCommand::Status, DEVICE, PIN).unwrap();
        s.finish(work.token, &answer);
        assert_eq!(
            (s.snapshot().phase, s.snapshot().end),
            (JoinerPhase::Ended, end)
        );
    }
    // A known (enabled or revoked) certificate is refused at join: no code.
    let v = vector();
    for (reason, end) in [
        ("identity_refused", JoinerEnd::IdentityRefused),
        ("expired", JoinerEnd::Expired),
        ("invalid_invitation", JoinerEnd::InvalidInvitation),
        ("already_used", JoinerEnd::AlreadyUsed),
    ] {
        let mut s = JoinerSession::default();
        let work = s
            .join(
                v["invitation_code"].as_str().unwrap(),
                v["device_fingerprint"].as_str().unwrap(),
                v["provider_fingerprint"].as_str().unwrap(),
                nonce(),
            )
            .unwrap();
        s.finish(work.token, &rejected(reason));
        let snap = s.snapshot();
        assert_eq!((snap.phase, snap.end), (JoinerPhase::Ended, end));
        assert!(snap.comparison_code.is_empty());
    }
}

#[test]
fn lost_replies_are_retried_identically_or_reported_unknown() {
    let v = vector();
    let mut s = JoinerSession::default();
    let first = s
        .join(
            v["invitation_code"].as_str().unwrap(),
            v["device_fingerprint"].as_str().unwrap(),
            v["provider_fingerprint"].as_str().unwrap(),
            nonce(),
        )
        .unwrap();
    let sent = first.body.clone();
    s.finish(first.token, &[]);
    assert!(s.snapshot().retryable);
    assert_eq!(s.snapshot().phase, JoinerPhase::Joining);
    let retry = s.begin(JoinerCommand::Retry, DEVICE, PIN).unwrap();
    assert_eq!(retry.body, sent);
    s.finish(retry.token, &rejected("busy"));
    assert!(s.snapshot().retryable);
    // A stale token is ignored; only one exchange at a time.
    let retry = s.begin(JoinerCommand::Retry, DEVICE, PIN).unwrap();
    assert!(s.begin(JoinerCommand::Retry, DEVICE, PIN).is_err());
    s.finish(retry.token + 1, &reply(&v["joined"]));
    assert_eq!(s.snapshot().phase, JoinerPhase::Joining);
    s.finish(retry.token, &reply(&v["joined"]));
    assert_eq!(s.snapshot().phase, JoinerPhase::Compare);
    // A confirmation whose reply was lost may have committed.
    let work = s.begin(JoinerCommand::Confirm, DEVICE, PIN).unwrap();
    s.finish(work.token, &[]);
    assert_eq!(s.snapshot().phase, JoinerPhase::Waiting);
    let work = s.begin(JoinerCommand::Confirm, DEVICE, PIN).unwrap();
    s.finish(work.token, &rejected("invalid_invitation"));
    assert_eq!(s.snapshot().end, JoinerEnd::OutcomeUnknown);
    // Enrolled: the fingerprint is this device's.
    let mut s = joined_session();
    let work = s.begin(JoinerCommand::Confirm, DEVICE, PIN).unwrap();
    s.finish(
        work.token,
        &state(json!({"state":"enrolled","identity":{"role":"companion","fingerprint":v["device_fingerprint"]}})),
    );
    let snap = s.snapshot();
    assert_eq!(snap.phase, JoinerPhase::Enrolled);
    assert_eq!(
        snap.enrolled_fingerprint,
        v["device_fingerprint"].as_str().unwrap()
    );
    assert!(snap.comparison_code.is_empty());
}

#[test]
fn malformed_invitations_and_identities_are_refused_locally() {
    let v = vector();
    let pin = v["provider_fingerprint"].as_str().unwrap();
    let device = v["device_fingerprint"].as_str().unwrap();
    let code = v["invitation_code"].as_str().unwrap();
    let mut s = JoinerSession::default();
    for (invitation, device, pin) in [
        ("vwe2.abc.def", device, pin),
        (&code.replacen("vwe1", "vwe2", 1)[..], device, pin),
        (&format!("{code}.extra")[..], device, pin),
        (code, "B".repeat(64).as_str(), pin),
        (code, device, ""),
    ] {
        assert!(s.join(invitation, device, pin, nonce()).is_err());
        assert_eq!(s.snapshot().phase, JoinerPhase::Idle);
    }
}

fn admin(command: AdminCommand) -> EnrollmentAdminRequest {
    EnrollmentAdminRequest {
        command,
        role: EnrolleeRole::Companion,
        label: String::new(),
        agent_uid: 0,
        agent_gid: 0,
        id: String::new(),
        code: String::new(),
        password: String::new(),
    }
}
const ID: &str = "TVVbY2lxd3-FjZOboamvt73Fy9PZ4efv9f0DCxEZHyc";

#[test]
fn the_owner_invites_and_sees_the_invitation_once() {
    let v = vector();
    let mut s = AdminSession::default();
    let mut request = admin(AdminCommand::Invite);
    request.label = "Studio Mac".into();
    let work = s.begin(request).unwrap();
    assert_eq!(
        body(&work.body),
        json!({"version":1,"command":"enroll_invite","kind":{"role":"companion","label":"Studio Mac"}})
    );
    s.finish(
        work.token,
        &reply(&json!({"version":1,"invitation":{"id":ID,"invitation_code":v["invitation_code"],"kind":{"role":"companion","label":"Studio Mac"},"expires_in_seconds":600}})),
    );
    let snap = s.snapshot();
    assert_eq!(snap.outcome, AdminOutcome::Invited);
    assert_eq!(snap.issued.unwrap().label, "Studio Mac");
    // The secret is read separately, never part of a snapshot.
    assert_eq!(s.invitation_code(), v["invitation_code"].as_str().unwrap());
    s.dismiss_invitation();
    assert!(s.snapshot().issued.is_none());
    assert!(s.invitation_code().is_empty());
    let mut agent = admin(AdminCommand::Invite);
    agent.role = EnrolleeRole::Agent;
    agent.label = "ci runner".into();
    agent.agent_uid = 42001;
    agent.agent_gid = 42003;
    let work = s.begin(agent.clone()).unwrap();
    assert_eq!(
        body(&work.body)["kind"],
        json!({"role":"agent","label":"ci runner","uid":42001,"gid":42003})
    );
    s.finish(work.token, &[]);
    for bad in [
        EnrollmentAdminRequest {
            label: " padded".into(),
            ..agent.clone()
        },
        EnrollmentAdminRequest {
            agent_uid: 0,
            ..agent.clone()
        },
        EnrollmentAdminRequest {
            label: "naïve".into(),
            ..agent.clone()
        },
        EnrollmentAdminRequest {
            label: String::new(),
            role: EnrolleeRole::Companion,
            ..agent
        },
    ] {
        assert!(s.begin(bad).is_err());
    }
}

#[test]
fn the_owner_types_the_code_and_never_receives_one() {
    let mut s = AdminSession::default();
    let work = s.begin(admin(AdminCommand::List)).unwrap();
    assert_eq!(
        body(&work.body),
        json!({"version":1,"command":"enroll_list"})
    );
    s.finish(
        work.token,
        &reply(&json!({"version":1,"enrollments":[{"id":ID,"kind":{"role":"companion","label":"Studio Mac"},"state":{"state":"awaiting_approvals","provider_approved":false,"joiner_confirmed":true},"expires_in_seconds":420,"joiner_fingerprint":"c".repeat(64)}]})),
    );
    let snap = s.snapshot();
    assert_eq!(snap.state, AdminState::Ready);
    assert_eq!(snap.sessions.len(), 1);
    assert_eq!(snap.sessions[0].state, AdminSessionState::AwaitingApprovals);
    assert!(snap.sessions[0].joiner_confirmed && !snap.sessions[0].provider_approved);
    let mut approve = admin(AdminCommand::Approve);
    approve.id = ID.into();
    approve.password = "synthetic-password".into();
    for wrong in ["", "1234-567", "1234-56789", "abcd-efgh"] {
        approve.code = wrong.into();
        assert!(s.begin(approve.clone()).is_err());
    }
    approve.code = "1234 5678".into();
    let work = s.begin(approve.clone()).unwrap();
    assert_eq!(
        body(&work.body),
        json!({"version":1,"command":"enroll_approve","id":ID,"code":"1234-5678","password":"synthetic-password"})
    );
    s.finish(
        work.token,
        &reply(&json!({"version":1,"error":"enrollment_refused","reason":"code_mismatch"})),
    );
    let snap = s.snapshot();
    assert_eq!(
        (snap.outcome, snap.refusal),
        (AdminOutcome::Refused, AdminRefusal::CodeMismatch)
    );
    let work = s.begin(approve).unwrap();
    s.finish(
        work.token,
        &reply(&json!({"version":1,"error":"authentication_failed"})),
    );
    assert_eq!(s.snapshot().outcome, AdminOutcome::AuthenticationFailed);
    // A provider answering with a comparison code is a protocol violation.
    let work = s.begin(admin(AdminCommand::List)).unwrap();
    s.finish(
        work.token,
        &reply(&json!({"version":1,"enrollments":[{"id":ID,"kind":{"role":"companion","label":"x"},"state":{"state":"awaiting_join"},"expires_in_seconds":1,"comparison_code":"1234-5678"}]})),
    );
    assert_eq!(s.snapshot().outcome, AdminOutcome::Invalid);
    assert!(s.snapshot().sessions.is_empty());
}

#[test]
fn authority_and_support_are_reported_for_the_manual_fallback() {
    for (answer, expected) in [
        (
            json!({"version":1,"error":"unauthorized"}),
            AdminState::Unauthorized,
        ),
        (
            json!({"version":1,"error":"invalid_request"}),
            AdminState::Unsupported,
        ),
        (
            json!({"version":1,"error":"unavailable"}),
            AdminState::Unavailable,
        ),
    ] {
        let mut s = AdminSession::default();
        let work = s.begin(admin(AdminCommand::List)).unwrap();
        s.finish(work.token, &reply(&answer));
        assert_eq!(s.snapshot().state, expected);
    }
    let mut s = AdminSession::default();
    let mut cancel = admin(AdminCommand::Cancel);
    cancel.id = ID.into();
    let work = s.begin(cancel).unwrap();
    assert_eq!(
        body(&work.body),
        json!({"version":1,"command":"enroll_cancel","id":ID})
    );
    s.finish(
        work.token,
        &reply(&json!({"version":1,"enrollment":{"id":ID,"kind":{"role":"companion","label":"Studio Mac"},"state":{"state":"cancelled","by":"provider"},"expires_in_seconds":0}})),
    );
    let snap = s.snapshot();
    assert_eq!(snap.outcome, AdminOutcome::Cancelled);
    assert_eq!(snap.sessions[0].state, AdminSessionState::Cancelled);
    s.invalidate();
    assert!(s.snapshot().sessions.is_empty());
}

#[test]
fn a_withdrawal_is_resent_until_acknowledged_and_never_becomes_a_confirm() {
    let v = vector();
    let mut s = joined_session();
    let work = s.begin(JoinerCommand::Decline, DEVICE, PIN).unwrap();
    s.finish(work.token, &[]);
    let snap = s.snapshot();
    assert!(snap.withdrawing && snap.retryable);
    // The background poll asks for a confirm or a status: the decline goes.
    for command in [JoinerCommand::Confirm, JoinerCommand::Status] {
        let work = s.begin(command, DEVICE, PIN).unwrap();
        assert_eq!(body(&work.body)["message"], v["decline"]);
        s.finish(work.token, &rejected("busy"));
    }
    // The session was forgotten meanwhile: still nothing this human enrolled.
    let work = s.begin(JoinerCommand::Status, DEVICE, PIN).unwrap();
    s.finish(work.token, &rejected("invalid_invitation"));
    assert_eq!(s.snapshot().end, JoinerEnd::Declined);
}

#[test]
fn provider_claims_never_replace_this_humans_consent_or_the_handshake() {
    // "Confirmed" by the provider while this human has not confirmed.
    let mut s = joined_session();
    let work = s.begin(JoinerCommand::Status, DEVICE, PIN).unwrap();
    s.finish(
        work.token,
        &state(
            json!({"state":"awaiting_approvals","provider_approved":true,"joiner_confirmed":true}),
        ),
    );
    assert_eq!(s.snapshot().end, JoinerEnd::Malformed);
    // "Enrolled" as the answer to the join, before the provider's proof.
    let v = vector();
    let mut s = JoinerSession::default();
    let work = s
        .join(v["invitation_code"].as_str().unwrap(), DEVICE, PIN, nonce())
        .unwrap();
    s.finish(
        work.token,
        &state(json!({"state":"enrolled","identity":{"role":"companion","fingerprint":DEVICE}})),
    );
    assert_eq!(s.snapshot().end, JoinerEnd::Malformed);
    // Another provider or certificate configured mid-session ends it.
    let mut s = joined_session();
    assert!(s
        .begin(JoinerCommand::Confirm, DEVICE, &"c".repeat(64))
        .is_err());
    assert_eq!(s.snapshot().end, JoinerEnd::ProviderChanged);
    assert!(s.snapshot().comparison_code.is_empty());
}

#[test]
fn owner_replies_must_match_the_request() {
    let v = vector();
    let row = |id: &str, state: Value| json!({"version":1,"enrollment":{"id":id,"kind":{"role":"companion","label":"Studio Mac"},"state":state,"expires_in_seconds":0}});
    let mut approve = admin(AdminCommand::Approve);
    approve.id = ID.into();
    approve.code = "12345678".into();
    approve.password = "synthetic-password".into();
    let other = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    for answer in [
        // Another enrollment's row.
        row(
            other,
            json!({"state":"awaiting_approvals","provider_approved":true,"joiner_confirmed":false}),
        ),
        // A 200 that did not approve anything.
        row(ID, json!({"state":"aborted","reason":"code_mismatch"})),
    ] {
        let mut s = AdminSession::default();
        let work = s.begin(approve.clone()).unwrap();
        s.finish(work.token, &reply(&answer));
        assert_eq!(s.snapshot().outcome, AdminOutcome::Invalid);
    }
    // An invitation for another kind than requested is not shown.
    let mut s = AdminSession::default();
    let mut request = admin(AdminCommand::Invite);
    request.label = "Studio Mac".into();
    let work = s.begin(request).unwrap();
    s.finish(
        work.token,
        &reply(&json!({"version":1,"invitation":{"id":ID,"invitation_code":v["invitation_code"],"kind":{"role":"companion","label":"Other Mac"},"expires_in_seconds":600}})),
    );
    assert_eq!(s.snapshot().outcome, AdminOutcome::Invalid);
    assert!(s.snapshot().issued.is_none() && s.invitation_code().is_empty());
    // No extra member can ride along on a list.
    let work = s.begin(admin(AdminCommand::List)).unwrap();
    s.finish(
        work.token,
        &reply(&json!({"version":1,"enrollments":[],"comparison_code":"1234-5678"})),
    );
    assert_eq!(s.snapshot().outcome, AdminOutcome::Invalid);
}

#[test]
fn a_confirmation_in_doubt_is_never_reported_as_nothing_enrolled() {
    // Confirm reply lost, then a cancel; the provider forgot the session.
    let mut s = joined_session();
    let work = s.begin(JoinerCommand::Confirm, DEVICE, PIN).unwrap();
    s.finish(work.token, &[]);
    let work = s.begin(JoinerCommand::Cancel, DEVICE, PIN).unwrap();
    s.finish(work.token, &rejected("invalid_invitation"));
    assert_eq!(s.snapshot().end, JoinerEnd::OutcomeUnknown);
    // "Enrolled" for a human who never confirmed is not believed.
    let mut s = joined_session();
    let work = s.begin(JoinerCommand::Status, DEVICE, PIN).unwrap();
    s.finish(
        work.token,
        &state(json!({"state":"enrolled","identity":{"role":"companion","fingerprint":DEVICE}})),
    );
    assert_eq!(s.snapshot().end, JoinerEnd::Malformed);
    // A provider change after confirming keeps `confirmed` for the message.
    let mut s = joined_session();
    let work = s.begin(JoinerCommand::Confirm, DEVICE, PIN).unwrap();
    s.finish(work.token, &[]);
    assert!(s
        .begin(JoinerCommand::Status, DEVICE, &"c".repeat(64))
        .is_err());
    let snap = s.snapshot();
    assert_eq!(snap.end, JoinerEnd::ProviderChanged);
    assert!(snap.confirmed);
}
