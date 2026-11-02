//! Production Touch ID approval v2 bridge (issue 49 PR B): golden vector,
//! refusals, decision/management wire shapes and outcome mapping.
use companion_core::api::biometric::{
    BiometricDecisionResult as Biometric, BiometricKeyCommand as KeyCommand,
    BiometricKeyOutcome as KeyOutcome, BiometricKeyState as KeyState, BiometricRefusal as Refusal,
    BiometricSupport,
};
use companion_core::api::provider::{ProviderCommand as Command, ProviderStatusProgress};
use companion_core::provider::approval_v2::{self as v2, ApprovalBinding, Pin, ReceivedReview};
use companion_core::provider::{
    biometric::BiometricKeySession, protocol::Review, session::ProviderSession,
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};

const ID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OTHER_ID: &str = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const TICKET: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn golden() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/approval-v2-golden.json"
    ))
    .unwrap()
}
fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

#[test]
fn golden_vector_review_digest_transcripts_and_signatures_reproduce_exactly() {
    let g = golden();
    let a = &g["approval"];
    let raw = &a["review"];
    assert_eq!(
        v2::canonical_json(raw).unwrap(),
        text(&a["review_canonical_json"])
    );
    assert_eq!(
        v2::hex(&v2::review_digest(raw).unwrap()),
        text(&a["review_digest"])
    );

    let review: Review = serde_json::from_value(raw.clone()).unwrap();
    let binding: ApprovalBinding = serde_json::from_value(json!({
        "version": 2,
        "domain": v2::APPROVAL_DOMAIN,
        "action": "approve",
        "provider_identity": a["provider_identity"],
        "approval_client": a["approval_client"],
        "key_id": a["key_id"],
        "biometric_allowed": true,
        "request_id": a["request_id"],
        "record_digest": a["record_digest"],
        "policy_digest": a["policy_digest"],
        "arguments_digest": a["arguments_digest"],
        "expires_at_unix_seconds": a["expires_at_unix_seconds"],
        "generation": a["generation"],
        "ticket": a["ticket"],
        "ticket_deadline_unix_ms": a["ticket_deadline_unix_ms"],
        "review_digest": a["review_digest"],
    }))
    .unwrap();
    let pin = Pin::new(text(&a["provider_identity"]), text(&a["approval_client"])).unwrap();
    let signing = v2::approval_transcript(
        &ReceivedReview {
            raw_review: raw,
            review: &review,
            ticket: Some(text(&a["ticket"])),
            generation: a["generation"].as_u64().unwrap(),
            binding: Some(&binding),
        },
        Some(&pin),
    )
    .unwrap();
    assert_eq!(v2::hex(&signing.transcript), text(&a["transcript_hex"]));
    assert_eq!(signing.key_id, text(&a["key_id"]));

    let public_key = v2::base64url_decode(text(&g["public_key"])).unwrap();
    assert_eq!(v2::key_id(&public_key), text(&a["key_id"]));
    assert!(v2::valid_public_key(&public_key));
    let approval_signature = v2::base64url_decode(text(&a["signature"])).unwrap();
    assert!(v2::verify(
        &public_key,
        &signing.transcript,
        &approval_signature
    ));

    let e = &g["enroll"];
    let enroll = v2::enroll_transcript(
        text(&a["provider_identity"]),
        text(&a["approval_client"]),
        &public_key,
        text(&e["ticket"]),
        text(&e["action_id"]),
    )
    .unwrap();
    assert_eq!(v2::hex(&enroll), text(&e["transcript_hex"]));
    let enroll_signature = v2::base64url_decode(text(&e["signature"])).unwrap();
    assert!(v2::verify(&public_key, &enroll, &enroll_signature));
    // Domain separation: neither signature verifies over the other transcript.
    assert!(!v2::verify(&public_key, &enroll, &approval_signature));
    assert!(!v2::verify(
        &public_key,
        &signing.transcript,
        &enroll_signature
    ));
}

#[test]
fn canonical_json_follows_the_documented_escaping_and_ordering_rules() {
    let value = json!({"b": "\u{1}\u{1f}\n\t\"\\/\u{7f}\u{85}\u{202e}é", "a": [1, -2, true, null], "B": {}});
    assert_eq!(
        v2::canonical_json(&value).unwrap(),
        "{\"B\":{},\"a\":[1,-2,true,null],\"b\":\"\\u0001\\u001f\\n\\t\\\"\\\\/\u{7f}\u{85}\u{202e}é\"}"
    );
    assert!(
        v2::canonical_json(&json!({"a": 1.5})).is_none(),
        "floats fail closed"
    );
}

#[test]
fn base64url_is_unpadded_canonical_and_round_trips() {
    let g = golden();
    for value in [text(&g["public_key"]), text(&g["approval"]["signature"])] {
        assert_eq!(v2::base64url(&v2::base64url_decode(value).unwrap()), value);
    }
    assert_eq!(v2::base64url(b""), "");
    assert_eq!(v2::base64url(b"f"), "Zg");
    assert_eq!(v2::base64url(b"fo"), "Zm8");
    assert_eq!(v2::base64url(&[0xfb, 0xff]), "-_8");
    for bad in ["Zg==", "Zh", "+_8", "/w", "Z", "Zm9v\n"] {
        assert!(v2::base64url_decode(bad).is_none(), "{bad}");
    }
}

// ---- session helpers -------------------------------------------------------

const PROVIDER: &str = "1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f";
const CLIENT: &str = "2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e";
const RECORD: &str = "3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d";

fn key() -> SigningKey {
    SigningKey::from_slice(&[7; 32]).unwrap()
}
fn pk_of(key: &SigningKey) -> Vec<u8> {
    key.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}
fn sign(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let signature: Signature = key.sign(message);
    signature.to_der().as_bytes().to_vec()
}
fn review_v1() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/companion/review.json"
    ))
    .unwrap()
}
/// A consistent v2 Review response for `ID` (future expiry, generation 1).
fn review_v2() -> Value {
    let mut value = review_v1();
    value["version"] = 2.into();
    let review = value["review"].clone();
    value["approval_binding"] = json!({
        "version": 2,
        "domain": v2::APPROVAL_DOMAIN,
        "action": "approve",
        "provider_identity": PROVIDER,
        "approval_client": CLIENT,
        "key_id": v2::key_id(&pk_of(&key())),
        "biometric_allowed": true,
        "request_id": ID,
        "record_digest": RECORD,
        "policy_digest": review["policy_digest"],
        "arguments_digest": review["arguments_digest"],
        "expires_at_unix_seconds": review["expires_at_unix_seconds"],
        "generation": 1,
        "ticket": TICKET,
        // The provider's wall clock, long past by the companion's: never enforced.
        "ticket_deadline_unix_ms": 1,
        "review_digest": v2::hex(&v2::review_digest(&review).unwrap()),
    });
    value
}
fn send(session: &mut ProviderSession, command: Command, id: &str, password: &str) -> Value {
    let work = session.begin(command, id.into(), password.into()).unwrap();
    let body: Value = serde_json::from_slice(&work.body).unwrap();
    json!({"token": work.token, "body": body})
}
fn exchange(session: &mut ProviderSession, command: Command, id: &str, reply: &[u8]) -> Value {
    let sent = send(session, command, id, "");
    session.finish(sent["token"].as_u64().unwrap() as u32, reply);
    sent["body"].clone()
}
fn connected(pinned: bool) -> ProviderSession {
    let mut session = ProviderSession::default();
    session.configure("").unwrap();
    if pinned {
        session.pin(PROVIDER, CLIENT).unwrap();
    }
    exchange(
        &mut session,
        Command::Session,
        "",
        br#"{"version":1,"state":"unlocked","generation":1}"#,
    );
    session
}
fn reviewed_with(value: &Value) -> ProviderSession {
    let mut session = connected(true);
    let body = exchange(
        &mut session,
        Command::Review,
        ID,
        &serde_json::to_vec(value).unwrap(),
    );
    assert_eq!(
        body,
        json!({"version":2,"command":"review","request_id":ID})
    );
    session
}
fn refusal_with(mutate: impl FnOnce(&mut Value)) -> Refusal {
    let mut value = review_v2();
    mutate(&mut value);
    let mut session = reviewed_with(&value);
    assert!(
        session.snapshot().can_decide,
        "password approval stays available"
    );
    let refusal = session.prepare_biometric().unwrap_err();
    assert_eq!(session.biometric_state().refusal, Some(refusal));
    assert!(!session.biometric_state().can_prepare);
    refusal
}

type Mutation = Box<dyn FnOnce(&mut Value)>;

// ---- approval -------------------------------------------------------------

#[test]
fn pinned_session_requests_v2_and_prepares_the_exact_signed_transcript() {
    let mut unpinned = connected(false);
    let body = exchange(
        &mut unpinned,
        Command::Review,
        ID,
        &serde_json::to_vec(&review_v1()).unwrap(),
    );
    assert_eq!(
        body["version"], 1,
        "unpinned sessions keep version 1 reviews"
    );
    assert_eq!(
        unpinned.prepare_biometric().unwrap_err(),
        Refusal::BindingUnavailable
    );

    let mut session = reviewed_with(&review_v2());
    let state = session.biometric_state();
    assert_eq!(state.support, BiometricSupport::Requested);
    assert!(state.binding_available && state.biometric_allowed && state.can_prepare);
    assert_eq!(state.key_id, v2::key_id(&pk_of(&key())));
    let request = session.prepare_biometric().unwrap();
    assert_eq!(request.request_id, ID);
    assert_eq!(request.key_id, state.key_id);
    // Independently framed expectation of the 14 fields.
    let review = review_v2()["review"].clone();
    let mut expected = Vec::new();
    for field in [
        v2::APPROVAL_DOMAIN.as_bytes().to_vec(),
        b"approve".to_vec(),
        unhex(PROVIDER),
        unhex(CLIENT),
        unhex(&request.key_id),
        ID.as_bytes().to_vec(),
        unhex(RECORD),
        unhex(&"b".repeat(64)),
        unhex(&"c".repeat(64)),
        2_000_000_000u64.to_be_bytes().to_vec(),
        1u64.to_be_bytes().to_vec(),
        unhex(TICKET),
        1u64.to_be_bytes().to_vec(),
        v2::review_digest(&review).unwrap().to_vec(),
    ] {
        expected.extend_from_slice(&(field.len() as u32).to_be_bytes());
        expected.extend_from_slice(&field);
    }
    assert_eq!(request.transcript, expected);
    // Preparing does not consume the review: password approval remains.
    assert!(session.snapshot().can_decide);
}

#[test]
fn digest_is_computed_over_the_received_review_json_not_a_reserialization() {
    // Reordered members and insignificant whitespace, as another serializer
    // might send them: the canonical digest is unchanged.
    let value = review_v2();
    let review = &value["review"];
    let mut members: Vec<(String, Value)> = review
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    members.reverse();
    let review_text = format!(
        "{{ {} }}",
        members
            .iter()
            .map(|(k, v)| format!("{} : {}", json!(k), v))
            .collect::<Vec<_>>()
            .join(" ,\n ")
    );
    let text = format!(
        r#"{{"version":2,"review":{review_text},"ticket":{},"generation":1,"approval_binding":{}}}"#,
        json!(TICKET),
        value["approval_binding"]
    );
    let mut session = connected(true);
    exchange(&mut session, Command::Review, ID, text.as_bytes());
    assert!(session.prepare_biometric().is_ok());
}

#[test]
fn every_binding_inconsistency_refuses_to_produce_a_signing_transcript() {
    let b = "approval_binding";
    let cases: Vec<(Refusal, Mutation)> = vec![
        (
            Refusal::ReviewDigestMismatch,
            Box::new(move |v| v[b]["review_digest"] = "e".repeat(64).into()),
        ),
        (
            Refusal::ReviewDigestMismatch,
            Box::new(move |v| {
                // The provider hashed a different review than the one shown.
                v["review"]["effect"] = "Deploy something else".into();
            }),
        ),
        (
            Refusal::BiometricNotAllowed,
            Box::new(move |v| v[b]["biometric_allowed"] = false.into()),
        ),
        (
            Refusal::BindingUnavailable,
            Box::new(move |v| v[b] = Value::Null),
        ),
        (
            Refusal::ProviderMismatch,
            Box::new(move |v| v[b]["provider_identity"] = "f".repeat(64).into()),
        ),
        (
            Refusal::ApprovalClientMismatch,
            Box::new(move |v| v[b]["approval_client"] = "f".repeat(64).into()),
        ),
        (
            Refusal::RequestMismatch,
            Box::new(move |v| v[b]["request_id"] = OTHER_ID.into()),
        ),
        (
            Refusal::GenerationMismatch,
            Box::new(move |v| v[b]["generation"] = 2.into()),
        ),
        (
            Refusal::TicketMismatch,
            Box::new(move |v| v[b]["ticket"] = "e".repeat(64).into()),
        ),
        (
            Refusal::ReviewMismatch,
            Box::new(move |v| v[b]["expires_at_unix_seconds"] = 2_000_000_001u64.into()),
        ),
        (
            Refusal::ReviewMismatch,
            Box::new(move |v| v[b]["policy_digest"] = "e".repeat(64).into()),
        ),
        (
            Refusal::NoEnrolledKey,
            Box::new(move |v| v[b]["key_id"] = Value::Null),
        ),
        (
            Refusal::MalformedBinding,
            Box::new(move |v| v[b]["domain"] = "dev.vaultwarden.companion.synthetic.v1".into()),
        ),
        (
            Refusal::MalformedBinding,
            Box::new(move |v| v[b]["record_digest"] = "E".repeat(64).into()),
        ),
    ];
    for (expected, mutate) in cases {
        assert_eq!(refusal_with(mutate), expected);
    }
}

#[test]
fn unpinned_or_repinned_sessions_never_sign_against_another_provider() {
    let mut session = reviewed_with(&review_v2());
    session.configure("").unwrap();
    assert_eq!(
        session.prepare_biometric().unwrap_err(),
        Refusal::NoDecidableReview
    );
    assert!(session.pin("x", CLIENT).is_err());
    let mut session = reviewed_with(&review_v2());
    session.pin(&"f".repeat(64), CLIENT).unwrap();
    // Pin change retires the review; a review under the new pin mismatches.
    assert_eq!(
        session.prepare_biometric().unwrap_err(),
        Refusal::NoDecidableReview
    );
    exchange(
        &mut session,
        Command::Review,
        ID,
        &serde_json::to_vec(&review_v2()).unwrap(),
    );
    assert_eq!(
        session.prepare_biometric().unwrap_err(),
        Refusal::ProviderMismatch
    );
}

#[test]
fn v2_review_schema_is_closed() {
    for mutate in [
        Box::new(|v: &mut Value| v["approval_binding"]["extra"] = 1.into())
            as Box<dyn Fn(&mut Value)>,
        Box::new(|v: &mut Value| {
            v.as_object_mut().unwrap().remove("approval_binding");
        }),
        Box::new(|v: &mut Value| {
            v["approval_binding"]
                .as_object_mut()
                .unwrap()
                .remove("key_id");
        }),
        Box::new(|v: &mut Value| v["version"] = 1.into()),
        Box::new(|v: &mut Value| v["approval_binding"]["ticket_deadline_unix_ms"] = 1.5.into()),
    ] {
        let mut value = review_v2();
        mutate(&mut value);
        let mut session = connected(true);
        exchange(
            &mut session,
            Command::Review,
            ID,
            &serde_json::to_vec(&value).unwrap(),
        );
        assert!(!session.snapshot().can_decide);
        assert!(session.snapshot().review.is_none());
    }
}

#[test]
fn older_provider_refusing_v2_review_falls_back_to_password_approval() {
    let mut session = connected(true);
    exchange(
        &mut session,
        Command::Review,
        ID,
        br#"{"version":1,"error":"invalid_request"}"#,
    );
    assert_eq!(
        session.biometric_state().support,
        BiometricSupport::Unsupported
    );
    exchange(
        &mut session,
        Command::Session,
        "",
        br#"{"version":1,"state":"unlocked","generation":1}"#,
    );
    let body = exchange(
        &mut session,
        Command::Review,
        ID,
        &serde_json::to_vec(&review_v1()).unwrap(),
    );
    assert_eq!(body["version"], 1);
    assert!(session.snapshot().can_decide);
    assert_eq!(
        session.prepare_biometric().unwrap_err(),
        Refusal::BindingUnavailable
    );
    let sent = send(&mut session, Command::Approve, "", "fresh");
    assert_eq!(
        sent["body"],
        json!({"version":1,"command":"decision","request_id":ID,"ticket":TICKET,"decision":"approve","password":"fresh"})
    );
}

#[test]
fn password_and_deny_after_a_v2_review_keep_their_wire_shapes() {
    let mut session = reviewed_with(&review_v2());
    let sent = send(&mut session, Command::Approve, "", "fresh");
    assert_eq!(
        sent["body"],
        json!({"version":1,"command":"decision","request_id":ID,"ticket":TICKET,"decision":"approve","password":"fresh"})
    );
    let mut session = reviewed_with(&review_v2());
    let sent = send(&mut session, Command::Deny, "", "");
    assert_eq!(
        sent["body"],
        json!({"version":1,"command":"decision","request_id":ID,"ticket":TICKET,"decision":"deny"})
    );
}

fn proof_sent() -> (ProviderSession, u32, Value) {
    let mut session = reviewed_with(&review_v2());
    let request = session.prepare_biometric().unwrap();
    let signature = sign(&key(), &request.transcript);
    let work = session
        .begin_biometric(request.handle, &request.key_id, &signature)
        .unwrap();
    let body: Value = serde_json::from_slice(&work.body).unwrap();
    assert_eq!(
        body,
        json!({"version":2,"command":"decision","request_id":ID,"ticket":TICKET,"decision":"approve",
               "proof":{"key_id":request.key_id,"signature":v2::base64url(&signature)}})
    );
    assert!(body.get("password").is_none());
    assert!(v2::verify(&pk_of(&key()), &request.transcript, &signature));
    assert_eq!(session.biometric_state().result, Biometric::InFlight);
    assert_eq!(session.snapshot().uncertain_id, ID);
    (session, work.token, body)
}

#[test]
fn biometric_decision_sends_exactly_one_proof_and_maps_approval() {
    let (mut session, token, _) = proof_sent();
    session.finish(token, br#"{"version":2,"status":{"status":"approved"}}"#);
    let state = session.snapshot();
    assert_eq!(state.uncertain_id, "");
    assert_eq!(state.status_progress, ProviderStatusProgress::Committed);
    assert_eq!(session.biometric_state().result, Biometric::Approved);
    // Single shot: the review was consumed.
    assert_eq!(
        session.prepare_biometric().unwrap_err(),
        Refusal::NoDecidableReview
    );
}

#[test]
fn biometric_error_results_match_password_path_recovery() {
    for (error, result, uncertain) in [
        ("authentication_failed", Biometric::PasswordRequired, false),
        ("rate_limited", Biometric::RateLimited, false),
        ("invalid_request", Biometric::Rejected, false),
        ("stale", Biometric::Stale, true),
        ("unavailable", Biometric::OutcomeUnknown, true),
    ] {
        let (mut session, token, _) = proof_sent();
        session.finish(
            token,
            json!({"version":1,"error":error}).to_string().as_bytes(),
        );
        assert_eq!(session.biometric_state().result, result, "{error}");
        assert_eq!(
            session.snapshot().uncertain_id.is_empty(),
            !uncertain,
            "{error}"
        );
        // The same reply to a password approval leaves the same recovery state.
        let mut password = reviewed_with(&review_v2());
        let sent = send(&mut password, Command::Approve, "", "fresh");
        password.finish(
            sent["token"].as_u64().unwrap() as u32,
            json!({"version":1,"error":error}).to_string().as_bytes(),
        );
        assert_eq!(
            password.snapshot().uncertain_id,
            session.snapshot().uncertain_id,
            "{error}"
        );
        assert_eq!(
            password.snapshot().message,
            session.snapshot().message,
            "{error}"
        );
    }
}

#[test]
fn lost_biometric_response_uses_status_only_recovery_and_never_resends() {
    for reply in [&b""[..], br#"{"version":1,"status":{"status":"approved"}}"#] {
        let (mut session, token, _) = proof_sent();
        session.finish(token, reply);
        assert_eq!(session.biometric_state().result, Biometric::OutcomeUnknown);
        assert_eq!(session.snapshot().uncertain_id, ID);
        assert!(session
            .begin(Command::Approve, ID.into(), "fresh".into())
            .is_err());
        assert!(session
            .begin(Command::Review, ID.into(), String::new())
            .is_err());
        assert_eq!(
            session.prepare_biometric().unwrap_err(),
            Refusal::OutcomeUncertain
        );
        let status = exchange(
            &mut session,
            Command::Status,
            ID,
            br#"{"version":1,"status":{"status":"pending"}}"#,
        );
        assert_eq!(
            status,
            json!({"version":1,"command":"status","request_id":ID})
        );
        assert_eq!(
            session.snapshot().uncertain_id,
            ID,
            "pending stays uncertain"
        );
        exchange(
            &mut session,
            Command::Status,
            ID,
            br#"{"version":1,"status":{"status":"running"}}"#,
        );
        assert_eq!(session.snapshot().uncertain_id, "");
        assert_eq!(session.biometric_state().result, Biometric::Approved);
    }
}

#[test]
fn submit_rechecks_handle_key_and_signature_before_sending() {
    let mut session = reviewed_with(&review_v2());
    let request = session.prepare_biometric().unwrap();
    let good = sign(&key(), &request.transcript);
    assert_eq!(
        session
            .begin_biometric(request.handle + 1, &request.key_id, &good)
            .err()
            .unwrap(),
        Refusal::StaleHandle
    );
    assert_eq!(
        session
            .begin_biometric(request.handle, &"f".repeat(64), &good)
            .err()
            .unwrap(),
        Refusal::KeyMismatch
    );
    for bad in [
        vec![0x30; 7],
        vec![0x30; 73],
        vec![0; 70],
        [good.clone(), vec![0]].concat(),
    ] {
        assert_eq!(
            session
                .begin_biometric(request.handle, &request.key_id, &bad)
                .err()
                .unwrap(),
            Refusal::InvalidSignature
        );
    }
    assert!(
        session.snapshot().can_decide,
        "local refusals send nothing and keep the review"
    );
    // A new review retires the handle.
    exchange(
        &mut session,
        Command::Review,
        ID,
        &serde_json::to_vec(&review_v2()).unwrap(),
    );
    assert_eq!(
        session
            .begin_biometric(request.handle, &request.key_id, &good)
            .err()
            .unwrap(),
        Refusal::StaleHandle
    );
    let handle = session.prepare_biometric().unwrap().handle;
    assert!(session
        .begin_biometric(handle, &request.key_id, &good)
        .is_ok());
}

// ---- key management -------------------------------------------------------

fn keys() -> BiometricKeySession {
    let mut s = BiometricKeySession::default();
    s.configure(PROVIDER, CLIENT).unwrap();
    s
}
fn key_exchange(s: &mut BiometricKeySession, command: KeyCommand, reply: Value) -> Value {
    let work = s.begin(command).unwrap();
    s.finish(work.token, &serde_json::to_vec(&reply).unwrap());
    serde_json::from_slice(&work.body).unwrap()
}
fn row(key_id: Value) -> Value {
    json!({"version":3,"identity":{"kind":"approval_client","id":CLIENT,"label":"This Mac","fingerprint":CLIENT,
        "roles":["approve"],"trust":"enabled","this_client":true,"biometric_key_id":key_id},"generation":4})
}
fn prepared(operation: &str, ticket: &str, action_id: &str) -> Value {
    json!({"version":2,"operation":operation,"target":{"kind":"approval_client","id":CLIENT},"action_id":action_id,
        "ticket":ticket,"generation":4,"valid_for_seconds":55,"provider_identity":PROVIDER,"biometric_key_id":null})
}

#[test]
fn identity_detail_v3_reports_this_devices_current_key_id() {
    let mut s = keys();
    let body = key_exchange(&mut s, KeyCommand::Read, row(json!("a".repeat(64))));
    assert_eq!(
        body,
        json!({"version":3,"command":"identity_detail","target":{"kind":"approval_client","id":CLIENT}})
    );
    assert_eq!(
        (s.snapshot().state, s.snapshot().key_id),
        (KeyState::Enrolled, "a".repeat(64))
    );
    key_exchange(&mut s, KeyCommand::Read, row(Value::Null));
    assert_eq!(s.snapshot().state, KeyState::NotEnrolled);
    let mut missing = row(Value::Null);
    missing["identity"]
        .as_object_mut()
        .unwrap()
        .remove("biometric_key_id");
    let mut foreign_device = row(Value::Null);
    foreign_device["identity"]["this_client"] = false.into();
    let mut v2_detail = row(Value::Null);
    v2_detail["version"] = 2.into();
    for bad in [
        row(json!("A".repeat(64))),
        missing,
        foreign_device,
        v2_detail,
    ] {
        key_exchange(&mut s, KeyCommand::Read, bad);
        assert_eq!(s.snapshot().outcome, KeyOutcome::Invalid);
    }
    let mut other = row(Value::Null);
    other["identity"]["id"] = "f".repeat(64).into();
    other["identity"]["fingerprint"] = "f".repeat(64).into();
    key_exchange(&mut s, KeyCommand::Read, other);
    assert_eq!(s.snapshot().outcome, KeyOutcome::Invalid);
    key_exchange(
        &mut s,
        KeyCommand::Read,
        json!({"version":1,"error":"invalid_request"}),
    );
    assert_eq!(
        (s.snapshot().state, s.snapshot().outcome),
        (KeyState::Unsupported, KeyOutcome::Unsupported)
    );
}

#[test]
fn enrollment_reproduces_the_golden_proof_transcript_and_sends_the_closed_command() {
    let g = golden();
    let (e, pk_text) = (&g["enroll"], text(&g["public_key"]));
    let public_key = v2::base64url_decode(pk_text).unwrap();
    let mut s = keys();
    let body = key_exchange(
        &mut s,
        KeyCommand::PrepareEnroll,
        prepared("enroll", text(&e["ticket"]), text(&e["action_id"])),
    );
    assert_eq!(
        body,
        json!({"version":2,"command":"biometric_prepare","operation":"enroll","target":{"kind":"approval_client","id":CLIENT}})
    );
    assert!(s.snapshot().can_enroll && !s.snapshot().can_revoke);
    let request = s.enroll_transcript(&public_key).unwrap();
    assert_eq!(v2::hex(&request.transcript), text(&e["transcript_hex"]));
    assert_eq!(request.key_id, text(&g["approval"]["key_id"]));
    let signature = v2::base64url_decode(text(&e["signature"])).unwrap();
    let approval_signature = v2::base64url_decode(text(&g["approval"]["signature"])).unwrap();
    assert_eq!(
        s.begin_enroll("fresh".into(), &public_key, &approval_signature)
            .err()
            .unwrap(),
        Refusal::InvalidSignature
    );
    assert_eq!(
        s.begin_enroll("fresh".into(), &pk_of(&key()), &signature)
            .err()
            .unwrap(),
        Refusal::KeyMismatch
    );
    assert_eq!(
        s.begin_enroll(String::new(), &public_key, &signature)
            .err()
            .unwrap(),
        Refusal::InvalidPassword
    );
    let work = s
        .begin_enroll("fresh".into(), &public_key, &signature)
        .unwrap();
    let body: Value = serde_json::from_slice(&work.body).unwrap();
    assert_eq!(
        body,
        json!({"version":2,"command":"biometric_enroll","action_id":e["action_id"],"ticket":e["ticket"],
               "password":"fresh","public_key":pk_text,"enroll_signature":e["signature"]})
    );
    assert!(!s.snapshot().can_enroll, "single use");
    s.finish(work.token, &serde_json::to_vec(&json!({"version":2,"operation":"enroll",
        "target":{"kind":"approval_client","id":CLIENT},"action_id":e["action_id"],"biometric_key_id":request.key_id})).unwrap());
    assert_eq!(
        (s.snapshot().outcome, s.snapshot().state),
        (KeyOutcome::Enrolled, KeyState::Enrolled)
    );
    assert_eq!(s.snapshot().key_id, request.key_id);
}

#[test]
fn enrollment_refuses_bad_keys_foreign_provider_and_unknown_outcomes() {
    let action = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk";
    let mut s = keys();
    assert_eq!(
        s.enroll_transcript(&pk_of(&key())).unwrap_err(),
        Refusal::NoPreparedOperation
    );
    let mut foreign = prepared("enroll", TICKET, action);
    foreign["provider_identity"] = "f".repeat(64).into();
    key_exchange(&mut s, KeyCommand::PrepareEnroll, foreign);
    assert!(!s.snapshot().can_enroll);
    key_exchange(
        &mut s,
        KeyCommand::PrepareEnroll,
        prepared("revoke", TICKET, action),
    );
    assert!(!s.snapshot().can_enroll, "operation must match");
    key_exchange(
        &mut s,
        KeyCommand::PrepareEnroll,
        prepared("enroll", TICKET, action),
    );
    let mut compressed = pk_of(&key());
    compressed.truncate(33);
    compressed[0] = 0x02;
    let mut off_curve = pk_of(&key());
    off_curve[64] ^= 1;
    for bad in [compressed, off_curve, vec![0x04; 65]] {
        assert_eq!(
            s.enroll_transcript(&bad).unwrap_err(),
            Refusal::InvalidPublicKey
        );
    }
    let request = s.enroll_transcript(&pk_of(&key())).unwrap();
    let work = s
        .begin_enroll(
            "fresh".into(),
            &pk_of(&key()),
            &sign(&key(), &request.transcript),
        )
        .unwrap();
    s.finish(work.token, b"");
    assert_eq!(
        (s.snapshot().outcome, s.snapshot().state),
        (KeyOutcome::Unknown, KeyState::Unknown)
    );
    // Recovery is a fresh read; nothing is resent.
    assert_eq!(
        s.begin_enroll("fresh".into(), &pk_of(&key()), &[0x30; 8])
            .err()
            .unwrap(),
        Refusal::NoPreparedOperation
    );
    key_exchange(&mut s, KeyCommand::Read, row(json!(request.key_id)));
    assert_eq!(s.snapshot().state, KeyState::Enrolled);
}

#[test]
fn revocation_sends_the_closed_command_and_maps_password_rejection() {
    let action = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk";
    let mut s = keys();
    assert_eq!(
        s.begin_revoke("fresh".into()).err().unwrap(),
        Refusal::NoPreparedOperation
    );
    let body = key_exchange(
        &mut s,
        KeyCommand::PrepareRevoke,
        prepared("revoke", TICKET, action),
    );
    assert_eq!(body["operation"], "revoke");
    assert!(s.snapshot().can_revoke);
    let work = s.begin_revoke("fresh".into()).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&work.body).unwrap(),
        json!({"version":2,"command":"biometric_revoke","target":{"kind":"approval_client","id":CLIENT},
               "action_id":action,"ticket":TICKET,"password":"fresh"})
    );
    s.finish(
        work.token,
        br#"{"version":1,"error":"authentication_failed"}"#,
    );
    assert_eq!(s.snapshot().outcome, KeyOutcome::PasswordRejected);
    key_exchange(
        &mut s,
        KeyCommand::PrepareRevoke,
        prepared("revoke", TICKET, action),
    );
    let work = s.begin_revoke("fresh".into()).unwrap();
    s.finish(work.token, &serde_json::to_vec(&json!({"version":2,"operation":"revoke",
        "target":{"kind":"approval_client","id":CLIENT},"action_id":action,"revoked_key_id":"a".repeat(64)})).unwrap());
    assert_eq!(
        (s.snapshot().outcome, s.snapshot().state),
        (KeyOutcome::Revoked, KeyState::NotEnrolled)
    );
    key_exchange(
        &mut s,
        KeyCommand::PrepareRevoke,
        json!({"version":1,"error":"invalid_request"}),
    );
    assert_eq!(s.snapshot().state, KeyState::Unsupported);
}
