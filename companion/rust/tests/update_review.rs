//! Issue 48 phase 2: the companion admits, shows and decides update reviews,
//! and asserts the `update-review.v1` capability when it approves one.
use companion_core::api::provider::{ProviderCommand as Command, ProviderOutcome};
use companion_core::provider::approval_v2 as v2;
use companion_core::provider::{protocol::*, session::ProviderSession};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};

const ID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const TICKET: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const PROVIDER: &str = "1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f";
const CLIENT: &str = "2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e";
const RECORD: &str = "3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d";

fn update_block() -> Value {
    json!({
        "server": "https://vault.example",
        "item_id": "33333333-3333-3333-3333-333333333333",
        "destination": {
            "account_id": "11111111-1111-1111-1111-111111111111",
            "folder": "homelab/production",
            "folder_id": "22222222-2222-2222-2222-222222222222",
            "reference": "homelab/production/github/token"
        },
        "fields": ["password", "custom:api-key"],
        "expected_revision": "2026-11-21T10:00:00.000000Z"
    })
}
/// A version 1 review response carrying an update block.
fn update_review() -> Value {
    let mut value: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/companion/review.json"
    ))
    .unwrap();
    value["review"]["update"] = update_block();
    value["review"]["effect"] = json!("UPDATE personal vault item (no create)");
    value["review"]["target"] = json!("homelab/production/github/token");
    value
}
fn key() -> SigningKey {
    SigningKey::from_slice(&[7; 32]).unwrap()
}
fn pk() -> Vec<u8> {
    key()
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}
fn update_review_v2() -> Value {
    let mut value = update_review();
    value["version"] = 2.into();
    let review = value["review"].clone();
    value["approval_binding"] = json!({
        "version": 2, "domain": v2::APPROVAL_DOMAIN, "action": "approve",
        "provider_identity": PROVIDER, "approval_client": CLIENT,
        "key_id": v2::key_id(&pk()), "biometric_allowed": true, "request_id": ID,
        "record_digest": RECORD, "policy_digest": review["policy_digest"],
        "arguments_digest": review["arguments_digest"],
        "expires_at_unix_seconds": review["expires_at_unix_seconds"],
        "generation": 1, "ticket": TICKET, "ticket_deadline_unix_ms": 1,
        "review_digest": v2::hex(&v2::review_digest(&review).unwrap()),
    });
    value
}
fn exchange(
    session: &mut ProviderSession,
    command: Command,
    password: &str,
    reply: &Value,
) -> Value {
    let work = session.begin(command, ID.into(), password.into()).unwrap();
    session.finish(work.token, &serde_json::to_vec(reply).unwrap());
    serde_json::from_slice(&work.body).unwrap()
}
fn connected(pinned: bool) -> ProviderSession {
    let mut session = ProviderSession::default();
    session.configure("").unwrap();
    if pinned {
        session.pin(PROVIDER, CLIENT).unwrap();
    }
    let work = session
        .begin(Command::Session, String::new(), String::new())
        .unwrap();
    session.finish(
        work.token,
        br#"{"version":1,"state":"unlocked","generation":1}"#,
    );
    session
}
fn reviewed(value: &Value, pinned: bool) -> ProviderSession {
    let mut session = connected(pinned);
    exchange(&mut session, Command::Review, "", value);
    session
}

#[test]
fn update_block_is_admitted_escaped_and_shown_in_text_and_typed_review() {
    let mut value = update_review();
    value["review"]["update"]["destination"]["reference"] = json!("homelab/production/\u{202e}x");
    let mut session = reviewed(&value, false);
    let state = session.snapshot();
    assert!(state.can_decide, "{}", state.message);
    let update = state.review.unwrap().update.unwrap();
    assert_eq!(update.item_id, "\"33333333-3333-3333-3333-333333333333\"");
    assert_eq!(update.server, "\"https://vault.example\"");
    assert_eq!(
        update.account_id,
        "\"11111111-1111-1111-1111-111111111111\""
    );
    assert_eq!(update.folder, "\"homelab/production\"");
    assert_eq!(update.folder_id, "\"22222222-2222-2222-2222-222222222222\"");
    assert_eq!(update.reference, "\"homelab/production/\\u{202e}x\"");
    assert_eq!(update.fields, ["\"password\"", "\"custom:api-key\""]);
    assert_eq!(update.expected_revision, "\"2026-11-21T10:00:00.000000Z\"");
    for fragment in [
        "Vault update (existing item; no create):",
        "  Item: \"33333333-3333-3333-3333-333333333333\"",
        "  Fields replaced (2):",
        "    \"custom:api-key\"",
        "  Expected revision: \"2026-11-21T10:00:00.000000Z\"",
        "  Reference: \"homelab/production/\\u{202e}x\"",
    ] {
        assert!(state.review_text.contains(fragment), "missing {fragment}");
    }
    assert!(!state.review_text.contains('\u{202e}'));
    // Every other review keeps no update block.
    let plain: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/companion/review.json"
    ))
    .unwrap();
    let mut session = reviewed(&plain, false);
    let state = session.snapshot();
    assert!(state.review.unwrap().update.is_none());
    assert!(!state.review_text.contains("Vault update"));
}

type Mutation = Box<dyn Fn(&mut Value)>;

#[test]
fn malformed_update_blocks_never_create_a_review() {
    let mutations: Vec<Mutation> = vec![
        Box::new(|u| u["unknown"] = json!(1)),
        Box::new(|u| u["destination"]["extra"] = json!("x")),
        Box::new(|u| {
            u.as_object_mut().unwrap().remove("expected_revision");
        }),
        Box::new(|u| u["fields"] = json!([])),
        Box::new(|u| u["fields"] = json!([""])),
        Box::new(|u| {
            u["fields"] = json!((0..35).map(|i| format!("custom:f{i}")).collect::<Vec<_>>())
        }),
        Box::new(|u| u["expected_revision"] = json!("")),
        Box::new(|u| u["server"] = json!("x".repeat(513))),
        Box::new(|u| u["item_id"] = json!(7)),
        Box::new(|u| *u = json!("update")),
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut value = update_review();
        mutate(&mut value["review"]["update"]);
        let mut session = reviewed(&value, false);
        let state = session.snapshot();
        assert_eq!(state.outcome, ProviderOutcome::Invalid, "{index}");
        assert!(
            state.review.is_none() && state.review_text.is_empty(),
            "{index}"
        );
        assert!(!state.can_decide, "{index}");
    }
    // At the limits the block is admitted.
    let mut value = update_review();
    value["review"]["update"]["fields"] =
        json!((0..34).map(|i| format!("custom:f{i}")).collect::<Vec<_>>());
    value["review"]["update"]["server"] = json!("x".repeat(512));
    assert!(reviewed(&value, false).snapshot().can_decide);
}

#[test]
fn approving_an_update_asserts_the_capability_in_a_version_two_decision() {
    let mut session = reviewed(&update_review(), false);
    let work = session
        .begin(Command::Approve, ID.into(), "fresh".into())
        .unwrap();
    let body: Value = serde_json::from_slice(&work.body).unwrap();
    assert_eq!(
        body,
        json!({"version":2,"command":"decision","request_id":ID,"ticket":TICKET,
               "decision":"approve","password":"fresh","capabilities":[UPDATE_REVIEW_CAPABILITY]})
    );
    assert_eq!(UPDATE_REVIEW_CAPABILITY, "update-review.v1");
    // The provider answers a version 2 decision with a version 2 status.
    session.finish(
        work.token,
        br#"{"version":2,"status":{"status":"approved"}}"#,
    );
    let state = session.snapshot();
    assert_eq!(
        state.outcome,
        ProviderOutcome::Accepted,
        "{}",
        state.message
    );
    assert!(state.uncertain_id.is_empty());
    // A denial asserts nothing and keeps version 1.
    let mut session = reviewed(&update_review(), false);
    let body = exchange(
        &mut session,
        Command::Deny,
        "",
        &json!({"version":1,"status":{"status":"denied"}}),
    );
    assert_eq!(body["version"], 1);
    assert!(body.get("capabilities").is_none());
    // Every other review keeps the version 1 password decision unchanged.
    let plain: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/companion/review.json"
    ))
    .unwrap();
    let mut session = reviewed(&plain, false);
    let work = session
        .begin(Command::Approve, ID.into(), "fresh".into())
        .unwrap();
    let body: Value = serde_json::from_slice(&work.body).unwrap();
    assert_eq!(body["version"], 1);
    assert!(body.get("capabilities").is_none());
}

#[test]
fn touch_id_signs_the_digest_over_the_update_block_and_asserts_the_capability() {
    let value = update_review_v2();
    let mut session = reviewed(&value, true);
    let request = session.prepare_biometric().unwrap();
    // Field 14 is the digest of the review as received, update block included.
    let digest = v2::review_digest(&value["review"]).unwrap();
    assert!(request.transcript.ends_with(&digest));
    let mut without = value["review"].clone();
    without.as_object_mut().unwrap().remove("update");
    assert_ne!(digest, v2::review_digest(&without).unwrap());
    let signature: Signature = key().sign(&request.transcript);
    let signature = signature.to_der().as_bytes().to_vec();
    let work = session
        .begin_biometric(request.handle, &pk(), &signature)
        .unwrap();
    let body: Value = serde_json::from_slice(&work.body).unwrap();
    assert_eq!(body["capabilities"], json!([UPDATE_REVIEW_CAPABILITY]));
    assert_eq!(body["version"], 2);
    assert!(body.get("password").is_none());
}

/// Windows Hello (desktop-approval-spec D-8) approves an update with the same
/// v2 decision as Touch ID: the capability rides beside the wrapped proof.
#[test]
fn windows_hello_proof_of_an_update_asserts_the_capability() {
    use companion_core::provider::key_class;
    let value = update_review_v2();
    let mut session = reviewed(&value, true);
    let request = session.prepare_biometric().unwrap();
    let mut data = key_class::rp_id_hash().to_vec();
    data.push(0x05);
    data.extend_from_slice(&[0; 4]);
    let message = key_class::signed_message(&request.transcript, &data).unwrap();
    let signature: Signature = key().sign(&message);
    let signature = signature.to_der().as_bytes().to_vec();
    let work = session
        .begin_biometric_wrapped(request.handle, &pk(), &signature, &data)
        .unwrap();
    let body: Value = serde_json::from_slice(&work.body).unwrap();
    assert_eq!(body["capabilities"], json!([UPDATE_REVIEW_CAPABILITY]));
    assert_eq!(body["version"], 2);
    assert_eq!(
        body["proof"]["authenticator_data"],
        json!(v2::base64url(&data))
    );
    assert!(body.get("password").is_none());
}
