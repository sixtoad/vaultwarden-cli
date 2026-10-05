use super::protocol::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;

fn fixture() -> SignedSubmission {
    SignedSubmission::sign(
        URL_SAFE_NO_PAD.encode([0x11u8; 32]),
        [0x22u8; 32],
        "deploy".into(),
        "ab".repeat(32),
        vec!["a".into(), "bc".into(), "é".into()],
        &SigningKey::from_bytes(&[7u8; 32]),
    )
    .unwrap()
}
fn public_key() -> String {
    super::encode_public_key(&SigningKey::from_bytes(&[7u8; 32]).verifying_key())
}

#[test]
fn canonical_vector() {
    let envelope = fixture();
    let hex: String = envelope
        .signing_bytes()
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    // Independently generated with Python cryptography Ed25519, seed [7; 32].
    assert_eq!(
        hex,
        "7661756c7477617264656e2d616363657373000101000000067375626d6974000000201111111111111111111111111111111111111111111111111111111111111111000000202222222222222222222222222222222222222222222222222222222222222222000000066465706c6f7900000020abababababababababababababababababababababababababababababababab00000003000000016100000002626300000002c3a9"
    );
    assert_eq!(
        envelope.signature,
        "6_negF7FLGMNQh5ELLOeLoK7dEm2I7J7V90tt2rYzXYhkYKJEIX5rdVgrtse0P-2Psx_P7hgNASBbH53q_kQBQ"
    );
    assert_eq!(
        envelope.replay_digest().unwrap(),
        "75e42aa7d8637d3c73fd58d6eb02d170589be7b6f3e89bd57306b6c1b6df6705"
    );
    envelope.verify(&public_key()).unwrap();
}

#[test]
fn every_signed_semantic_field_is_bound() {
    let baseline = fixture();
    type Mutation = Box<dyn Fn(&mut SignedSubmission)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|e| e.protocol_version = 2),
        Box::new(|e| e.purpose = "poll".into()),
        Box::new(|e| e.binding_id = URL_SAFE_NO_PAD.encode([0x12u8; 32])),
        Box::new(|e| e.nonce = URL_SAFE_NO_PAD.encode([0x23u8; 32])),
        Box::new(|e| e.operation_id = "other".into()),
        Box::new(|e| e.expected_policy_revision = "ac".repeat(32)),
        Box::new(|e| e.args.swap(0, 1)),
        Box::new(|e| e.args = vec!["ab".into(), "c".into(), "é".into()]),
        Box::new(|e| e.args.push(String::new())),
        Box::new(|e| e.args[2] = "e\u{301}".into()),
    ];
    for mutate in mutations {
        let mut envelope = baseline.clone();
        mutate(&mut envelope);
        assert!(envelope.verify(&public_key()).is_err());
    }
}

#[test]
fn json_order_and_escaping_do_not_change_semantics() {
    let baseline = fixture();
    let json = format!(
        r#"{{"signature":"{}","args":["\u0061","bc","\u00e9"],"expected_policy_revision":"{}","operation_id":"deploy","nonce":"{}","binding_id":"{}","purpose":"submit","protocol_version":1}}"#,
        baseline.signature, baseline.expected_policy_revision, baseline.nonce, baseline.binding_id
    );
    let parsed = SignedSubmission::parse(json.as_bytes()).unwrap();
    assert!(parsed == baseline);
    assert_eq!(
        parsed.signing_bytes().unwrap(),
        baseline.signing_bytes().unwrap()
    );
    parsed.verify(&public_key()).unwrap();
}

#[test]
fn closed_envelope_rejects_ambiguous_missing_and_noncanonical_input() {
    let baseline = fixture();
    let json = serde_json::to_string(&baseline).unwrap();
    for invalid in [
        format!("{json}{{}}"),
        json.replacen('{', "{\"purpose\":\"submit\",", 1),
        json.replacen('{', "{\"public_key\":\"attacker\",", 1),
        json.replace("\"protocol_version\":1", "\"protocol_version\":null"),
        json.replace("\"protocol_version\":1", "\"protocol_version\":\"1\""),
        json.replace("\"purpose\":\"submit\",", ""),
        json.replace(&baseline.nonce, &(baseline.nonce.clone() + "=")),
        json.replace(&baseline.binding_id, &URL_SAFE_NO_PAD.encode([1u8; 31])),
        json.replace(&baseline.signature, &URL_SAFE_NO_PAD.encode([1u8; 63])),
        json.replace(&baseline.expected_policy_revision, &"AB".repeat(32)),
    ] {
        assert!(matches!(
            SignedSubmission::parse(invalid.as_bytes()),
            Err(AgentRejection::Malformed)
        ));
    }
    assert!(matches!(
        SignedSubmission::parse(
            json.replace("\"protocol_version\":1", "\"protocol_version\":2")
                .as_bytes()
        ),
        Err(AgentRejection::UnsupportedVersion)
    ));
    assert!(SignedSubmission::parse(&[0xff]).is_err());
    assert!(SignedSubmission::parse(&vec![b' '; MAX_REQUEST_FRAME_BYTES + 1]).is_err());
    let fields = [
        "protocol_version",
        "purpose",
        "binding_id",
        "nonce",
        "operation_id",
        "expected_policy_revision",
        "args",
        "signature",
    ];
    for field in fields {
        let mut value = serde_json::to_value(&baseline).unwrap();
        value.as_object_mut().unwrap().remove(field);
        assert!(SignedSubmission::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut value = serde_json::to_value(&baseline).unwrap();
        value[field] = serde_json::Value::Null;
        assert!(SignedSubmission::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        let duplicate = format!(
            "{{\"{field}\":{},{}",
            serde_json::to_value(&baseline).unwrap()[field],
            &json[1..]
        );
        assert!(SignedSubmission::parse(duplicate.as_bytes()).is_err());
    }
}

#[test]
fn stored_key_and_strict_signature_validation_fail_closed() {
    let baseline = fixture();
    let wrong_key = super::encode_public_key(&SigningKey::from_bytes(&[8u8; 32]).verifying_key());
    let mut identity = [0u8; 32];
    identity[0] = 1;
    for key in [
        wrong_key,
        URL_SAFE_NO_PAD.encode(identity),
        URL_SAFE_NO_PAD.encode([0u8; 32]),
        public_key() + "=",
        "bad".into(),
    ] {
        assert_eq!(baseline.verify(&key), Err(AgentRejection::Unauthorized));
    }
    let mut bad = baseline.clone();
    let mut sig = URL_SAFE_NO_PAD.decode(&bad.signature).unwrap();
    sig[0] ^= 1;
    bad.signature = URL_SAFE_NO_PAD.encode(&sig);
    assert_eq!(bad.verify(&public_key()), Err(AgentRejection::Unauthorized));
    // Noncanonical S cannot be accepted as an equivalent scalar modulo the group order.
    let mut sig = URL_SAFE_NO_PAD.decode(&baseline.signature).unwrap();
    sig[32..].fill(0xff);
    bad.signature = URL_SAFE_NO_PAD.encode(sig);
    assert_eq!(bad.verify(&public_key()), Err(AgentRejection::Unauthorized));
    let mut sig = [0u8; 64];
    sig[0] = 1; // Small-order R, zero S.
    bad.signature = URL_SAFE_NO_PAD.encode(sig);
    assert_eq!(bad.verify(&public_key()), Err(AgentRejection::Unauthorized));
}

#[test]
fn replay_digest_is_binding_scoped_and_independent_of_request_fields() {
    let baseline = fixture();
    let mut changed = baseline.clone();
    changed.operation_id = "other".into();
    changed.args.clear();
    changed.expected_policy_revision = "cd".repeat(32);
    assert_eq!(
        baseline.replay_digest().unwrap(),
        changed.replay_digest().unwrap()
    );
    changed.binding_id = URL_SAFE_NO_PAD.encode([0x33u8; 32]);
    assert_ne!(
        baseline.replay_digest().unwrap(),
        changed.replay_digest().unwrap()
    );
    changed = baseline.clone();
    changed.nonce = URL_SAFE_NO_PAD.encode([0x33u8; 32]);
    assert_ne!(
        baseline.replay_digest().unwrap(),
        changed.replay_digest().unwrap()
    );
}

#[test]
fn response_is_closed_and_contains_only_acknowledgment_or_category() {
    let response = AgentResponse::pending(URL_SAFE_NO_PAD.encode([9u8; 32]));
    let json = serde_json::to_vec(&response).unwrap();
    assert!(json.len() < MAX_RESPONSE_FRAME_BYTES);
    assert_eq!(AgentResponse::parse(&json).unwrap(), response);
    assert_eq!(
        serde_json::to_value(response)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        3
    );
    let response = AgentResponse::rejected(AgentRejection::Unauthorized);
    assert_eq!(
        serde_json::to_string(&response).unwrap(),
        r#"{"status":"rejected","protocol_version":1,"category":"unauthorized"}"#
    );
    for invalid in [
        r#"{"status":"approved","protocol_version":1}"#,
        r#"{"status":"rejected","protocol_version":1,"category":"secret-value"}"#,
        r#"{"status":"rejected","protocol_version":1,"category":"busy","url":"secret"}"#,
        r#"{"status":"rejected","protocol_version":2,"category":"busy"}"#,
        r#"{"status":"pending","protocol_version":1,"request_id":"secret-value"}"#,
    ] {
        assert!(AgentResponse::parse(invalid.as_bytes()).is_err());
    }
}

#[test]
fn signed_strict_verification_rejects_an_ordinary_valid_small_order_r_witness() {
    use ed25519_dalek::{Signature, Verifier};
    let mut envelope = fixture();
    // Independently derived from the synthetic seed: identity R, r = 0,
    // S = H(R || A || M) * clamped SHA512(seed) mod L. Ordinary verification
    // accepts the equation, so this witness specifically requires verify_strict.
    envelope.signature =
        "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB6yxX3XlX3wxo3e_RIAJeJdD9hMF_uwq_fvqK19sfrCA"
            .into();
    let bytes = envelope.signing_bytes().unwrap();
    assert_eq!(
        super::hex_sha256(&bytes),
        "fd976be56279e5b93cbe7293bba5cf34abe17dbd6cfbb37c746f56bbaa09279c"
    );
    let signature =
        Signature::from_slice(&URL_SAFE_NO_PAD.decode(&envelope.signature).unwrap()).unwrap();
    let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
    key.verify(&bytes, &signature).unwrap();
    assert_eq!(
        envelope.verify(&public_key()),
        Err(AgentRejection::Unauthorized)
    );
}
