//! Golden vector and cross-domain checks for the production approval contract.
//! Software P-256 keys only; no Secure Enclave or biometric prompt is involved.
use super::*;
use crate::access::{
    approval_v2::{self as v2, ApprovalContext},
    direct_request::{ApprovalBinding, DirectReview},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};

const GOLDEN: &str = include_str!("../../tests/fixtures/approval-v2-golden.json");

pub(crate) fn software_key() -> EcdsaKeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap()
}
pub(crate) fn sign(key: &EcdsaKeyPair, message: &[u8]) -> Vec<u8> {
    key.sign(&SystemRandom::new(), message)
        .unwrap()
        .as_ref()
        .to_vec()
}

struct Golden {
    json: serde_json::Value,
    review: DirectReview,
    binding: ApprovalBinding,
}
fn golden() -> Golden {
    let json: serde_json::Value = serde_json::from_str(GOLDEN).unwrap();
    let a = &json["approval"];
    let review: DirectReview = serde_json::from_value(a["review"].clone()).unwrap();
    let binding = ApprovalBinding {
        request_id: a["request_id"].as_str().unwrap().into(),
        requester_uid: 501,
        agent_owner: None,
        policy_digest: a["policy_digest"].as_str().unwrap().into(),
        arguments_digest: a["arguments_digest"].as_str().unwrap().into(),
        expires_at_unix_seconds: a["expires_at_unix_seconds"].as_u64().unwrap(),
        lifecycle_epoch: 0,
        record_digest: a["record_digest"].as_str().unwrap().into(),
    };
    Golden {
        json,
        review,
        binding,
    }
}
fn s<'a>(json: &'a serde_json::Value, key: &str) -> &'a str {
    json[key].as_str().unwrap()
}
fn transcript(g: &Golden) -> Vec<u8> {
    let a = &g.json["approval"];
    v2::approval_transcript(
        &ApprovalContext {
            provider_identity: s(a, "provider_identity"),
            approval_client: s(a, "approval_client"),
            ticket: s(a, "ticket"),
            ticket_deadline_unix_ms: a["ticket_deadline_unix_ms"].as_u64().unwrap(),
            review: &g.review,
        },
        &g.binding,
        a["generation"].as_u64().unwrap(),
        s(a, "key_id"),
    )
    .unwrap()
}

#[test]
fn biometric_golden_vector_transcript_digest_and_signature() {
    let g = golden();
    let a = &g.json["approval"];
    let public_key = URL_SAFE_NO_PAD.decode(s(&g.json, "public_key")).unwrap();
    assert_eq!(v2::key_id(&public_key), s(a, "key_id"));
    assert_eq!(
        v2::hex(&v2::review_digest(&g.review).unwrap()),
        s(a, "review_digest")
    );
    // The companion hashes the received JSON value; both paths must agree.
    assert_eq!(
        v2::hex(&v2::review_digest_value(&a["review"]).unwrap()),
        s(a, "review_digest")
    );
    {
        use sha2::{Digest, Sha256};
        assert_eq!(
            v2::hex(&Sha256::digest(s(a, "review_canonical_json").as_bytes())),
            s(a, "review_digest")
        );
    }
    let bytes = transcript(&g);
    assert_eq!(v2::hex(&bytes), s(a, "transcript_hex"));
    let signature = URL_SAFE_NO_PAD.decode(s(a, "signature")).unwrap();
    assert_eq!(
        RingBiometricVerifier.verify(&public_key, &bytes, &signature),
        Ok(())
    );
    let mut changed = bytes.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(
        RingBiometricVerifier
            .verify(&public_key, &changed, &signature)
            .is_err()
    );

    let e = &g.json["enroll"];
    let enroll = v2::enroll_transcript(
        s(a, "provider_identity"),
        s(a, "approval_client"),
        &public_key,
        s(e, "ticket"),
        s(e, "action_id"),
    )
    .unwrap();
    assert_eq!(v2::hex(&enroll), s(e, "transcript_hex"));
    let enroll_signature = URL_SAFE_NO_PAD.decode(s(e, "signature")).unwrap();
    assert_eq!(
        RingBiometricVerifier.verify(&public_key, &enroll, &enroll_signature),
        Ok(())
    );
    // Domain separation: neither signature authorizes the other action.
    assert!(
        RingBiometricVerifier
            .verify(&public_key, &bytes, &enroll_signature)
            .is_err()
    );
    assert!(
        RingBiometricVerifier
            .verify(&public_key, &enroll, &signature)
            .is_err()
    );
}

#[test]
fn biometric_transcript_binds_every_provider_field() {
    let g = golden();
    let original = transcript(&g);
    let hex = |c: char| c.to_string().repeat(64);
    let mut changed = Vec::new();
    for field in [
        "record_digest",
        "policy_digest",
        "arguments_digest",
        "expires",
    ] {
        let mut b = g.binding.clone();
        match field {
            "record_digest" => b.record_digest = hex('1'),
            "policy_digest" => b.policy_digest = hex('2'),
            "arguments_digest" => b.arguments_digest = hex('3'),
            _ => b.expires_at_unix_seconds += 1,
        }
        let a = &g.json["approval"];
        changed.push(
            v2::approval_transcript(
                &ApprovalContext {
                    provider_identity: s(a, "provider_identity"),
                    approval_client: s(a, "approval_client"),
                    ticket: s(a, "ticket"),
                    ticket_deadline_unix_ms: a["ticket_deadline_unix_ms"].as_u64().unwrap(),
                    review: &g.review,
                },
                &b,
                a["generation"].as_u64().unwrap(),
                s(a, "key_id"),
            )
            .unwrap(),
        );
    }
    let a = &g.json["approval"];
    let mut review = g.review.clone();
    review.effect.push_str(" changed");
    for (provider, client, ticket, ms, review, generation, key) in [
        (
            hex('4'),
            s(a, "approval_client").to_owned(),
            s(a, "ticket").to_owned(),
            0,
            &g.review,
            7,
            s(a, "key_id").to_owned(),
        ),
        (
            s(a, "provider_identity").to_owned(),
            hex('5'),
            s(a, "ticket").to_owned(),
            0,
            &g.review,
            7,
            s(a, "key_id").to_owned(),
        ),
        (
            s(a, "provider_identity").to_owned(),
            s(a, "approval_client").to_owned(),
            hex('6'),
            0,
            &g.review,
            7,
            s(a, "key_id").to_owned(),
        ),
        (
            s(a, "provider_identity").to_owned(),
            s(a, "approval_client").to_owned(),
            s(a, "ticket").to_owned(),
            1,
            &g.review,
            7,
            s(a, "key_id").to_owned(),
        ),
        (
            s(a, "provider_identity").to_owned(),
            s(a, "approval_client").to_owned(),
            s(a, "ticket").to_owned(),
            0,
            &review,
            7,
            s(a, "key_id").to_owned(),
        ),
        (
            s(a, "provider_identity").to_owned(),
            s(a, "approval_client").to_owned(),
            s(a, "ticket").to_owned(),
            0,
            &g.review,
            8,
            s(a, "key_id").to_owned(),
        ),
        (
            s(a, "provider_identity").to_owned(),
            s(a, "approval_client").to_owned(),
            s(a, "ticket").to_owned(),
            0,
            &g.review,
            7,
            hex('7'),
        ),
    ] {
        changed.push(
            v2::approval_transcript(
                &ApprovalContext {
                    provider_identity: &provider,
                    approval_client: &client,
                    ticket: &ticket,
                    ticket_deadline_unix_ms: a["ticket_deadline_unix_ms"].as_u64().unwrap() + ms,
                    review,
                },
                &g.binding,
                a["generation"].as_u64().unwrap() + generation - 7,
                &key,
            )
            .unwrap(),
        );
    }
    assert_eq!(changed.len(), 11);
    for (index, bytes) in changed.iter().enumerate() {
        assert_ne!(*bytes, original, "field {index} is not bound");
    }
    // Malformed provider-owned values never encode.
    let mut b = g.binding.clone();
    b.request_id = "not-a-request-id".into();
    assert!(
        v2::approval_transcript(
            &ApprovalContext {
                provider_identity: s(a, "provider_identity"),
                approval_client: s(a, "approval_client"),
                ticket: s(a, "ticket"),
                ticket_deadline_unix_ms: 1,
                review: &g.review,
            },
            &b,
            1,
            s(a, "key_id"),
        )
        .is_none()
    );
}

#[test]
fn biometric_verifier_rejects_synthetic_domain_sizes_and_other_keys() {
    let g = golden();
    let bytes = transcript(&g);
    let key = software_key();
    let public_key = key.public_key().as_ref().to_vec();
    assert_eq!(public_key.len(), 65);
    let good = sign(&key, &bytes);
    assert_eq!(
        RingBiometricVerifier.verify(&public_key, &bytes, &good),
        Ok(())
    );
    // The synthetic test contract (companion lifecycle.rs) never verifies here,
    // even when its framed fields were otherwise identical.
    let mut synthetic = bytes.clone();
    let domain = b"dev.vaultwarden.companion.synthetic.v1";
    synthetic.splice(0..4 + v2::APPROVAL_DOMAIN.len(), {
        let mut f = (domain.len() as u32).to_be_bytes().to_vec();
        f.extend_from_slice(domain);
        f
    });
    let synthetic_signature = sign(&key, &synthetic);
    assert!(
        RingBiometricVerifier
            .verify(&public_key, &bytes, &synthetic_signature)
            .is_err()
    );
    // Another device's key.
    let other = software_key();
    assert!(
        RingBiometricVerifier
            .verify(other.public_key().as_ref(), &bytes, &good)
            .is_err()
    );
    // Compressed / truncated keys and out-of-bound signature sizes.
    let mut compressed = public_key[..33].to_vec();
    compressed[0] = 0x02 | (public_key[64] & 1);
    assert!(
        RingBiometricVerifier
            .verify(&compressed, &bytes, &good)
            .is_err()
    );
    assert!(
        RingBiometricVerifier
            .verify(&public_key[..64], &bytes, &good)
            .is_err()
    );
    let mut wrong_prefix = public_key.clone();
    wrong_prefix[0] = 0x06;
    assert!(
        RingBiometricVerifier
            .verify(&wrong_prefix, &bytes, &good)
            .is_err()
    );
    let mut long = good.clone();
    long.resize(73, 0);
    assert!(
        RingBiometricVerifier
            .verify(&public_key, &bytes, &long)
            .is_err()
    );
    assert!(
        RingBiometricVerifier
            .verify(&public_key, &bytes, &good[..7])
            .is_err()
    );
    assert!(
        RingBiometricVerifier
            .verify(&public_key, &bytes, &[])
            .is_err()
    );
}

/// Regenerates the committed golden vector. Run explicitly:
/// `VW_WRITE_APPROVAL_GOLDEN=<path> cargo test --lib -- --ignored write_approval_v2_golden`
#[test]
#[ignore = "fixture generator"]
fn write_approval_v2_golden() {
    let path = std::env::var("VW_WRITE_APPROVAL_GOLDEN").unwrap();
    let key = software_key();
    let public_key = key.public_key().as_ref().to_vec();
    let review = serde_json::json!({
        "id": URL_SAFE_NO_PAD.encode([7u8; 32]),
        "requester": "local human terminal",
        "operation": "deploy",
        "effect": "Deploy \"staging\" <img> caf\u{e9}",
        "target": "staging",
        "arguments": ["staging", "safe"],
        "credentials": [{"label": "Deployment <login>", "use_type": "login"}],
        "executable_digest": "a".repeat(64),
        "policy_digest": "b".repeat(64),
        "arguments_digest": crate::access::direct_request::arguments_digest(&["staging".into(), "safe".into()]),
        "expires_at_unix_seconds": 1_700_000_300u64,
        "one_time": crate::access::direct_request::ONE_TIME,
        "status": {"status": "pending"},
    });
    let parsed: DirectReview = serde_json::from_value(review.clone()).unwrap();
    let mut approval = serde_json::json!({
        "provider_identity": "1f".repeat(32),
        "approval_client": "2e".repeat(32),
        "key_id": v2::key_id(&public_key),
        "request_id": parsed.id,
        "record_digest": "3d".repeat(32),
        "policy_digest": parsed.policy_digest,
        "arguments_digest": parsed.arguments_digest,
        "expires_at_unix_seconds": parsed.expires_at_unix_seconds,
        "generation": 7u64,
        "ticket": "4c".repeat(32),
        "ticket_deadline_unix_ms": 1_700_000_060_000u64,
        "review_digest": v2::hex(&v2::review_digest(&parsed).unwrap()),
        "review": review,
    });
    let mut json = serde_json::json!({"public_key": URL_SAFE_NO_PAD.encode(&public_key), "approval": approval.clone()});
    let g = Golden {
        binding: ApprovalBinding {
            request_id: parsed.id.clone(),
            requester_uid: 501,
            agent_owner: None,
            policy_digest: parsed.policy_digest.clone(),
            arguments_digest: parsed.arguments_digest.clone(),
            expires_at_unix_seconds: parsed.expires_at_unix_seconds,
            lifecycle_epoch: 0,
            record_digest: "3d".repeat(32),
        },
        review: parsed,
        json: json.clone(),
    };
    let bytes = transcript(&g);
    approval["transcript_hex"] = v2::hex(&bytes).into();
    approval["signature"] = URL_SAFE_NO_PAD.encode(sign(&key, &bytes)).into();
    let action_id = URL_SAFE_NO_PAD.encode([9u8; 32]);
    let enroll = v2::enroll_transcript(
        &"1f".repeat(32),
        &"2e".repeat(32),
        &public_key,
        &"5b".repeat(32),
        &action_id,
    )
    .unwrap();
    json["approval"] = approval;
    json["enroll"] = serde_json::json!({
        "ticket": "5b".repeat(32),
        "action_id": action_id,
        "transcript_hex": v2::hex(&enroll),
        "signature": URL_SAFE_NO_PAD.encode(sign(&key, &enroll)),
    });
    std::fs::write(path, serde_json::to_string_pretty(&json).unwrap() + "\n").unwrap();
}
