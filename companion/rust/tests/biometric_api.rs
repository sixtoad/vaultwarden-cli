//! The pin rule through the bridge entry points (issue 49 PR B). One test in
//! its own binary: the provider and key sessions are process-global.
use companion_core::api::biometric::{
    biometric_key_begin, biometric_key_begin_enroll, biometric_key_configure,
    biometric_key_enroll_transcript, biometric_key_finish, biometric_key_snapshot,
    provider_biometric_pin, BiometricKeyCommand as KeyCommand, BiometricRefusal as Refusal,
};
use companion_core::api::provider::provider_configure;
use companion_core::provider::approval_v2 as v2;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::json;

const PROVIDER: &str = "1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f";
const NEW_PROVIDER: &str = "4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c";
const CLIENT: &str = "2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e";
const TICKET: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const ACTION: &str = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk";

fn pin(provider: &str) {
    provider_configure(String::new()).unwrap();
    provider_biometric_pin(provider.into(), CLIENT.into()).unwrap();
}

#[test]
fn key_session_follows_the_provider_pin_and_a_provider_switch_drops_its_tickets() {
    pin(PROVIDER);
    // The key session must be pinned with the provider session's values.
    assert_eq!(
        biometric_key_configure(NEW_PROVIDER.into(), CLIENT.into()).unwrap_err(),
        Refusal::NotPinned
    );
    assert!(!biometric_key_snapshot().unwrap().configured);
    assert!(
        biometric_key_configure(PROVIDER.into(), CLIENT.into())
            .unwrap()
            .configured
    );

    let work = biometric_key_begin(KeyCommand::PrepareEnroll).unwrap();
    let prepared = json!({"version":2,"operation":"enroll","target":{"kind":"approval_client","id":CLIENT},
        "action_id":ACTION,"ticket":TICKET,"generation":4,"valid_for_seconds":55,
        "provider_identity":PROVIDER,"biometric_key_id":null});
    let snapshot =
        biometric_key_finish(work.token, serde_json::to_vec(&prepared).unwrap()).unwrap();
    assert!(snapshot.can_enroll);
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let public_key = key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let request = biometric_key_enroll_transcript(public_key.clone()).unwrap();
    let signature: Signature = key.sign(&request.transcript);
    let signature = signature.to_der().as_bytes().to_vec();
    assert!(v2::verify(&public_key, &request.transcript, &signature));

    // Provider switch: the pending enroll ticket can never be submitted.
    pin(NEW_PROVIDER);
    assert_eq!(
        biometric_key_begin_enroll("fresh".into(), public_key.clone(), signature.clone()).err(),
        Some(Refusal::NotPinned)
    );
    let snapshot = biometric_key_snapshot().unwrap();
    assert!(!snapshot.configured && !snapshot.can_enroll);
    // Nor after the key session is pinned to the new provider.
    biometric_key_configure(NEW_PROVIDER.into(), CLIENT.into()).unwrap();
    assert_eq!(
        biometric_key_begin_enroll("fresh".into(), public_key.clone(), signature.clone()).err(),
        Some(Refusal::NoPreparedOperation)
    );
    // Reconfiguring the provider (even back to the same values) resets it too.
    provider_configure(String::new()).unwrap();
    assert!(!biometric_key_snapshot().unwrap().configured);
    assert_eq!(
        biometric_key_begin(KeyCommand::Read).err(),
        Some(Refusal::NotPinned)
    );
}
