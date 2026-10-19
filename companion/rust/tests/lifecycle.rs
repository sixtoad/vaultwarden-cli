use companion_core::{
    api::*,
    lifecycle::{transcript, Core},
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

fn key(n: u8) -> SigningKey {
    SigningKey::from_slice(&[n; 32]).unwrap()
}
fn result(outcome: Outcome) -> Completion {
    Completion {
        outcome,
        public_key: vec![],
        signature: vec![],
    }
}
fn retain(core: &mut Core, key: &SigningKey) {
    let work = core.begin(Operation::Reopen).unwrap();
    let mut completion = result(Outcome::Reopened);
    completion.public_key = key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    core.finish(work.token, work.epoch, completion);
    assert!(core.snapshot().has_key);
}
fn proof(work: &Work, key: &SigningKey) -> Completion {
    let signature: Signature = key.sign(&transcript(work).unwrap());
    Completion {
        signature: signature.to_der().as_bytes().to_vec(),
        ..result(Outcome::Verified)
    }
}
fn ready() -> (Core, SigningKey) {
    let mut c = Core::default();
    let k = key(1);
    retain(&mut c, &k);
    c.select(1).unwrap();
    (c, k)
}

#[test]
fn two_requests_verify_once_each_and_review_is_consumed() {
    let (mut core, key) = ready();
    for id in [1, 2] {
        core.select(id).unwrap();
        let work = core.begin(Operation::Sign).unwrap();
        assert!(core.begin(Operation::Sign).is_err());
        let completion = proof(&work, &key);
        core.finish(work.token, work.epoch, completion.clone());
        core.finish(work.token, work.epoch, completion);
        assert_eq!(core.snapshot().verified, id);
        assert!(!core.snapshot().can_sign);
        assert!(core.begin(Operation::Sign).is_err());
    }
}

#[test]
fn every_transcript_binding_and_wrong_key_are_rejected() {
    for mutation in 0..8 {
        let (mut core, key) = ready();
        let work = core.begin(Operation::Sign).unwrap();
        let mut altered = work.clone();
        match mutation {
            0 => altered.fixture = 2,
            1 => altered.epoch += 1,
            2 => altered.token += 1,
            3 => altered.expires_unix_ms += 1,
            4 => altered.nonce[0] ^= 1,
            5 => altered.key_id[0] ^= 1,
            _ => {}
        }
        let wrong_key = SigningKey::from_slice(&[2; 32]).unwrap();
        let mut completion = proof(&altered, if mutation == 6 { &wrong_key } else { &key });
        if mutation == 7 {
            completion.signature[5] ^= 1;
        }
        core.finish(work.token, work.epoch, completion);
        assert_eq!(
            core.snapshot().outcome,
            Outcome::Rejected,
            "mutation {mutation}"
        );
        assert_eq!(core.snapshot().verified, 0);
    }
}

#[test]
fn cancellation_selection_sleep_close_discard_late_success_and_keep_admission_closed() {
    for reason in [
        Invalidation::Cancel,
        Invalidation::Selection,
        Invalidation::Sleep,
        Invalidation::Close,
    ] {
        let (mut core, key) = ready();
        let work = core.begin(Operation::Sign).unwrap();
        core.invalidate(reason);
        core.select(2).unwrap();
        assert!(core.begin(Operation::Sign).is_err());
        core.finish(work.token + 1, work.epoch, proof(&work, &key));
        core.finish(work.token, work.epoch + 1, proof(&work, &key));
        assert!(core.snapshot().busy);
        core.finish(work.token, work.epoch, proof(&work, &key));
        assert!(!core.snapshot().busy);
        assert_eq!(core.snapshot().verified, 0);
        assert_eq!(core.snapshot().outcome, Outcome::Cancelled);
    }
}

#[test]
fn noninteractive_success_remains_unsafe_after_cancellation() {
    let (mut core, key) = ready();
    let work = core.begin(Operation::NoInteraction).unwrap();
    core.invalidate(Invalidation::Cancel);
    core.finish(work.token, work.epoch, proof(&work, &key));
    assert_eq!(core.snapshot().outcome, Outcome::Unsafe);
    assert_eq!(core.snapshot().blocked_without_interaction, 0);
}

#[test]
fn only_specific_noninteraction_result_counts() {
    let (mut core, _) = ready();
    for outcome in [
        Outcome::Failed,
        Outcome::Unavailable,
        Outcome::MissingKey,
        Outcome::Cancelled,
        Outcome::InteractionRequired,
    ] {
        core.select(1).unwrap();
        let work = core.begin(Operation::NoInteraction).unwrap();
        core.finish(work.token, work.epoch, result(outcome));
    }
    assert_eq!(core.snapshot().blocked_without_interaction, 1);
}

#[test]
fn cancelled_key_mutations_are_preserved_and_failures_preserve_counters() {
    let mut core = Core::default();
    let work = core.begin(Operation::Create).unwrap();
    core.invalidate(Invalidation::Cancel);
    let mut created = result(Outcome::Created);
    created.public_key = key(1)
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    core.finish(work.token, work.epoch, created);
    assert_eq!(core.snapshot().outcome, Outcome::Created);
    assert!(core.begin(Operation::Create).is_err());
    core.select(1).unwrap();
    let work = core.begin(Operation::Sign).unwrap();
    core.finish(work.token, work.epoch, proof(&work, &key(1)));
    let work = core.begin(Operation::Delete).unwrap();
    core.finish(work.token, work.epoch, result(Outcome::Failed));
    assert_eq!(core.snapshot().verified, 1);
    assert!(core.snapshot().has_key);
    let work = core.begin(Operation::Delete).unwrap();
    core.invalidate(Invalidation::Cancel);
    core.finish(work.token, work.epoch, result(Outcome::Deleted));
    assert_eq!(core.snapshot().verified, 0);
    assert!(!core.snapshot().has_key);
    assert_eq!(core.snapshot().outcome, Outcome::Deleted);
}

#[test]
fn replaced_key_and_completion_key_cannot_replace_retained_identity() {
    let (mut core, key1) = ready();
    let work = core.begin(Operation::Reopen).unwrap();
    let mut changed = result(Outcome::Reopened);
    changed.public_key = key(2)
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    core.finish(work.token, work.epoch, changed);
    assert_eq!(core.snapshot().outcome, Outcome::Rejected);
    core.select(1).unwrap();
    let work = core.begin(Operation::Sign).unwrap();
    let mut completion = proof(&work, &key1);
    completion.public_key = key1
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    core.finish(work.token, work.epoch, completion);
    assert_eq!(core.snapshot().outcome, Outcome::Rejected);
}

#[test]
fn unavailable_and_malformed_proofs_cannot_approve() {
    let (mut core, _) = ready();
    for completion in [
        result(Outcome::Unavailable),
        result(Outcome::Verified),
        Completion {
            signature: vec![0; 73],
            ..result(Outcome::Verified)
        },
    ] {
        core.select(1).unwrap();
        let work = core.begin(Operation::Sign).unwrap();
        core.finish(work.token, work.epoch, completion);
        assert_eq!(core.snapshot().verified, 0);
    }
    assert!(core.select(3).is_err());
}
