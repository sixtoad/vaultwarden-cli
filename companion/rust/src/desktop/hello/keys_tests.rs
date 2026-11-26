use super::*;
use crate::desktop::hello::attested::tests::{created, point};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;

const SESSION: &str = "0123456789abcdef0123456789abcdef";

/// A software stand-in for Windows Hello.
#[derive(Default)]
struct Fake {
    unavailable: AtomicBool,
    /// Flags of the next assertion's authenticator data (0: UP|UV).
    flags: AtomicU8,
    failure: Mutex<Option<Failure>>,
    cancelled: Mutex<Vec<CancelId>>,
    /// While set, `assert` waits until `cancel` is called.
    hold: AtomicBool,
}
fn key() -> SigningKey {
    SigningKey::from_slice(&[7; 32]).unwrap()
}
impl Authenticator for Arc<Fake> {
    fn available(&self) -> bool {
        !self.unavailable.load(Ordering::SeqCst)
    }
    fn create(&self, _user: &[u8; 32]) -> Result<Vec<u8>, Failure> {
        if let Some(failure) = *self.failure.lock().unwrap() {
            return Err(failure);
        }
        Ok(created(0x45, b"credential", &point()))
    }
    fn assert(
        &self,
        credential: &[u8],
        client_data: &[u8],
        cancel: Option<CancelId>,
    ) -> Result<(Vec<u8>, Vec<u8>), Failure> {
        assert_eq!(credential, b"credential");
        while self.hold.load(Ordering::SeqCst) {
            if self.cancelled.lock().unwrap().contains(&cancel.unwrap()) {
                return Err(Failure::Cancelled);
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        if let Some(failure) = *self.failure.lock().unwrap() {
            return Err(failure);
        }
        let mut data = key_class::rp_id_hash().to_vec();
        data.push(match self.flags.load(Ordering::SeqCst) {
            0 => 0x05,
            flags => flags,
        });
        data.extend_from_slice(&[0, 0, 0, 3]);
        let mut message = data.clone();
        message.extend_from_slice(&Sha256::digest(client_data));
        let signature: Signature = key().sign(&message);
        Ok((data, signature.to_der().as_bytes().to_vec()))
    }
    fn cancellation(&self) -> Option<CancelId> {
        Some([9; 16])
    }
    fn cancel(&self, id: CancelId) {
        self.cancelled.lock().unwrap().push(id);
    }
}

fn binding() -> Binding {
    Binding::parse(&"1f".repeat(32), &"2e".repeat(32)).unwrap()
}
fn frame(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}
fn approval(public_key: &[u8]) -> Vec<u8> {
    let b = binding();
    let key_id = Sha256::digest(public_key);
    frame(&[
        crate::provider::approval_v2::APPROVAL_DOMAIN.as_bytes(),
        b"approve",
        &b.provider_identity,
        &b.approval_client,
        &key_id,
        &[b'A'; 43],
        &[1; 32],
        &[2; 32],
        &[3; 32],
        &[0; 8],
        &[0; 8],
        &[4; 32],
        &[0; 8],
        &[5; 32],
    ])
}
fn setup() -> (tempfile::TempDir, Arc<Fake>, Arc<Keys<Arc<Fake>>>) {
    let dir = tempfile::tempdir().unwrap();
    let fake = Arc::new(Fake::default());
    let keys = Arc::new(Keys::new(fake.clone(), dir.path().join("provider")));
    (dir, fake, keys)
}

#[test]
fn create_read_sign_and_delete_follow_the_channel_contract() {
    let (_dir, _fake, keys) = setup();
    assert_eq!(keys.read(&binding()).outcome, Outcome::Absent);
    let created = keys.create(&binding());
    assert_eq!(
        (created.outcome, created.public_key.clone()),
        (Outcome::Created, point())
    );
    assert_eq!(
        keys.create(&binding()).outcome,
        Outcome::Refused,
        "one key per binding"
    );
    assert_eq!(keys.read(&binding()).public_key, point());
    let transcript = approval(&point());
    let signed = keys.sign(&binding(), SESSION, 1, Purpose::Approve, &transcript);
    assert_eq!(signed.outcome, Outcome::Signed);
    let message = key_class::signed_message(&transcript, &signed.authenticator_data).unwrap();
    assert!(v2::verify(&point(), &message, &signed.signature));
    // Another binding never sees this key.
    let other = Binding::parse(&"1f".repeat(32), &"3d".repeat(32)).unwrap();
    assert_eq!(keys.read(&other).outcome, Outcome::Absent);
    assert_eq!(keys.delete(&binding()).outcome, Outcome::Deleted);
    assert_eq!(keys.read(&binding()).outcome, Outcome::Absent);
    assert_eq!(keys.delete(&binding()).outcome, Outcome::Deleted);
}

#[test]
fn sign_refuses_foreign_transcripts_replayed_tokens_and_unsafe_assertions() {
    let (_dir, fake, keys) = setup();
    keys.create(&binding());
    let transcript = approval(&point());
    let mut other_key = point();
    other_key[64] ^= 1;
    assert_eq!(
        keys.sign(
            &binding(),
            SESSION,
            1,
            Purpose::Approve,
            &approval(&other_key)
        )
        .outcome,
        Outcome::Refused
    );
    assert_eq!(
        keys.sign(&binding(), SESSION, 1, Purpose::Enroll, &transcript)
            .outcome,
        Outcome::Refused
    );
    assert_eq!(
        keys.sign(&binding(), SESSION, 2, Purpose::Approve, &transcript)
            .outcome,
        Outcome::Signed
    );
    assert_eq!(
        keys.sign(&binding(), SESSION, 2, Purpose::Approve, &transcript)
            .outcome,
        Outcome::Failed
    );
    assert_eq!(
        keys.sign(&binding(), "XYZ", 3, Purpose::Approve, &transcript)
            .outcome,
        Outcome::Failed
    );
    // A new session restarts the numbering.
    let session = "fedcba9876543210fedcba9876543210";
    assert_eq!(
        keys.sign(&binding(), session, 1, Purpose::Approve, &transcript)
            .outcome,
        Outcome::Signed
    );
    for flags in [0x01, 0x0d, 0x15, 0x45] {
        fake.flags.store(flags, Ordering::SeqCst);
        assert_eq!(
            keys.sign(
                &binding(),
                session,
                10 + u32::from(flags),
                Purpose::Approve,
                &transcript
            )
            .outcome,
            Outcome::Unsafe,
            "{flags:#x}"
        );
    }
    fake.flags.store(0, Ordering::SeqCst);
    for (token, (failure, outcome)) in (200..).zip([
        (Failure::Cancelled, Outcome::Cancelled),
        (Failure::NotFound, Outcome::Invalidated),
        (Failure::Unavailable, Outcome::Unavailable),
        (Failure::Failed, Outcome::Failed),
    ]) {
        *fake.failure.lock().unwrap() = Some(failure);
        let reply = keys.sign(&binding(), session, token, Purpose::Approve, &transcript);
        assert_eq!(reply.outcome, outcome);
        assert!(reply.signature.is_empty() && reply.authenticator_data.is_empty());
    }
    *fake.failure.lock().unwrap() = None;
    fake.unavailable.store(true, Ordering::SeqCst);
    assert_eq!(
        keys.sign(&binding(), session, 300, Purpose::Approve, &transcript)
            .outcome,
        Outcome::Unavailable
    );
    assert_eq!(
        keys.create(&Binding::parse(&"aa".repeat(32), &"bb".repeat(32)).unwrap())
            .outcome,
        Outcome::Unavailable
    );
}

#[test]
fn cancel_reaches_only_the_open_signature_and_overlap_is_refused() {
    let (_dir, fake, keys) = setup();
    keys.create(&binding());
    fake.hold.store(true, Ordering::SeqCst);
    let worker = {
        let keys = keys.clone();
        std::thread::spawn(move || {
            keys.sign(
                &binding(),
                SESSION,
                5,
                Purpose::Approve,
                &approval(&point()),
            )
        })
    };
    while keys.idle() {
        std::thread::yield_now();
    }
    assert_eq!(
        keys.read(&binding()).outcome,
        Outcome::Failed,
        "waits for the signature"
    );
    assert_eq!(
        keys.sign(
            &binding(),
            SESSION,
            6,
            Purpose::Approve,
            &approval(&point())
        )
        .outcome,
        Outcome::Failed
    );
    keys.cancel(SESSION, 4);
    keys.cancel("fedcba9876543210fedcba9876543210", 5);
    assert!(fake.cancelled.lock().unwrap().is_empty());
    keys.cancel(SESSION, 5);
    assert_eq!(worker.join().unwrap().outcome, Outcome::Cancelled);
    assert!(keys.idle());
}

#[test]
fn a_damaged_key_file_is_never_used() {
    let (dir, _fake, keys) = setup();
    keys.create(&binding());
    let path = dir.path().join("provider").join(FILE);
    let mut file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    file["keys"][binding().alias()]["public_key"] = "04".into();
    std::fs::write(&path, file.to_string()).unwrap();
    assert_eq!(keys.read(&binding()).outcome, Outcome::Unsafe);
    assert_eq!(
        keys.sign(
            &binding(),
            SESSION,
            1,
            Purpose::Approve,
            &approval(&point())
        )
        .outcome,
        Outcome::Unsafe
    );
    std::fs::write(&path, b"{\"version\":2,\"keys\":{}}").unwrap();
    assert_eq!(keys.read(&binding()).outcome, Outcome::Failed);
}
