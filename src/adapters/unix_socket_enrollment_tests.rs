//! Agent-socket admission for guided enrollment (#59): only the invited OS
//! identity reaches enrollment messages, and they never confer submission.
use super::*;
use crate::access::{
    direct_request_tests::{Fixture, Launcher, fixture, input},
    enrollment::{
        AbortReason, EnrolleeKind, EnrollmentRejection, EnrollmentState, InvitationRequest,
        IssuedInvitation, Party,
        joiner::{InvitationCode, JoinAttempt},
    },
};

const UID: u32 = 41071;
const OTHER_UID: u32 = 41073;
const GID: u32 = 42071;

async fn serve(f: &Fixture, uid: u32, frame: &impl serde::Serialize) -> Vec<u8> {
    let mut wire = serde_json::to_vec(frame).unwrap();
    wire.push(b'\n');
    let (mut client, server) = UnixStream::pair().unwrap();
    let capacity = Arc::new(Semaphore::new(1));
    let permit = Arc::new(capacity.acquire_owned().await.unwrap());
    let serving = tokio::spawn(serve_one(
        server,
        PeerCredentials {
            uid,
            groups: vec![GID],
        },
        f.app.clone(),
        Arc::new(Launcher::default()),
        permit,
        Instant::now() + IO_TIMEOUT,
    ));
    client.write_all(&wire).await.unwrap();
    client.shutdown().await.unwrap();
    let response = read_frame(
        &mut client,
        MAX_RESPONSE_FRAME_BYTES,
        Instant::now() + IO_TIMEOUT,
    )
    .await
    .unwrap();
    serving.await.unwrap();
    response
}

/// `serve` from a plain thread, so a test can hold a provider lock meanwhile.
fn serve_blocking(f: &Fixture, uid: u32, frame: &impl serde::Serialize) -> Vec<u8> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(serve(f, uid, frame))
}

/// What the joiner's client makes of the provider's bytes.
fn joiner_sees(bytes: &[u8]) -> EnrollmentReply {
    enrollment_reply(bytes).expect("an enrollment-shaped reply, never a transport error")
}

fn invite(f: &Fixture, label: &str, uid: u32) -> IssuedInvitation {
    f.app
        .enrollment_invite(
            f.app.human_owner(),
            InvitationRequest {
                kind: EnrolleeKind::Agent {
                    label: label.into(),
                    uid,
                    gid: GID,
                },
                ttl_seconds: None,
            },
        )
        .unwrap()
}

fn attempt(issued: &IssuedInvitation, key: &SigningKey) -> JoinAttempt {
    JoinAttempt::agent(
        InvitationCode::parse(&issued.invitation_code).unwrap(),
        key,
        [2; 32],
    )
}

#[tokio::test]
async fn only_an_invited_identity_reaches_enrollment_and_it_never_submits() {
    let f = fixture();
    let owner = f.app.human_owner();
    let key = SigningKey::from_bytes(&[71; 32]);
    let unauthorized = br#"{"status":"rejected","protocol_version":1,"category":"unauthorized"}"#;
    let issued = invite(&f, "socket", UID);
    let attempt = attempt(&issued, &key);
    // Another unpaired account is refused before its frame is parsed.
    assert_eq!(serve(&f, UID + 1, attempt.request()).await, unauthorized);
    // The invited account may not submit work with its future key.
    let submission = crate::access::protocol::SignedSubmission::sign(
        issued.id.clone(),
        [3; 32],
        input().operation,
        "0".repeat(64),
        Vec::new(),
        &key,
    )
    .unwrap();
    assert_eq!(serve(&f, UID, &submission).await, unauthorized);
    let reply = EnrollmentReply::parse(&serve(&f, UID, attempt.request()).await).unwrap();
    let session = attempt.accept(&reply).unwrap();
    f.app
        .enrollment_approve(owner, &issued.id, &session.comparison_code)
        .unwrap();
    let reply =
        EnrollmentReply::parse(&serve(&f, UID, &session.confirm(Some(&key))).await).unwrap();
    assert!(matches!(
        reply,
        EnrollmentReply::State {
            state: EnrollmentState::Enrolled { .. },
            ..
        }
    ));
    assert!(f.app.agent_peer_eligible(UID, &[GID]).is_ok());
    // Lost final reply: the now paired account re-sends its confirmation and
    // learns the outcome; nothing is committed twice.
    let again =
        EnrollmentReply::parse(&serve(&f, UID, &session.confirm(Some(&key))).await).unwrap();
    assert_eq!(again, reply);
    assert_eq!(f.app.list_agents(owner).unwrap().len(), 1);
}

#[tokio::test]
async fn a_cancelled_session_tells_its_joiner_it_was_cancelled() {
    let f = fixture();
    let key = SigningKey::from_bytes(&[73; 32]);
    let issued = invite(&f, "cancelled", OTHER_UID);
    let attempt = attempt(&issued, &key);
    let reply = EnrollmentReply::parse(&serve(&f, OTHER_UID, attempt.request()).await).unwrap();
    let session = attempt.accept(&reply).unwrap();
    let cancelled = f
        .app
        .enrollment_cancel(f.app.human_owner(), &issued.id)
        .unwrap();
    assert_eq!(
        cancelled.state,
        EnrollmentState::Cancelled {
            by: Party::Provider
        }
    );
    // The joined identity is still admitted while the session is retained,
    // and learns the real end rather than an unexplained refusal.
    assert_eq!(
        joiner_sees(&serve(&f, OTHER_UID, &session.status()).await),
        EnrollmentReply::State {
            protocol_version: crate::access::enrollment::ENROLLMENT_PROTOCOL_VERSION,
            invitation_id: issued.id.clone(),
            state: EnrollmentState::Cancelled {
                by: Party::Provider
            },
        }
    );
    // Admission is no authority: a message for any other session is still
    // refused, indistinguishably from an unknown invitation.
    let stranger = JoinAttempt::agent(
        InvitationCode::parse(&invite(&f, "other", UID).invitation_code).unwrap(),
        &key,
        [4; 32],
    );
    assert_eq!(
        joiner_sees(&serve(&f, OTHER_UID, stranger.request()).await),
        EnrollmentReply::rejected(EnrollmentRejection::InvalidInvitation)
    );
}

/// The end states that signal an attack (a relay typing the wrong code, a
/// leaked secret joining twice) reach the legitimate agent joiner.
#[tokio::test]
async fn a_code_mismatch_or_a_duplicate_join_reaches_the_agent_joiner() {
    let f = fixture();
    let owner = f.app.human_owner();
    let key = SigningKey::from_bytes(&[76; 32]);
    let issued = invite(&f, "mismatch", UID);
    let attempt = attempt(&issued, &key);
    let session = attempt
        .accept(&joiner_sees(&serve(&f, UID, attempt.request()).await))
        .unwrap();
    let wrong = if session.comparison_code == "0000-0000" {
        "0000-0001"
    } else {
        "0000-0000"
    };
    assert!(f.app.enrollment_approve(owner, &issued.id, wrong).is_err());
    assert!(matches!(
        joiner_sees(&serve(&f, UID, &session.confirm(Some(&key))).await),
        EnrollmentReply::State {
            state: EnrollmentState::Aborted {
                reason: AbortReason::CodeMismatch
            },
            ..
        }
    ));

    let issued = invite(&f, "duplicate", OTHER_UID);
    let attempt = attempt(&issued, &key);
    let session = attempt
        .accept(&joiner_sees(&serve(&f, OTHER_UID, attempt.request()).await))
        .unwrap();
    let intruder = JoinAttempt::agent(
        InvitationCode::parse(&issued.invitation_code).unwrap(),
        &SigningKey::from_bytes(&[77; 32]),
        [5; 32],
    );
    assert_eq!(
        joiner_sees(&serve(&f, OTHER_UID, intruder.request()).await),
        EnrollmentReply::rejected(EnrollmentRejection::AlreadyUsed)
    );
    assert!(matches!(
        joiner_sees(&serve(&f, OTHER_UID, &session.status()).await),
        EnrollmentReply::State {
            state: EnrollmentState::Aborted {
                reason: AbortReason::DuplicateJoin
            },
            ..
        }
    ));
}

/// A now-paired agent resending its confirmation (lost final reply) while
/// the sessions are locked hears `busy`, never the agent vocabulary's
/// `malformed`, which its client would take as a definitive failure.
#[test]
fn a_paired_agent_resending_its_confirmation_under_contention_hears_busy() {
    let f = fixture();
    let key = SigningKey::from_bytes(&[78; 32]);
    let issued = invite(&f, "paired busy", UID);
    let attempt = attempt(&issued, &key);
    let session = attempt
        .accept(&joiner_sees(&serve_blocking(&f, UID, attempt.request())))
        .unwrap();
    f.app
        .enrollment_approve(f.app.human_owner(), &issued.id, &session.comparison_code)
        .unwrap();
    assert!(matches!(
        joiner_sees(&serve_blocking(&f, UID, &session.confirm(Some(&key)))),
        EnrollmentReply::State {
            state: EnrollmentState::Enrolled { .. },
            ..
        }
    ));
    assert!(f.app.agent_peer_eligible(UID, &[GID]).is_ok());
    let mut held = Vec::new();
    f.app.enrollment_hold_for_test(|| {
        held = serve_blocking(&f, UID, &session.confirm(Some(&key)));
    });
    assert_eq!(
        joiner_sees(&held),
        EnrollmentReply::rejected(EnrollmentRejection::Busy)
    );
}

/// A poisoned session lock is a provider fault, `unavailable`, as for every
/// other enrollment action; never "not invited".
#[tokio::test]
async fn a_poisoned_session_lock_is_unavailable_to_the_joiner() {
    let f = fixture();
    let key = SigningKey::from_bytes(&[79; 32]);
    let issued = invite(&f, "poisoned", UID);
    let attempt = attempt(&issued, &key);
    f.app.enrollment_poison_for_test();
    assert_eq!(
        joiner_sees(&serve(&f, UID, attempt.request()).await),
        EnrollmentReply::rejected(EnrollmentRejection::Unavailable)
    );
}

#[test]
fn contention_is_a_retryable_busy_and_a_held_gate_does_not_refuse_enrollment() {
    let f = fixture();
    let key = SigningKey::from_bytes(&[74; 32]);
    let issued = invite(&f, "busy", UID);
    let attempt = attempt(&issued, &key);
    // The sessions are momentarily locked: busy, never "not invited".
    let mut held = Vec::new();
    f.app
        .enrollment_hold_for_test(|| held = serve_blocking(&f, UID, attempt.request()));
    assert_eq!(
        joiner_sees(&held),
        EnrollmentReply::rejected(EnrollmentRejection::Busy)
    );
    let joined = joiner_sees(&serve_blocking(&f, UID, attempt.request()));
    let session = attempt.accept(&joined).unwrap();
    // The provider's gate is busy with other work: an invited joiner's
    // enrollment message is still answered in the enrollment vocabulary.
    let mut status = Vec::new();
    f.app
        .management_hold_gate_for_test(|| status = serve_blocking(&f, UID, &session.status()));
    assert!(matches!(
        joiner_sees(&status),
        EnrollmentReply::State {
            state: EnrollmentState::AwaitingApprovals { .. },
            ..
        }
    ));
}

#[tokio::test]
async fn after_a_provider_restart_the_joiner_sees_an_invalid_invitation() {
    let f = fixture();
    let key = SigningKey::from_bytes(&[75; 32]);
    let issued = invite(&f, "restart", UID);
    let attempt = attempt(&issued, &key);
    let joined = joiner_sees(&serve(&f, UID, attempt.request()).await);
    let session = attempt.accept(&joined).unwrap();
    // A restarted provider has forgotten every invitation (memory only).
    let restarted = fixture();
    for message in [session.status(), session.confirm(Some(&key))] {
        assert_eq!(
            joiner_sees(&serve(&restarted, UID, &message).await),
            EnrollmentReply::rejected(EnrollmentRejection::InvalidInvitation)
        );
    }
}
