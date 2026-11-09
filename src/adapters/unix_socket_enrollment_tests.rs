//! Agent-socket admission for guided enrollment (#59): only the invited OS
//! identity reaches enrollment messages, and they never confer submission.
use super::*;
use crate::access::{
    direct_request_tests::{Fixture, Launcher, fixture, input},
    enrollment::{
        EnrolleeKind, EnrollmentState, InvitationRequest,
        joiner::{InvitationCode, JoinAttempt},
    },
};

const UID: u32 = 41071;
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

#[tokio::test]
async fn only_an_invited_identity_reaches_enrollment_and_it_never_submits() {
    let f = fixture();
    let owner = f.app.human_owner();
    let key = SigningKey::from_bytes(&[71; 32]);
    let unauthorized = br#"{"status":"rejected","protocol_version":1,"category":"unauthorized"}"#;
    let issued = f
        .app
        .enrollment_invite(
            owner,
            InvitationRequest {
                kind: EnrolleeKind::Agent {
                    label: "socket".into(),
                    uid: UID,
                    gid: GID,
                },
                ttl_seconds: None,
            },
        )
        .unwrap();
    let attempt = JoinAttempt::agent(
        InvitationCode::parse(&issued.invitation_code).unwrap(),
        &key,
        [2; 32],
    );
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
    // Without a live invitation, enrollment messages are refused again.
    assert_eq!(serve(&f, UID + 1, &session.status()).await, unauthorized);
}
