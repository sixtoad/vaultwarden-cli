// Guided companion enrollment over the mTLS command surface (#59 phase 1).
// Included into `companion::tests`; reuses its `service` fixture.
fn enroll(
    service: &Companion,
    f: &Fixture,
    device: &str,
    message: crate::access::enrollment::wire::EnrollmentRequest,
) -> crate::access::enrollment::wire::EnrollmentReply {
    let response = service.dispatch(device, Command::Enroll { version: 1, message }, &f.app);
    assert_eq!(response.status, 200, "{}", response.body);
    crate::access::enrollment::wire::EnrollmentReply::parse(response.body.as_bytes()).unwrap()
}
fn companion_invite(f: &Fixture, label: &str) -> crate::access::enrollment::IssuedInvitation {
    f.app
        .enrollment_invite(
            f.app.human_owner(),
            crate::access::enrollment::InvitationRequest {
                kind: crate::access::enrollment::EnrolleeKind::Companion {
                    label: label.into(),
                },
                ttl_seconds: None,
            },
        )
        .unwrap()
}
#[test]
fn guided_companion_enrollment_needs_both_humans_and_grants_no_administration() {
    use crate::access::enrollment::{
        EnrollmentState,
        joiner::{InvitationCode, JoinAttempt},
        wire::EnrollmentReply,
    };
    let f = fixture();
    let (service, _, _) = service(&f);
    let device = "c".repeat(64);
    let list = || Command::List { version: 1 };
    assert_eq!(service.dispatch(&device, list(), &f.app).status, 403);
    let issued = companion_invite(&f, "Studio Mac");
    let attempt = JoinAttempt::companion(
        InvitationCode::parse(&issued.invitation_code).unwrap(),
        &device,
        &service.provider_fingerprint,
        [4; 32],
    )
    .unwrap();
    let joined = enroll(&service, &f, &device, attempt.request().clone());
    let session = attempt.accept(&joined).unwrap();
    // Joined and confirmed by the device: still no access to anything.
    let reply = enroll(&service, &f, &device, session.confirm(None));
    assert!(matches!(
        reply,
        EnrollmentReply::State {
            state: EnrollmentState::AwaitingApprovals { .. },
            ..
        }
    ));
    assert_eq!(service.dispatch(&device, list(), &f.app).status, 403);
    f.app
        .enrollment_approve(f.app.human_owner(), &issued.id, &session.comparison_code)
        .unwrap();
    let reply = enroll(&service, &f, &device, session.confirm(None));
    assert!(matches!(
        reply,
        EnrollmentReply::State {
            state: EnrollmentState::Enrolled { .. },
            ..
        }
    ));
    assert_eq!(service.dispatch(&device, list(), &f.app).status, 200);
    assert!(!identity::administrator(&service.identity_store, &device));
}
#[test]
fn guided_companion_enrollment_never_reactivates_a_revoked_device() {
    use crate::access::enrollment::{
        EnrollmentRejection,
        joiner::{InvitationCode, JoinAttempt},
        wire::EnrollmentReply,
    };
    let f = fixture();
    let (service, _, _) = service(&f);
    let revoked = "b".repeat(64);
    let root = service.identity_store.parent().unwrap().to_owned();
    identity::revoke_online(&root, &revoked, "local_owner").unwrap();
    // Same label as the revoked device, same certificate: refused at join.
    let issued = companion_invite(&f, "Other Mac");
    let attempt = JoinAttempt::companion(
        InvitationCode::parse(&issued.invitation_code).unwrap(),
        &revoked,
        &service.provider_fingerprint,
        [5; 32],
    )
    .unwrap();
    assert_eq!(
        enroll(&service, &f, &revoked, attempt.request().clone()),
        EnrollmentReply::Rejected {
            protocol_version: 1,
            reason: EnrollmentRejection::IdentityRefused
        }
    );
    let records = identity::management_records(&service.identity_store).unwrap();
    assert!(
        records
            .iter()
            .any(|(entry, revoked_flag, _)| entry.fingerprint == revoked && *revoked_flag)
    );
    assert_eq!(service.dispatch(&revoked, Command::List { version: 1 }, &f.app).status, 403);
    // A malformed enrollment message is refused before the protocol runs.
    let bad = service.dispatch(
        &revoked,
        Command::Enroll {
            version: 2,
            message: attempt.request().clone(),
        },
        &f.app,
    );
    assert_eq!(bad.status, 400);
}
