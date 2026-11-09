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
#[test]
fn the_first_companion_enrolls_through_the_guided_flow() {
    use crate::access::enrollment::{
        EnrollmentState,
        joiner::{InvitationCode, JoinAttempt},
        wire::EnrollmentReply,
    };
    use std::os::unix::fs::MetadataExt;
    let f = fixture();
    let root = f.dir.path().join("provider");
    let server = write_private(
        &root,
        "server.pem",
        include_bytes!("../../tests/fixtures/provider-tls/server.pem"),
    );
    let key = write_private(
        &root,
        "server-key.pem",
        include_bytes!("../../tests/fixtures/provider-tls/server-key.pem"),
    );
    let ca = write_private(&root, "client-ca.pem", CLIENT_CA);
    // A fresh provider: no companion was ever enrolled, so no registry.
    let store = root.join(identity::STORE_FILE);
    assert!(!store.exists());
    let service = Companion::bind("127.0.0.1:0".parse().unwrap(), &server, &key, &ca, &store)
        .expect("the companion endpoint starts with zero companions");
    let device = "c".repeat(64);
    let list = || Command::List { version: 1 };
    // Zero identities: every ordinary command is refused, nothing is created.
    assert_eq!(service.dispatch(&device, list(), &f.app).status, 403);
    assert!(!store.exists());
    // Without a live invitation the enrollment command admits nothing either.
    let stale = companion_invite(&f, "Stale");
    f.app
        .enrollment_cancel(f.app.human_owner(), &stale.id)
        .unwrap();
    let stale = JoinAttempt::companion(
        InvitationCode::parse(&stale.invitation_code).unwrap(),
        &device,
        &service.provider_fingerprint,
        [3; 32],
    )
    .unwrap();
    assert!(matches!(
        enroll(&service, &f, &device, stale.request().clone()),
        EnrollmentReply::Rejected { .. }
    ));
    assert!(!store.exists());
    let issued = companion_invite(&f, "First Mac");
    let attempt = JoinAttempt::companion(
        InvitationCode::parse(&issued.invitation_code).unwrap(),
        &device,
        &service.provider_fingerprint,
        [4; 32],
    )
    .unwrap();
    let joined = enroll(&service, &f, &device, attempt.request().clone());
    let session = attempt.accept(&joined).unwrap();
    f.app
        .enrollment_approve(f.app.human_owner(), &issued.id, &session.comparison_code)
        .unwrap();
    assert!(matches!(
        enroll(&service, &f, &device, session.confirm(None)),
        EnrollmentReply::State {
            state: EnrollmentState::Enrolled { .. },
            ..
        }
    ));
    // Created on the first guided commit, private to the provider account.
    let metadata = std::fs::symlink_metadata(&store).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(identity::enrolled(&store).unwrap().len(), 1);
    assert_eq!(service.dispatch(&device, list(), &f.app).status, 200);
    assert!(!identity::administrator(&service.identity_store, &device));
}
#[test]
fn an_unreadable_registry_is_unavailable_and_does_not_burn_the_invitation() {
    use crate::access::enrollment::{
        EnrollmentRejection, EnrollmentState,
        joiner::{InvitationCode, JoinAttempt},
        wire::EnrollmentReply,
    };
    let f = fixture();
    let (service, _, _) = service(&f);
    let saved = std::fs::read(&service.identity_store).unwrap();
    std::fs::write(&service.identity_store, b"{").unwrap();
    let device = "c".repeat(64);
    let issued = companion_invite(&f, "Studio Mac");
    let attempt = JoinAttempt::companion(
        InvitationCode::parse(&issued.invitation_code).unwrap(),
        &device,
        &service.provider_fingerprint,
        [4; 32],
    )
    .unwrap();
    // A storage fault is not a verdict on the device: retryable, not burned.
    assert_eq!(
        enroll(&service, &f, &device, attempt.request().clone()),
        EnrollmentReply::Rejected {
            protocol_version: 1,
            reason: EnrollmentRejection::Unavailable
        }
    );
    let views = f.app.enrollment_list(f.app.human_owner()).unwrap();
    assert_eq!(views[0].state, EnrollmentState::AwaitingJoin {});
    std::fs::write(&service.identity_store, saved).unwrap();
    let joined = enroll(&service, &f, &device, attempt.request().clone());
    assert!(attempt.accept(&joined).is_ok());
}
