//! Provider-level guided enrollment: authority, the real pairing store,
//! revoked identities and expiry (#59 phase 1).
use crate::access::{
    agent_binding::{AgentBindingStatus, AgentPairing},
    direct_request::AuthenticatedHuman,
    direct_request_tests::{Fixture, fixture},
    encode_public_key,
    enrollment::{
        EnrolledIdentity, EnrolleeKind, EnrollmentRejection, EnrollmentState, HumanEnrollmentError,
        InvitationRequest, IssuedInvitation,
        joiner::{InvitationCode, JoinAttempt, JoinedSession},
        wire::EnrollmentReply,
    },
};
use ed25519_dalek::SigningKey;
use std::sync::atomic::Ordering;

/// Whether the agent socket admits `uid` to the enrollment messages.
fn admitted(f: &Fixture, uid: u32) -> bool {
    f.app.enrollment_peer_eligible(uid, &[GID])
        == crate::access::enrollment::EnrollmentAdmission::Admitted
}
const UID: u32 = 41059;
const GID: u32 = 42059;

fn kind(label: &str) -> EnrolleeKind {
    EnrolleeKind::Agent {
        label: label.into(),
        uid: UID,
        gid: GID,
    }
}
fn invite(f: &Fixture, label: &str) -> IssuedInvitation {
    f.app
        .enrollment_invite(
            f.app.human_owner(),
            InvitationRequest {
                kind: kind(label),
                ttl_seconds: None,
            },
        )
        .unwrap()
}
fn join(
    f: &Fixture,
    issued: &IssuedInvitation,
    key: &SigningKey,
) -> Result<JoinedSession, EnrollmentReply> {
    let attempt = JoinAttempt::agent(
        InvitationCode::parse(&issued.invitation_code).unwrap(),
        key,
        [8; 32],
    );
    let reply = f
        .app
        .enrollment_agent_message(UID, &[GID], attempt.request());
    attempt.accept(&reply).map_err(|_error| reply)
}
fn confirm(f: &Fixture, session: &JoinedSession, key: &SigningKey) -> EnrollmentState {
    match f
        .app
        .enrollment_agent_message(UID, &[GID], &session.confirm(Some(key)))
    {
        EnrollmentReply::State { state, .. } => state,
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn only_the_provider_owner_invites_lists_approves_or_cancels() {
    let f = fixture();
    let stranger = AuthenticatedHuman::from_peer_uid(f.app.human_owner().uid() + 1);
    let request = InvitationRequest {
        kind: kind("ci"),
        ttl_seconds: None,
    };
    assert_eq!(
        f.app.enrollment_invite(stranger, request.clone()).err(),
        Some(HumanEnrollmentError::Unauthorized)
    );
    let issued = invite(&f, "ci");
    assert_eq!(
        f.app.enrollment_list(stranger),
        Err(HumanEnrollmentError::Unauthorized)
    );
    assert_eq!(
        f.app.enrollment_approve(stranger, &issued.id, "1234-5678"),
        Err(HumanEnrollmentError::Unauthorized)
    );
    assert_eq!(
        f.app.enrollment_cancel(stranger, &issued.id),
        Err(HumanEnrollmentError::Unauthorized)
    );
    // The provider's own account is never an enrollable agent.
    let own = InvitationRequest {
        kind: EnrolleeKind::Agent {
            label: "self".into(),
            uid: f.app.human_owner().uid(),
            gid: GID,
        },
        ttl_seconds: None,
    };
    assert_eq!(
        f.app.enrollment_invite(f.app.human_owner(), own).err(),
        Some(HumanEnrollmentError::InvalidRequest)
    );
    assert!(!admitted(&f, f.app.human_owner().uid()));
}

#[test]
fn agent_enrollment_pairs_through_the_store_only_after_both_approvals() {
    let f = fixture();
    let owner = f.app.human_owner();
    assert!(!admitted(&f, UID));
    let issued = invite(&f, "ci");
    assert!(admitted(&f, UID));
    assert!(!admitted(&f, UID + 1));
    let key = SigningKey::from_bytes(&[59; 32]);
    let session = join(&f, &issued, &key).unwrap();
    assert!(matches!(
        confirm(&f, &session, &key),
        EnrollmentState::AwaitingApprovals {
            provider_approved: false,
            joiner_confirmed: true
        }
    ));
    assert!(
        f.app.list_agents(owner).unwrap().is_empty(),
        "the agent alone enrolls nothing"
    );
    f.app
        .enrollment_approve(owner, &issued.id, &session.comparison_code)
        .unwrap();
    assert!(f.app.list_agents(owner).unwrap().is_empty());
    let EnrollmentState::Enrolled {
        identity: EnrolledIdentity::Agent { binding_id, .. },
    } = confirm(&f, &session, &key)
    else {
        panic!("not enrolled")
    };
    let agents = f.app.list_agents(owner).unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].id, binding_id);
    assert_eq!(agents[0].label, "ci");
    assert_eq!((agents[0].uid, agents[0].gid), (UID, GID));
    assert_eq!(agents[0].status, AgentBindingStatus::Enabled);
    assert!(f.app.agent_peer_eligible(UID, &[GID]).is_ok());
    // A lost final reply is recoverable: the joiner may still read the outcome.
    assert!(matches!(
        f.app
            .enrollment_agent_message(UID, &[GID], &session.status()),
        EnrollmentReply::State {
            state: EnrollmentState::Enrolled { .. },
            ..
        }
    ));
    // A second invitation for the same enabled label is refused up front.
    assert_eq!(
        f.app
            .enrollment_invite(
                owner,
                InvitationRequest {
                    kind: kind("ci"),
                    ttl_seconds: None
                }
            )
            .err(),
        Some(HumanEnrollmentError::Duplicate)
    );
}

#[test]
fn a_revoked_agent_key_is_never_reactivated_by_a_matching_name() {
    let f = fixture();
    let owner = f.app.human_owner();
    let old = SigningKey::from_bytes(&[60; 32]);
    let paired = f
        .app
        .pair_agent(
            owner,
            AgentPairing {
                label: "ci".into(),
                public_key: encode_public_key(&old.verifying_key()),
                uid: UID,
                gid: GID,
            },
        )
        .unwrap();
    f.app.revoke_agent(owner, &paired.id).unwrap();
    // Same label, same OS identity, same key: refused before any code exists.
    let issued = invite(&f, "ci");
    let refused = join(&f, &issued, &old).err().unwrap();
    assert_eq!(
        refused,
        EnrollmentReply::Rejected {
            protocol_version: 1,
            reason: EnrollmentRejection::IdentityRefused
        }
    );
    // A new key may take the label; the revoked binding stays revoked.
    let issued = invite(&f, "ci");
    let new = SigningKey::from_bytes(&[61; 32]);
    let session = join(&f, &issued, &new).unwrap();
    f.app
        .enrollment_approve(owner, &issued.id, &session.comparison_code)
        .unwrap();
    assert!(matches!(
        confirm(&f, &session, &new),
        EnrollmentState::Enrolled { .. }
    ));
    let agents = f.app.list_agents(owner).unwrap();
    assert_eq!(agents.len(), 2);
    let old_view = agents.iter().find(|a| a.id == paired.id).unwrap();
    assert_eq!(old_view.status, AgentBindingStatus::Revoked);
    assert!(
        agents
            .iter()
            .any(|a| a.id != paired.id && a.status == AgentBindingStatus::Enabled)
    );
}

#[test]
fn invitations_expire_on_the_provider_clock_and_shutdown_refuses_enrollment() {
    let f = fixture();
    let owner = f.app.human_owner();
    let issued = invite(&f, "ci");
    let key = SigningKey::from_bytes(&[62; 32]);
    let session = join(&f, &issued, &key).unwrap();
    f.monotonic
        .fetch_add(issued.expires_in_seconds, Ordering::SeqCst);
    assert_eq!(
        f.app
            .enrollment_approve(owner, &issued.id, &session.comparison_code),
        Err(HumanEnrollmentError::Expired)
    );
    assert_eq!(confirm(&f, &session, &key), EnrollmentState::Expired {});
    f.monotonic.fetch_add(
        crate::access::enrollment::FINAL_RETENTION.as_secs(),
        Ordering::SeqCst,
    );
    assert!(!admitted(&f, UID));
    assert!(f.app.list_agents(owner).unwrap().is_empty());
    // Closed admission (shutdown) refuses every enrollment action.
    f.app.close_admission();
    assert_eq!(
        f.app.enrollment_list(owner),
        Err(HumanEnrollmentError::Unavailable)
    );
}

/// A poisoned session lock is a provider fault for admission too, as for
/// every enrollment action (`enrollment_book`): never "not invited".
#[test]
fn a_poisoned_session_lock_makes_admission_unavailable() {
    let f = fixture();
    let _issued = invite(&f, "poisoned");
    assert!(admitted(&f, UID));
    f.app.enrollment_poison_for_test();
    assert_eq!(
        f.app.enrollment_peer_eligible(UID, &[GID]),
        crate::access::enrollment::EnrollmentAdmission::Unavailable
    );
    assert_eq!(
        f.app.enrollment_list(f.app.human_owner()),
        Err(HumanEnrollmentError::Unavailable)
    );
}
