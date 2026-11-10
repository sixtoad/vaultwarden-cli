//! Protocol and state-machine tests: every failure case in
//! `docs/guided-enrollment.md` without any transport or provider store.
use super::{
    book::{Book, EnrollmentHooks, Joiner},
    joiner::{InvitationCode, JoinAttempt, JoinedSession, JoinerError},
    wire::{EnrollmentReply, EnrollmentRequest},
    *,
};
use ed25519_dalek::SigningKey;
use std::time::Duration;

const PROVIDER_FP: &str = "aa00000000000000000000000000000000000000000000000000000000000001";
const DEVICE_FP: &str = "bb00000000000000000000000000000000000000000000000000000000000002";
const OTHER_FP: &str = "cc00000000000000000000000000000000000000000000000000000000000003";
const OWNER: u32 = 501;

#[derive(Default)]
struct Hooks {
    refused: Vec<String>,
    /// The identity store cannot answer `admissible`.
    store_down: bool,
    commits: Vec<(EnrolleeKind, Joiner, u32)>,
    fail_commit: Option<FailureReason>,
}
impl EnrollmentHooks for Hooks {
    fn admissible(&mut self, _: &EnrolleeKind, joiner: &Joiner) -> Result<bool, FailureReason> {
        if self.store_down {
            return Err(FailureReason::Unavailable);
        }
        Ok(!self.refused.contains(&joiner.fingerprint))
    }
    fn commit(
        &mut self,
        kind: &EnrolleeKind,
        joiner: &Joiner,
        approver: u32,
    ) -> Result<EnrolledIdentity, FailureReason> {
        if let Some(reason) = self.fail_commit {
            return Err(reason);
        }
        self.commits.push((kind.clone(), joiner.clone(), approver));
        Ok(match kind {
            EnrolleeKind::Agent { .. } => EnrolledIdentity::Agent {
                binding_id: "binding".into(),
                fingerprint: joiner.fingerprint.clone(),
            },
            EnrolleeKind::Companion { .. } => EnrolledIdentity::Companion {
                fingerprint: joiner.fingerprint.clone(),
            },
        })
    }
}

fn agent_kind() -> EnrolleeKind {
    EnrolleeKind::Agent {
        label: "build agent".into(),
        uid: 4100,
        gid: 4200,
    }
}
fn agent_peer() -> Peer {
    Peer::Agent {
        uid: 4100,
        groups: vec![20, 4200],
    }
}
fn companion_peer(fp: &str) -> Peer {
    Peer::Companion {
        fingerprint: fp.into(),
    }
}
fn now(seconds: u64) -> Duration {
    Duration::from_secs(1_000 + seconds)
}
fn random(seed: u8) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8).wrapping_mul(7) | 1;
    }
    out
}
fn invite(book: &mut Book, kind: EnrolleeKind, seed: u8) -> IssuedInvitation {
    book.invite(
        InvitationRequest {
            kind,
            ttl_seconds: None,
        },
        now(0),
        &random(seed),
    )
    .unwrap()
}
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn send(
    book: &mut Book,
    peer: &Peer,
    request: &EnrollmentRequest,
    at: u64,
    hooks: &mut Hooks,
) -> EnrollmentReply {
    let provider = match peer {
        Peer::Agent { .. } => Vec::new(),
        Peer::Companion { .. } => unhex32(PROVIDER_FP).unwrap().to_vec(),
    };
    book.handle(peer, &provider, request, now(at), [9u8; 32], hooks)
}
fn agent_join(book: &mut Book, issued: &IssuedInvitation, hooks: &mut Hooks) -> JoinedSession {
    let attempt = JoinAttempt::agent(
        InvitationCode::parse(&issued.invitation_code).unwrap(),
        &key(3),
        [5u8; 32],
    );
    let reply = send(book, &agent_peer(), attempt.request(), 1, hooks);
    attempt.accept(&reply).unwrap()
}
fn state_of(reply: &EnrollmentReply) -> EnrollmentState {
    match reply {
        EnrollmentReply::State { state, .. } => state.clone(),
        other => panic!("expected state, got {other:?}"),
    }
}
fn rejection(reply: &EnrollmentReply) -> EnrollmentRejection {
    match reply {
        EnrollmentReply::Rejected { reason, .. } => *reason,
        other => panic!("expected rejection, got {other:?}"),
    }
}
fn view(book: &mut Book, id: &str, at: u64) -> EnrollmentView {
    book.list(now(at)).into_iter().find(|v| v.id == id).unwrap()
}

#[test]
fn agent_happy_path_requires_both_humans_and_shows_the_same_code() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let issued = invite(&mut book, agent_kind(), 1);
    assert!(issued.invitation_code.starts_with("vwe1."));
    assert!(!format!("{issued:?}").contains(&issued.invitation_code));
    let joined = agent_join(&mut book, &issued, &mut hooks);
    assert_eq!(joined.kind, agent_kind());
    let provider_view = view(&mut book, &issued.id, 2);
    assert_eq!(
        provider_view.joiner_fingerprint,
        Some(hex(&transcript::hash(&key(3).verifying_key().to_bytes())))
    );
    assert!(joined.comparison_code.len() == 9 && joined.comparison_code.as_bytes()[4] == b'-');
    // The joiner's approval alone never enrolls.
    let reply = send(
        &mut book,
        &agent_peer(),
        &joined.confirm(Some(&key(3))),
        3,
        &mut hooks,
    );
    assert_eq!(
        state_of(&reply),
        EnrollmentState::AwaitingApprovals {
            provider_approved: false,
            joiner_confirmed: true
        }
    );
    assert!(hooks.commits.is_empty());
    let approved = book
        .approve(
            &issued.id,
            &joined.comparison_code.replace('-', ""),
            OWNER,
            now(4),
        )
        .unwrap();
    assert_eq!(
        approved.state,
        EnrollmentState::AwaitingApprovals {
            provider_approved: true,
            joiner_confirmed: true
        }
    );
    assert!(
        hooks.commits.is_empty(),
        "commit happens on the joiner's channel"
    );
    let reply = send(
        &mut book,
        &agent_peer(),
        &joined.confirm(Some(&key(3))),
        5,
        &mut hooks,
    );
    let EnrollmentState::Enrolled { identity } = state_of(&reply) else {
        panic!("not enrolled")
    };
    assert!(matches!(identity, EnrolledIdentity::Agent { .. }));
    assert_eq!(hooks.commits.len(), 1);
    assert_eq!(hooks.commits[0].2, OWNER);
    assert_eq!(
        hooks.commits[0].1.public_key.as_deref(),
        Some(b64(&key(3).verifying_key().to_bytes()).as_str())
    );
    // Confirm and status are idempotent after the commit; no second commit.
    let again = send(
        &mut book,
        &agent_peer(),
        &joined.confirm(Some(&key(3))),
        6,
        &mut hooks,
    );
    assert!(matches!(state_of(&again), EnrollmentState::Enrolled { .. }));
    assert!(matches!(
        state_of(&send(
            &mut book,
            &agent_peer(),
            &joined.status(),
            6,
            &mut hooks
        )),
        EnrollmentState::Enrolled { .. }
    ));
    assert_eq!(hooks.commits.len(), 1);
}

/// The owner learns the code only from the joiner's screen and types it. A
/// code the provider printed could be copied into `approve` without ever
/// looking at the joiner, which would void the comparison.
#[test]
fn the_provider_never_displays_the_comparison_code() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let issued = invite(&mut book, agent_kind(), 1);
    let joined = agent_join(&mut book, &issued, &mut hooks);
    let digits = joined.comparison_code.replace('-', "");
    let leaks = |views: &[EnrollmentView]| {
        let text = serde_json::to_string(views).unwrap();
        text.contains(&joined.comparison_code) || text.contains(&digits)
    };
    assert!(!leaks(&book.list(now(2))), "joined, nothing approved");
    send(
        &mut book,
        &agent_peer(),
        &joined.confirm(Some(&key(3))),
        3,
        &mut hooks,
    );
    assert!(!leaks(&book.list(now(3))), "joiner confirmed");
    let approved = book
        .approve(&issued.id, &joined.comparison_code, OWNER, now(4))
        .unwrap();
    assert!(!leaks(std::slice::from_ref(&approved)), "approve reply");
    assert!(!leaks(&book.list(now(4))), "provider approved");
}

/// Agent-socket admission after a final state: a joined session keeps
/// admitting its joiner while retained, whatever its end, so the joiner
/// learns that end (a lost final reply, a relay, a leaked secret). A final
/// session nobody joined admits nobody.
#[test]
fn a_joined_session_keeps_admitting_its_joiner_while_retained() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let unjoined = invite(&mut book, agent_kind(), 3);
    book.cancel(&unjoined.id, now(1)).unwrap();
    assert!(!book.peer_eligible(&agent_peer(), now(1)));
    let cancelled = invite(&mut book, agent_kind(), 2);
    let joined = agent_join(&mut book, &cancelled, &mut hooks);
    book.cancel(&cancelled.id, now(1)).unwrap();
    assert!(book.peer_eligible(&agent_peer(), now(1)));
    let reply = send(&mut book, &agent_peer(), &joined.status(), 1, &mut hooks);
    assert_eq!(
        state_of(&reply),
        EnrollmentState::Cancelled {
            by: Party::Provider
        }
    );
    let issued = invite(&mut book, agent_kind(), 1);
    let joined = agent_join(&mut book, &issued, &mut hooks);
    book.approve(&issued.id, &joined.comparison_code, OWNER, now(2))
        .unwrap();
    send(
        &mut book,
        &agent_peer(),
        &joined.confirm(Some(&key(3))),
        3,
        &mut hooks,
    );
    assert!(book.peer_eligible(&agent_peer(), now(4)));
    let forgotten = 3 + FINAL_RETENTION.as_secs();
    assert!(!book.peer_eligible(&agent_peer(), now(forgotten)));
}

/// A wrong code typed at the provider (e.g. a relay between the endpoints)
/// is the joiner's MITM signal: it must reach the joiner, not be hidden
/// behind a pre-parse refusal.
#[test]
fn a_code_mismatch_reaches_the_admitted_joiner() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let issued = invite(&mut book, agent_kind(), 1);
    let joined = agent_join(&mut book, &issued, &mut hooks);
    let wrong = if joined.comparison_code == "0000-0000" {
        "0000-0001"
    } else {
        "0000-0000"
    };
    assert_eq!(
        book.approve(&issued.id, wrong, OWNER, now(2)),
        Err(HumanEnrollmentError::CodeMismatch)
    );
    assert!(book.peer_eligible(&agent_peer(), now(3)));
    let reply = send(
        &mut book,
        &agent_peer(),
        &joined.confirm(Some(&key(3))),
        3,
        &mut hooks,
    );
    assert_eq!(
        state_of(&reply),
        EnrollmentState::Aborted {
            reason: AbortReason::CodeMismatch
        }
    );
}

/// A second join (the secret leaked) is the legitimate joiner's signal too.
#[test]
fn a_duplicate_join_reaches_the_admitted_joiner() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let issued = invite(&mut book, agent_kind(), 1);
    let joined = agent_join(&mut book, &issued, &mut hooks);
    let intruder = JoinAttempt::agent(
        InvitationCode::parse(&issued.invitation_code).unwrap(),
        &key(4),
        [6; 32],
    );
    let refused = send(&mut book, &agent_peer(), intruder.request(), 2, &mut hooks);
    assert_eq!(rejection(&refused), EnrollmentRejection::AlreadyUsed);
    assert!(book.peer_eligible(&agent_peer(), now(3)));
    let reply = send(&mut book, &agent_peer(), &joined.status(), 3, &mut hooks);
    assert_eq!(
        state_of(&reply),
        EnrollmentState::Aborted {
            reason: AbortReason::DuplicateJoin
        }
    );
}

#[test]
fn provider_may_approve_first_and_the_joiner_confirmation_commits() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let issued = invite(&mut book, agent_kind(), 1);
    assert_eq!(
        book.approve(&issued.id, "1234-5678", OWNER, now(1)),
        Err(HumanEnrollmentError::AwaitingPeer),
        "offline peer: nothing to compare yet"
    );
    let joined = agent_join(&mut book, &issued, &mut hooks);
    book.approve(&issued.id, &joined.comparison_code, OWNER, now(2))
        .unwrap();
    let reply = send(
        &mut book,
        &agent_peer(),
        &joined.confirm(Some(&key(3))),
        3,
        &mut hooks,
    );
    assert!(matches!(state_of(&reply), EnrollmentState::Enrolled { .. }));
}

#[test]
fn companion_happy_path_is_bound_to_both_tls_identities() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let kind = EnrolleeKind::Companion {
        label: "Studio Mac".into(),
    };
    let issued = invite(&mut book, kind.clone(), 2);
    let code = || InvitationCode::parse(&issued.invitation_code).unwrap();
    // A joiner pinned to another provider certificate computes another
    // transcript: the provider rejects its proof.
    let wrong_pin = JoinAttempt::companion(code(), DEVICE_FP, OTHER_FP, [1; 32]).unwrap();
    let reply = send(
        &mut book,
        &companion_peer(DEVICE_FP),
        wrong_pin.request(),
        1,
        &mut hooks,
    );
    assert_eq!(rejection(&reply), EnrollmentRejection::InvalidInvitation);
    let attempt = JoinAttempt::companion(code(), DEVICE_FP, PROVIDER_FP, [1; 32]).unwrap();
    let reply = send(
        &mut book,
        &companion_peer(DEVICE_FP),
        attempt.request(),
        1,
        &mut hooks,
    );
    let joined = attempt.accept(&reply).unwrap();
    assert_eq!(
        view(&mut book, &issued.id, 1).joiner_fingerprint.as_deref(),
        Some(DEVICE_FP)
    );
    // Another CA-valid device cannot act on this session, even with the secret.
    let reply = send(
        &mut book,
        &companion_peer(OTHER_FP),
        &joined.confirm(None),
        2,
        &mut hooks,
    );
    assert_eq!(rejection(&reply), EnrollmentRejection::InvalidInvitation);
    book.approve(&issued.id, &joined.comparison_code, OWNER, now(3))
        .unwrap();
    let reply = send(
        &mut book,
        &companion_peer(DEVICE_FP),
        &joined.confirm(None),
        4,
        &mut hooks,
    );
    assert_eq!(
        state_of(&reply),
        EnrollmentState::Enrolled {
            identity: EnrolledIdentity::Companion {
                fingerprint: DEVICE_FP.into()
            }
        }
    );
}

#[test]
fn code_mismatch_at_the_provider_aborts_and_never_commits() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let issued = invite(&mut book, agent_kind(), 1);
    let joined = agent_join(&mut book, &issued, &mut hooks);
    send(
        &mut book,
        &agent_peer(),
        &joined.confirm(Some(&key(3))),
        2,
        &mut hooks,
    );
    let wrong = if joined.comparison_code == "0000-0000" {
        "0000-0001"
    } else {
        "0000-0000"
    };
    assert_eq!(
        book.approve(&issued.id, "not a code", OWNER, now(2)),
        Err(HumanEnrollmentError::InvalidRequest),
        "a typo in the format does not burn the session"
    );
    assert_eq!(
        book.approve(&issued.id, wrong, OWNER, now(3)),
        Err(HumanEnrollmentError::CodeMismatch)
    );
    assert_eq!(
        book.approve(&issued.id, &joined.comparison_code, OWNER, now(4)),
        Err(HumanEnrollmentError::Final),
        "no retry after a mismatch"
    );
    let reply = send(
        &mut book,
        &agent_peer(),
        &joined.confirm(Some(&key(3))),
        5,
        &mut hooks,
    );
    assert_eq!(
        state_of(&reply),
        EnrollmentState::Aborted {
            reason: AbortReason::CodeMismatch
        }
    );
    assert!(hooks.commits.is_empty());
}

#[test]
fn joiner_reported_mismatch_and_cancellation_are_final() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let issued = invite(&mut book, agent_kind(), 1);
    let joined = agent_join(&mut book, &issued, &mut hooks);
    let reply = send(
        &mut book,
        &agent_peer(),
        &joined.cancel(JoinerCancelReason::CodeMismatch),
        2,
        &mut hooks,
    );
    assert_eq!(
        state_of(&reply),
        EnrollmentState::Aborted {
            reason: AbortReason::JoinerReportedMismatch
        }
    );
    assert_eq!(
        book.approve(&issued.id, &joined.comparison_code, OWNER, now(3)),
        Err(HumanEnrollmentError::Final)
    );

    let issued = invite(&mut book, agent_kind(), 7);
    let joined = agent_join(&mut book, &issued, &mut hooks);
    let reply = send(
        &mut book,
        &agent_peer(),
        &joined.cancel(JoinerCancelReason::Cancelled),
        2,
        &mut hooks,
    );
    assert_eq!(
        state_of(&reply),
        EnrollmentState::Cancelled { by: Party::Joiner }
    );
    assert!(hooks.commits.is_empty());
}

#[test]
fn provider_cancellation_stops_a_session_in_any_live_phase() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let issued = invite(&mut book, agent_kind(), 1);
    assert_eq!(
        book.cancel(&issued.id, now(1)).unwrap().state,
        EnrollmentState::Cancelled {
            by: Party::Provider
        }
    );
    let attempt = JoinAttempt::agent(
        InvitationCode::parse(&issued.invitation_code).unwrap(),
        &key(3),
        [5; 32],
    );
    assert_eq!(
        rejection(&send(
            &mut book,
            &agent_peer(),
            attempt.request(),
            2,
            &mut hooks
        )),
        EnrollmentRejection::AlreadyUsed
    );
    assert_eq!(
        book.cancel(&issued.id, now(3)),
        Err(HumanEnrollmentError::Final)
    );
    // Cancelled after both approvals but before the commit: nothing enrolls.
    let issued = invite(&mut book, agent_kind(), 9);
    let joined = agent_join(&mut book, &issued, &mut hooks);
    book.approve(&issued.id, &joined.comparison_code, OWNER, now(2))
        .unwrap();
    book.cancel(&issued.id, now(3)).unwrap();
    let reply = send(
        &mut book,
        &agent_peer(),
        &joined.confirm(Some(&key(3))),
        4,
        &mut hooks,
    );
    assert_eq!(
        state_of(&reply),
        EnrollmentState::Cancelled {
            by: Party::Provider
        }
    );
    assert!(hooks.commits.is_empty());
    assert_eq!(
        book.cancel("unknown", now(5)),
        Err(HumanEnrollmentError::NotFound)
    );
}

#[test]
fn invitations_expire_and_expired_sessions_are_forgotten_later() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let issued = book
        .invite(
            InvitationRequest {
                kind: agent_kind(),
                ttl_seconds: Some(MIN_TTL_SECONDS),
            },
            now(0),
            &random(1),
        )
        .unwrap();
    let joined = agent_join(&mut book, &issued, &mut hooks);
    book.approve(&issued.id, &joined.comparison_code, OWNER, now(2))
        .unwrap();
    // Both approvals present, but the joiner's confirmation arrives too late.
    let late = MIN_TTL_SECONDS;
    let reply = send(
        &mut book,
        &agent_peer(),
        &joined.confirm(Some(&key(3))),
        late,
        &mut hooks,
    );
    assert_eq!(state_of(&reply), EnrollmentState::Expired {});
    assert!(hooks.commits.is_empty());
    assert_eq!(
        book.approve(&issued.id, &joined.comparison_code, OWNER, now(late)),
        Err(HumanEnrollmentError::Expired)
    );
    // The joined session still admits its joiner while retained, so it
    // learns `expired` rather than an unexplained refusal.
    assert!(book.peer_eligible(&agent_peer(), now(late)));
    let forgotten = late + FINAL_RETENTION.as_secs();
    assert!(book.list(now(forgotten)).is_empty());
    let reply = send(
        &mut book,
        &agent_peer(),
        &joined.status(),
        forgotten,
        &mut hooks,
    );
    assert_eq!(rejection(&reply), EnrollmentRejection::InvalidInvitation);

    let issued = invite(&mut book, agent_kind(), 4);
    let attempt = JoinAttempt::agent(
        InvitationCode::parse(&issued.invitation_code).unwrap(),
        &key(3),
        [5; 32],
    );
    let expired_join = book.handle(
        &agent_peer(),
        &[],
        attempt.request(),
        now(DEFAULT_TTL_SECONDS),
        [9; 32],
        &mut hooks,
    );
    assert_eq!(rejection(&expired_join), EnrollmentRejection::Expired);
}

#[test]
fn a_retransmitted_join_is_idempotent_but_a_different_join_burns_the_invitation() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let issued = invite(&mut book, agent_kind(), 1);
    let code = || InvitationCode::parse(&issued.invitation_code).unwrap();
    let attempt = JoinAttempt::agent(code(), &key(3), [5; 32]);
    let first = send(&mut book, &agent_peer(), attempt.request(), 1, &mut hooks);
    let second = send(&mut book, &agent_peer(), attempt.request(), 2, &mut hooks);
    assert_eq!(first, second, "a lost reply is recovered by resending");
    // The secret leaked: a second key joins the same invitation.
    let intruder = JoinAttempt::agent(code(), &key(4), [6; 32]);
    let reply = send(&mut book, &agent_peer(), intruder.request(), 3, &mut hooks);
    assert_eq!(rejection(&reply), EnrollmentRejection::AlreadyUsed);
    assert_eq!(
        view(&mut book, &issued.id, 3).state,
        EnrollmentState::Aborted {
            reason: AbortReason::DuplicateJoin
        }
    );
    // Replaying the original join after the session finished is refused too.
    let replay = send(&mut book, &agent_peer(), attempt.request(), 5, &mut hooks);
    assert_eq!(rejection(&replay), EnrollmentRejection::AlreadyUsed);
    let joined = attempt.accept(&first).unwrap();
    assert_eq!(
        book.approve(&issued.id, &joined.comparison_code, OWNER, now(4)),
        Err(HumanEnrollmentError::Final)
    );
}

#[test]
fn replay_across_invitations_channels_and_after_enrollment_is_refused() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let first = invite(&mut book, agent_kind(), 1);
    let joined = agent_join(&mut book, &first, &mut hooks);
    book.approve(&first.id, &joined.comparison_code, OWNER, now(2))
        .unwrap();
    let confirm = joined.confirm(Some(&key(3)));
    send(&mut book, &agent_peer(), &confirm, 3, &mut hooks);
    assert_eq!(hooks.commits.len(), 1);
    // The same confirm against a new invitation for the same agent: other
    // invitation id and secret, so the MAC does not verify.
    let second = invite(&mut book, agent_kind(), 2);
    let EnrollmentRequest::EnrollConfirm { mac, signature, .. } = confirm.clone() else {
        panic!("not a confirm")
    };
    let moved = EnrollmentRequest::EnrollConfirm {
        protocol_version: ENROLLMENT_PROTOCOL_VERSION,
        invitation_id: second.id.clone(),
        mac,
        signature,
    };
    assert_eq!(
        rejection(&send(&mut book, &agent_peer(), &moved, 4, &mut hooks)),
        EnrollmentRejection::InvalidInvitation
    );
    // A confirm before any join has no transcript to bind to.
    assert_eq!(
        rejection(&send(&mut book, &agent_peer(), &moved, 4, &mut hooks)),
        EnrollmentRejection::InvalidInvitation
    );
    assert_eq!(hooks.commits.len(), 1);
    // An agent join sent from a companion connection is refused.
    let attempt = JoinAttempt::agent(
        InvitationCode::parse(&second.invitation_code).unwrap(),
        &key(8),
        [1; 32],
    );
    assert_eq!(
        rejection(&send(
            &mut book,
            &companion_peer(DEVICE_FP),
            attempt.request(),
            5,
            &mut hooks
        )),
        EnrollmentRejection::InvalidInvitation
    );
}

#[test]
fn wrong_proofs_are_indistinguishable_from_unknown_ids_and_burn_after_three() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let issued = invite(&mut book, agent_kind(), 1);
    let real = InvitationCode::parse(&issued.invitation_code).unwrap();
    let forged_code = format!("vwe1.{}.{}", real.id(), b64(&[0x42; 32]));
    let unknown_code = format!("vwe1.{}.{}", b64(&[0x43; 32]), b64(&[0x42; 32]));
    let unknown = JoinAttempt::agent(
        InvitationCode::parse(&unknown_code).unwrap(),
        &key(3),
        [5; 32],
    );
    let reply = send(&mut book, &agent_peer(), unknown.request(), 1, &mut hooks);
    assert_eq!(rejection(&reply), EnrollmentRejection::InvalidInvitation);
    for attempt in 0..MAX_PROOF_FAILURES {
        let forged = JoinAttempt::agent(
            InvitationCode::parse(&forged_code).unwrap(),
            &key(3),
            [attempt; 32],
        );
        let reply = send(&mut book, &agent_peer(), forged.request(), 1, &mut hooks);
        assert_eq!(rejection(&reply), EnrollmentRejection::InvalidInvitation);
    }
    assert_eq!(
        view(&mut book, &issued.id, 2).state,
        EnrollmentState::Aborted {
            reason: AbortReason::TooManyFailures
        }
    );
    let honest = JoinAttempt::agent(real, &key(3), [5; 32]);
    let reply = send(&mut book, &agent_peer(), honest.request(), 3, &mut hooks);
    assert_eq!(rejection(&reply), EnrollmentRejection::AlreadyUsed);
}

#[test]
fn the_joiner_rejects_a_provider_without_the_secret() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let issued = invite(&mut book, agent_kind(), 1);
    let attempt = JoinAttempt::agent(
        InvitationCode::parse(&issued.invitation_code).unwrap(),
        &key(3),
        [5; 32],
    );
    let EnrollmentReply::Joined {
        protocol_version,
        invitation_id,
        kind,
        provider_nonce,
        expires_in_seconds,
        ..
    } = send(&mut book, &agent_peer(), attempt.request(), 1, &mut hooks)
    else {
        panic!("not joined")
    };
    // A substituted role (e.g. a different uid) breaks the provider's MAC.
    let forged = EnrollmentReply::Joined {
        protocol_version,
        invitation_id: invitation_id.clone(),
        kind: EnrolleeKind::Agent {
            label: "build agent".into(),
            uid: 4101,
            gid: 4200,
        },
        provider_nonce: provider_nonce.clone(),
        provider_mac: b64(&[7; 32]),
        expires_in_seconds,
    };
    assert_eq!(
        attempt.accept(&forged).err(),
        Some(JoinerError::ProviderNotAuthenticated)
    );
    assert_eq!(kind, agent_kind());
    assert!(InvitationCode::parse("vwe2.a.b").is_err());
    assert!(InvitationCode::parse(&format!("vwe1.{}", b64(&[1; 32]))).is_err());
}

#[test]
fn an_agent_must_prove_possession_of_the_key_it_joined_with() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let issued = invite(&mut book, agent_kind(), 1);
    let joined = agent_join(&mut book, &issued, &mut hooks);
    book.approve(&issued.id, &joined.comparison_code, OWNER, now(2))
        .unwrap();
    let wrong_key = send(
        &mut book,
        &agent_peer(),
        &joined.confirm(Some(&key(4))),
        3,
        &mut hooks,
    );
    assert_eq!(
        rejection(&wrong_key),
        EnrollmentRejection::InvalidInvitation
    );
    let no_key = send(
        &mut book,
        &agent_peer(),
        &joined.confirm(None),
        3,
        &mut hooks,
    );
    assert_eq!(rejection(&no_key), EnrollmentRejection::Malformed);
    assert!(hooks.commits.is_empty());
}

#[test]
fn only_the_invited_os_identity_reaches_or_acts_on_an_agent_invitation() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let issued = invite(&mut book, agent_kind(), 1);
    assert!(book.peer_eligible(&agent_peer(), now(1)));
    let other_uid = Peer::Agent {
        uid: 4101,
        groups: vec![4200],
    };
    let missing_group = Peer::Agent {
        uid: 4100,
        groups: vec![20],
    };
    assert!(!book.peer_eligible(&other_uid, now(1)));
    assert!(!book.peer_eligible(&missing_group, now(1)));
    assert!(!book.peer_eligible(&companion_peer(DEVICE_FP), now(1)));
    let attempt = JoinAttempt::agent(
        InvitationCode::parse(&issued.invitation_code).unwrap(),
        &key(3),
        [5; 32],
    );
    let reply = send(&mut book, &other_uid, attempt.request(), 1, &mut hooks);
    assert_eq!(rejection(&reply), EnrollmentRejection::InvalidInvitation);
    assert_eq!(
        view(&mut book, &issued.id, 1).state,
        EnrollmentState::AwaitingJoin {}
    );
}

#[test]
fn a_revoked_or_known_identity_is_refused_before_any_code_is_shown() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let issued = invite(&mut book, agent_kind(), 1);
    hooks
        .refused
        .push(hex(&transcript::hash(&key(3).verifying_key().to_bytes())));
    let attempt = JoinAttempt::agent(
        InvitationCode::parse(&issued.invitation_code).unwrap(),
        &key(3),
        [5; 32],
    );
    let reply = send(&mut book, &agent_peer(), attempt.request(), 1, &mut hooks);
    assert_eq!(rejection(&reply), EnrollmentRejection::IdentityRefused);
    let refused = view(&mut book, &issued.id, 1);
    assert_eq!(
        refused.state,
        EnrollmentState::Failed {
            reason: FailureReason::IdentityRefused
        }
    );
    assert!(refused.joiner_fingerprint.is_none());
}

#[test]
fn a_store_that_cannot_answer_at_join_is_unavailable_and_burns_nothing() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let issued = invite(&mut book, agent_kind(), 1);
    let attempt = JoinAttempt::agent(
        InvitationCode::parse(&issued.invitation_code).unwrap(),
        &key(3),
        [5; 32],
    );
    hooks.store_down = true;
    let reply = send(&mut book, &agent_peer(), attempt.request(), 1, &mut hooks);
    assert_eq!(rejection(&reply), EnrollmentRejection::Unavailable);
    assert_eq!(
        view(&mut book, &issued.id, 1).state,
        EnrollmentState::AwaitingJoin {}
    );
    hooks.store_down = false;
    let reply = send(&mut book, &agent_peer(), attempt.request(), 2, &mut hooks);
    assert!(attempt.accept(&reply).is_ok());
}

#[test]
fn a_store_refusal_at_commit_fails_the_session_without_enrolling() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    hooks.fail_commit = Some(FailureReason::IdentityRefused);
    let issued = invite(&mut book, agent_kind(), 1);
    let joined = agent_join(&mut book, &issued, &mut hooks);
    book.approve(&issued.id, &joined.comparison_code, OWNER, now(2))
        .unwrap();
    let reply = send(
        &mut book,
        &agent_peer(),
        &joined.confirm(Some(&key(3))),
        3,
        &mut hooks,
    );
    assert_eq!(
        state_of(&reply),
        EnrollmentState::Failed {
            reason: FailureReason::IdentityRefused
        }
    );
}

#[test]
fn invitation_requests_are_bounded_and_duplicates_are_refused() {
    let mut book = Book::default();
    let bad = [
        InvitationRequest {
            kind: agent_kind(),
            ttl_seconds: Some(MIN_TTL_SECONDS - 1),
        },
        InvitationRequest {
            kind: agent_kind(),
            ttl_seconds: Some(MAX_TTL_SECONDS + 1),
        },
        InvitationRequest {
            kind: EnrolleeKind::Agent {
                label: "".into(),
                uid: 4100,
                gid: 4200,
            },
            ttl_seconds: None,
        },
        InvitationRequest {
            kind: EnrolleeKind::Agent {
                label: "ok".into(),
                uid: 0,
                gid: 4200,
            },
            ttl_seconds: None,
        },
        InvitationRequest {
            kind: EnrolleeKind::Companion {
                label: "bad\nlabel".into(),
            },
            ttl_seconds: None,
        },
    ];
    for request in bad {
        assert_eq!(
            book.invite(request, now(0), &random(1)),
            Err(HumanEnrollmentError::InvalidRequest)
        );
    }
    invite(&mut book, agent_kind(), 1);
    assert_eq!(
        book.invite(
            InvitationRequest {
                kind: agent_kind(),
                ttl_seconds: None
            },
            now(0),
            &random(2)
        ),
        Err(HumanEnrollmentError::Duplicate)
    );
    for index in 1..MAX_LIVE_INVITATIONS {
        invite(
            &mut book,
            EnrolleeKind::Companion {
                label: format!("device {index}"),
            },
            10 + index as u8,
        );
    }
    assert_eq!(
        book.invite(
            InvitationRequest {
                kind: EnrolleeKind::Companion {
                    label: "one too many".into()
                },
                ttl_seconds: None
            },
            now(0),
            &random(99)
        ),
        Err(HumanEnrollmentError::LimitReached)
    );
}

#[test]
fn wire_messages_are_closed_and_versioned() {
    let issued_id = b64(&[1; 32]);
    let ok = format!(
        r#"{{"purpose":"enroll_status","protocol_version":1,"invitation_id":"{issued_id}","mac":"{issued_id}"}}"#
    );
    assert!(EnrollmentRequest::parse(ok.as_bytes()).is_ok());
    let unknown_field = ok.replace("\"mac\"", "\"extra\":1,\"mac\"");
    assert_eq!(
        EnrollmentRequest::parse(unknown_field.as_bytes()),
        Err(EnrollmentRejection::Malformed)
    );
    let version = ok.replace("\"protocol_version\":1", "\"protocol_version\":2");
    assert_eq!(
        EnrollmentRequest::parse(version.as_bytes()),
        Err(EnrollmentRejection::UnsupportedVersion)
    );
    let padded = ok.replace(
        &format!("\"mac\":\"{issued_id}\""),
        &format!("\"mac\":\"{issued_id}=\""),
    );
    assert_eq!(
        EnrollmentRequest::parse(padded.as_bytes()),
        Err(EnrollmentRejection::Malformed)
    );
    assert_eq!(
        EnrollmentRequest::parse(&vec![b' '; wire::MAX_ENROLLMENT_FRAME_BYTES + 1]),
        Err(EnrollmentRejection::Malformed)
    );
    // An agent submission frame is never an enrollment message.
    assert!(EnrollmentRequest::parse(br#"{"protocol_version":1,"purpose":"submit"}"#).is_err());
}

#[test]
fn comparison_codes_depend_on_every_transcript_input() {
    let secret = [1u8; 32];
    let id = [2u8; 32];
    let join = transcript::join_transcript(Channel::AgentSocket, &id, &[3; 32], &[4; 32], &[]);
    let base = transcript::hash(&transcript::full_transcript(&join, &agent_kind(), &[5; 32]));
    let code = transcript::comparison_code(&secret, &id, &base);
    let variants = [
        transcript::join_transcript(Channel::CompanionMtls, &id, &[3; 32], &[4; 32], &[]),
        transcript::join_transcript(Channel::AgentSocket, &id, &[6; 32], &[4; 32], &[]),
        transcript::join_transcript(Channel::AgentSocket, &id, &[3; 32], &[7; 32], &[]),
        transcript::join_transcript(Channel::AgentSocket, &id, &[3; 32], &[4; 32], &[8]),
    ];
    for other in variants {
        let hash = transcript::hash(&transcript::full_transcript(
            &other,
            &agent_kind(),
            &[5; 32],
        ));
        assert_ne!(transcript::comparison_code(&secret, &id, &hash), code);
    }
    let other_role = transcript::hash(&transcript::full_transcript(
        &join,
        &EnrolleeKind::Companion {
            label: "build agent".into(),
        },
        &[5; 32],
    ));
    assert_ne!(transcript::comparison_code(&secret, &id, &other_role), code);
    assert_ne!(transcript::comparison_code(&[9; 32], &id, &base), code);
    assert_eq!(
        transcript::normalize_code("1234 5678").as_deref(),
        Some("1234-5678")
    );
    assert_eq!(transcript::normalize_code("1234-567"), None);
    assert_eq!(transcript::normalize_code("1234-567x"), None);
    assert!(transcript::codes_equal("1234-5678", "1234-5678"));
    assert!(!transcript::codes_equal("1234-5678", "1234-5679"));
}

/// The joiner's cancel reason is covered by its MAC: a relay that swaps
/// "cancelled" for "code mismatch" (or back) is refused like a wrong proof.
#[test]
fn the_cancel_reason_is_authenticated() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let issued = invite(&mut book, agent_kind(), 1);
    let joined = agent_join(&mut book, &issued, &mut hooks);
    let EnrollmentRequest::EnrollCancel {
        protocol_version,
        invitation_id,
        mac,
        ..
    } = joined.cancel(JoinerCancelReason::Cancelled)
    else {
        panic!("not a cancel")
    };
    let swapped = EnrollmentRequest::EnrollCancel {
        protocol_version,
        invitation_id,
        reason: JoinerCancelReason::CodeMismatch,
        mac,
    };
    let reply = send(&mut book, &agent_peer(), &swapped, 2, &mut hooks);
    assert_eq!(rejection(&reply), EnrollmentRejection::InvalidInvitation);
    assert_eq!(
        view(&mut book, &issued.id, 2).state,
        EnrollmentState::AwaitingApprovals {
            provider_approved: false,
            joiner_confirmed: false
        }
    );
    let reply = send(
        &mut book,
        &agent_peer(),
        &joined.cancel(JoinerCancelReason::Cancelled),
        3,
        &mut hooks,
    );
    assert_eq!(
        state_of(&reply),
        EnrollmentState::Cancelled { by: Party::Joiner }
    );
}

/// When the retained sessions are full, a just-enrolled session (whose
/// joiner may still need its lost final reply) is evicted last.
#[test]
fn eviction_keeps_enrolled_sessions_over_other_finished_ones() {
    let (mut book, mut hooks) = (Book::default(), Hooks::default());
    let issued = invite(&mut book, agent_kind(), 1);
    let joined = agent_join(&mut book, &issued, &mut hooks);
    book.approve(&issued.id, &joined.comparison_code, OWNER, now(2))
        .unwrap();
    send(
        &mut book,
        &agent_peer(),
        &joined.confirm(Some(&key(3))),
        3,
        &mut hooks,
    );
    for seed in 2..=(MAX_RETAINED_SESSIONS as u8) {
        let other = invite(&mut book, agent_kind(), seed);
        book.cancel(&other.id, now(4)).unwrap();
    }
    assert_eq!(book.list(now(5)).len(), MAX_RETAINED_SESSIONS);
    invite(&mut book, agent_kind(), 99);
    let views = book.list(now(5));
    assert_eq!(views.len(), MAX_RETAINED_SESSIONS);
    assert!(
        views
            .iter()
            .any(|v| v.id == issued.id && matches!(v.state, EnrollmentState::Enrolled { .. }))
    );
}
