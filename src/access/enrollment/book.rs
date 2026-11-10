//! In-memory enrollment sessions and their state machine. Pure: the caller
//! supplies time, randomness, the peer's transport identity and the commit.
//!
//! Sessions are deliberately not persisted: a provider restart forgets every
//! invitation, which fails closed (the joiner sees `invalid_invitation`).

use super::{
    AbortReason, DEFAULT_TTL_SECONDS, ENROLLMENT_PROTOCOL_VERSION, EnrolledIdentity, EnrolleeKind,
    EnrollmentRejection, EnrollmentState, EnrollmentView, FINAL_RETENTION, FailureReason,
    HumanEnrollmentError, INVITATION_PREFIX, InvitationRequest, IssuedInvitation,
    JoinerCancelReason, MAX_LIVE_INVITATIONS, MAX_PROOF_FAILURES, MAX_RETAINED_SESSIONS,
    MAX_TTL_SECONDS, MIN_TTL_SECONDS, Party, Peer, b64, decode_fixed, hex,
    transcript::{self as t},
    unhex32,
    wire::{EnrollmentReply, EnrollmentRequest},
};
use std::time::Duration;
use zeroize::Zeroizing;

/// The verified joining endpoint. Its fingerprint is SHA-256 of the agent
/// public key or of the companion's mTLS leaf certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Joiner {
    pub fingerprint: String,
    pub public_key: Option<String>,
}

/// Provider-side effects the book cannot decide alone.
pub trait EnrollmentHooks {
    /// `Ok(false)` refuses an identity that is already enrolled or was ever
    /// revoked, which burns the invitation. `Err` means the store could not
    /// answer: the join is refused as `unavailable` and the invitation stays
    /// open, because a storage fault is no verdict on the joining identity.
    fn admissible(&mut self, kind: &EnrolleeKind, joiner: &Joiner) -> Result<bool, FailureReason>;
    /// Durably enroll; called once, after both humans approved.
    fn commit(
        &mut self,
        kind: &EnrolleeKind,
        joiner: &Joiner,
        approver_uid: u32,
    ) -> Result<EnrolledIdentity, FailureReason>;
}

struct Joined {
    joiner: Joiner,
    join_digest: [u8; 32],
    reply: EnrollmentReply,
    transcript_hash: [u8; 32],
    code: String,
    provider_approver: Option<u32>,
    joiner_confirmed: bool,
}

enum Phase {
    Open,
    Joined(Box<Joined>),
    Final {
        state: EnrollmentState,
        at: Duration,
        joined: Option<Box<Joined>>,
    },
}

struct Session {
    id: [u8; 32],
    id_text: String,
    secret: Zeroizing<[u8; 32]>,
    kind: EnrolleeKind,
    expires_at: Duration,
    failures: u8,
    phase: Phase,
}

impl Session {
    fn live(&self) -> bool {
        !matches!(self.phase, Phase::Final { .. })
    }
    fn state(&self) -> EnrollmentState {
        match &self.phase {
            Phase::Open => EnrollmentState::AwaitingJoin {},
            Phase::Joined(joined) => EnrollmentState::AwaitingApprovals {
                provider_approved: joined.provider_approver.is_some(),
                joiner_confirmed: joined.joiner_confirmed,
            },
            Phase::Final { state, .. } => state.clone(),
        }
    }
    fn finish(&mut self, state: EnrollmentState, now: Duration) {
        let joined = match std::mem::replace(&mut self.phase, Phase::Open) {
            Phase::Joined(joined) => Some(joined),
            Phase::Final { joined, .. } => joined,
            Phase::Open => None,
        };
        self.phase = Phase::Final {
            state,
            at: now,
            joined,
        };
    }
    fn joined(&self) -> Option<&Joined> {
        match &self.phase {
            Phase::Joined(joined) => Some(joined),
            Phase::Final { joined, .. } => joined.as_deref(),
            Phase::Open => None,
        }
    }
    /// A wrong proof of the secret. The third one burns a live invitation.
    fn proof_failed(&mut self, now: Duration) {
        if self.live() {
            self.failures = self.failures.saturating_add(1);
            if self.failures >= MAX_PROOF_FAILURES {
                self.finish(
                    EnrollmentState::Aborted {
                        reason: AbortReason::TooManyFailures,
                    },
                    now,
                );
            }
        }
    }
    fn view(&self, now: Duration) -> EnrollmentView {
        let joined = self.joined();
        EnrollmentView {
            id: self.id_text.clone(),
            kind: self.kind.clone(),
            state: self.state(),
            expires_in_seconds: if self.live() {
                self.expires_at.saturating_sub(now).as_secs()
            } else {
                0
            },
            joiner_fingerprint: joined.map(|j| j.joiner.fingerprint.clone()),
        }
    }
}

#[derive(Default)]
pub struct Book {
    sessions: Vec<Session>,
}

impl Book {
    /// Expire overdue sessions and forget old finished ones.
    pub fn tick(&mut self, now: Duration) {
        for session in &mut self.sessions {
            if session.live() && now >= session.expires_at {
                session.finish(EnrollmentState::Expired {}, now);
            }
        }
        self.sessions.retain(|session| match &session.phase {
            Phase::Final { at, .. } => now < at.saturating_add(FINAL_RETENTION),
            _ => true,
        });
    }

    /// `random` supplies the 32-byte id and the 32-byte secret.
    pub fn invite(
        &mut self,
        request: InvitationRequest,
        now: Duration,
        random: &[u8; 64],
    ) -> Result<IssuedInvitation, HumanEnrollmentError> {
        self.tick(now);
        let ttl = request.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
        if !request.kind.valid() || !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&ttl) {
            return Err(HumanEnrollmentError::InvalidRequest);
        }
        let live = self.sessions.iter().filter(|s| s.live()).count();
        if self.sessions.iter().any(|s| {
            s.live()
                && (s.kind == request.kind
                    || (s.kind.channel() == request.kind.channel()
                        && s.kind.label() == request.kind.label()))
        }) {
            return Err(HumanEnrollmentError::Duplicate);
        }
        if live >= MAX_LIVE_INVITATIONS {
            return Err(HumanEnrollmentError::LimitReached);
        }
        // Evict the oldest finished session, but an enrolled one last: its
        // joiner may still need the final reply it lost (sessions are in
        // creation order).
        while self.sessions.len() >= MAX_RETAINED_SESSIONS {
            let enrolled = |s: &Session| matches!(s.state(), EnrollmentState::Enrolled { .. });
            let Some(oldest) = self
                .sessions
                .iter()
                .position(|s| !s.live() && !enrolled(s))
                .or_else(|| self.sessions.iter().position(|s| !s.live()))
            else {
                return Err(HumanEnrollmentError::LimitReached);
            };
            self.sessions.remove(oldest);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&random[..32]);
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&random[32..]);
        if id == [0u8; 32] || *secret == [0u8; 32] || id == *secret {
            return Err(HumanEnrollmentError::Unavailable);
        }
        let id_text = b64(&id);
        // The code is built in one allocation of its final size, and
        // `IssuedInvitation` wipes it on drop. Copies made later, when it is
        // serialized for the owner, are outside this type's control.
        let secret_text = Zeroizing::new(b64(&*secret));
        let mut code = String::with_capacity(INVITATION_PREFIX.len() + id_text.len() + 45);
        code.push_str(INVITATION_PREFIX);
        code.push('.');
        code.push_str(&id_text);
        code.push('.');
        code.push_str(&secret_text);
        self.sessions.push(Session {
            id,
            id_text: id_text.clone(),
            secret,
            kind: request.kind.clone(),
            expires_at: now.saturating_add(Duration::from_secs(ttl)),
            failures: 0,
            phase: Phase::Open,
        });
        Ok(IssuedInvitation {
            id: id_text,
            invitation_code: code,
            kind: request.kind,
            expires_in_seconds: ttl,
        })
    }

    pub fn list(&mut self, now: Duration) -> Vec<EnrollmentView> {
        self.tick(now);
        self.sessions.iter().map(|s| s.view(now)).collect()
    }

    fn find_human(&mut self, id: &str) -> Result<&mut Session, HumanEnrollmentError> {
        self.sessions
            .iter_mut()
            .find(|s| s.id_text == id)
            .ok_or(HumanEnrollmentError::NotFound)
    }

    /// The provider's human approves by typing the code the joiner displays.
    /// A different code aborts the session; it never retries.
    pub fn approve(
        &mut self,
        id: &str,
        code: &str,
        approver_uid: u32,
        now: Duration,
    ) -> Result<EnrollmentView, HumanEnrollmentError> {
        self.tick(now);
        let typed = t::normalize_code(code).ok_or(HumanEnrollmentError::InvalidRequest)?;
        let session = self.find_human(id)?;
        let matched = match &mut session.phase {
            Phase::Final {
                state: EnrollmentState::Expired {},
                ..
            } => return Err(HumanEnrollmentError::Expired),
            Phase::Final { .. } => return Err(HumanEnrollmentError::Final),
            Phase::Open => return Err(HumanEnrollmentError::AwaitingPeer),
            Phase::Joined(joined) => {
                let matched = t::codes_equal(&typed, &joined.code);
                if matched {
                    joined.provider_approver.get_or_insert(approver_uid);
                }
                matched
            }
        };
        if !matched {
            session.finish(
                EnrollmentState::Aborted {
                    reason: AbortReason::CodeMismatch,
                },
                now,
            );
            return Err(HumanEnrollmentError::CodeMismatch);
        }
        Ok(session.view(now))
    }

    pub fn cancel(
        &mut self,
        id: &str,
        now: Duration,
    ) -> Result<EnrollmentView, HumanEnrollmentError> {
        self.tick(now);
        let session = self.find_human(id)?;
        match &session.phase {
            Phase::Final {
                state: EnrollmentState::Expired {},
                ..
            } => Err(HumanEnrollmentError::Expired),
            Phase::Final { .. } => Err(HumanEnrollmentError::Final),
            _ => {
                session.finish(
                    EnrollmentState::Cancelled {
                        by: Party::Provider,
                    },
                    now,
                );
                Ok(session.view(now))
            }
        }
    }

    /// Kernel admission for an unpaired agent: only the OS identity an
    /// invitation names may reach the enrollment messages, while the session
    /// is live or, once final, while it is retained and was joined. A joined
    /// session's end is the joiner's to learn whatever it is: `enrolled` (a
    /// lost final reply), but also `code_mismatch` or `duplicate_join` (a
    /// relay or a leaked secret), `cancelled` or `expired`. A final session
    /// nobody joined has nothing to tell and admits nobody. Admission is no
    /// authority: every message still needs the MAC.
    pub fn peer_eligible(&mut self, peer: &Peer, now: Duration) -> bool {
        self.tick(now);
        matches!(peer, Peer::Agent { .. })
            && self
                .sessions
                .iter()
                .any(|s| (s.live() || s.joined().is_some()) && peer.matches(&s.kind))
    }

    /// One joiner message. `provider_identity` is empty on the agent socket
    /// (kernel credentials authenticate the provider) and the provider's TLS
    /// certificate fingerprint bytes on the companion endpoint.
    pub fn handle(
        &mut self,
        peer: &Peer,
        provider_identity: &[u8],
        request: &EnrollmentRequest,
        now: Duration,
        provider_nonce: [u8; 32],
        hooks: &mut dyn EnrollmentHooks,
    ) -> EnrollmentReply {
        self.tick(now);
        match self.handle_inner(peer, provider_identity, request, now, provider_nonce, hooks) {
            Ok(reply) => reply,
            Err(reason) => EnrollmentReply::rejected(reason),
        }
    }

    fn handle_inner(
        &mut self,
        peer: &Peer,
        provider_identity: &[u8],
        request: &EnrollmentRequest,
        now: Duration,
        provider_nonce: [u8; 32],
        hooks: &mut dyn EnrollmentHooks,
    ) -> Result<EnrollmentReply, EnrollmentRejection> {
        request.validate()?;
        let session = self
            .sessions
            .iter_mut()
            .find(|s| s.id_text == request.invitation_id())
            .ok_or(EnrollmentRejection::InvalidInvitation)?;
        if !peer.matches(&session.kind) {
            return Err(EnrollmentRejection::InvalidInvitation);
        }
        match request {
            EnrollmentRequest::EnrollJoin {
                public_key,
                nonce,
                mac,
                ..
            } => join(
                session,
                peer,
                provider_identity,
                public_key.as_deref(),
                nonce,
                mac,
                now,
                provider_nonce,
                hooks,
            ),
            EnrollmentRequest::EnrollStatus { mac, .. } => {
                control(session, peer, t::STATUS, mac, now)?;
                Ok(EnrollmentReply::state(&session.id_text, session.state()))
            }
            EnrollmentRequest::EnrollCancel { reason, mac, .. } => {
                control(session, peer, t::cancel_action(*reason), mac, now)?;
                if session.live() {
                    session.finish(
                        match reason {
                            JoinerCancelReason::Cancelled => {
                                EnrollmentState::Cancelled { by: Party::Joiner }
                            }
                            JoinerCancelReason::CodeMismatch => EnrollmentState::Aborted {
                                reason: AbortReason::JoinerReportedMismatch,
                            },
                        },
                        now,
                    );
                }
                Ok(EnrollmentReply::state(&session.id_text, session.state()))
            }
            EnrollmentRequest::EnrollConfirm { mac, signature, .. } => {
                control(session, peer, t::CONFIRM, mac, now)?;
                confirm(session, signature.as_deref(), now, hooks)?;
                Ok(EnrollmentReply::state(&session.id_text, session.state()))
            }
        }
    }
}

fn joiner_identity(
    peer: &Peer,
    public_key: Option<&str>,
) -> Result<(Joiner, Vec<u8>), EnrollmentRejection> {
    match (peer, public_key) {
        (Peer::Agent { .. }, Some(key)) => {
            let bytes = decode_fixed::<32>(key).ok_or(EnrollmentRejection::Malformed)?;
            crate::access::decode_public_key(key)
                .map_err(|_error| EnrollmentRejection::Malformed)?;
            Ok((
                Joiner {
                    fingerprint: hex(&t::hash(&bytes)),
                    public_key: Some(key.into()),
                },
                bytes.to_vec(),
            ))
        }
        (Peer::Companion { fingerprint }, None) => {
            let bytes = unhex32(fingerprint).ok_or(EnrollmentRejection::Malformed)?;
            Ok((
                Joiner {
                    fingerprint: fingerprint.clone(),
                    public_key: None,
                },
                bytes.to_vec(),
            ))
        }
        _ => Err(EnrollmentRejection::Malformed),
    }
}

#[allow(clippy::too_many_arguments)]
fn join(
    session: &mut Session,
    peer: &Peer,
    provider_identity: &[u8],
    public_key: Option<&str>,
    nonce: &str,
    mac: &str,
    now: Duration,
    provider_nonce: [u8; 32],
    hooks: &mut dyn EnrollmentHooks,
) -> Result<EnrollmentReply, EnrollmentRejection> {
    let (joiner, identity) = joiner_identity(peer, public_key)?;
    let joiner_nonce = decode_fixed::<32>(nonce).ok_or(EnrollmentRejection::Malformed)?;
    let tag = decode_fixed::<32>(mac).ok_or(EnrollmentRejection::Malformed)?;
    let join_bytes = t::join_transcript(
        peer.channel(),
        &session.id,
        &identity,
        &joiner_nonce,
        provider_identity,
    );
    if !t::verify_mac(&session.secret, &session.id, t::JOIN, &join_bytes, &tag) {
        session.proof_failed(now);
        return Err(EnrollmentRejection::InvalidInvitation);
    }
    let join_digest = t::hash(&join_bytes);
    match &session.phase {
        Phase::Final {
            state: EnrollmentState::Expired {},
            ..
        } => return Err(EnrollmentRejection::Expired),
        Phase::Final { .. } => return Err(EnrollmentRejection::AlreadyUsed),
        // A retransmission after a lost reply gets the identical reply.
        Phase::Joined(joined) if joined.join_digest == join_digest => {
            return Ok(joined.reply.clone());
        }
        Phase::Joined(_) => {
            session.finish(
                EnrollmentState::Aborted {
                    reason: AbortReason::DuplicateJoin,
                },
                now,
            );
            return Err(EnrollmentRejection::AlreadyUsed);
        }
        Phase::Open => {}
    }
    let admissible = hooks
        .admissible(&session.kind, &joiner)
        .map_err(|_error| EnrollmentRejection::Unavailable)?;
    if !admissible {
        session.finish(
            EnrollmentState::Failed {
                reason: FailureReason::IdentityRefused,
            },
            now,
        );
        return Err(EnrollmentRejection::IdentityRefused);
    }
    let full = t::full_transcript(&join_bytes, &session.kind, &provider_nonce);
    let transcript_hash = t::hash(&full);
    let reply = EnrollmentReply::Joined {
        protocol_version: ENROLLMENT_PROTOCOL_VERSION,
        invitation_id: session.id_text.clone(),
        kind: session.kind.clone(),
        provider_nonce: b64(&provider_nonce),
        provider_mac: b64(&t::mac(&session.secret, &session.id, t::PROVIDER, &full)),
        expires_in_seconds: session.expires_at.saturating_sub(now).as_secs(),
    };
    session.phase = Phase::Joined(Box::new(Joined {
        joiner,
        join_digest,
        reply: reply.clone(),
        transcript_hash,
        code: t::comparison_code(&session.secret, &session.id, &transcript_hash),
        provider_approver: None,
        joiner_confirmed: false,
    }));
    Ok(reply)
}

/// Authenticate a post-join message: same peer, proof bound to the transcript.
fn control(
    session: &mut Session,
    peer: &Peer,
    action: &str,
    mac: &str,
    now: Duration,
) -> Result<(), EnrollmentRejection> {
    let tag = decode_fixed::<32>(mac).ok_or(EnrollmentRejection::Malformed)?;
    let Some(joined) = session.joined() else {
        return Err(EnrollmentRejection::InvalidInvitation);
    };
    if let Peer::Companion { fingerprint } = peer
        && *fingerprint != joined.joiner.fingerprint
    {
        return Err(EnrollmentRejection::InvalidInvitation);
    }
    let message = t::control_message(action, &joined.transcript_hash);
    if !t::verify_mac(&session.secret, &session.id, t::CONTROL, &message, &tag) {
        session.proof_failed(now);
        return Err(EnrollmentRejection::InvalidInvitation);
    }
    Ok(())
}

fn confirm(
    session: &mut Session,
    signature: Option<&str>,
    now: Duration,
    hooks: &mut dyn EnrollmentHooks,
) -> Result<(), EnrollmentRejection> {
    let Phase::Joined(joined) = &mut session.phase else {
        return Ok(()); // Final: idempotent, the caller reports the state.
    };
    match (&joined.joiner.public_key, signature) {
        (Some(key), Some(signature)) => {
            let key = crate::access::decode_public_key(key)
                .map_err(|_error| EnrollmentRejection::Malformed)?;
            let signature = decode_fixed::<64>(signature).ok_or(EnrollmentRejection::Malformed)?;
            key.verify_strict(
                &t::control_message(t::POSSESSION, &joined.transcript_hash),
                &ed25519_dalek::Signature::from_bytes(&signature),
            )
            .map_err(|_error| EnrollmentRejection::InvalidInvitation)?;
        }
        (None, None) => {}
        _ => return Err(EnrollmentRejection::Malformed),
    }
    joined.joiner_confirmed = true;
    let Some(approver) = joined.provider_approver else {
        return Ok(());
    };
    let state = match hooks.commit(&session.kind, &joined.joiner, approver) {
        Ok(identity) => EnrollmentState::Enrolled { identity },
        Err(reason) => EnrollmentState::Failed { reason },
    };
    session.finish(state, now);
    Ok(())
}
