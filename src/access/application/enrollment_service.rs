//! Guided enrollment use cases (#59 phase 1). Only the provider owner, over
//! the human transport, creates, approves or cancels; joiners only join,
//! confirm, observe or withdraw through their own authenticated channel.

use super::ProviderApplication;
use crate::access::{
    agent_binding::{AgentBinding, AgentBindingStatus, AgentPairing},
    direct_request::{AuthenticatedHuman, DirectRequestError},
    enrollment::{
        EnrolledIdentity, EnrolleeKind, EnrollmentAdmission, EnrollmentRejection, EnrollmentView,
        FailureReason, HumanEnrollmentError, InvitationRequest, IssuedInvitation, Peer,
        book::{Book, EnrollmentHooks, Joiner},
        wire::{EnrollmentReply, EnrollmentRequest},
    },
};
use zeroize::Zeroizing;

impl ProviderApplication {
    fn enrollment_book(&self) -> Result<std::sync::MutexGuard<'_, Book>, HumanEnrollmentError> {
        if self.admission_closed() {
            return Err(HumanEnrollmentError::Unavailable);
        }
        self.enrollment
            .lock()
            .map_err(|_error| HumanEnrollmentError::Unavailable)
    }

    fn enrollment_owner(&self, human: AuthenticatedHuman) -> Result<(), HumanEnrollmentError> {
        self.check_owner(human)
            .map_err(|_error| HumanEnrollmentError::Unauthorized)
    }

    pub fn enrollment_invite(
        &self,
        human: AuthenticatedHuman,
        request: InvitationRequest,
    ) -> Result<IssuedInvitation, HumanEnrollmentError> {
        self.enrollment_owner(human)?;
        if let EnrolleeKind::Agent { label, uid, gid } = &request.kind {
            // Same OS-identity rules as `agent pair` (provider/operator UIDs,
            // the native agent group), checked now rather than at commit.
            let probe = AgentPairing {
                label: label.clone(),
                public_key: crate::access::encode_public_key(
                    &ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key(),
                ),
                uid: *uid,
                gid: *gid,
            };
            if *uid == self.owner.uid() || AgentBinding::new(probe, self.owner.uid()).is_err() {
                return Err(HumanEnrollmentError::InvalidRequest);
            }
            // A label names one enabled agent. A revoked binding keeps its
            // label as history; a new enrollment never reactivates it.
            let agents = self.list_agents(human).map_err(human_error)?;
            if agents
                .iter()
                .any(|agent| agent.status == AgentBindingStatus::Enabled && agent.label == *label)
            {
                return Err(HumanEnrollmentError::Duplicate);
            }
        }
        let mut random = Zeroizing::new([0u8; 64]);
        getrandom::fill(random.as_mut()).map_err(|_error| HumanEnrollmentError::Unavailable)?;
        self.enrollment_book()?
            .invite(request, self.clock.now(), &random)
    }

    pub fn enrollment_list(
        &self,
        human: AuthenticatedHuman,
    ) -> Result<Vec<EnrollmentView>, HumanEnrollmentError> {
        self.enrollment_owner(human)?;
        Ok(self.enrollment_book()?.list(self.clock.now()))
    }

    /// `code` is what the joining endpoint displays, typed by the human.
    pub fn enrollment_approve(
        &self,
        human: AuthenticatedHuman,
        id: &str,
        code: &str,
    ) -> Result<EnrollmentView, HumanEnrollmentError> {
        self.enrollment_owner(human)?;
        self.enrollment_book()?
            .approve(id, code, human.uid(), self.clock.now())
    }

    pub fn enrollment_cancel(
        &self,
        human: AuthenticatedHuman,
        id: &str,
    ) -> Result<EnrollmentView, HumanEnrollmentError> {
        self.enrollment_owner(human)?;
        self.enrollment_book()?.cancel(id, self.clock.now())
    }

    /// Run `action` while the enrollment sessions are locked (contention seam).
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn enrollment_hold_for_test(&self, action: impl FnOnce()) {
        let _guard = self.enrollment.lock().unwrap();
        action();
    }

    /// Kernel admission of an otherwise unpaired agent peer. Never waits:
    /// contention is reported as `Busy`, never as "not invited".
    pub fn enrollment_peer_eligible(&self, uid: u32, groups: &[u32]) -> EnrollmentAdmission {
        if self.admission_closed() || uid == self.owner.uid() {
            return EnrollmentAdmission::Refused;
        }
        let mut book = match self.enrollment.try_lock() {
            Ok(book) => book,
            Err(std::sync::TryLockError::WouldBlock) => return EnrollmentAdmission::Busy,
            Err(std::sync::TryLockError::Poisoned(_)) => return EnrollmentAdmission::Refused,
        };
        if book.peer_eligible(
            &Peer::Agent {
                uid,
                groups: groups.to_vec(),
            },
            self.clock.now(),
        ) {
            EnrollmentAdmission::Admitted
        } else {
            EnrollmentAdmission::Refused
        }
    }

    /// One joiner message from the agent socket, after kernel admission.
    pub fn enrollment_agent_message(
        &self,
        uid: u32,
        groups: &[u32],
        request: &EnrollmentRequest,
    ) -> EnrollmentReply {
        if uid == self.owner.uid() {
            return EnrollmentReply::rejected(EnrollmentRejection::InvalidInvitation);
        }
        let peer = Peer::Agent {
            uid,
            groups: groups.to_vec(),
        };
        self.enrollment_message(&peer, &[], request, &mut AgentHooks { app: self })
    }

    /// One joiner message from the companion endpoint, after mTLS. The
    /// adapter supplies the hooks that write its identity registry.
    pub fn enrollment_companion_message(
        &self,
        device_fingerprint: &str,
        provider_identity: &[u8],
        request: &EnrollmentRequest,
        hooks: &mut dyn EnrollmentHooks,
    ) -> EnrollmentReply {
        let peer = Peer::Companion {
            fingerprint: device_fingerprint.into(),
        };
        self.enrollment_message(&peer, provider_identity, request, hooks)
    }

    fn enrollment_message(
        &self,
        peer: &Peer,
        provider_identity: &[u8],
        request: &EnrollmentRequest,
        hooks: &mut dyn EnrollmentHooks,
    ) -> EnrollmentReply {
        let mut nonce = [0u8; 32];
        if getrandom::fill(&mut nonce).is_err() {
            return EnrollmentReply::rejected(EnrollmentRejection::Unavailable);
        }
        let Ok(mut book) = self.enrollment_book() else {
            return EnrollmentReply::rejected(EnrollmentRejection::Unavailable);
        };
        book.handle(
            peer,
            provider_identity,
            request,
            self.clock.now(),
            nonce,
            hooks,
        )
    }
}

fn human_error(error: DirectRequestError) -> HumanEnrollmentError {
    match error {
        DirectRequestError::Unauthorized => HumanEnrollmentError::Unauthorized,
        _ => HumanEnrollmentError::Unavailable,
    }
}

/// An agent enrollment becomes an ordinary pairing, made by the approving
/// human: the same validation, uniqueness and audit as `agent pair`.
struct AgentHooks<'a> {
    app: &'a ProviderApplication,
}

impl EnrollmentHooks for AgentHooks<'_> {
    fn admissible(&mut self, _: &EnrolleeKind, joiner: &Joiner) -> Result<bool, FailureReason> {
        // Any binding with this key, enabled or revoked, refuses it. A store
        // that cannot answer is unavailable, not a refusal.
        self.app
            .list_agents(self.app.owner)
            .map(|agents| agents.iter().all(|a| a.fingerprint != joiner.fingerprint))
            .map_err(|_error| FailureReason::Unavailable)
    }

    fn commit(
        &mut self,
        kind: &EnrolleeKind,
        joiner: &Joiner,
        approver_uid: u32,
    ) -> Result<EnrolledIdentity, FailureReason> {
        let (EnrolleeKind::Agent { label, uid, gid }, Some(public_key)) =
            (kind, &joiner.public_key)
        else {
            return Err(FailureReason::IdentityRefused);
        };
        let pairing = AgentPairing {
            label: label.clone(),
            public_key: public_key.clone(),
            uid: *uid,
            gid: *gid,
        };
        match self
            .app
            .pair_agent(AuthenticatedHuman::from_peer_uid(approver_uid), pairing)
        {
            Ok(view) => Ok(EnrolledIdentity::Agent {
                binding_id: view.id,
                fingerprint: view.fingerprint,
            }),
            Err(DirectRequestError::InvalidRequest | DirectRequestError::Unauthorized) => {
                Err(FailureReason::IdentityRefused)
            }
            Err(_) => Err(FailureReason::Unavailable),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "enrollment_service_tests.rs"]
mod tests;
