//! Guided enrollment over mTLS (#59). A CA-valid client leaf that is not (or
//! no longer) enrolled may send only the joiner messages (`dispatch`). An
//! enrolled administrator companion may also act for the provider owner
//! (`admin`, phase 2): invite, list, approve and cancel. Approval needs the
//! code read on the joining endpoint and a fresh provider password; no reply
//! ever carries a comparison code.

use super::{Command, Companion, Error, Response, identity, valid_password};
use crate::access::{
    application::ProviderApplication,
    enrollment::{
        EnrolledIdentity, EnrolleeKind, FailureReason, HumanEnrollmentError, InvitationRequest,
        book::{EnrollmentHooks, Joiner},
        decode_fixed, unhex32,
    },
    ports::SessionError,
};

pub(super) fn dispatch(
    service: &Companion,
    device: &str,
    command: &Command,
    app: &ProviderApplication,
) -> Response {
    let Command::Enroll { version, message } = command else {
        return Response::error(Error::Invalid);
    };
    if *version != 1 || message.validate().is_err() {
        return Response::error(Error::Invalid);
    }
    if service.management.lock().map_or(true, |state| state.failed) {
        return Response::error(Error::Unavailable);
    }
    let Some(provider) = unhex32(&service.provider_fingerprint) else {
        return Response::error(Error::Unavailable);
    };
    let reply =
        app.enrollment_companion_message(device, &provider, message, &mut Hooks { service });
    match serde_json::to_value(reply) {
        Ok(value) => Response::ok(value),
        Err(_) => Response::error(Error::Unavailable),
    }
}

struct Hooks<'a> {
    service: &'a Companion,
}

impl Hooks<'_> {
    fn root(&self) -> Option<&std::path::Path> {
        self.service.identity_store.parent()
    }
}

impl EnrollmentHooks for Hooks<'_> {
    fn admissible(&mut self, _: &EnrolleeKind, joiner: &Joiner) -> Result<bool, FailureReason> {
        // An unreadable registry is unavailable: it neither refuses the
        // device nor burns the invitation.
        let root = self.root().ok_or(FailureReason::Unavailable)?;
        identity::known(root, &joiner.fingerprint)
            .map(|known| !known)
            .map_err(|_error| FailureReason::Unavailable)
    }

    fn commit(
        &mut self,
        kind: &EnrolleeKind,
        joiner: &Joiner,
        _approver_uid: u32,
    ) -> Result<EnrolledIdentity, FailureReason> {
        let EnrolleeKind::Companion { label } = kind else {
            return Err(FailureReason::IdentityRefused);
        };
        let root = self.root().ok_or(FailureReason::Unavailable)?;
        let Ok(_commit) = self.service.identity_commit.lock() else {
            return Err(FailureReason::Unavailable);
        };
        if self
            .service
            .management
            .lock()
            .map_or(true, |state| state.failed)
        {
            return Err(FailureReason::Unavailable);
        }
        match identity::enroll_online(root, &joiner.fingerprint, label) {
            Ok(()) => Ok(EnrolledIdentity::Companion {
                fingerprint: joiner.fingerprint.clone(),
            }),
            Err(SessionError::InvalidRequest) => Err(FailureReason::IdentityRefused),
            Err(_) => Err(FailureReason::Unavailable),
        }
    }
}

/// `Some` for the administrator enrollment commands (closed v1 shapes).
pub(super) fn valid_admin(command: &Command) -> Option<bool> {
    Some(match command {
        Command::EnrollInvite { version, kind, .. } => *version == 1 && kind.valid(),
        Command::EnrollList { version } => *version == 1,
        Command::EnrollApprove {
            version,
            id,
            code,
            password,
        } => {
            // A malformed code is the book's input error (it never burns the
            // session); only bound its size here.
            *version == 1
                && decode_fixed::<32>(id).is_some()
                && !code.is_empty()
                && code.len() <= 32
                && valid_password(password)
        }
        Command::EnrollCancel { version, id } => *version == 1 && decode_fixed::<32>(id).is_some(),
        _ => return None,
    })
}

/// A refusal the owner can act on (`code_mismatch`, `awaiting_peer`, ...).
fn refused(error: HumanEnrollmentError) -> Response {
    match error {
        HumanEnrollmentError::Unauthorized => Response::error(Error::Unauthorized),
        HumanEnrollmentError::Unavailable => Response::error(Error::Unavailable),
        reason => Response {
            status: 409,
            body: serde_json::json!({"version":1,"error":"enrollment_refused","reason":reason})
                .to_string(),
        },
    }
}

/// The provider owner's enrollment actions, for an administrator companion.
/// They run under the owner's authority, as identity revocation does; an
/// agent binding created this way is paired by the owner (`pair_agent`).
pub(super) fn admin(
    service: &Companion,
    actor: &str,
    command: Command,
    app: &ProviderApplication,
) -> Response {
    if service.management.lock().map_or(true, |state| state.failed) {
        return Response::error(Error::Unavailable);
    }
    // `dispatch` already required a current enrollment; re-checked here so
    // this entry point never depends on its caller's order.
    if !service.authorized(actor) || !identity::administrator(&service.identity_store, actor) {
        return Response::error(Error::Unauthorized);
    }
    let owner = app.human_owner();
    let result = match command {
        Command::EnrollInvite {
            kind, ttl_seconds, ..
        } => app
            .enrollment_invite(owner, InvitationRequest { kind, ttl_seconds })
            .map(|issued| serde_json::json!({"version":1,"invitation":issued})),
        Command::EnrollList { .. } => app
            .enrollment_list(owner)
            .map(|views| serde_json::json!({"version":1,"enrollments":views})),
        Command::EnrollApprove {
            id, code, password, ..
        } => {
            // The same throttle and password check as a remote approval.
            let Ok(_authentication) = service.authentication.try_lock() else {
                return Response::error(Error::RateLimited);
            };
            if !service.attempt(actor, app.companion_now()) {
                return Response::error(Error::RateLimited);
            }
            let Some(authenticator) = service.approval_authenticator.as_ref() else {
                return Response::error(Error::Unavailable);
            };
            if authenticator.authenticate(password).is_err() {
                return Response::error(Error::Authentication);
            }
            // Administration may have been revoked while authenticating.
            if !service.authorized(actor)
                || !identity::administrator(&service.identity_store, actor)
            {
                return Response::error(Error::Unauthorized);
            }
            app.enrollment_approve(owner, &id, &code)
                .map(|view| serde_json::json!({"version":1,"enrollment":view}))
        }
        Command::EnrollCancel { id, .. } => app
            .enrollment_cancel(owner, &id)
            .map(|view| serde_json::json!({"version":1,"enrollment":view})),
        _ => return Response::error(Error::Invalid),
    };
    match result {
        Ok(value) => Response::ok(value),
        Err(error) => refused(error),
    }
}
