//! Guided enrollment over mTLS (#59 phase 1). A CA-valid client leaf that is
//! not (or no longer) enrolled may send only these joiner messages. The
//! provider owner approves on the human transport; nothing here approves.

use super::{Command, Companion, Error, Response, identity};
use crate::access::{
    application::ProviderApplication,
    enrollment::{
        EnrolledIdentity, EnrolleeKind, FailureReason,
        book::{EnrollmentHooks, Joiner},
        unhex32,
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
