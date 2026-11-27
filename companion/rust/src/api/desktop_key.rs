//! The Windows Hello approval key (desktop-approval-spec D-6): the
//! `approvalKey` channel of `docs/mobile-clients.md` section 2, called from
//! Dart by `CoreApprovalKeyPlatform`. Every other system answers
//! `unavailable` (Linux approves with the password, D-9).
#[cfg(windows)]
use crate::desktop::hello::{
    admit::{Binding, Purpose},
    keys::{Keys, Outcome, Reply},
    webauthn::WebAuthn,
};

/// The closed key reply: `outcome` is a Dart `KeyOutcome` name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DesktopKeyReply {
    pub outcome: String,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    /// Only with `signed`: the 37-byte WebAuthn authenticator data.
    pub authenticator_data: Vec<u8>,
}
#[cfg(not(windows))]
fn unavailable() -> DesktopKeyReply {
    DesktopKeyReply {
        outcome: "unavailable".into(),
        ..DesktopKeyReply::default()
    }
}
#[cfg(windows)]
fn keys() -> Option<&'static Keys<WebAuthn>> {
    use std::sync::OnceLock;
    static KEYS: OnceLock<Option<Keys<WebAuthn>>> = OnceLock::new();
    KEYS.get_or_init(|| {
        crate::desktop::store::Store::default_directory().map(|dir| Keys::new(WebAuthn, dir))
    })
    .as_ref()
}
#[cfg(windows)]
fn wire(reply: Reply) -> DesktopKeyReply {
    let outcome = match reply.outcome {
        Outcome::Present => "present",
        Outcome::Absent => "absent",
        Outcome::Created => "created",
        Outcome::Deleted => "deleted",
        Outcome::Signed => "signed",
        Outcome::Invalidated => "invalidated",
        Outcome::Cancelled => "cancelled",
        Outcome::Unavailable => "unavailable",
        Outcome::Refused => "refused",
        Outcome::Failed => "failed",
        Outcome::Unsafe => "unsafe",
    };
    DesktopKeyReply {
        outcome: outcome.into(),
        public_key: reply.public_key,
        signature: reply.signature,
        authenticator_data: reply.authenticator_data,
    }
}
#[cfg(windows)]
fn with(
    provider_identity: &str,
    approval_client: &str,
    f: impl FnOnce(&Keys<WebAuthn>, &Binding) -> Reply,
) -> DesktopKeyReply {
    let failed = || DesktopKeyReply {
        outcome: "failed".into(),
        ..DesktopKeyReply::default()
    };
    let Some(binding) = Binding::parse(provider_identity, approval_client) else {
        return failed();
    };
    keys().map_or_else(failed, |keys| wire(f(keys, &binding)))
}

/// `windowsHello` when a user-verifying platform authenticator is available.
pub fn desktop_key_availability() -> String {
    #[cfg(windows)]
    if keys().is_some_and(|keys| keys.available()) {
        return "windowsHello".into();
    }
    "unavailable".into()
}
pub fn desktop_key_read(provider_identity: String, approval_client: String) -> DesktopKeyReply {
    #[cfg(windows)]
    return with(&provider_identity, &approval_client, |k, b| k.read(b));
    #[cfg(not(windows))]
    {
        let _ = (provider_identity, approval_client);
        unavailable()
    }
}
pub fn desktop_key_create(provider_identity: String, approval_client: String) -> DesktopKeyReply {
    #[cfg(windows)]
    return with(&provider_identity, &approval_client, |k, b| k.create(b));
    #[cfg(not(windows))]
    {
        let _ = (provider_identity, approval_client);
        unavailable()
    }
}
pub fn desktop_key_delete(provider_identity: String, approval_client: String) -> DesktopKeyReply {
    #[cfg(windows)]
    return with(&provider_identity, &approval_client, |k, b| k.delete(b));
    #[cfg(not(windows))]
    {
        let _ = (provider_identity, approval_client);
        unavailable()
    }
}
pub fn desktop_key_sign(
    provider_identity: String,
    approval_client: String,
    session: String,
    token: u32,
    purpose: String,
    transcript: Vec<u8>,
) -> DesktopKeyReply {
    #[cfg(windows)]
    return match Purpose::parse(&purpose) {
        Some(purpose) => with(&provider_identity, &approval_client, |k, b| {
            k.sign(b, &session, token, purpose, &transcript)
        }),
        None => DesktopKeyReply {
            outcome: "failed".into(),
            ..DesktopKeyReply::default()
        },
    };
    #[cfg(not(windows))]
    {
        let _ = (
            provider_identity,
            approval_client,
            session,
            token,
            purpose,
            transcript,
        );
        unavailable()
    }
}
/// Cancels the open prompt of this session and token, if any.
#[flutter_rust_bridge::frb(sync)]
pub fn desktop_key_cancel(session: String, token: u32) {
    #[cfg(windows)]
    if let Some(keys) = keys() {
        keys.cancel(&session, token);
    }
    #[cfg(not(windows))]
    let _ = (session, token);
}
