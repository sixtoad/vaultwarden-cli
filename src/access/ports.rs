//! Narrow backend-neutral ports used by the provider application.

use std::fmt;

use super::policy::LoginField;

/// The only login metadata the policy application may request from a secret
/// backend.  It names an immutable backend item and standard login fields; it
/// never transports an item object or a secret value.
pub trait LoginEligibilityVerifier {
    /// Return `true` only when the exact immutable item has every requested
    /// field and an exact `vw-access=<operation-id>` custom-field marker.
    fn is_login_eligible(
        &self,
        immutable_item_id: &str,
        required_fields: &[LoginField],
        required_marker: &str,
    ) -> Result<bool, LoginEligibilityError>;
}

/// Deliberately detail-free backend failure.  The provider maps this to the
/// same stable ineligibility diagnostic as a false eligibility result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoginEligibilityError;

impl fmt::Display for LoginEligibilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("login eligibility unavailable")
    }
}

impl std::error::Error for LoginEligibilityError {}

/// Non-serializable, zeroizing input or scoped credential value.
/// Debug deliberately never delegates to the inner string.
pub struct SensitiveString(zeroize::Zeroizing<String>);
impl SensitiveString {
    pub fn new(value: String) -> Self {
        Self(zeroize::Zeroizing::new(value))
    }
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for SensitiveString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    Locked,
    Incompatible,
    AuthenticationFailed,
    BackendUnavailable,
    CleanupFailed,
    InvalidRequest,
}
impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Locked => "provider locked",
            Self::Incompatible => "unsupported vaultwarden compatibility",
            Self::AuthenticationFailed => "authentication failed",
            Self::BackendUnavailable => "backend unavailable",
            Self::CleanupFailed => "authority cleanup failed",
            Self::InvalidRequest => "invalid human request",
        })
    }
}
impl std::error::Error for SessionError {}

/// Session material never leaves the adapter implementing this port.
pub trait ProviderSession: Send {
    fn probe_compatibility(&mut self) -> Result<(), SessionError>;
    fn unlock(&mut self, password: SensitiveString) -> Result<std::time::Duration, SessionError>;
    fn clear(&mut self) -> Result<(), SessionError>;
}

pub struct CredentialBinding<'a> {
    pub immutable_item_id: &'a str,
    pub fields: &'a [LoginField],
    pub marker: &'a str,
}
/// Only the provider application owns and invokes this capability.
pub trait SecretBackend: ProviderSession {
    fn eligible(&mut self, binding: &CredentialBinding<'_>) -> Result<bool, SessionError>;
    fn resolve(
        &mut self,
        binding: &CredentialBinding<'_>,
    ) -> Result<Vec<SensitiveString>, SessionError>;
}
/// Only the protected human UI invokes authentication; platform adapters are deferred.
pub trait ApprovalAuthenticator {
    fn authenticate(&self, password: SensitiveString) -> Result<(), SessionError>;
}
/// Elapsed monotonic time, unrelated to wall-clock adjustments.
pub trait SessionClock: Send + Sync {
    fn now(&self) -> std::time::Duration;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_are_stable_and_sensitive_debug_is_redacted() {
        for (error, expected) in [
            (SessionError::Locked, "provider locked"),
            (
                SessionError::Incompatible,
                "unsupported vaultwarden compatibility",
            ),
            (SessionError::AuthenticationFailed, "authentication failed"),
            (SessionError::BackendUnavailable, "backend unavailable"),
            (SessionError::CleanupFailed, "authority cleanup failed"),
            (SessionError::InvalidRequest, "invalid human request"),
        ] {
            assert_eq!(error.to_string(), expected);
        }
        for value in ["password-sentinel", "session-sentinel", "secret-sentinel"] {
            assert_eq!(
                format!("{:?}", SensitiveString::new(value.into())),
                "[REDACTED]"
            );
        }
    }
}
