//! Narrow backend-neutral ports used by the provider application.

use std::{collections::HashSet, ffi::c_char, fmt};

use super::policy::LoginField;

/// Provider-owned image selection. Never accepted from a request client.
#[allow(dead_code)] // Story 1.7 connects preparation to supervised dispatch.
pub(crate) struct ExecutionImage<'a> {
    pub(crate) root: &'a std::path::Path,
    pub(crate) path: &'a std::path::Path,
    pub(crate) sha256: &'a str,
    pub(crate) profile: super::policy::ExecutionProfile,
}

#[allow(dead_code)]
/// Preparation owns a noncloneable bytes capability; it grants no approval.
/// The adapter chooses its opaque resource type, keeping OS handles out of core.
pub(crate) trait ProtectedExecution {
    type Prepared;
    fn prepare(
        &self,
        image: ExecutionImage<'_>,
        argv: Vec<String>,
    ) -> Result<Self::Prepared, ExecutionError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum ExecutionOutcome {
    ExitedZero,
    ExitedNonZero,
    Signaled,
}

/// An explicit owned environment. It never reads or mutates the provider's
/// inherited environment, and its bytes are zeroized when discarded.
#[allow(dead_code)]
pub(crate) struct ChildEnvironment {
    entries: Vec<zeroize::Zeroizing<Vec<u8>>>,
    pointers: Vec<*const c_char>,
}
impl ChildEnvironment {
    const MAX_ENTRIES: usize = 32;
    const MAX_BYTES: usize = 32 * 1024;
    pub(crate) fn from_mappings(
        mappings: impl IntoIterator<Item = (String, SensitiveString)>,
    ) -> Result<Self, ExecutionError> {
        let baseline = [
            ("LANG".to_owned(), SensitiveString::new("C".to_owned())),
            ("LC_ALL".to_owned(), SensitiveString::new("C".to_owned())),
        ];
        let mut names = HashSet::new();
        let mut entries = Vec::new();
        for (name, value) in baseline.into_iter().chain(mappings) {
            let baseline_name = matches!(name.as_str(), "LANG" | "LC_ALL");
            if (!baseline_name && !valid_environment_name(&name))
                || !names.insert(name.clone())
                || value.expose().as_bytes().contains(&0)
            {
                return Err(ExecutionError::InvalidArguments);
            }
            let mut entry = Vec::with_capacity(name.len() + value.expose().len() + 2);
            entry.extend_from_slice(name.as_bytes());
            entry.push(b'=');
            entry.extend_from_slice(value.expose().as_bytes());
            entry.push(0);
            entries.push(zeroize::Zeroizing::new(entry));
            if entries.len() > Self::MAX_ENTRIES
                || entries.iter().map(|entry| entry.len()).sum::<usize>() > Self::MAX_BYTES
            {
                return Err(ExecutionError::InvalidArguments);
            }
        }
        let mut pointers = entries
            .iter()
            .map(|entry| entry.as_ptr().cast::<c_char>())
            .collect::<Vec<_>>();
        pointers.push(std::ptr::null());
        Ok(Self { entries, pointers })
    }
    #[cfg(test)]
    pub(crate) fn pointers(&self) -> &[*const c_char] {
        &self.pointers
    }
}
impl fmt::Debug for ChildEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChildEnvironment")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}
fn valid_environment_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().enumerate().all(|(index, b)| {
            (index == 0 && (b == b'_' || b.is_ascii_uppercase()))
                || (index > 0 && (b == b'_' || b.is_ascii_uppercase() || b.is_ascii_digit()))
        })
        && !matches!(
            name,
            "LANG" | "LC_ALL" | "PATH" | "IFS" | "SHELL" | "LD_PRELOAD" | "LD_LIBRARY_PATH"
        )
        && !name.starts_with("VAULTWARDEN_")
        && !name.starts_with("BITWARDEN_")
}

/// Production remains closed until Story 1.8 provides a manager-bound
/// implementation. This port prevents a direct-child fallback.
#[allow(dead_code)]
pub(crate) trait ProcessSupervisor<P: ProtectedExecution> {
    fn available(&self) -> bool;
    fn supervise(
        &self,
        prepared: P::Prepared,
        environment: ChildEnvironment,
    ) -> Result<ExecutionOutcome, ExecutionError>;
}

/// Closed diagnostics deliberately contain no OS error, image path or argv.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExecutionError {
    InvalidImage,
    UnsafePath,
    UnsafeSource,
    DigestMismatch,
    UnsupportedImage,
    Unavailable,
    InvalidArguments,
    ExecutionFailed,
}
impl fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidImage => "invalid executable image",
            Self::UnsafePath => "unsafe executable location",
            Self::UnsafeSource => "unsafe executable source",
            Self::DigestMismatch => "executable digest mismatch",
            Self::UnsupportedImage => "unsupported executable image",
            Self::Unavailable => "executable preparation unavailable",
            Self::InvalidArguments => "invalid executable arguments",
            Self::ExecutionFailed => "descriptor execution failed",
        })
    }
}
impl std::error::Error for ExecutionError {}

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
    /// Provider wall time is for display only; deadlines use suspend-aware now().
    fn unix_seconds(&self) -> Result<u64, SessionError> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_error| SessionError::BackendUnavailable)
    }
}

/// Desktop-only handoff. Implementations must never expose a URL to request clients.
pub trait DirectReviewLauncher: Send + Sync {
    fn launch(&self, request_id: &str) -> Result<(), super::direct_request::DirectRequestError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_environment_is_explicit_redacted_and_rejects_unsafe_mappings() {
        let environment = ChildEnvironment::from_mappings([(
            "LOGIN_TOKEN".to_owned(),
            SensitiveString::new("synthetic-secret".to_owned()),
        )])
        .unwrap();
        assert_eq!(
            format!("{environment:?}"),
            "ChildEnvironment { entries: 3, .. }"
        );
        let entries = environment
            .pointers()
            .iter()
            .take(3)
            .map(|pointer| unsafe { std::ffi::CStr::from_ptr(*pointer) }.to_bytes())
            .collect::<Vec<_>>();
        assert_eq!(
            entries,
            vec![
                b"LANG=C".as_slice(),
                b"LC_ALL=C".as_slice(),
                b"LOGIN_TOKEN=synthetic-secret".as_slice(),
            ]
        );
        for forbidden in ["PATH", "LANG", "VAULTWARDEN_TOKEN", "bad=name", "bad\0name"] {
            assert_eq!(
                ChildEnvironment::from_mappings([(
                    forbidden.to_owned(),
                    SensitiveString::new("value".to_owned()),
                )])
                .unwrap_err()
                .to_string(),
                "invalid executable arguments"
            );
        }
        assert!(
            ChildEnvironment::from_mappings([(
                "LOGIN_TOKEN".to_owned(),
                SensitiveString::new("has\0nul".to_owned()),
            )])
            .is_err()
        );
    }

    #[test]
    fn child_environment_enforces_independent_entry_and_byte_bounds() {
        let exact_entries = (0..30).map(|index| {
            (
                format!("TOKEN_{index}"),
                SensitiveString::new("v".to_owned()),
            )
        });
        assert!(ChildEnvironment::from_mappings(exact_entries).is_ok());
        let too_many_entries = (0..31).map(|index| {
            (
                format!("TOKEN_{index}"),
                SensitiveString::new("v".to_owned()),
            )
        });
        assert_eq!(
            ChildEnvironment::from_mappings(too_many_entries).unwrap_err(),
            ExecutionError::InvalidArguments
        );

        // LANG=C and LC_ALL=C occupy 16 bytes including their NULs. The
        // remaining exact 32-KiB boundary is accepted; one more byte is not.
        let exact = SensitiveString::new("v".repeat(32 * 1024 - 16 - 7));
        assert!(ChildEnvironment::from_mappings([("TOKEN".to_owned(), exact)]).is_ok());
        let too_large = SensitiveString::new("v".repeat(32 * 1024 - 16 - 6));
        assert_eq!(
            ChildEnvironment::from_mappings([("TOKEN".to_owned(), too_large)]).unwrap_err(),
            ExecutionError::InvalidArguments
        );
    }

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
    #[test]
    fn production_clock_wall_time_matches_the_current_unix_bracket() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let clock = crate::adapters::session::MonotonicClock::default();
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let observed = clock.unix_seconds().unwrap();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!((before..=after).contains(&observed));
    }
}
