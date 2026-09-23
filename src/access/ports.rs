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
