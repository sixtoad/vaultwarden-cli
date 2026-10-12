//! Closed, secret-free operator provisioning diagnostics and bounds.
use serde::{Deserialize, Serialize};

pub const MAX_POLICY_BYTES: usize = 128 * 1024;
pub const MAX_INSPECTION_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningError {
    Unauthorized,
    Locked,
    Conflict,
    InvalidInput,
    CredentialIneligible,
    NotFound,
    Unavailable,
    Incompatible,
    OversizedResult,
}
impl std::fmt::Display for ProvisioningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unauthorized => "unauthorized human",
            Self::Locked => "provider locked",
            Self::Conflict => "record already exists; use show to reconcile",
            Self::InvalidInput => "invalid provisioning input",
            Self::CredentialIneligible => "credential is not eligible",
            Self::NotFound => "record not found",
            Self::Unavailable => "provider unavailable",
            Self::Incompatible => "unsupported vaultwarden compatibility",
            Self::OversizedResult => "inspection result too large",
        })
    }
}
impl std::error::Error for ProvisioningError {}
impl From<super::ports::SessionError> for ProvisioningError {
    fn from(error: super::ports::SessionError) -> Self {
        match error {
            super::ports::SessionError::Locked => Self::Locked,
            super::ports::SessionError::Incompatible => Self::Incompatible,
            _ => Self::Unavailable,
        }
    }
}
impl From<super::provider::ProviderError> for ProvisioningError {
    fn from(error: super::provider::ProviderError) -> Self {
        use super::provider::ProviderDiagnostic as D;
        match error.diagnostic() {
            D::Conflict => Self::Conflict,
            D::InvalidOperationPolicy => Self::InvalidInput,
            D::CredentialIneligible => Self::CredentialIneligible,
            D::ExpiredAccessRequest => Self::Locked,
            _ => Self::Unavailable,
        }
    }
}
pub(crate) fn bounded<T: Serialize>(value: T) -> Result<T, ProvisioningError> {
    // Metadata is already constrained by policy validation; reject a complete
    // oversized result rather than truncating records or returning partial JSON.
    if serde_json::to_vec(&value)
        .map_err(|_error| ProvisioningError::Unavailable)?
        .len()
        > MAX_INSPECTION_BYTES
    {
        return Err(ProvisioningError::OversizedResult);
    }
    Ok(value)
}
