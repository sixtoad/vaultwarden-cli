//! Windows Hello through the documented Win32 WebAuthn API (`webauthn.dll`,
//! API version 1+, Windows 10 1903 and later; desktop-approval-spec D-6):
//! the platform authenticator only, user verification required, ES256 only,
//! no attestation, a 60 s timeout and a cancellation id per call. Everything
//! the calls return is copied, then freed; nothing is trusted here: `keys`
//! and `attested` check the data and the signature.
use super::keys::{Authenticator, CancelId, Failure};
use crate::provider::key_class::WEBAUTHN_RP_ID;
use windows_sys::core::{GUID, HRESULT, PCWSTR};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Networking::WindowsWebServices::*;
use windows_sys::Win32::System::Threading::GetCurrentProcessId;
use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};

const TIMEOUT_MS: u32 = 60_000;
/// HRESULTs (winerror.h) mapped to the channel outcomes.
const NTE_USER_CANCELLED: HRESULT = 0x8009_0036_u32 as HRESULT;
const NTE_NOT_FOUND: HRESULT = 0x8009_0011_u32 as HRESULT;
const ERROR_CANCELLED: HRESULT = 0x8007_04C7_u32 as HRESULT;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}
fn failure(result: HRESULT) -> Failure {
    match result {
        NTE_USER_CANCELLED | ERROR_CANCELLED => Failure::Cancelled,
        NTE_NOT_FOUND => Failure::NotFound,
        _ => Failure::Failed,
    }
}
/// This process's foreground window: the prompt's owner. None while the
/// app is not in front (the approval UI never signs in the background).
fn owner() -> Option<HWND> {
    // SAFETY: plain Win32 queries with valid out-pointers.
    unsafe {
        let window = GetForegroundWindow();
        if window.is_null() {
            return None;
        }
        let mut process = 0u32;
        GetWindowThreadProcessId(window, &mut process);
        (process == GetCurrentProcessId()).then_some(window)
    }
}
fn guid(id: CancelId) -> GUID {
    GUID::from_u128(u128::from_be_bytes(id))
}
fn id(guid: &GUID) -> CancelId {
    let mut out = [0; 16];
    out[..4].copy_from_slice(&guid.data1.to_be_bytes());
    out[4..6].copy_from_slice(&guid.data2.to_be_bytes());
    out[6..8].copy_from_slice(&guid.data3.to_be_bytes());
    out[8..].copy_from_slice(&guid.data4);
    out
}
/// Copies `len` bytes at `ptr` (empty for null).
///
/// # Safety
/// `ptr` must be null or valid for `len` bytes.
unsafe fn copy(ptr: *const u8, len: u32) -> Vec<u8> {
    if ptr.is_null() {
        return Vec::new();
    }
    // SAFETY: guaranteed by the caller.
    unsafe { std::slice::from_raw_parts(ptr, len as usize) }.to_vec()
}

pub struct WebAuthn;
impl WebAuthn {
    fn client_data(json: &[u8], hash: &[u16]) -> WEBAUTHN_CLIENT_DATA {
        WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: json.len() as u32,
            pbClientDataJSON: json.as_ptr().cast_mut(),
            pwszHashAlgId: hash.as_ptr(),
        }
    }
}
impl Authenticator for WebAuthn {
    fn available(&self) -> bool {
        let mut available = 0;
        // SAFETY: valid out-pointer; version 1 has every call used here.
        unsafe {
            WebAuthNGetApiVersionNumber() >= WEBAUTHN_API_VERSION_1
                && WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(&mut available) == 0
                && available != 0
        }
    }
    fn create(&self, user: &[u8; 32]) -> Result<Vec<u8>, Failure> {
        let window = owner().ok_or(Failure::Unavailable)?;
        let (rp_id, rp_name) = (wide(WEBAUTHN_RP_ID), wide("Vaultwarden Access"));
        let name = wide("Vaultwarden Access approval key");
        let hash = wide("SHA-256");
        let mut user_id = *user;
        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: rp_id.as_ptr(),
            pwszName: rp_name.as_ptr(),
            pwszIcon: std::ptr::null(),
        };
        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: 32,
            pbId: user_id.as_mut_ptr(),
            pwszName: name.as_ptr(),
            pwszIcon: std::ptr::null(),
            pwszDisplayName: name.as_ptr(),
        };
        let mut parameter = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        };
        let parameters = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: 1,
            pCredentialParameters: &mut parameter,
        };
        // A creation challenge is not verified by anyone (no attestation);
        // possession is proven afterwards by an assertion over the
        // provider's enrollment transcript.
        let json = br#"{"type":"webauthn.create","challenge":"","origin":"vaultwarden-access.approval-v2"}"#;
        let client = Self::client_data(json, &hash);
        // SAFETY: an all-zero options value is valid (null pointers, zero counts).
        let mut options: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS =
            unsafe { std::mem::zeroed() };
        options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_1;
        options.dwTimeoutMilliseconds = TIMEOUT_MS;
        options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM;
        options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
        options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
        let mut attestation: *mut WEBAUTHN_CREDENTIAL_ATTESTATION = std::ptr::null_mut();
        // SAFETY: every pointer refers to a live local for the whole call.
        let result = unsafe {
            WebAuthNAuthenticatorMakeCredential(
                window,
                &rp,
                &user,
                &parameters,
                &client,
                &options,
                &mut attestation,
            )
        };
        if result != 0 || attestation.is_null() {
            return Err(failure(result));
        }
        // SAFETY: a successful call returned a valid attestation to free.
        unsafe {
            let data = copy(
                (*attestation).pbAuthenticatorData,
                (*attestation).cbAuthenticatorData,
            );
            WebAuthNFreeCredentialAttestation(attestation);
            Ok(data)
        }
    }
    fn assert(
        &self,
        credential: &[u8],
        client_data: &[u8],
        cancel: Option<CancelId>,
    ) -> Result<(Vec<u8>, Vec<u8>), Failure> {
        let window = owner().ok_or(Failure::Unavailable)?;
        let rp_id = wide(WEBAUTHN_RP_ID);
        let hash = wide("SHA-256");
        let mut id = credential.to_vec();
        let mut allowed = WEBAUTHN_CREDENTIAL {
            dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
            cbId: id.len() as u32,
            pbId: id.as_mut_ptr(),
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        };
        let mut cancellation = cancel.map(guid);
        let client = Self::client_data(client_data, &hash);
        // SAFETY: an all-zero options value is valid (null pointers, zero counts).
        let mut options: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS =
            unsafe { std::mem::zeroed() };
        options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_3;
        options.dwTimeoutMilliseconds = TIMEOUT_MS;
        options.CredentialList = WEBAUTHN_CREDENTIALS {
            cCredentials: 1,
            pCredentials: &mut allowed,
        };
        options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM;
        options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
        options.pCancellationId = cancellation
            .as_mut()
            .map_or(std::ptr::null_mut(), |g| g as *mut GUID);
        let mut assertion: *mut WEBAUTHN_ASSERTION = std::ptr::null_mut();
        let rp: PCWSTR = rp_id.as_ptr();
        // SAFETY: every pointer refers to a live local for the whole call.
        let result = unsafe {
            WebAuthNAuthenticatorGetAssertion(window, rp, &client, &options, &mut assertion)
        };
        if result != 0 || assertion.is_null() {
            return Err(failure(result));
        }
        // SAFETY: a successful call returned a valid assertion to free.
        unsafe {
            let a = &*assertion;
            let data = copy(a.pbAuthenticatorData, a.cbAuthenticatorData);
            let signature = copy(a.pbSignature, a.cbSignature);
            let used = copy(a.Credential.pbId, a.Credential.cbId);
            WebAuthNFreeAssertion(assertion);
            if used != credential {
                return Err(Failure::Failed);
            }
            Ok((data, signature))
        }
    }
    fn cancellation(&self) -> Option<CancelId> {
        let mut guid = GUID::from_u128(0);
        // SAFETY: valid out-pointer.
        (unsafe { WebAuthNGetCancellationId(&mut guid) } == 0).then(|| id(&guid))
    }
    fn cancel(&self, id: CancelId) {
        // SAFETY: the id is a value; an unknown id is a no-op error.
        let _ = unsafe { WebAuthNCancelCurrentOperation(&guid(id)) };
    }
}
