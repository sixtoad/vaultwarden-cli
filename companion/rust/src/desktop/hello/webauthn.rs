//! Windows Hello through the documented Win32 WebAuthn API (`webauthn.dll`,
//! API version 1+, Windows 10 1903 and later; desktop-approval-spec D-6):
//! the platform authenticator only, user verification required, ES256 only,
//! no attestation, a 60 s timeout and a cancellation id per call. Everything
//! the calls return is copied, then freed; nothing is trusted here: `keys`
//! and `attested` check the data and the signature.
//!
//! `webauthn.dll` is loaded at run time from System32: a Windows without it
//! (older releases, some server editions) reports Windows Hello unavailable
//! and approves with the password; the core library still loads.
use super::keys::{Authenticator, CancelId, Failure};
use crate::provider::key_class::WEBAUTHN_RP_ID;
use std::sync::OnceLock;
use windows_sys::core::{BOOL, GUID, HRESULT, PCWSTR};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Networking::WindowsWebServices::*;
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;
use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};

type ApiVersion = unsafe extern "system" fn() -> u32;
type Uvpaa = unsafe extern "system" fn(*mut BOOL) -> HRESULT;
type MakeCredential = unsafe extern "system" fn(
    HWND,
    *const WEBAUTHN_RP_ENTITY_INFORMATION,
    *const WEBAUTHN_USER_ENTITY_INFORMATION,
    *const WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    *const WEBAUTHN_CLIENT_DATA,
    *const WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    *mut *mut WEBAUTHN_CREDENTIAL_ATTESTATION,
) -> HRESULT;
type GetAssertion = unsafe extern "system" fn(
    HWND,
    PCWSTR,
    *const WEBAUTHN_CLIENT_DATA,
    *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    *mut *mut WEBAUTHN_ASSERTION,
) -> HRESULT;
type FreeAttestation = unsafe extern "system" fn(*const WEBAUTHN_CREDENTIAL_ATTESTATION);
type FreeAssertion = unsafe extern "system" fn(*const WEBAUTHN_ASSERTION);
type GetCancellation = unsafe extern "system" fn(*mut GUID) -> HRESULT;
type Cancel = unsafe extern "system" fn(*const GUID) -> HRESULT;

/// The `webauthn.dll` entry points this module uses.
struct Api {
    version: ApiVersion,
    uvpaa: Uvpaa,
    make_credential: MakeCredential,
    get_assertion: GetAssertion,
    free_attestation: FreeAttestation,
    free_assertion: FreeAssertion,
    get_cancellation: GetCancellation,
    cancel: Cancel,
}
fn api() -> Option<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(|| {
        let name = wide("webauthn.dll");
        // SAFETY: a NUL-terminated name; System32 only, never the app or
        // current directory. The module stays loaded for the process.
        let module = unsafe {
            LoadLibraryExW(
                name.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return None;
        }
        macro_rules! entry {
            ($name:literal, $type:ty) => {{
                // SAFETY: a NUL-terminated ASCII name in a loaded module; the
                // pointer is cast to the documented signature of that export.
                let raw = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) }?;
                unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $type>(raw) }
            }};
        }
        Some(Api {
            version: entry!("WebAuthNGetApiVersionNumber", ApiVersion),
            uvpaa: entry!(
                "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable",
                Uvpaa
            ),
            make_credential: entry!("WebAuthNAuthenticatorMakeCredential", MakeCredential),
            get_assertion: entry!("WebAuthNAuthenticatorGetAssertion", GetAssertion),
            free_attestation: entry!("WebAuthNFreeCredentialAttestation", FreeAttestation),
            free_assertion: entry!("WebAuthNFreeAssertion", FreeAssertion),
            get_cancellation: entry!("WebAuthNGetCancellationId", GetCancellation),
            cancel: entry!("WebAuthNCancelCurrentOperation", Cancel),
        })
    })
    .as_ref()
}

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
        let Some(api) = api() else {
            return false;
        };
        let mut available = 0;
        // SAFETY: valid out-pointer; version 1 has every call used here.
        unsafe {
            (api.version)() >= WEBAUTHN_API_VERSION_1
                && (api.uvpaa)(&mut available) == 0
                && available != 0
        }
    }
    fn create(&self, user: &[u8; 32]) -> Result<Vec<u8>, Failure> {
        let api = api().ok_or(Failure::Unavailable)?;
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
            (api.make_credential)(
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
            (api.free_attestation)(attestation);
            Ok(data)
        }
    }
    fn assert(
        &self,
        credential: &[u8],
        client_data: &[u8],
        cancel: Option<CancelId>,
    ) -> Result<(Vec<u8>, Vec<u8>), Failure> {
        let api = api().ok_or(Failure::Unavailable)?;
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
        let result = unsafe { (api.get_assertion)(window, rp, &client, &options, &mut assertion) };
        if result != 0 || assertion.is_null() {
            return Err(failure(result));
        }
        // SAFETY: a successful call returned a valid assertion to free.
        unsafe {
            let a = &*assertion;
            let data = copy(a.pbAuthenticatorData, a.cbAuthenticatorData);
            let signature = copy(a.pbSignature, a.cbSignature);
            let used = copy(a.Credential.pbId, a.Credential.cbId);
            (api.free_assertion)(assertion);
            if used != credential {
                return Err(Failure::Failed);
            }
            Ok((data, signature))
        }
    }
    fn cancellation(&self) -> Option<CancelId> {
        let api = api()?;
        let mut guid = GUID::from_u128(0);
        // SAFETY: valid out-pointer.
        (unsafe { (api.get_cancellation)(&mut guid) } == 0).then(|| id(&guid))
    }
    fn cancel(&self, id: CancelId) {
        if let Some(api) = api() {
            // SAFETY: the id is a value; an unknown id is a no-op error.
            let _ = unsafe { (api.cancel)(&guid(id)) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs on the Windows CI runner (no Windows Hello there): the DLL
    /// loads from System32 and answers without any UI.
    #[test]
    fn webauthn_loads_and_answers_without_ui() {
        let api = api().expect("webauthn.dll in System32");
        // SAFETY: no arguments.
        assert!(unsafe { (api.version)() } >= WEBAUTHN_API_VERSION_1);
        let _available = WebAuthn.available();
        let id = WebAuthn.cancellation().expect("a cancellation id");
        assert_ne!(id, [0; 16]);
        WebAuthn.cancel(id);
        assert_eq!(guid(id).data1.to_be_bytes(), id[..4]);
    }
}
