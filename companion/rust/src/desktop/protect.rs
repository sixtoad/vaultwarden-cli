//! At-rest protection of the client identity (desktop-approval-spec D-3).
//! Windows: DPAPI, current user (`CryptProtectData`, no UI). Linux (and the
//! macOS test host): none beyond the 0600 file in a 0700 directory that
//! `super::store` writes; any process of the same user can read either.
use zeroize::Zeroizing;

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };
    use zeroize::Zeroizing;

    /// Binds the blob to this purpose (not a secret).
    const ENTROPY: &[u8] = b"dev.vaultwarden.companion.desktop-identity.v1";

    fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_ptr().cast_mut(),
        }
    }
    fn call(
        input: &[u8],
        f: unsafe extern "system" fn(
            *const CRYPT_INTEGER_BLOB,
            *mut CRYPT_INTEGER_BLOB,
        ) -> windows_sys::core::BOOL,
    ) -> Option<Zeroizing<Vec<u8>>> {
        if u32::try_from(input.len()).is_err() {
            return None;
        }
        let mut out = CRYPT_INTEGER_BLOB::default();
        let source = blob(input);
        // SAFETY: `source` borrows `input` for the call; `out` is written by
        // the API and released with LocalFree below.
        if unsafe { f(&source, &mut out) } == 0 || out.pbData.is_null() {
            return None;
        }
        // SAFETY: the API returned `cbData` readable bytes at `pbData`.
        let bytes = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) };
        let copy = Zeroizing::new(bytes.to_vec());
        // SAFETY: wipe, then free the buffer the API allocated.
        unsafe {
            std::ptr::write_bytes(out.pbData, 0, out.cbData as usize);
            LocalFree(out.pbData.cast());
        }
        Some(copy)
    }
    unsafe extern "system" fn seal(
        input: *const CRYPT_INTEGER_BLOB,
        output: *mut CRYPT_INTEGER_BLOB,
    ) -> windows_sys::core::BOOL {
        let entropy = blob(ENTROPY);
        // SAFETY: forwarded pointers are valid for the call (see `call`).
        unsafe {
            CryptProtectData(
                input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                output,
            )
        }
    }
    unsafe extern "system" fn open(
        input: *const CRYPT_INTEGER_BLOB,
        output: *mut CRYPT_INTEGER_BLOB,
    ) -> windows_sys::core::BOOL {
        let entropy = blob(ENTROPY);
        // SAFETY: forwarded pointers are valid for the call (see `call`).
        unsafe {
            CryptUnprotectData(
                input,
                std::ptr::null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                output,
            )
        }
    }
    pub fn protect(plain: &[u8]) -> Option<Vec<u8>> {
        call(plain, seal).map(|sealed| sealed.to_vec())
    }
    pub fn unprotect(sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        call(sealed, open)
    }
}

#[cfg(not(windows))]
mod imp {
    use zeroize::Zeroizing;
    pub fn protect(plain: &[u8]) -> Option<Vec<u8>> {
        Some(plain.to_vec())
    }
    pub fn unprotect(sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        Some(Zeroizing::new(sealed.to_vec()))
    }
}

/// How the stored identity is protected, as the UI may name it.
pub const PROTECTION: &str = if cfg!(windows) {
    "dpapi_current_user"
} else {
    "user_file"
};

pub fn protect(plain: &[u8]) -> Option<Vec<u8>> {
    imp::protect(plain)
}
pub fn unprotect(sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    imp::unprotect(sealed)
}

#[cfg(test)]
mod tests {
    #[test]
    fn protection_round_trips_and_windows_never_stores_plaintext() {
        let plain = b"synthetic identity bytes".to_vec();
        let sealed = super::protect(&plain).unwrap();
        assert_eq!(&*super::unprotect(&sealed).unwrap(), &plain);
        if cfg!(windows) {
            assert_ne!(sealed, plain);
            assert!(!sealed.windows(plain.len()).any(|w| w == plain.as_slice()));
            let mut damaged = sealed.clone();
            let last = damaged.len() - 1;
            damaged[last] ^= 1;
            assert!(super::unprotect(&damaged).is_none());
        }
    }
}
