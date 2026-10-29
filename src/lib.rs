//! vaultwarden-cli library
//!

#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
pub mod access;
#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
pub mod adapters;
pub mod api;
pub mod commands;
pub mod config;
pub mod crypto;
pub mod models;
pub mod secret_storage;
mod totp;
pub mod write_journal;

pub fn install_rustls_crypto_provider() {
    match rustls::crypto::ring::default_provider().install_default() {
        Ok(()) | Err(_) => {}
    }
}

#[cfg(test)]
pub(crate) static KEYRING_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
