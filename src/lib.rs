//! vaultwarden-cli library
//!

#[cfg(target_os = "linux")]
pub mod access;
#[cfg(target_os = "linux")]
pub mod adapters;
pub mod api;
pub mod commands;
pub mod config;
pub mod crypto;
pub mod models;
mod totp;

pub fn install_rustls_crypto_provider() {
    match rustls::crypto::ring::default_provider().install_default() {
        Ok(()) | Err(_) => {}
    }
}

#[cfg(test)]
pub(crate) static KEYRING_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
