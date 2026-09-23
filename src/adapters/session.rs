//! Provider-specific OS-keyring storage. Never calls CLI fallback/session loaders.
use crate::{
    access::ports::{SensitiveString, SessionClock, SessionError},
    config::Config,
    crypto::{CryptoKeys, KdfIterations, MasterKey},
};
use keyring_core::{Entry, Error};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::Mutex,
    time::Duration,
};
use zeroize::Zeroizing;

pub const KEYRING_SERVICE: &str = "vaultwarden-accessd";
pub const BOOTSTRAP_ACCOUNT: &str = "bootstrap-client-secret";
pub const SESSION_ACCOUNT: &str = "revocable-session";
/// Linux boot time includes suspend; clock faults permanently expire authority.
#[derive(Default)]
pub struct MonotonicClock(Mutex<Duration>);
impl MonotonicClock {
    fn observe(&self, sample: impl FnOnce() -> Option<Duration>) -> Duration {
        let Ok(mut last) = self.0.lock() else {
            return Duration::MAX;
        };
        *last = match sample() {
            Some(now) if now >= *last => now,
            _ => Duration::MAX,
        };
        *last
    }
}
fn boot_time() -> Option<Duration> {
    #[cfg(target_os = "linux")]
    {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // CLOCK_BOOTTIME is monotonic and includes suspended time.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
            return None;
        }
        boot_duration(time.tv_sec, time.tv_nsec)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}
fn boot_duration(seconds: i64, nanos: i64) -> Option<Duration> {
    if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
        return None;
    }
    Some(Duration::new(seconds as u64, nanos as u32))
}
impl SessionClock for MonotonicClock {
    fn now(&self) -> Duration {
        self.observe(boot_time)
    }
}

pub(crate) struct ProviderKeyring;
impl ProviderKeyring {
    fn entry(account: &str) -> Result<Entry, SessionError> {
        crate::config::ensure_native_keyring_store()
            .map_err(|_| SessionError::BackendUnavailable)?;
        Entry::new(KEYRING_SERVICE, account).map_err(|_| SessionError::BackendUnavailable)
    }
    pub(crate) fn bootstrap(&self) -> Result<SensitiveString, SessionError> {
        Self::entry(BOOTSTRAP_ACCOUNT)?
            .get_password()
            .map(SensitiveString::new)
            .map_err(|_| SessionError::BackendUnavailable)
    }
    pub(crate) fn save(&self, token: &str, keys: &CryptoKeys) -> Result<(), SessionError> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        #[derive(serde::Serialize)]
        struct StoredSession<'a> {
            access_token: &'a str,
            enc_key: &'a str,
            mac_key: &'a str,
        }
        let enc_key = Zeroizing::new(STANDARD.encode(keys.enc_key_bytes()));
        let mac_key = Zeroizing::new(STANDARD.encode(keys.mac_key_bytes()));
        let record = Zeroizing::new(
            serde_json::to_string(&StoredSession {
                access_token: token,
                enc_key: &enc_key,
                mac_key: &mac_key,
            })
            .map_err(|_| SessionError::BackendUnavailable)?,
        );
        Self::entry(SESSION_ACCOUNT)?
            .set_password(&record)
            .map_err(|_| SessionError::BackendUnavailable)
    }
    pub(crate) fn clear(&self) -> Result<(), SessionError> {
        match Self::entry(SESSION_ACCOUNT)?.delete_credential() {
            Ok(()) | Err(Error::NoEntry) => Ok(()),
            Err(_) => Err(SessionError::CleanupFailed),
        }
    }
}
/// Always clear prior provider authority before setup is inspected, including
/// installations that have no backend configured. Keyring failures fail closed.
pub fn clear_persisted_session() -> Result<(), SessionError> {
    ProviderKeyring.clear()
}

/// Read setup only, not Config::load(), which also restores CLI authority.
pub(crate) fn load_setup(path: &Path) -> Result<Config, SessionError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| SessionError::BackendUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| SessionError::BackendUnavailable)?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(SessionError::BackendUnavailable);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.by_ref()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| SessionError::BackendUnavailable)?;
    if bytes.len() > 65536 {
        return Err(SessionError::BackendUnavailable);
    }
    let raw: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| SessionError::BackendUnavailable)?;
    for forbidden in [
        "access_token",
        "refresh_token",
        "token_expiry",
        "crypto_keys",
        "org_crypto_keys",
        "client_secret",
    ] {
        if raw.get(forbidden).is_some() {
            return Err(SessionError::BackendUnavailable);
        }
    }
    if raw.get("kdf").is_some_and(|kdf| kdf != 0) {
        return Err(SessionError::BackendUnavailable);
    }
    let config: Config =
        serde_json::from_value(raw).map_err(|_| SessionError::BackendUnavailable)?;
    if config.email.as_deref().is_none_or(str::is_empty)
        || config.client_id.as_deref().is_none_or(str::is_empty)
        || config.encrypted_key.is_none()
        || config.kdf_iterations.is_none()
    {
        return Err(SessionError::BackendUnavailable);
    }
    Ok(config)
}
pub(crate) fn derive_keys(
    config: &Config,
    password: &SensitiveString,
) -> Result<CryptoKeys, SessionError> {
    let iterations = bounded_kdf_iterations(config)?;
    let encrypted = config
        .encrypted_key
        .as_deref()
        .ok_or(SessionError::AuthenticationFailed)?;
    if !encrypted.starts_with("2.") || encrypted.split('|').count() != 3 {
        return Err(SessionError::AuthenticationFailed);
    }
    MasterKey::derive(
        password.expose(),
        config
            .email
            .as_deref()
            .ok_or(SessionError::AuthenticationFailed)?,
        iterations,
    )
    .decrypt_symmetric_key(encrypted)
    .map_err(|_| SessionError::AuthenticationFailed)
}

fn bounded_kdf_iterations(config: &Config) -> Result<KdfIterations, SessionError> {
    let iterations = config
        .kdf_iterations
        .ok_or(SessionError::AuthenticationFailed)?;
    if iterations.get() > 2_000_000 {
        return Err(SessionError::AuthenticationFailed);
    }
    Ok(iterations)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn suspend_clock_boundaries_and_failures_never_extend_authority() {
        assert_eq!(boot_duration(0, 0), Some(Duration::ZERO));
        assert_eq!(
            boot_duration(1, 999_999_999),
            Some(Duration::new(1, 999_999_999))
        );
        for (sec, ns) in [(-1, 0), (0, -1), (0, 1_000_000_000)] {
            assert_eq!(boot_duration(sec, ns), None);
        }
        assert!(boot_time().is_some());
        let clock = MonotonicClock::default();
        assert_eq!(
            clock.observe(|| Some(Duration::from_secs(10))),
            Duration::from_secs(10)
        );
        assert_eq!(
            clock.observe(|| Some(Duration::from_secs(10))),
            Duration::from_secs(10)
        );
        // A suspend advances boot time even while runtime Instant would be paused.
        assert_eq!(
            clock.observe(|| Some(Duration::from_secs(910))),
            Duration::from_secs(910)
        );
        assert_eq!(
            clock.observe(|| Some(Duration::from_secs(909))),
            Duration::MAX
        );
        assert_eq!(
            clock.observe(|| Some(Duration::from_secs(911))),
            Duration::MAX
        );
        let failed = MonotonicClock::default();
        assert_eq!(failed.observe(|| None), Duration::MAX);
        assert_eq!(failed.observe(|| Some(Duration::ZERO)), Duration::MAX);
        let poisoned = MonotonicClock::default();
        let _ = std::panic::catch_unwind(|| {
            let _guard = poisoned.0.lock().unwrap();
            panic!("synthetic clock mutex failure");
        });
        assert_eq!(poisoned.now(), Duration::MAX);
    }
    #[test]
    fn provider_guards_ignore_the_direct_cli_insecure_mac_override() {
        for test in [
            "adapters::session::tests::silent_derivation_and_setup_require_supported_authenticated_keys",
            "adapters::vaultwarden::tests::resolution_rejects_wrong_deleted_unmarked_or_ambiguous_items",
            "adapters::vaultwarden::tests::organization_binding_uses_only_provisioned_org_keys",
            "adapters::vaultwarden::tests::personal_and_organization_item_keys_authenticate_before_selected_fields",
        ] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test, "--quiet"])
                .env("VAULTWARDEN_ALLOW_INSECURE_MAC", "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated provider check failed: {test}\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "isolated check did not run: {test}"
            );
        }
    }
    #[test]
    fn kdf_cost_is_validated_before_expensive_derivation() {
        for count in [1, 1_999_999, 2_000_000] {
            let config = Config {
                kdf_iterations: KdfIterations::new(count),
                ..Config::default()
            };
            assert_eq!(bounded_kdf_iterations(&config).unwrap().get(), count);
        }
        for count in [0, 2_000_001, u32::MAX] {
            let config = Config {
                kdf_iterations: KdfIterations::new(count),
                ..Config::default()
            };
            assert_eq!(
                bounded_kdf_iterations(&config),
                Err(SessionError::AuthenticationFailed)
            );
        }
    }
    #[test]
    fn production_clock_advances_monotonically() {
        let clock = MonotonicClock::default();
        let first = clock.now();
        std::thread::sleep(Duration::from_millis(2));
        assert!(clock.now() > first);
    }

    #[test]
    fn valid_setup_still_rejects_authority_unsafe_modes_links_and_oversize() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("setup.json");
        let raw = serde_json::json!({"server":"https://example.test/", "email":"human@example.test", "client_id":"human", "encrypted_key":"2.encrypted", "kdf_iterations":1});
        let write = |value: &serde_json::Value| {
            std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        write(&raw);
        assert!(load_setup(&path).is_ok());
        for key in [
            "access_token",
            "refresh_token",
            "token_expiry",
            "crypto_keys",
            "org_crypto_keys",
            "client_secret",
        ] {
            let mut forbidden = raw.clone();
            forbidden[key] = serde_json::json!("authority-sentinel");
            write(&forbidden);
            assert!(load_setup(&path).is_err(), "accepted forbidden field {key}");
        }
        write(&raw);
        for mode in [0o644, 0o640, 0o660, 0o400] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(load_setup(&path).is_err(), "accepted mode {mode:o}");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let linked = dir.path().join("hard-link.json");
        std::fs::hard_link(&path, &linked).unwrap();
        assert!(load_setup(&path).is_err());
        std::fs::remove_file(linked).unwrap();
        assert!(load_setup(&path).is_ok());
        let symlink = dir.path().join("symlink.json");
        std::os::unix::fs::symlink(&path, &symlink).unwrap();
        assert!(load_setup(&symlink).is_err());
        let mut padded = serde_json::to_vec(&raw).unwrap();
        padded.resize(65536, b' ');
        std::fs::write(&path, &padded).unwrap();
        assert!(load_setup(&path).is_ok());
        padded.push(b' ');
        std::fs::write(&path, &padded).unwrap();
        assert!(load_setup(&path).is_err());
    }
    #[test]
    fn provider_keyring_deletes_real_record_and_preserves_cli_and_bootstrap() {
        let _guard = crate::KEYRING_TEST_LOCK.lock().unwrap();
        let previous = keyring_core::unset_default_store();
        keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap());
        let cli = Entry::new("vaultwarden-cli", "test:tokens").unwrap();
        cli.set_password("cli-session-sentinel").unwrap();
        ProviderKeyring::entry(BOOTSTRAP_ACCOUNT)
            .unwrap()
            .set_password("bootstrap-sentinel")
            .unwrap();
        let keys = CryptoKeys::from_key_bytes([1; 32], [2; 32]);
        ProviderKeyring.save("session-sentinel", &keys).unwrap();
        assert!(
            ProviderKeyring::entry(SESSION_ACCOUNT)
                .unwrap()
                .get_password()
                .unwrap()
                .contains("session-sentinel")
        );
        ProviderKeyring.clear().unwrap();
        assert!(matches!(
            ProviderKeyring::entry(SESSION_ACCOUNT)
                .unwrap()
                .get_password(),
            Err(Error::NoEntry)
        ));
        ProviderKeyring.clear().unwrap();
        assert_eq!(cli.get_password().unwrap(), "cli-session-sentinel");
        assert_eq!(
            ProviderKeyring.bootstrap().unwrap().expose(),
            "bootstrap-sentinel"
        );
        if let Some(previous) = previous {
            keyring_core::set_default_store(previous);
        } else {
            keyring_core::unset_default_store();
        }
    }

    #[test]
    fn setup_rejects_owned_fifo_even_with_valid_complete_configuration() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let contents = br#"{"server":"https://example.test/","email":"human@example.test","client_id":"human","encrypted_key":"2.encrypted","kdf_iterations":1}"#;
        let regular = dir.path().join("setup.json");
        std::fs::write(&regular, contents).unwrap();
        std::fs::set_permissions(&regular, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_setup(&regular).is_ok());
        let fifo = dir.path().join("setup.fifo");
        let _keeper = crate::adapters::buffered_fifo(&fifo, contents);
        assert_eq!(
            crate::adapters::within_test_deadline(move || load_setup(&fifo).unwrap_err()),
            SessionError::BackendUnavailable
        );
    }
    #[test]
    fn setup_rejects_authority_and_unsafe_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("setup.json");
        for contents in [r#"{"access_token":"token-sentinel"}"#, "password-sentinel"] {
            std::fs::write(&path, contents).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(
                load_setup(&path).unwrap_err(),
                SessionError::BackendUnavailable
            );
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            load_setup(&path).unwrap_err(),
            SessionError::BackendUnavailable
        );
    }
    #[test]
    fn silent_derivation_and_setup_require_supported_authenticated_keys() {
        use crate::crypto::{
            KdfIterations, crypto_keys::tests::test_helpers::encrypt_bytes_for_test,
        };
        use std::os::unix::fs::PermissionsExt;
        let iterations = KdfIterations::new(1).unwrap();
        let stretched = MasterKey::derive("password-sentinel", "human@example.test", iterations)
            .stretch()
            .unwrap();
        let encrypted = encrypt_bytes_for_test(&[42; 64], stretched.enc_key(), stretched.mac_key());
        let config = Config {
            server: Some("https://example.test/".into()),
            email: Some("human@example.test".into()),
            client_id: Some("human".into()),
            encrypted_key: Some(encrypted),
            kdf_iterations: Some(iterations),
            ..Config::default()
        };
        let password = || SensitiveString::new("password-sentinel".into());
        assert_eq!(
            derive_keys(&config, &password()).unwrap().enc_key_bytes(),
            &[42; 32]
        );
        assert_eq!(
            derive_keys(&config, &SensitiveString::new("wrong".into())).unwrap_err(),
            SessionError::AuthenticationFailed
        );
        for bad in [
            Config {
                kdf_iterations: None,
                ..config.clone()
            },
            Config {
                kdf_iterations: KdfIterations::new(2_000_001),
                ..config.clone()
            },
            Config {
                encrypted_key: Some("0.unverified".into()),
                ..config.clone()
            },
            Config {
                encrypted_key: Some("2.unverified|missing-mac".into()),
                ..config.clone()
            },
            Config {
                encrypted_key: Some(
                    config
                        .encrypted_key
                        .as_ref()
                        .unwrap()
                        .rsplit_once('|')
                        .unwrap()
                        .0
                        .to_owned(),
                ),
                ..config.clone()
            },
            Config {
                email: None,
                ..config.clone()
            },
        ] {
            assert!(derive_keys(&bad, &password()).is_err());
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("setup.json");
        let raw = serde_json::to_value(&config).unwrap();
        std::fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_setup(&path).is_ok());
        for field in ["email", "client_id", "encrypted_key", "kdf_iterations"] {
            let mut invalid = raw.clone();
            invalid.as_object_mut().unwrap().remove(field);
            std::fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
            assert!(load_setup(&path).is_err());
        }
        let mut invalid = raw;
        invalid["kdf"] = serde_json::json!(1);
        std::fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(load_setup(&path).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(load_setup(&link).is_err());
    }
}
