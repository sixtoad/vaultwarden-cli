//! The desktop provider transport for Windows and Linux (D-2): the
//! `ProviderPlatform` methods of `docs/mobile-clients.md` section 1, called
//! from Dart by `CoreProviderPlatform`. Errors are closed codes only. On
//! targets without the desktop module every call is `provider_unavailable`.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use crate::desktop::service::Service;

/// The `configuration` reply (`NativeProviderPlatform._parse` fields).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DesktopProviderConfiguration {
    pub configured: bool,
    pub endpoint: String,
    pub pin: String,
    pub fingerprint: String,
    pub uncertain_id: String,
    pub management_recovery: String,
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn service() -> Result<&'static Service, String> {
    use std::sync::OnceLock;
    static SERVICE: OnceLock<Option<Service>> = OnceLock::new();
    SERVICE
        .get_or_init(|| {
            crate::desktop::store::Store::default_directory()
                .map(|dir| Service::new(crate::desktop::store::Store::new(dir)))
        })
        .as_ref()
        .ok_or_else(|| "provider_unavailable".to_owned())
}
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn wire(c: crate::desktop::service::Configuration) -> DesktopProviderConfiguration {
    DesktopProviderConfiguration {
        configured: c.configured,
        endpoint: c.endpoint,
        pin: c.pin,
        fingerprint: c.fingerprint,
        uncertain_id: c.uncertain_id,
        management_recovery: c.management_recovery,
    }
}
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn unavailable<T>() -> Result<T, String> {
    Err("provider_unavailable".to_owned())
}

pub fn desktop_provider_configuration() -> Result<DesktopProviderConfiguration, String> {
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    return service()?.configuration().map(wire).map_err(str::to_owned);
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    unavailable()
}
/// Reads the CA (DER) and the PKCS#12 from absolute paths (D-4); the bytes,
/// the passphrase and the key never return to Dart.
pub fn desktop_provider_setup(
    endpoint: String,
    pin: String,
    ca_path: String,
    identity_path: String,
    passphrase: String,
) -> Result<DesktopProviderConfiguration, String> {
    let passphrase = zeroize::Zeroizing::new(passphrase);
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    return service()?
        .setup(&endpoint, &pin, &ca_path, &identity_path, &passphrase)
        .map(wire)
        .map_err(str::to_owned);
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (endpoint, pin, ca_path, identity_path, passphrase);
        unavailable()
    }
}
/// One exchange; `foreground` is whether Flutter reports the app resumed.
pub fn desktop_provider_send(body: Vec<u8>, foreground: bool) -> Result<Vec<u8>, String> {
    let body = zeroize::Zeroizing::new(body);
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    return service()?.send(&body, foreground).map_err(str::to_owned);
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (body, foreground);
        unavailable()
    }
}
pub fn desktop_provider_settle(id: String) -> Result<(), String> {
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    return service()?.settle(&id).map_err(str::to_owned);
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = id;
        unavailable()
    }
}
/// The app left the foreground: discard any prepared administrative ticket.
#[flutter_rust_bridge::frb(sync)]
pub fn desktop_provider_invalidate() {
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    if let Ok(service) = service() {
        service.invalidate();
    }
}
