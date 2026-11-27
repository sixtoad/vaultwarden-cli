//! The `ProviderPlatform` contract of `docs/mobile-clients.md` section 1
//! (configuration, setup, send, settle, invalidation) for Windows and Linux,
//! over `store`, `recovery` and `transport`. One exchange at a time.
use super::identity::{ClientIdentity, MAX_CA, MAX_PKCS12};
use super::recovery::{ManagementGate, Recovery};
use super::rules::{valid_hex, valid_request_id, Endpoint, MAX_REQUEST};
use super::store::{Saved, Store};
use super::transport::{self, Exchange};
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Configuration {
    pub configured: bool,
    pub endpoint: String,
    pub pin: String,
    pub fingerprint: String,
    pub uncertain_id: String,
    pub management_recovery: String,
}
impl Configuration {
    fn of(saved: &Saved) -> Self {
        Self {
            configured: true,
            endpoint: saved.endpoint.url(),
            pin: saved.pin.clone(),
            fingerprint: saved.identity.fingerprint(),
            uncertain_id: saved.recovery.pending_id.clone().unwrap_or_default(),
            management_recovery: saved.recovery.management_json(),
        }
    }
}

const CONFIGURATION: &str = "provider_configuration_invalid";
const UNAVAILABLE: &str = "provider_unavailable";

#[derive(Default)]
struct State {
    gate: ManagementGate,
    active: bool,
}
pub struct Service {
    store: Store,
    state: Mutex<State>,
}

fn read_file(path: &str, maximum: usize) -> Result<Vec<u8>, &'static str> {
    use std::io::Read;
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(CONFIGURATION);
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(maximum as u64 + 1).read_to_end(&mut bytes))
        .map_err(|_| CONFIGURATION)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(CONFIGURATION);
    }
    Ok(bytes)
}

impl Service {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            state: Mutex::new(State::default()),
        }
    }
    fn state(&self) -> Result<std::sync::MutexGuard<'_, State>, &'static str> {
        self.state.lock().map_err(|_| UNAVAILABLE)
    }
    pub fn configuration(&self) -> Result<Configuration, &'static str> {
        if !self.store.exists() {
            return Ok(Configuration::default());
        }
        let saved = self.store.load().map_err(|e| e.code())?;
        Ok(Configuration::of(&saved))
    }
    /// Validates everything before writing; refused while a decision or an
    /// administrative revocation is unresolved, or while an exchange runs.
    pub fn setup(
        &self,
        endpoint: &str,
        pin: &str,
        ca_path: &str,
        identity_path: &str,
        passphrase: &str,
    ) -> Result<Configuration, &'static str> {
        let state = self.state()?;
        if state.active
            || (self.store.exists()
                && self
                    .store
                    .load()
                    .map(|saved| saved.recovery.has_pending())
                    .unwrap_or(true))
        {
            return Err(CONFIGURATION);
        }
        let endpoint = Endpoint::parse(endpoint).ok_or(CONFIGURATION)?;
        if !valid_hex(pin, 64) || passphrase.len() > 4096 {
            return Err(CONFIGURATION);
        }
        let ca = read_file(ca_path, MAX_CA)?;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(ca.clone()))
            .map_err(|_| CONFIGURATION)?;
        let bundle = zeroize::Zeroizing::new(read_file(identity_path, MAX_PKCS12)?);
        let identity = ClientIdentity::from_pkcs12(&bundle, passphrase)
            .ok_or("provider_identity_unavailable")?;
        let saved = Saved {
            endpoint,
            ca,
            pin: pin.into(),
            identity,
            recovery: Recovery::default(),
        };
        self.store.save(&saved).map_err(|e| e.code())?;
        drop(state);
        Ok(Configuration::of(&saved))
    }
    pub fn send(&self, body: &[u8], foreground: bool) -> Result<Vec<u8>, &'static str> {
        if body.len() > MAX_REQUEST {
            return Err(CONFIGURATION);
        }
        let (epoch, saved) = {
            let mut state = self.state()?;
            if state.active {
                return Err(CONFIGURATION);
            }
            let epoch = state
                .gate
                .begin(body, foreground, Instant::now())
                .ok_or(CONFIGURATION)?;
            let mut saved = self.store.load().map_err(|e| e.code())?;
            // Persist before sending: even a process kill stays uncertain.
            let next = saved.recovery.before_send(body).ok_or(CONFIGURATION)?;
            if next != saved.recovery {
                saved.recovery = next;
                self.store.save(&saved).map_err(|e| e.code())?;
            }
            state.active = true;
            (epoch, saved)
        };
        let result = transport::send(
            &Exchange {
                endpoint: &saved.endpoint,
                ca: &saved.ca,
                pin: &saved.pin,
                identity: &saved.identity,
            },
            body,
        );
        let mut state = self.state()?;
        state.active = false;
        let response = result.map_err(|e| e.code())?;
        if !state
            .gate
            .finish(body, &response, epoch, foreground, Instant::now())
        {
            return Err(CONFIGURATION);
        }
        Ok(response)
    }
    pub fn settle(&self, id: &str) -> Result<(), &'static str> {
        let _state = self.state()?;
        if !valid_request_id(id) {
            return Err(CONFIGURATION);
        }
        let saved = self.store.load().map_err(|e| e.code())?;
        let next = saved.recovery.settle(id).ok_or(CONFIGURATION)?;
        self.store.save_recovery(saved, next).map_err(|e| e.code())
    }
    /// A lifecycle change: any prepared administrative ticket is discarded.
    pub fn invalidate(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.gate.invalidate();
        }
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
