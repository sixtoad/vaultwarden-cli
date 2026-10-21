use crate::provider::session::ProviderSession;
use std::sync::{Mutex, OnceLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderCommand {
    Session,
    List,
    Review,
    Approve,
    Deny,
    Unlock,
    Status,
}

/// Transient wire bytes are handed directly to the native TLS adapter. Do not log.
pub struct ProviderWork {
    pub token: u32,
    pub body: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct ProviderSnapshot {
    pub configured: bool,
    pub busy: bool,
    pub locked: bool,
    pub requests: Vec<String>,
    pub review_text: String,
    pub review_id: String,
    pub can_decide: bool,
    pub uncertain_id: String,
    pub status_id: String,
    pub status_text: String,
    pub message: String,
}
fn session() -> &'static Mutex<ProviderSession> {
    static SESSION: OnceLock<Mutex<ProviderSession>> = OnceLock::new();
    SESSION.get_or_init(|| Mutex::new(ProviderSession::default()))
}
#[flutter_rust_bridge::frb(sync)]
pub fn provider_snapshot() -> ProviderSnapshot {
    session()
        .lock()
        .expect("provider mutex poisoned")
        .snapshot()
}
#[flutter_rust_bridge::frb(sync)]
pub fn provider_configure(uncertain_id: String) -> Result<ProviderSnapshot, String> {
    let mut state = session().lock().map_err(|_| "Provider core unavailable.")?;
    state.configure(&uncertain_id)?;
    Ok(state.snapshot())
}
#[flutter_rust_bridge::frb(sync)]
pub fn provider_invalidate() -> ProviderSnapshot {
    let mut state = session().lock().expect("provider mutex poisoned");
    state.invalidate();
    state.snapshot()
}
#[flutter_rust_bridge::frb(sync)]
pub fn provider_begin(
    command: ProviderCommand,
    request_id: String,
    password: String,
) -> Result<ProviderWork, String> {
    session()
        .lock()
        .map_err(|_| "Provider core unavailable.")?
        .begin(command, request_id, password)
        .map_err(String::from)
}
#[flutter_rust_bridge::frb(sync)]
pub fn provider_finish(token: u32, response: Vec<u8>) -> ProviderSnapshot {
    let mut state = session().lock().expect("provider mutex poisoned");
    state.finish(token, &response);
    state.snapshot()
}
