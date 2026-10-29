use crate::provider::session::ProviderSession;
use std::sync::{Mutex, OnceLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderCommand {
    Session,
    List,
    History,
    Review,
    Approve,
    Deny,
    Unlock,
    Status,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProviderOutcome {
    #[default]
    None,
    Accepted,
    Rejected,
    Invalid,
    Stale,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProviderStatusProgress {
    #[default]
    None,
    Pending,
    Committed,
    Terminal,
}

/// Transient wire bytes are handed directly to the native TLS adapter. Do not log.
pub struct ProviderWork {
    pub token: u32,
    pub body: Vec<u8>,
}
/// Display-only projection of a validated review. Strings originating in the
/// response are already quoted and escaped; no ticket or decision authority is
/// exposed here. The snapshot's can_decide remains the authority indicator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderReview {
    pub id: String,
    pub requester: String,
    pub operation: String,
    pub effect: String,
    pub target: String,
    pub arguments: Vec<String>,
    pub credentials: Vec<ProviderReviewCredential>,
    pub executable_digest: String,
    pub policy_digest: String,
    pub arguments_digest: String,
    pub expires_at_unix_seconds: u64,
    pub one_time: String,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderReviewCredential {
    pub label: String,
    pub use_type: String,
}

/// History is display-only; none of these values convey decision authority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProviderHistoryState {
    #[default]
    Idle,
    Loading,
    Available,
    Unavailable,
}

#[derive(Clone, Copy, Debug, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderHistoryOutcome {
    Submitted,
    Approved,
    Denied,
    Expired,
    ReviewUnavailable,
    ExecutionStarted,
    Succeeded,
    ExecutionNonzero,
    ExecutionSignaled,
    ExecutionRejected,
    ExecutionUnavailable,
    Invalidated,
    Recovered,
    LegacyUnknown,
    Reconciled,
    ObservationLost,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderHistoryEvent {
    pub request_id: String,
    pub operation: String,
    pub at_unix_seconds: Option<u64>,
    pub ordinal: u32,
    pub outcome: ProviderHistoryOutcome,
}

#[derive(Clone, Debug)]
pub struct ProviderSnapshot {
    pub outcome: ProviderOutcome,
    pub status_progress: ProviderStatusProgress,
    pub configured: bool,
    pub busy: bool,
    pub locked: bool,
    pub authority_known: bool,
    pub history_state: ProviderHistoryState,
    pub history: Vec<ProviderHistoryEvent>,
    pub requests: Vec<String>,
    pub review_text: String,
    pub review: Option<ProviderReview>,
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
