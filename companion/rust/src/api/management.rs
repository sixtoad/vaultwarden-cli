//! Display-only management projections. Tickets never leave the Rust session.
use crate::provider::management::ManagementSession;
use serde::{Deserialize, Serialize};
use std::sync::{Mutex, OnceLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    ApprovalClient,
    RequesterAgent,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedIdentity {
    pub kind: IdentityKind,
    pub id: String,
    pub label: String,
    pub fingerprint: String,
    pub roles: Vec<IdentityRole>,
    pub trust: IdentityTrust,
    pub this_client: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityRole {
    Approve,
    Admin,
    Request,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityTrust {
    Enabled,
    Revoked,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementCommand {
    List,
    Next,
    Detail,
    Prepare,
    Revoke,
    Status,
    Origin,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum InventoryState {
    #[default]
    Unavailable,
    Ready,
    Empty,
    Unauthorized,
    Stale,
    Revoked,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ManagementOutcome {
    #[default]
    None,
    Accepted,
    Rejected,
    Invalid,
    Stale,
    Unsupported,
}
#[derive(Clone, Debug)]
pub struct ManagementSnapshot {
    pub state: InventoryState,
    pub outcome: ManagementOutcome,
    pub busy: bool,
    pub identities: Vec<ManagedIdentity>,
    pub detail: Option<ManagedIdentity>,
    pub can_revoke: bool,
    pub has_next: bool,
    pub provider_fingerprint: String,
    pub execution_configured: bool,
    pub execution_available: bool,
    pub recovery: String,
    pub action_id: String,
    pub action_target: String,
    pub revocation: String,
    pub cleanup: String,
    pub message: String,
    pub origin_id: String,
    pub origin_text: String,
}
fn session() -> &'static Mutex<ManagementSession> {
    static SESSION: OnceLock<Mutex<ManagementSession>> = OnceLock::new();
    SESSION.get_or_init(|| Mutex::new(ManagementSession::default()))
}
#[flutter_rust_bridge::frb(sync)]
pub fn management_snapshot() -> ManagementSnapshot {
    session().lock().expect("management core").snapshot()
}
#[flutter_rust_bridge::frb(sync)]
pub fn management_configure(recovery: String) -> Result<ManagementSnapshot, String> {
    let mut s = session().lock().map_err(|_| "Management unavailable")?;
    s.configure(&recovery).map_err(String::from)?;
    Ok(s.snapshot())
}
#[flutter_rust_bridge::frb(sync)]
pub fn management_invalidate() -> ManagementSnapshot {
    let mut s = session().lock().expect("management core");
    s.invalidate();
    s.snapshot()
}
#[flutter_rust_bridge::frb(sync)]
pub fn management_begin(
    command: ManagementCommand,
    kind: IdentityKind,
    id: String,
    password: String,
) -> Result<super::provider::ProviderWork, String> {
    session()
        .lock()
        .map_err(|_| "Management unavailable")?
        .begin(command, kind, id, password)
        .map_err(String::from)
}
#[flutter_rust_bridge::frb(sync)]
pub fn management_finish(token: u32, response: Vec<u8>) -> ManagementSnapshot {
    let mut s = session().lock().expect("management core");
    s.finish(token, &response);
    s.snapshot()
}
