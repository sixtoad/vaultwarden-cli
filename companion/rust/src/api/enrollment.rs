//! Guided enrollment (#59 phase 2). Display-only projections: the invitation
//! secret and the session transcript never leave Rust. The joiner shows its
//! comparison code; the owner side never receives or shows one.
use super::provider::ProviderWork;
use crate::provider::{enrollment::JoinerSession, enrollment_admin::AdminSession};
use std::sync::{Mutex, OnceLock};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EnrolleeRole {
    #[default]
    Companion,
    Agent,
}

/// Joiner messages after the join. `Retry` resends the identical join.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinerCommand {
    Retry,
    Status,
    Confirm,
    Decline,
    Cancel,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum JoinerPhase {
    #[default]
    Idle,
    /// The join was sent; no verified provider half yet.
    Joining,
    /// The provider proved the invitation: show the code, ask the human.
    Compare,
    /// This human confirmed; waiting for the provider owner's approval.
    Waiting,
    Enrolled,
    Ended,
}

/// Why a joiner session ended (closed set; never provider free text).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum JoinerEnd {
    #[default]
    None,
    /// This human said the codes differ.
    Declined,
    Cancelled,
    CancelledByProvider,
    /// The provider owner typed a different code (a relay, or a typo).
    CodeMismatch,
    /// A second, different join used the invitation: it leaked.
    DuplicateJoin,
    TooManyFailures,
    Expired,
    /// Known to the provider (enrolled or revoked): never reactivated.
    IdentityRefused,
    /// The provider could not record the device; the outcome is unclear.
    CommitUnavailable,
    InvalidInvitation,
    AlreadyUsed,
    /// The reply did not prove knowledge of the invitation secret.
    ProviderNotAuthenticated,
    /// The invitation is for another kind of endpoint (an agent).
    WrongRole,
    Malformed,
    /// A confirmation's reply was lost and the provider forgot the session.
    OutcomeUnknown,
}

#[derive(Clone, Debug, Default)]
pub struct JoinerSnapshot {
    pub phase: JoinerPhase,
    pub busy: bool,
    pub role: EnrolleeRole,
    pub label: String,
    /// `1234-5678`, only while the session is live and verified.
    pub comparison_code: String,
    pub seconds_remaining: u64,
    pub provider_approved: bool,
    pub confirmed: bool,
    pub end: JoinerEnd,
    /// The last exchange failed transiently (offline, busy): retry is safe.
    pub retryable: bool,
    /// Diagnostics only.
    pub invitation_id: String,
    pub enrolled_fingerprint: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminCommand {
    Invite,
    List,
    Approve,
    Cancel,
}

#[derive(Clone, Debug)]
pub struct EnrollmentAdminRequest {
    pub command: AdminCommand,
    pub role: EnrolleeRole,
    pub label: String,
    pub agent_uid: u32,
    pub agent_gid: u32,
    pub id: String,
    /// The code read on the joining endpoint, typed by this human.
    pub code: String,
    pub password: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AdminState {
    #[default]
    Unknown,
    Ready,
    /// This approval client is not a provider administrator.
    Unauthorized,
    /// The provider does not offer enrollment to companions.
    Unsupported,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AdminOutcome {
    #[default]
    None,
    Listed,
    Invited,
    Approved,
    Cancelled,
    Refused,
    AuthenticationFailed,
    RateLimited,
    Unavailable,
    Invalid,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AdminRefusal {
    #[default]
    None,
    InvalidRequest,
    Duplicate,
    LimitReached,
    NotFound,
    Expired,
    Final,
    AwaitingPeer,
    CodeMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminSessionState {
    AwaitingJoin,
    AwaitingApprovals,
    Enrolled,
    Cancelled,
    Expired,
    Aborted,
    Failed,
}

#[derive(Clone, Debug)]
pub struct AdminSessionView {
    pub id: String,
    pub role: EnrolleeRole,
    pub label: String,
    pub agent_uid: u32,
    pub agent_gid: u32,
    pub state: AdminSessionState,
    pub provider_approved: bool,
    pub joiner_confirmed: bool,
    /// Closed detail: who cancelled, why aborted/failed, or the enrolled id.
    pub detail: String,
    pub expires_in_seconds: u64,
    pub joiner_fingerprint: String,
}

/// Returned once; dismissing wipes it from Rust.
#[derive(Clone, Debug)]
pub struct IssuedInvitationView {
    pub id: String,
    pub invitation_code: String,
    pub role: EnrolleeRole,
    pub label: String,
    pub expires_in_seconds: u64,
}

#[derive(Clone, Debug, Default)]
pub struct EnrollmentAdminSnapshot {
    pub state: AdminState,
    pub outcome: AdminOutcome,
    pub refusal: AdminRefusal,
    pub busy: bool,
    pub issued: Option<IssuedInvitationView>,
    pub sessions: Vec<AdminSessionView>,
}

fn joiner() -> &'static Mutex<JoinerSession> {
    static SESSION: OnceLock<Mutex<JoinerSession>> = OnceLock::new();
    SESSION.get_or_init(|| Mutex::new(JoinerSession::default()))
}
fn admin() -> &'static Mutex<AdminSession> {
    static SESSION: OnceLock<Mutex<AdminSession>> = OnceLock::new();
    SESSION.get_or_init(|| Mutex::new(AdminSession::default()))
}

#[flutter_rust_bridge::frb(sync)]
pub fn enrollment_joiner_snapshot() -> JoinerSnapshot {
    joiner().lock().expect("enrollment core").snapshot()
}
/// Start a join with the typed invitation. The fingerprints come from the
/// configured pinned transport (this client leaf, the provider leaf).
#[flutter_rust_bridge::frb(sync)]
pub fn enrollment_join(
    mut invitation: String,
    device_fingerprint: String,
    provider_pin: String,
) -> Result<ProviderWork, String> {
    let mut nonce = [0u8; 32];
    let result = getrandom::fill(&mut nonce)
        .map_err(|_| "Enrollment unavailable")
        .and_then(|()| {
            joiner().lock().map_err(|_| "Enrollment unavailable")?.join(
                &invitation,
                &device_fingerprint,
                &provider_pin,
                nonce,
            )
        });
    zeroize::Zeroize::zeroize(&mut invitation);
    result.map_err(String::from)
}
#[flutter_rust_bridge::frb(sync)]
pub fn enrollment_joiner_begin(command: JoinerCommand) -> Result<ProviderWork, String> {
    joiner()
        .lock()
        .map_err(|_| "Enrollment unavailable")?
        .begin(command)
        .map_err(String::from)
}
#[flutter_rust_bridge::frb(sync)]
pub fn enrollment_joiner_finish(token: u32, response: Vec<u8>) -> JoinerSnapshot {
    let mut s = joiner().lock().expect("enrollment core");
    s.finish(token, &response);
    s.snapshot()
}
/// Forget the session and wipe its secret (also after a final state).
#[flutter_rust_bridge::frb(sync)]
pub fn enrollment_joiner_reset() -> JoinerSnapshot {
    let mut s = joiner().lock().expect("enrollment core");
    s.reset();
    s.snapshot()
}

#[flutter_rust_bridge::frb(sync)]
pub fn enrollment_admin_snapshot() -> EnrollmentAdminSnapshot {
    admin().lock().expect("enrollment core").snapshot()
}
#[flutter_rust_bridge::frb(sync)]
pub fn enrollment_admin_begin(request: EnrollmentAdminRequest) -> Result<ProviderWork, String> {
    admin()
        .lock()
        .map_err(|_| "Enrollment unavailable")?
        .begin(request)
        .map_err(String::from)
}
#[flutter_rust_bridge::frb(sync)]
pub fn enrollment_admin_finish(token: u32, response: Vec<u8>) -> EnrollmentAdminSnapshot {
    let mut s = admin().lock().expect("enrollment core");
    s.finish(token, &response);
    s.snapshot()
}
#[flutter_rust_bridge::frb(sync)]
pub fn enrollment_admin_dismiss_invitation() -> EnrollmentAdminSnapshot {
    let mut s = admin().lock().expect("enrollment core");
    s.dismiss_invitation();
    s.snapshot()
}
#[flutter_rust_bridge::frb(sync)]
pub fn enrollment_admin_invalidate() -> EnrollmentAdminSnapshot {
    let mut s = admin().lock().expect("enrollment core");
    s.invalidate();
    s.snapshot()
}
