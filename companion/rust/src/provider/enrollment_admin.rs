//! Provider-owner half of guided enrollment (#59 phase 2) for an
//! administrator companion. The provider never sends a comparison code and a
//! reply carrying one is refused: the owner must read the code on the joining
//! endpoint and type it here.
use super::enrollment::{display_label, valid_label};
use super::protocol::{valid_hex, valid_id, ErrorCode, ErrorResponse, RESPONSE_LIMIT};
use crate::api::enrollment::*;
use crate::api::provider::ProviderWork;
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

/// Live invitations plus recently finished sessions the provider retains.
const MAX_SESSIONS: usize = 32;

#[derive(Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
enum Kind {
    Agent { label: String, uid: u32, gid: u32 },
    Companion { label: String },
}
impl Kind {
    fn valid(&self) -> bool {
        match self {
            Self::Agent { label, uid, gid } => valid_agent(label, *uid, *gid),
            Self::Companion { label } => valid_label(label),
        }
    }
    /// Role, the label as sent (not the display form), uid, gid.
    fn raw(&self) -> (EnrolleeRole, &str, u32, u32) {
        match self {
            Self::Agent { label, uid, gid } => (EnrolleeRole::Agent, label, *uid, *gid),
            Self::Companion { label } => (EnrolleeRole::Companion, label, 0, 0),
        }
    }
    fn parts(&self) -> (EnrolleeRole, String, u32, u32) {
        match self {
            Self::Agent { label, uid, gid } => {
                (EnrolleeRole::Agent, display_label(label), *uid, *gid)
            }
            Self::Companion { label } => (EnrolleeRole::Companion, display_label(label), 0, 0),
        }
    }
}
fn valid_agent(label: &str, uid: u32, gid: u32) -> bool {
    valid_label(label)
        && label.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
        && ![0, u32::MAX].contains(&uid)
        && ![0, u32::MAX].contains(&gid)
}
#[derive(Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
enum Identity {
    Agent {
        binding_id: String,
        #[allow(dead_code)]
        fingerprint: String,
    },
    Companion {
        fingerprint: String,
    },
}
#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum State {
    AwaitingJoin {},
    AwaitingApprovals {
        provider_approved: bool,
        joiner_confirmed: bool,
    },
    Enrolled {
        identity: Identity,
    },
    Cancelled {
        by: Closed,
    },
    Expired {},
    Aborted {
        reason: Closed,
    },
    Failed {
        reason: Closed,
    },
}
/// Closed reason words from the provider (snake_case, bounded).
#[derive(Deserialize)]
#[serde(try_from = "String")]
struct Closed(String);
impl TryFrom<String> for Closed {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        (!value.is_empty()
            && value.len() <= 32
            && value.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
        .then_some(Self(value))
        .ok_or("closed reason")
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct View {
    id: String,
    kind: Kind,
    state: State,
    expires_in_seconds: u64,
    #[serde(default)]
    joiner_fingerprint: Option<String>,
}
impl View {
    fn project(self) -> Option<AdminSessionView> {
        if !valid_id(&self.id)
            || !self.kind.valid()
            || self.expires_in_seconds > 1800
            || self
                .joiner_fingerprint
                .as_deref()
                .is_some_and(|f| !valid_hex(f))
        {
            return None;
        }
        let (role, label, agent_uid, agent_gid) = self.kind.parts();
        let (state, provider_approved, joiner_confirmed, detail) = match self.state {
            State::AwaitingJoin {} => {
                (AdminSessionState::AwaitingJoin, false, false, String::new())
            }
            State::AwaitingApprovals {
                provider_approved,
                joiner_confirmed,
            } => (
                AdminSessionState::AwaitingApprovals,
                provider_approved,
                joiner_confirmed,
                String::new(),
            ),
            State::Enrolled { identity } => {
                let detail = match identity {
                    Identity::Agent { binding_id, .. } if valid_id(&binding_id) => binding_id,
                    Identity::Companion { fingerprint } if valid_hex(&fingerprint) => fingerprint,
                    _ => return None,
                };
                (AdminSessionState::Enrolled, true, true, detail)
            }
            State::Cancelled { by } => (AdminSessionState::Cancelled, false, false, by.0),
            State::Expired {} => (AdminSessionState::Expired, false, false, String::new()),
            State::Aborted { reason } => (AdminSessionState::Aborted, false, false, reason.0),
            State::Failed { reason } => (AdminSessionState::Failed, false, false, reason.0),
        };
        Some(AdminSessionView {
            id: self.id,
            role,
            label,
            agent_uid,
            agent_gid,
            state,
            provider_approved,
            joiner_confirmed,
            detail,
            expires_in_seconds: self.expires_in_seconds,
            joiner_fingerprint: self.joiner_fingerprint.unwrap_or_default(),
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Issued {
    id: String,
    invitation_code: String,
    kind: Kind,
    expires_in_seconds: u64,
}
impl Drop for Issued {
    fn drop(&mut self) {
        self.invitation_code.zeroize();
    }
}
// One closed reply shape per command, each refusing unknown fields, so no
// extra member (a code, say) can ride along unnoticed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invited {
    version: u8,
    invitation: Issued,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Listed {
    version: u8,
    enrollments: Vec<View>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct One {
    version: u8,
    enrollment: View,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Refused {
    version: u8,
    error: Closed,
    reason: Closed,
}

/// `12345678`, `1234-5678` or `1234 5678` as `1234-5678`.
fn normalize_code(input: &str) -> Option<String> {
    let digits: String = input.chars().filter(|c| !matches!(c, '-' | ' ')).collect();
    (digits.len() == 8 && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| format!("{}-{}", &digits[..4], &digits[4..]))
}

/// Request bodies serialized from borrowed fields: the password is written
/// once, into the returned buffer, never into an intermediate JSON value.
#[derive(serde::Serialize)]
struct Approve<'a> {
    version: u8,
    command: &'static str,
    id: &'a str,
    code: &'a str,
    password: &'a str,
}

/// What an exchange asked for; its reply must match it.
struct Pending {
    token: u32,
    command: AdminCommand,
    id: String,
    kind: Option<(EnrolleeRole, String, u32, u32)>,
}

#[derive(Default)]
pub struct AdminSession {
    state: AdminState,
    outcome: AdminOutcome,
    refusal: AdminRefusal,
    issued: Option<IssuedInvitationView>,
    issued_code: Zeroizing<String>,
    sessions: Vec<AdminSessionView>,
    token: u32,
    pending: Option<Pending>,
}

impl AdminSession {
    pub fn snapshot(&self) -> EnrollmentAdminSnapshot {
        EnrollmentAdminSnapshot {
            state: self.state,
            outcome: self.outcome,
            refusal: self.refusal,
            busy: self.pending.is_some(),
            issued: self.issued.clone(),
            sessions: self.sessions.clone(),
        }
    }

    /// The shown invitation's secret code, kept out of every snapshot so the
    /// UI copies it once. Empty when none is shown.
    pub fn invitation_code(&self) -> String {
        self.issued_code.as_str().to_owned()
    }

    pub fn dismiss_invitation(&mut self) {
        self.issued = None;
        self.issued_code.zeroize();
    }

    /// Navigation, sleep or a provider change: forget everything shown.
    pub fn invalidate(&mut self) {
        self.dismiss_invitation();
        let token = self.token;
        *self = Self::default();
        self.token = token;
    }

    pub fn begin(
        &mut self,
        mut request: EnrollmentAdminRequest,
    ) -> Result<ProviderWork, &'static str> {
        let password = Zeroizing::new(std::mem::take(&mut request.password));
        let typed = Zeroizing::new(std::mem::take(&mut request.code));
        if self.pending.is_some() {
            return Err("Waiting for the provider.");
        }
        let mut kind = None;
        let body = match request.command {
            AdminCommand::Invite => {
                let value = match request.role {
                    EnrolleeRole::Companion if valid_label(&request.label) => {
                        serde_json::json!({"role":"companion","label":request.label})
                    }
                    EnrolleeRole::Agent
                        if valid_agent(&request.label, request.agent_uid, request.agent_gid) =>
                    {
                        serde_json::json!({"role":"agent","label":request.label,"uid":request.agent_uid,"gid":request.agent_gid})
                    }
                    EnrolleeRole::Companion => {
                        return Err("Enter a name of 1–128 characters without leading or trailing spaces.")
                    }
                    EnrolleeRole::Agent => {
                        return Err("Enter an ASCII agent name and the agent account's numeric user and group IDs (not 0).")
                    }
                };
                kind = Some(match request.role {
                    EnrolleeRole::Companion => (request.role, request.label.clone(), 0, 0),
                    EnrolleeRole::Agent => (
                        request.role,
                        request.label.clone(),
                        request.agent_uid,
                        request.agent_gid,
                    ),
                });
                serde_json::to_vec(
                    &serde_json::json!({"version":1,"command":"enroll_invite","kind":value}),
                )
            }
            AdminCommand::List => {
                serde_json::to_vec(&serde_json::json!({"version":1,"command":"enroll_list"}))
            }
            AdminCommand::Approve => {
                if !valid_id(&request.id) {
                    return Err("Select an enrollment first.");
                }
                let code = Zeroizing::new(
                    normalize_code(&typed)
                        .ok_or("Type the 8-digit code shown on the joining device.")?,
                );
                if password.is_empty() || password.len() > 4096 {
                    return Err("Enter the provider password.");
                }
                serde_json::to_vec(&Approve {
                    version: 1,
                    command: "enroll_approve",
                    id: &request.id,
                    code: &code,
                    password: &password,
                })
            }
            AdminCommand::Cancel => {
                if !valid_id(&request.id) {
                    return Err("Select an enrollment first.");
                }
                serde_json::to_vec(
                    &serde_json::json!({"version":1,"command":"enroll_cancel","id":request.id}),
                )
            }
        }
        .map_err(|_| "Enrollment unavailable")?;
        self.token = self.token.wrapping_add(1);
        self.pending = Some(Pending {
            token: self.token,
            command: request.command,
            id: request.id,
            kind,
        });
        self.outcome = AdminOutcome::None;
        self.refusal = AdminRefusal::None;
        Ok(ProviderWork {
            token: self.token,
            body,
        })
    }

    pub fn finish(&mut self, token: u32, response: &[u8]) {
        if self.pending.as_ref().is_none_or(|p| p.token != token) {
            return;
        }
        let Some(pending) = self.pending.take() else {
            return;
        };
        let command = pending.command;
        if response.is_empty() || response.len() > RESPONSE_LIMIT {
            // No reply: an approval or cancel may still have applied.
            self.outcome = AdminOutcome::Unavailable;
            return;
        }
        if self.reply(&pending, response) {
            self.state = AdminState::Ready;
            return;
        }
        if let Ok(refused) = serde_json::from_slice::<Refused>(response) {
            if refused.version == 1 && refused.error.0 == "enrollment_refused" {
                self.outcome = AdminOutcome::Refused;
                self.refusal = match refused.reason.0.as_str() {
                    "invalid_request" => AdminRefusal::InvalidRequest,
                    "duplicate" => AdminRefusal::Duplicate,
                    "limit_reached" => AdminRefusal::LimitReached,
                    "not_found" => AdminRefusal::NotFound,
                    "expired" => AdminRefusal::Expired,
                    "final" => AdminRefusal::Final,
                    "awaiting_peer" => AdminRefusal::AwaitingPeer,
                    "code_mismatch" => AdminRefusal::CodeMismatch,
                    _ => {
                        self.outcome = AdminOutcome::Invalid;
                        AdminRefusal::None
                    }
                };
                return;
            }
        }
        match serde_json::from_slice::<ErrorResponse>(response) {
            Ok(ErrorResponse { version: 1, error }) => match error {
                ErrorCode::Unauthorized => {
                    self.state = AdminState::Unauthorized;
                    self.sessions.clear();
                    self.dismiss_invitation();
                    self.outcome = AdminOutcome::Invalid;
                }
                // An older provider does not know these commands.
                ErrorCode::InvalidRequest => {
                    if matches!(command, AdminCommand::List | AdminCommand::Invite) {
                        self.state = AdminState::Unsupported;
                    }
                    self.outcome = AdminOutcome::Invalid;
                }
                ErrorCode::AuthenticationFailed => {
                    self.outcome = AdminOutcome::AuthenticationFailed
                }
                ErrorCode::RateLimited => self.outcome = AdminOutcome::RateLimited,
                ErrorCode::Unavailable | ErrorCode::Stale => {
                    if command == AdminCommand::List {
                        self.state = AdminState::Unavailable;
                    }
                    self.outcome = AdminOutcome::Unavailable;
                }
            },
            _ => {
                // An unparseable reply (for example a list carrying a code)
                // is refused whole: nothing previously shown stays current.
                self.outcome = AdminOutcome::Invalid;
                if command == AdminCommand::List {
                    self.sessions.clear();
                }
            }
        }
    }

    /// True when `response` is the success shape for this exact request.
    fn reply(&mut self, pending: &Pending, response: &[u8]) -> bool {
        match pending.command {
            AdminCommand::Invite => serde_json::from_slice::<Invited>(response)
                .is_ok_and(|r| r.version == 1 && self.invited(&r.invitation, pending)),
            AdminCommand::List => {
                let Ok(Listed {
                    version: 1,
                    enrollments,
                }) = serde_json::from_slice::<Listed>(response)
                else {
                    return false;
                };
                if enrollments.len() > MAX_SESSIONS {
                    return false;
                }
                let projected: Option<Vec<_>> =
                    enrollments.into_iter().map(View::project).collect();
                projected.is_some_and(|rows| {
                    self.sessions = rows;
                    self.outcome = AdminOutcome::Listed;
                    true
                })
            }
            AdminCommand::Approve | AdminCommand::Cancel => {
                let Ok(One {
                    version: 1,
                    enrollment,
                }) = serde_json::from_slice::<One>(response)
                else {
                    return false;
                };
                let Some(row) = enrollment.project().filter(|row| row.id == pending.id) else {
                    return false;
                };
                // A 200 must show the effect asked for; anything else is not
                // reported as success.
                let applied = if pending.command == AdminCommand::Approve {
                    row.provider_approved || row.state == AdminSessionState::Enrolled
                } else {
                    row.state == AdminSessionState::Cancelled
                };
                if !applied {
                    return false;
                }
                self.outcome = if pending.command == AdminCommand::Approve {
                    AdminOutcome::Approved
                } else {
                    AdminOutcome::Cancelled
                };
                match self.sessions.iter_mut().find(|s| s.id == row.id) {
                    Some(existing) => *existing = row,
                    None => self.sessions.push(row),
                }
                true
            }
        }
    }

    fn invited(&mut self, issued: &Issued, pending: &Pending) -> bool {
        let code_ok = {
            let mut parts = issued.invitation_code.split('.');
            matches!(
                (parts.next(), parts.next(), parts.next(), parts.next()),
                (Some("vwe1"), Some(id), Some(secret), None)
                    if id == issued.id && valid_id(id) && valid_id(secret)
            )
        };
        let (role, raw_label, uid, gid) = issued.kind.raw();
        let same_kind = pending
            .kind
            .as_ref()
            .is_some_and(|(r, l, u, g)| (*r, l.as_str(), *u, *g) == (role, raw_label, uid, gid));
        if !code_ok || !same_kind || !issued.kind.valid() || issued.expires_in_seconds > 1800 {
            return false;
        }
        self.dismiss_invitation();
        let (role, label, _, _) = issued.kind.parts();
        self.issued_code = Zeroizing::new(issued.invitation_code.clone());
        self.issued = Some(IssuedInvitationView {
            id: issued.id.clone(),
            role,
            label,
            expires_in_seconds: issued.expires_in_seconds,
        });
        self.outcome = AdminOutcome::Invited;
        true
    }
}
