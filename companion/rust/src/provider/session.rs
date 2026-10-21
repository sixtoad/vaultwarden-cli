use super::protocol::*;
use crate::api::provider::{ProviderCommand as Command, ProviderSnapshot, ProviderWork};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

struct Reviewed {
    response: ReviewResponse,
    started: Instant,
}
struct Flight {
    token: u32,
    epoch: u64,
    command: Command,
    id: String,
    started: Instant,
}

/// One foreground session. Reads are generation-scoped; a sent decision survives
/// invalidation and is resolved only against its original provider/request.
#[derive(Default)]
pub struct ProviderSession {
    configured: bool,
    epoch: u64,
    serial: u32,
    authority: Option<(SessionState, u64)>,
    requests: Vec<String>,
    reviewed: Option<Reviewed>,
    flight: Option<Flight>,
    unresolved: Option<String>,
    status_id: String,
    status_text: String,
    message: String,
}
impl ProviderSession {
    pub fn configure(&mut self, uncertain_id: &str) -> Result<(), &'static str> {
        if self.flight.is_some() || self.unresolved.is_some() {
            return Err("Resolve the original provider decision before changing setup.");
        }
        self.invalidate();
        if !uncertain_id.is_empty() && !valid_id(uncertain_id) {
            return Err("Invalid recovery identifier.");
        }
        self.unresolved = (!uncertain_id.is_empty()).then(|| uncertain_id.to_string());
        self.configured = true;
        self.authority = None;
        self.requests.clear();
        self.status_id.clear();
        self.status_text.clear();
        self.message = if self.unresolved.is_some() { "Restored an uncertain decision. Refresh its original status; no decision will be resent." }
            else { "Connect to refresh provider authority." }.into();
        Ok(())
    }
    pub fn invalidate(&mut self) {
        self.epoch = self.epoch.checked_add(1).expect("provider epoch exhausted");
        self.reviewed = None;
    }
    fn can_decide(&self) -> bool {
        self.flight.is_none()
            && self.unresolved.is_none()
            && self.reviewed.as_ref().is_some_and(|r| {
                r.response.ticket.is_some()
                    && r.response.review.status == (Status::Pending {})
                    && self.authority == Some((SessionState::Unlocked, r.response.generation))
                    && r.started.elapsed() < Duration::from_secs(55)
                    && unix_seconds() < r.response.review.expires_at_unix_seconds
            })
    }
    pub fn snapshot(&mut self) -> ProviderSnapshot {
        if self.reviewed.as_ref().is_some_and(|r| {
            r.started.elapsed() >= Duration::from_secs(55)
                || unix_seconds() >= r.response.review.expires_at_unix_seconds
        }) {
            self.invalidate();
            self.message = "Review expired. Select the request again.".into();
        }
        ProviderSnapshot {
            configured: self.configured,
            busy: self.flight.is_some(),
            locked: self.authority.map(|a| a.0) != Some(SessionState::Unlocked),
            requests: self.requests.clone(),
            review_text: self
                .reviewed
                .as_ref()
                .map(|r| r.response.review.visible())
                .unwrap_or_default(),
            review_id: self
                .reviewed
                .as_ref()
                .map(|r| r.response.review.id.clone())
                .unwrap_or_default(),
            can_decide: self.can_decide(),
            uncertain_id: self.unresolved.clone().unwrap_or_default(),
            status_id: self.status_id.clone(),
            status_text: self.status_text.clone(),
            message: self.message.clone(),
        }
    }
    pub fn begin(
        &mut self,
        command: Command,
        id: String,
        password: String,
    ) -> Result<ProviderWork, &'static str> {
        let password = Zeroizing::new(password);
        if !self.configured || self.flight.is_some() {
            return Err("Provider is unavailable or busy.");
        }
        if matches!(command, Command::Review | Command::Status) && !valid_id(&id) {
            return Err("Invalid request identifier.");
        }
        if matches!(command, Command::Approve | Command::Unlock)
            && (password.is_empty() || password.len() > 4096)
        {
            return Err("Enter a fresh password (1–4096 UTF-8 bytes).");
        }
        if let Some(unresolved) = &self.unresolved {
            if command != Command::Status || id != *unresolved {
                return Err("Outcome uncertain. Refresh the original request status; no decision will be resent.");
            }
        }
        let mut request = serde_json::json!({"version": 1});
        let mut request_id = id;
        match command {
            Command::Session => request["command"] = "session".into(),
            Command::List => request["command"] = "list".into(),
            Command::Review => {
                self.invalidate();
                request["command"] = "review".into();
                request["request_id"] = request_id.clone().into();
            }
            Command::Status => {
                request["command"] = "status".into();
                request["request_id"] = request_id.clone().into();
            }
            Command::Unlock => {
                self.invalidate();
                self.authority = None;
                self.requests.clear();
                request["command"] = "unlock".into();
                request["password"] = password.to_string().into();
            }
            Command::Approve | Command::Deny => {
                if !self.can_decide() {
                    self.invalidate();
                    return Err("A fresh complete review is required.");
                }
                let review = self.reviewed.take().expect("checked review");
                request_id = review.response.review.id;
                request["command"] = "decision".into();
                request["request_id"] = request_id.clone().into();
                request["ticket"] = review.response.ticket.expect("checked ticket").into();
                request["decision"] = if command == Command::Approve {
                    "approve"
                } else {
                    "deny"
                }
                .into();
                if command == Command::Approve {
                    request["password"] = password.to_string().into();
                }
                self.invalidate();
                self.unresolved = Some(request_id.clone());
                self.status_id = request_id.clone();
                self.status_text = "Decision in flight; it may have committed.".into();
            }
        }
        let mut body = serde_json::to_vec(&request).map_err(|_| "Invalid request.")?;
        // Erase the temporary JSON password; no password is retained by the session.
        if let Some(serde_json::Value::String(value)) = request.get_mut("password") {
            use zeroize::Zeroize;
            value.zeroize();
        }
        if body.len() > REQUEST_LIMIT {
            use zeroize::Zeroize;
            body.zeroize();
            // No native call occurred, so there is no ambiguous commit to recover.
            if matches!(command, Command::Approve | Command::Deny) {
                self.unresolved = None;
                self.status_text = "Decision not sent: request exceeded the size limit.".into();
            }
            return Err("Request exceeded the size limit.");
        }
        self.serial = self
            .serial
            .checked_add(1)
            .ok_or("Provider operation limit reached.")?;
        self.flight = Some(Flight {
            token: self.serial,
            epoch: self.epoch,
            command,
            id: request_id,
            started: Instant::now(),
        });
        self.message = "Contacting provider…".into();
        Ok(ProviderWork {
            token: self.serial,
            body,
        })
    }
    pub fn finish(&mut self, token: u32, bytes: &[u8]) {
        if self.flight.as_ref().map(|f| f.token) != Some(token) {
            return;
        }
        let flight = self.flight.take().expect("matched flight");
        let decision = matches!(flight.command, Command::Approve | Command::Deny);
        if !decision && flight.epoch != self.epoch {
            return;
        }
        if let Ok(error) = decode::<ErrorResponse>(bytes) {
            if error.version == 1 {
                self.invalidate();
                if decision && error.error.definite_rejection() {
                    self.unresolved = None;
                    self.message = "Decision rejected. Obtain a new review and fresh password before trying again.".into();
                    self.status_text = self.message.clone();
                } else if self.unresolved.is_some() {
                    self.message = "Outcome uncertain. Refresh original request status; no decision was resent.".into();
                } else {
                    self.message =
                        "Provider rejected the request. Refresh authority or obtain a new review."
                            .into();
                }
                return;
            }
        }
        if self.accept(&flight, bytes).is_err() {
            self.invalidate();
            self.authority = None;
            self.requests.clear();
            self.message = if self.unresolved.is_some() {
                "Outcome uncertain: status unavailable. No decision was resent."
            } else {
                "Provider unavailable, untrusted, or invalid response. Refresh to reconnect."
            }
            .into();
        }
    }
    fn accept(&mut self, flight: &Flight, bytes: &[u8]) -> Result<(), &'static str> {
        match flight.command {
            Command::Session | Command::Unlock => {
                let reply: SessionResponse = decode(bytes)?;
                if reply.version != 1 {
                    return Err("version");
                }
                let authority = (reply.state, reply.generation);
                if self.authority != Some(authority) {
                    self.invalidate();
                }
                self.authority = Some(authority);
                self.message = if reply.state == SessionState::Locked {
                    "Provider locked. Unlock separately; the agent must submit new work."
                } else {
                    "Provider unlocked. Refresh the inbox and review a request."
                }
                .into();
            }
            Command::List => {
                let reply: ListResponse = decode(bytes)?;
                if !reply.valid() {
                    return Err("list");
                }
                if self
                    .reviewed
                    .as_ref()
                    .is_some_and(|r| !reply.requests.contains(&r.response.review.id))
                {
                    self.invalidate();
                }
                self.requests = reply.requests;
            }
            Command::Review => {
                let reply: ReviewResponse = decode(bytes)?;
                if reply.version != 1
                    || !reply.review.valid()
                    || reply.review.id != flight.id
                    || reply.ticket.as_ref().is_some_and(|t| !valid_hex(t))
                    || reply.ticket.is_some() && reply.review.status != (Status::Pending {})
                    || self.authority != Some((SessionState::Unlocked, reply.generation))
                {
                    return Err("review");
                }
                self.message = reply.review.status.summary();
                self.reviewed = Some(Reviewed {
                    response: reply,
                    started: flight.started,
                });
            }
            Command::Approve | Command::Deny | Command::Status => {
                let reply: StatusResponse = decode(bytes)?;
                if reply.version != 1 {
                    return Err("version");
                }
                self.status_id = flight.id.clone();
                if reply.status == (Status::Pending {})
                    && self.unresolved.as_deref() == Some(&flight.id)
                {
                    self.message = "Outcome uncertain: still pending. Only status recovery is allowed; no decision was resent.".into();
                } else {
                    if self.unresolved.as_deref() == Some(&flight.id) {
                        self.unresolved = None;
                    }
                    self.message = reply.status.summary();
                }
                self.status_text = self.message.clone();
            }
        }
        Ok(())
    }
}
fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_expiry_checks_monotonic_and_wall_deadlines_independently() {
        for monotonic in [true, false] {
            let mut session = ProviderSession::default();
            session.configure("").unwrap();
            session.authority = Some((SessionState::Unlocked, 1));
            let mut response: ReviewResponse = decode(include_bytes!(
                "../../../../tests/fixtures/companion/review.json"
            ))
            .unwrap();
            response.review.expires_at_unix_seconds = if monotonic {
                unix_seconds() + 60
            } else {
                unix_seconds()
            };
            session.reviewed = Some(Reviewed {
                response,
                started: if monotonic {
                    Instant::now() - Duration::from_secs(56)
                } else {
                    Instant::now()
                },
            });
            assert!(!session.can_decide());
            assert!(session.snapshot().review_text.is_empty());
            assert!(session
                .begin(Command::Approve, String::new(), "fresh".into())
                .is_err());
        }
    }
}
