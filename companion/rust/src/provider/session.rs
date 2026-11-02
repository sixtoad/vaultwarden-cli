use super::approval_v2::{self as v2, ApprovalBinding, Pin, ReceivedReview};
use super::protocol::*;
use crate::api::biometric::{
    BiometricDecisionResult as Biometric, BiometricRefusal as Refusal, BiometricSigningRequest,
    BiometricSupport, ProviderBiometricState,
};
use crate::api::provider::{
    ProviderCommand as Command, ProviderHistoryEvent, ProviderHistoryState, ProviderOutcome,
    ProviderSnapshot, ProviderStatusProgress, ProviderWork,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

struct Reviewed {
    response: ReviewResponse,
    started: Instant,
    /// Version 2 only: the `review` member as received and the binding.
    signed: Option<(serde_json::Value, Option<ApprovalBinding>)>,
}
struct Flight {
    token: u32,
    epoch: u64,
    command: Command,
    id: String,
    started: Instant,
    /// A version 2 review request, or a version 2 Touch ID decision.
    v2: bool,
    proof: bool,
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
    history_state: ProviderHistoryState,
    history: Vec<ProviderHistoryEvent>,
    reviewed: Option<Reviewed>,
    flight: Option<Flight>,
    unresolved: Option<String>,
    status_id: String,
    status_text: String,
    message: String,
    outcome: ProviderOutcome,
    status_progress: ProviderStatusProgress,
    pin: Option<Pin>,
    support: BiometricSupport,
    prepared: Option<u64>,
    biometric: Biometric,
    proof_id: Option<String>,
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
        // A (re)configured provider must be pinned again before Touch ID.
        self.pin = None;
        self.support = BiometricSupport::Unpinned;
        self.biometric = Biometric::None;
        self.proof_id = None;
        self.authority = None;
        self.requests.clear();
        self.status_id.clear();
        self.status_text.clear();
        self.status_progress = ProviderStatusProgress::None;
        self.outcome = ProviderOutcome::None;
        self.message = if self.unresolved.is_some() { "Restored an uncertain decision. Refresh its original status; no decision will be resent." }
            else { "Connect to refresh provider authority." }.into();
        Ok(())
    }
    pub fn invalidate(&mut self) {
        self.epoch = self.epoch.checked_add(1).expect("provider epoch exhausted");
        self.reviewed = None;
        self.prepared = None;
        self.history.clear();
        self.history_state = ProviderHistoryState::Idle;
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
            outcome: self.outcome,
            status_progress: self.status_progress,
            configured: self.configured,
            busy: self.flight.is_some(),
            locked: self.authority.map(|a| a.0) != Some(SessionState::Unlocked),
            authority_known: self.authority.is_some(),
            history_state: self.history_state,
            history: self.history.clone(),
            requests: self.requests.clone(),
            review_text: self
                .reviewed
                .as_ref()
                .map(|r| r.response.review.visible())
                .unwrap_or_default(),
            review: self
                .reviewed
                .as_ref()
                .map(|r| r.response.review.projection()),
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
            Command::History => {
                if self.authority.map(|a| a.0) != Some(SessionState::Unlocked) {
                    return Err("Refresh unlocked provider authority before reading history.");
                }
                self.history.clear();
                self.history_state = ProviderHistoryState::Loading;
                request["command"] = "history".into();
                request["limit"] = DEFAULT_HISTORY_LIMIT.into();
            }
            Command::Review => {
                self.invalidate();
                if self.support == BiometricSupport::Requested {
                    request["version"] = 2.into();
                }
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
                self.proof_id = None;
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
            v2: request["version"] == 2,
            proof: false,
        });
        self.message = "Contacting provider…".into();
        self.outcome = ProviderOutcome::None;
        Ok(ProviderWork {
            token: self.serial,
            body,
        })
    }
    /// Pin the provider leaf and this device's client leaf SHA-256 values.
    /// Retires the current review so the next one is requested as version 2.
    pub fn pin(&mut self, provider_identity: &str, approval_client: &str) -> Result<(), Refusal> {
        if !self.configured {
            return Err(Refusal::NotConfigured);
        }
        if self.flight.is_some() {
            return Err(Refusal::Busy);
        }
        let pin = Pin::new(provider_identity, approval_client).ok_or(Refusal::NotPinned)?;
        if self.pin.as_ref() != Some(&pin) {
            self.invalidate();
            self.support = BiometricSupport::Requested;
        }
        self.pin = Some(pin);
        Ok(())
    }
    fn signing_transcript(&self) -> Result<(String, v2::SigningTranscript), Refusal> {
        if !self.configured {
            return Err(Refusal::NotConfigured);
        }
        if self.flight.is_some() {
            return Err(Refusal::Busy);
        }
        if self.unresolved.is_some() {
            return Err(Refusal::OutcomeUncertain);
        }
        let decidable = self.can_decide();
        let reviewed = self
            .reviewed
            .as_ref()
            .filter(|_| decidable)
            .ok_or(Refusal::NoDecidableReview)?;
        let (raw_review, binding) = reviewed
            .signed
            .as_ref()
            .ok_or(Refusal::BindingUnavailable)?;
        let received = ReceivedReview {
            raw_review,
            review: &reviewed.response.review,
            ticket: reviewed.response.ticket.as_deref(),
            generation: reviewed.response.generation,
            binding: binding.as_ref(),
        };
        let transcript = v2::approval_transcript(&received, self.pin.as_ref())?;
        Ok((reviewed.response.review.id.clone(), transcript))
    }
    pub fn biometric_state(&self) -> ProviderBiometricState {
        let binding = self
            .reviewed
            .as_ref()
            .and_then(|r| r.signed.as_ref())
            .and_then(|(_, binding)| binding.as_ref());
        let refusal = self.signing_transcript().err();
        ProviderBiometricState {
            support: self.support,
            binding_available: binding.is_some(),
            biometric_allowed: binding.is_some_and(|b| b.biometric_allowed),
            key_id: binding.and_then(|b| b.key_id.clone()).unwrap_or_default(),
            can_prepare: refusal.is_none(),
            refusal,
            result: self.biometric,
        }
    }
    /// The exact transcript to sign for the current review. The review stays
    /// usable for a password approval if Touch ID is cancelled.
    pub fn prepare_biometric(&mut self) -> Result<BiometricSigningRequest, Refusal> {
        let (request_id, signing) = self.signing_transcript()?;
        self.prepared = Some(self.epoch);
        Ok(BiometricSigningRequest {
            handle: self.epoch,
            request_id,
            key_id: signing.key_id,
            transcript: signing.transcript,
        })
    }
    /// Send a Touch ID approval (Decision v2 with `proof`, never `password`).
    /// Same single-shot and uncertain-outcome rules as a password approval.
    pub fn begin_biometric(
        &mut self,
        handle: u64,
        key_id: &str,
        signature: &[u8],
    ) -> Result<ProviderWork, Refusal> {
        if self.prepared != Some(handle) || handle != self.epoch {
            if self.flight.is_some() {
                return Err(Refusal::Busy);
            }
            return Err(Refusal::StaleHandle);
        }
        // Every binding check runs again against the review as it is now.
        let (request_id, signing) = self.signing_transcript()?;
        if key_id != signing.key_id {
            return Err(Refusal::KeyMismatch);
        }
        if !v2::valid_signature(signature) {
            return Err(Refusal::InvalidSignature);
        }
        let serial = self.serial.checked_add(1).ok_or(Refusal::Busy)?;
        let review = self.reviewed.take().ok_or(Refusal::NoDecidableReview)?;
        let request = serde_json::json!({
            "version": 2,
            "command": "decision",
            "request_id": request_id,
            "ticket": review.response.ticket,
            "decision": "approve",
            "proof": {"key_id": signing.key_id, "signature": v2::base64url(signature)},
        });
        let body = serde_json::to_vec(&request).map_err(|_| Refusal::RequestTooLarge)?;
        self.invalidate();
        if body.len() > REQUEST_LIMIT {
            // Not sent: no ambiguous commit to recover.
            self.status_text = "Decision not sent: request exceeded the size limit.".into();
            return Err(Refusal::RequestTooLarge);
        }
        self.unresolved = Some(request_id.clone());
        self.proof_id = Some(request_id.clone());
        self.biometric = Biometric::InFlight;
        self.status_id = request_id.clone();
        self.status_text = "Decision in flight; it may have committed.".into();
        self.serial = serial;
        self.flight = Some(Flight {
            token: serial,
            epoch: self.epoch,
            command: Command::Approve,
            id: request_id,
            started: Instant::now(),
            v2: true,
            proof: true,
        });
        self.message = "Contacting provider…".into();
        self.outcome = ProviderOutcome::None;
        Ok(ProviderWork {
            token: serial,
            body,
        })
    }
    pub fn finish(&mut self, token: u32, bytes: &[u8]) {
        if self.flight.as_ref().map(|f| f.token) != Some(token) {
            self.outcome = ProviderOutcome::Stale;
            return;
        }
        let flight = self.flight.take().expect("matched flight");
        let decision = matches!(flight.command, Command::Approve | Command::Deny);
        if !decision && flight.epoch != self.epoch {
            self.authority = None;
            self.requests.clear();
            self.outcome = ProviderOutcome::Stale;
            return;
        }
        if let Ok(error) = decode::<ErrorResponse>(bytes) {
            if error.version == 1 {
                if flight.proof {
                    self.biometric = match error.error {
                        ErrorCode::AuthenticationFailed => Biometric::PasswordRequired,
                        ErrorCode::RateLimited => Biometric::RateLimited,
                        ErrorCode::Stale => Biometric::Stale,
                        ErrorCode::InvalidRequest | ErrorCode::Unauthorized => Biometric::Rejected,
                        ErrorCode::Unavailable => Biometric::OutcomeUnknown,
                    };
                }
                self.invalidate();
                self.authority = None;
                self.requests.clear();
                self.outcome = ProviderOutcome::Rejected;
                if flight.command == Command::History {
                    self.history_state = ProviderHistoryState::Unavailable;
                    self.message =
                        "Activity unavailable from this provider. Refresh to reconnect.".into();
                    return;
                }
                if flight.v2
                    && flight.command == Command::Review
                    && error.error == ErrorCode::InvalidRequest
                {
                    // An older provider: keep version 1 reviews and passwords.
                    self.support = BiometricSupport::Unsupported;
                    self.message = "Provider does not offer Touch ID approval. Refresh and review the request again to approve with a password.".into();
                    return;
                }
                if decision && error.error.definite_rejection() {
                    self.unresolved = None;
                    self.message = "Decision rejected. Obtain a new review and fresh password before trying again.".into();
                    self.status_text = self.message.clone();
                    self.status_progress = ProviderStatusProgress::Terminal;
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
            if flight.proof {
                self.biometric = Biometric::OutcomeUnknown;
            }
            self.invalidate();
            self.authority = None;
            self.requests.clear();
            self.outcome = ProviderOutcome::Invalid;
            if flight.command == Command::History {
                self.history_state = ProviderHistoryState::Unavailable;
            }
            self.message = if self.unresolved.is_some() {
                "Outcome uncertain: status unavailable. No decision was resent."
            } else {
                "Provider unavailable, untrusted, or invalid response. Refresh to reconnect."
            }
            .into();
        } else {
            self.outcome = ProviderOutcome::Accepted;
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
                if reply.state == SessionState::Locked {
                    self.requests.clear();
                }
                self.message = if reply.state == SessionState::Locked {
                    "Provider locked. Unlock separately; the agent must submit new work."
                } else {
                    "Provider unlocked. Refresh the inbox and review a request."
                }
                .into();
            }
            Command::History => {
                let reply: HistoryResponse = decode(bytes)?;
                if !reply.valid(DEFAULT_HISTORY_LIMIT)
                    || self.authority.map(|a| a.0) != Some(SessionState::Unlocked)
                {
                    return Err("history");
                }
                self.history = reply.events.iter().map(HistoryEvent::projection).collect();
                self.history_state = ProviderHistoryState::Available;
                self.message =
                    "Recent redacted provider activity. History does not authorize operations."
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
                let (reply, signed) = if flight.v2 {
                    let (reply, raw, binding) = v2::decode_review(bytes)?;
                    (reply, Some((raw, binding)))
                } else {
                    (decode::<ReviewResponse>(bytes)?, None)
                };
                if reply.version != if flight.v2 { 2 } else { 1 }
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
                    signed,
                });
            }
            Command::Approve | Command::Deny | Command::Status => {
                let reply: StatusResponse = decode(bytes)?;
                if reply.version != if flight.proof { 2 } else { 1 } {
                    return Err("version");
                }
                if self.proof_id.as_deref() == Some(&flight.id) {
                    self.biometric = match reply.status {
                        Status::Approved {} | Status::Running {} | Status::Completed { .. } => {
                            Biometric::Approved
                        }
                        Status::Pending {} => Biometric::OutcomeUnknown,
                        _ => Biometric::Rejected,
                    };
                }
                self.status_id = flight.id.clone();
                self.status_progress = match reply.status {
                    Status::Pending {} => ProviderStatusProgress::Pending,
                    Status::Approved {} | Status::Running {} => ProviderStatusProgress::Committed,
                    _ => ProviderStatusProgress::Terminal,
                };
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
                signed: None,
            });
            assert!(!session.can_decide());
            assert!(session.snapshot().review_text.is_empty());
            assert!(session.snapshot().review.is_none());
            assert!(session
                .begin(Command::Approve, String::new(), "fresh".into())
                .is_err());
        }
    }
}
