//! Own-device Touch ID key management (management protocol version 2
//! `biometric_*` commands, `identity_detail` version 3). Separate from the
//! administrative identity session: its tickets are purpose-bound on the
//! provider and never authorize identity revocation, and vice versa.
use super::approval_v2::{self as v2, Pin};
use super::protocol::{decode, valid_hex, valid_id, ErrorCode, ErrorResponse, REQUEST_LIMIT};
use crate::api::biometric::{
    BiometricEnrollRequest, BiometricKeyCommand as KeyCommand, BiometricKeyOutcome as Outcome,
    BiometricKeySnapshot, BiometricKeyState as KeyState, BiometricRefusal as Refusal,
};
use crate::api::management::{IdentityKind, IdentityRole, IdentityTrust};
use crate::api::provider::ProviderWork;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Target {
    kind: IdentityKind,
    id: String,
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Enroll,
    Revoke,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepared {
    version: u8,
    operation: Operation,
    target: Target,
    action_id: String,
    ticket: String,
    generation: u64,
    valid_for_seconds: u32,
    provider_identity: String,
    #[serde(deserialize_with = "Option::deserialize")]
    biometric_key_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrolled {
    version: u8,
    operation: Operation,
    target: Target,
    action_id: String,
    biometric_key_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revoked {
    version: u8,
    operation: Operation,
    target: Target,
    action_id: String,
    #[serde(deserialize_with = "Option::deserialize")]
    revoked_key_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Detail {
    version: u8,
    identity: IdentityV3,
    generation: u64,
}
/// A version 3 identity row: the version 2 row plus `biometric_key_id`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityV3 {
    kind: IdentityKind,
    id: String,
    label: String,
    fingerprint: String,
    roles: Vec<IdentityRole>,
    trust: IdentityTrust,
    this_client: bool,
    #[serde(deserialize_with = "Option::deserialize")]
    biometric_key_id: Option<String>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sent {
    Read,
    Prepare(Operation),
    Enroll,
    Revoke,
}
struct Flight {
    token: u32,
    epoch: u64,
    sent: Sent,
    action_id: String,
    public_key: Vec<u8>,
    started: Instant,
}
struct Ticket {
    prepared: Prepared,
    started: Instant,
}
impl Ticket {
    fn fresh(&self, operation: Operation) -> bool {
        self.prepared.operation == operation
            && self.started.elapsed() < Duration::from_secs(self.prepared.valid_for_seconds.into())
    }
}

#[derive(Default)]
pub struct BiometricKeySession {
    pin: Option<Pin>,
    epoch: u64,
    serial: u32,
    flight: Option<Flight>,
    ticket: Option<Ticket>,
    enroll_key: Option<Vec<u8>>,
    state: KeyState,
    key_id: String,
    outcome: Outcome,
    message: String,
}
impl BiometricKeySession {
    pub fn configure(
        &mut self,
        provider_identity: &str,
        approval_client: &str,
    ) -> Result<(), Refusal> {
        if self.flight.is_some() {
            return Err(Refusal::Busy);
        }
        let pin = Pin::new(provider_identity, approval_client).ok_or(Refusal::NotPinned)?;
        self.invalidate();
        self.pin = Some(pin);
        self.state = KeyState::Unknown;
        self.key_id.clear();
        self.outcome = Outcome::None;
        self.message = "Read this device's Touch ID key from the provider.".into();
        Ok(())
    }
    fn invalidate(&mut self) {
        self.epoch = self.epoch.checked_add(1).expect("biometric key epoch");
        self.ticket = None;
        self.enroll_key = None;
    }
    fn own(&self) -> Result<Target, Refusal> {
        let pin = self.pin.as_ref().ok_or(Refusal::NotPinned)?;
        Ok(Target {
            kind: IdentityKind::ApprovalClient,
            id: pin.approval_client.clone(),
        })
    }
    fn can(&self, operation: Operation) -> bool {
        self.flight.is_none() && self.ticket.as_ref().is_some_and(|t| t.fresh(operation))
    }
    pub fn snapshot(&mut self) -> BiometricKeySnapshot {
        if self.ticket.as_ref().is_some_and(|t| {
            t.started.elapsed() >= Duration::from_secs(t.prepared.valid_for_seconds.into())
        }) {
            self.invalidate();
            self.message = "Confirmation expired. Prepare the key operation again.".into();
        }
        BiometricKeySnapshot {
            configured: self.pin.is_some(),
            busy: self.flight.is_some(),
            state: self.state,
            key_id: self.key_id.clone(),
            can_enroll: self.can(Operation::Enroll),
            can_revoke: self.can(Operation::Revoke),
            outcome: self.outcome,
            message: self.message.clone(),
        }
    }
    pub fn begin(&mut self, command: KeyCommand) -> Result<ProviderWork, Refusal> {
        let target = self.own()?;
        if self.flight.is_some() {
            return Err(Refusal::Busy);
        }
        self.invalidate();
        let (sent, body) = match command {
            KeyCommand::Read => (
                Sent::Read,
                serde_json::json!({"version":3,"command":"identity_detail","target":target}),
            ),
            KeyCommand::PrepareEnroll | KeyCommand::PrepareRevoke => {
                let (operation, name) = if command == KeyCommand::PrepareEnroll {
                    (Operation::Enroll, "enroll")
                } else {
                    (Operation::Revoke, "revoke")
                };
                (
                    Sent::Prepare(operation),
                    serde_json::json!({"version":2,"command":"biometric_prepare","operation":name,"target":target}),
                )
            }
        };
        let bytes = serde_json::to_vec(&body).map_err(|_| Refusal::RequestTooLarge)?;
        self.launch(sent, String::new(), Vec::new(), bytes)
    }
    /// Enrollment proof-of-possession transcript for `public_key` under the
    /// current enroll ticket, with the pinned identities (which the prepare
    /// response's `provider_identity` was already checked against).
    pub fn enroll_transcript(
        &mut self,
        public_key: &[u8],
    ) -> Result<BiometricEnrollRequest, Refusal> {
        let pin = self.pin.clone().ok_or(Refusal::NotPinned)?;
        if !self.can(Operation::Enroll) {
            return Err(Refusal::NoPreparedOperation);
        }
        if !v2::valid_public_key(public_key) {
            return Err(Refusal::InvalidPublicKey);
        }
        let prepared = &self.ticket.as_ref().expect("checked ticket").prepared;
        let transcript = v2::enroll_transcript(
            &pin.provider_identity,
            &pin.approval_client,
            public_key,
            &prepared.ticket,
            &prepared.action_id,
        )
        .ok_or(Refusal::MalformedBinding)?;
        self.enroll_key = Some(public_key.to_vec());
        Ok(BiometricEnrollRequest {
            key_id: v2::key_id(public_key),
            transcript,
        })
    }
    pub fn begin_enroll(
        &mut self,
        password: String,
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<ProviderWork, Refusal> {
        let password = Zeroizing::new(password);
        let pin = self.pin.clone().ok_or(Refusal::NotPinned)?;
        if !self.can(Operation::Enroll) {
            return Err(Refusal::NoPreparedOperation);
        }
        if self.enroll_key.as_deref() != Some(public_key) {
            return Err(Refusal::KeyMismatch);
        }
        if password.is_empty() || password.len() > 4096 {
            return Err(Refusal::InvalidPassword);
        }
        let prepared = &self.ticket.as_ref().expect("checked ticket").prepared;
        let transcript = v2::enroll_transcript(
            &pin.provider_identity,
            &pin.approval_client,
            public_key,
            &prepared.ticket,
            &prepared.action_id,
        )
        .ok_or(Refusal::MalformedBinding)?;
        if !v2::verify(public_key, &transcript, signature) {
            return Err(Refusal::InvalidSignature);
        }
        let ticket = self.ticket.take().expect("checked ticket").prepared;
        let mut body = serde_json::json!({
            "version": 2,
            "command": "biometric_enroll",
            "action_id": ticket.action_id,
            "ticket": ticket.ticket,
            "password": password.as_str(),
            "public_key": v2::base64url(public_key),
            "enroll_signature": v2::base64url(signature),
        });
        self.send_mutation(
            Sent::Enroll,
            ticket.action_id,
            public_key.to_vec(),
            &mut body,
        )
    }
    pub fn begin_revoke(&mut self, password: String) -> Result<ProviderWork, Refusal> {
        let password = Zeroizing::new(password);
        let target = self.own()?;
        if !self.can(Operation::Revoke) {
            return Err(Refusal::NoPreparedOperation);
        }
        if password.is_empty() || password.len() > 4096 {
            return Err(Refusal::InvalidPassword);
        }
        let ticket = self.ticket.take().expect("checked ticket").prepared;
        let mut body = serde_json::json!({
            "version": 2,
            "command": "biometric_revoke",
            "target": target,
            "action_id": ticket.action_id,
            "ticket": ticket.ticket,
            "password": password.as_str(),
        });
        self.send_mutation(Sent::Revoke, ticket.action_id, Vec::new(), &mut body)
    }
    fn send_mutation(
        &mut self,
        sent: Sent,
        action_id: String,
        public_key: Vec<u8>,
        body: &mut serde_json::Value,
    ) -> Result<ProviderWork, Refusal> {
        let bytes = serde_json::to_vec(&*body).map_err(|_| Refusal::RequestTooLarge);
        for key in ["password", "ticket"] {
            if let Some(serde_json::Value::String(v)) = body.get_mut(key) {
                v.zeroize();
            }
        }
        self.invalidate();
        self.launch(sent, action_id, public_key, bytes?)
    }
    fn launch(
        &mut self,
        sent: Sent,
        action_id: String,
        public_key: Vec<u8>,
        mut bytes: Vec<u8>,
    ) -> Result<ProviderWork, Refusal> {
        if bytes.len() > REQUEST_LIMIT {
            bytes.zeroize();
            return Err(Refusal::RequestTooLarge);
        }
        self.serial = self.serial.checked_add(1).ok_or(Refusal::Busy)?;
        self.flight = Some(Flight {
            token: self.serial,
            epoch: self.epoch,
            sent,
            action_id,
            public_key,
            started: Instant::now(),
        });
        self.outcome = Outcome::None;
        self.message = "Contacting provider…".into();
        Ok(ProviderWork {
            token: self.serial,
            body: bytes,
        })
    }
    pub fn finish(&mut self, token: u32, bytes: &[u8]) {
        if self.flight.as_ref().map(|f| f.token) != Some(token) {
            self.outcome = Outcome::Stale;
            return;
        }
        let flight = self.flight.take().expect("matched flight");
        let mutation = matches!(flight.sent, Sent::Enroll | Sent::Revoke);
        if !mutation && flight.epoch != self.epoch {
            self.outcome = Outcome::Stale;
            return;
        }
        if let Ok(error) = decode::<ErrorResponse>(bytes) {
            if error.version == 1 {
                self.invalidate();
                self.outcome = match (mutation, error.error) {
                    (false, ErrorCode::InvalidRequest) => Outcome::Unsupported,
                    (_, ErrorCode::AuthenticationFailed) => Outcome::PasswordRejected,
                    (_, ErrorCode::RateLimited) => Outcome::RateLimited,
                    (_, ErrorCode::Stale) => Outcome::Stale,
                    (true, ErrorCode::Unavailable) => Outcome::Unknown,
                    _ => Outcome::Rejected,
                };
                if self.outcome == Outcome::Unsupported {
                    self.state = KeyState::Unsupported;
                    self.key_id.clear();
                }
                if self.outcome == Outcome::Unknown {
                    self.state = KeyState::Unknown;
                    self.key_id.clear();
                }
                self.message = match self.outcome {
                    Outcome::Unsupported => "This provider does not offer Touch ID approval. Password approval continues.",
                    Outcome::Unknown => "Outcome unknown. Read the key state again; nothing was resent.",
                    Outcome::PasswordRejected => "Password not accepted. Prepare again with a fresh password.",
                    _ => "Provider refused the key operation. Prepare it again.",
                }
                .into();
                return;
            }
        }
        if self.accept(&flight, bytes).is_err() {
            self.invalidate();
            self.outcome = if mutation {
                Outcome::Unknown
            } else {
                Outcome::Invalid
            };
            if mutation {
                self.state = KeyState::Unknown;
                self.key_id.clear();
            }
            self.message = if mutation {
                "Outcome unknown. Read the key state again; nothing was resent."
            } else {
                "Unavailable or invalid response. No key state is inferred."
            }
            .into();
        }
    }
    fn record_key(&mut self, key_id: Option<String>) -> Result<(), &'static str> {
        match key_id {
            Some(id) if valid_hex(&id) => {
                self.state = KeyState::Enrolled;
                self.key_id = id;
            }
            Some(_) => return Err("key id"),
            None => {
                self.state = KeyState::NotEnrolled;
                self.key_id.clear();
            }
        }
        Ok(())
    }
    fn accept(&mut self, flight: &Flight, bytes: &[u8]) -> Result<(), &'static str> {
        let own = self.own().map_err(|_| "pin")?;
        match flight.sent {
            Sent::Read => {
                let r: Detail = decode(bytes)?;
                let row = r.identity;
                if r.version != 3
                    || row.kind != IdentityKind::ApprovalClient
                    || row.id != own.id
                    || row.fingerprint != row.id
                    || !row.this_client
                    || row.label.is_empty()
                    || row.label.len() > 128
                    || row.label.chars().any(char::is_control)
                    || (row.trust == IdentityTrust::Revoked) != row.roles.is_empty()
                {
                    return Err("detail");
                }
                let _session_generation = r.generation;
                self.record_key(row.biometric_key_id)?;
                self.outcome = Outcome::Accepted;
                self.message = "Touch ID key state read from the provider.".into();
            }
            Sent::Prepare(operation) => {
                let r: Prepared = decode(bytes)?;
                let pin = self.pin.as_ref().ok_or("pin")?;
                if r.version != 2
                    || r.operation != operation
                    || r.target != own
                    || !valid_id(&r.action_id)
                    || !valid_hex(&r.ticket)
                    || !(1..=55).contains(&r.valid_for_seconds)
                    || flight.started.elapsed() >= Duration::from_secs(r.valid_for_seconds.into())
                    || r.provider_identity != pin.provider_identity
                {
                    return Err("prepare");
                }
                let _session_generation = r.generation;
                self.record_key(r.biometric_key_id.clone())?;
                self.ticket = Some(Ticket {
                    prepared: r,
                    started: flight.started,
                });
                self.outcome = Outcome::Accepted;
                self.message = "Fresh password authorizes only this key operation. Confirmation expires within 55 seconds.".into();
            }
            Sent::Enroll => {
                let r: Enrolled = decode(bytes)?;
                if r.version != 2
                    || r.operation != Operation::Enroll
                    || r.target != own
                    || r.action_id != flight.action_id
                    || r.biometric_key_id != v2::key_id(&flight.public_key)
                {
                    return Err("enroll");
                }
                self.record_key(Some(r.biometric_key_id))?;
                self.outcome = Outcome::Enrolled;
                self.message = "Touch ID approval enabled for this device.".into();
            }
            Sent::Revoke => {
                let r: Revoked = decode(bytes)?;
                if r.version != 2
                    || r.operation != Operation::Revoke
                    || r.target != own
                    || r.action_id != flight.action_id
                    || r.revoked_key_id.as_deref().is_some_and(|k| !valid_hex(k))
                {
                    return Err("revoke");
                }
                self.record_key(None)?;
                self.outcome = Outcome::Revoked;
                self.message = "Touch ID approval disabled. Password approval continues.".into();
            }
        }
        Ok(())
    }
}
