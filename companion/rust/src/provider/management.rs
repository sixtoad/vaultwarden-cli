//! Closed v2 management protocol and single-action authority/recovery lifecycle.
use super::protocol::{
    decode, valid_hex, valid_id, visible, ErrorCode, ErrorResponse, REQUEST_LIMIT,
};
use crate::api::{management::*, provider::ProviderWork};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Target {
    kind: IdentityKind,
    id: String,
}
impl Target {
    fn valid(&self) -> bool {
        match self.kind {
            IdentityKind::ApprovalClient => valid_hex(&self.id),
            IdentityKind::RequesterAgent => valid_id(&self.id),
        }
    }
    fn key(&self) -> String {
        format!(
            "{}:{}",
            if self.kind == IdentityKind::ApprovalClient {
                "approval_client"
            } else {
                "requester_agent"
            },
            self.id
        )
    }
}
impl ManagedIdentity {
    fn target(&self) -> Target {
        Target {
            kind: self.kind,
            id: self.id.clone(),
        }
    }
    fn valid(&self) -> bool {
        self.target().valid()
            && valid_hex(&self.fingerprint)
            && !self.label.is_empty()
            && self.label.len() <= 128
            && !self.label.chars().any(char::is_control)
            && match self.trust {
                IdentityTrust::Revoked => self.roles.is_empty(),
                IdentityTrust::Enabled => match self.kind {
                    IdentityKind::ApprovalClient => {
                        self.roles == [IdentityRole::Approve]
                            || self.roles == [IdentityRole::Approve, IdentityRole::Admin]
                    }
                    IdentityKind::RequesterAgent => self.roles == [IdentityRole::Request],
                },
            }
            && match self.kind {
                IdentityKind::ApprovalClient => self.id == self.fingerprint,
                IdentityKind::RequesterAgent => !self.this_client,
            }
    }
    fn projection(&self) -> Self {
        let mut row = self.clone();
        row.label = visible(&row.label);
        row
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Recovery {
    target: Target,
    action_id: String,
}
impl Recovery {
    fn valid(&self) -> bool {
        self.target.valid() && valid_id(&self.action_id)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Provider {
    fingerprint: String,
    execution_configured: bool,
    execution_available: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    version: u8,
    identities: Vec<ManagedIdentity>,
    #[serde(deserialize_with = "Option::deserialize")]
    next_cursor: Option<String>,
    generation: u64,
    provider: Provider,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Detail {
    version: u8,
    identity: ManagedIdentity,
    generation: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepared {
    version: u8,
    identity: ManagedIdentity,
    action_id: String,
    ticket: String,
    generation: u64,
    valid_for_seconds: u32,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Revocation {
    NotRecorded,
    Pending,
    Recorded,
    Unknown,
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Cleanup {
    Pending,
    Complete,
    Unknown,
    NotApplicable,
}
fn valid_action_facts(revocation: &Revocation, cleanup: &Cleanup) -> bool {
    matches!(
        (revocation, cleanup),
        (Revocation::NotRecorded, Cleanup::NotApplicable)
            | (Revocation::Pending, Cleanup::Pending | Cleanup::Unknown)
            | (Revocation::Recorded, Cleanup::Complete | Cleanup::Unknown)
            | (Revocation::Unknown, Cleanup::Unknown)
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Action {
    version: u8,
    owner_reconciled: bool,
    target: Target,
    action_id: String,
    revocation: Revocation,
    cleanup: Cleanup,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Origin {
    version: u8,
    request_id: String,
    #[serde(deserialize_with = "Option::deserialize")]
    origin: Option<OriginBinding>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginBinding {
    kind: IdentityKind,
    binding_id: String,
    label: String,
    fingerprint: String,
    evidence: OriginEvidence,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum OriginEvidence {
    SignedOsBinding,
}
struct Flight {
    token: u32,
    epoch: u64,
    command: ManagementCommand,
    target: Target,
    after: String,
    started: Instant,
}
struct Ticket {
    prepared: Prepared,
    started: Instant,
}
#[derive(Default)]
pub struct ManagementSession {
    configured: bool,
    epoch: u64,
    serial: u32,
    flight: Option<Flight>,
    ticket: Option<Ticket>,
    recovery: Option<Recovery>,
    identities: Vec<ManagedIdentity>,
    detail: Option<ManagedIdentity>,
    next: String,
    refreshed: Option<Instant>,
    state: InventoryState,
    outcome: ManagementOutcome,
    provider_fingerprint: String,
    configured_execution: bool,
    available_execution: bool,
    action_id: String,
    action_target: String,
    revocation: String,
    cleanup: String,
    message: String,
    origin_id: String,
    origin_text: String,
}
impl ManagementSession {
    pub fn configure(&mut self, saved: &str) -> Result<(), &'static str> {
        if self.flight.is_some() || self.recovery.is_some() {
            return Err("Resolve original administrative action first.");
        }
        let recovery = if saved.is_empty() {
            None
        } else {
            if saved.len() > 512 {
                return Err("Invalid recovery");
            }
            let r: Recovery = decode(saved.as_bytes())?;
            if !r.valid() {
                return Err("Invalid recovery");
            }
            Some(r)
        };
        self.invalidate();
        self.recovery = recovery;
        self.configured = true;
        self.message = "Refresh authoritative provider identities.".into();
        self.outcome = ManagementOutcome::None;
        self.action_id.clear();
        self.action_target.clear();
        self.revocation.clear();
        self.cleanup.clear();
        if let Some(r) = &self.recovery {
            self.action_id = r.action_id.clone();
            self.action_target = r.target.key();
            self.message = "Administrative outcome unknown. Check the original action only.".into();
        }
        Ok(())
    }
    pub fn invalidate(&mut self) {
        self.epoch = self.epoch.checked_add(1).expect("management epoch");
        self.ticket = None;
        self.identities.clear();
        self.detail = None;
        self.next.clear();
        self.refreshed = None;
        self.provider_fingerprint.clear();
        self.available_execution = false;
        self.configured_execution = false;
        self.origin_id.clear();
        self.origin_text.clear();
        self.state = InventoryState::Stale;
    }
    fn can_revoke(&self) -> bool {
        self.flight.is_none()
            && self.recovery.is_none()
            && self.ticket.as_ref().is_some_and(|t| {
                t.started.elapsed() < Duration::from_secs(t.prepared.valid_for_seconds.into())
                    && self
                        .detail
                        .as_ref()
                        .is_some_and(|d| d == &t.prepared.identity)
            })
    }
    pub fn snapshot(&mut self) -> ManagementSnapshot {
        if self.ticket.as_ref().is_some_and(|t| {
            t.started.elapsed() >= Duration::from_secs(t.prepared.valid_for_seconds.into())
        }) {
            self.ticket = None;
            self.message = "Confirmation expired. Review this identity again.".into();
        }
        if self
            .refreshed
            .is_some_and(|at| at.elapsed() >= Duration::from_secs(30))
        {
            self.identities.clear();
            self.detail = None;
            self.ticket = None;
            self.next.clear();
            self.refreshed = None;
            self.state = InventoryState::Stale;
            self.available_execution = false;
        }
        ManagementSnapshot {
            state: self.state,
            outcome: self.outcome,
            busy: self.flight.is_some(),
            identities: self
                .identities
                .iter()
                .map(ManagedIdentity::projection)
                .collect(),
            detail: self.detail.as_ref().map(ManagedIdentity::projection),
            can_revoke: self.can_revoke(),
            has_next: !self.next.is_empty(),
            provider_fingerprint: self.provider_fingerprint.clone(),
            execution_configured: self.configured_execution,
            execution_available: self.available_execution,
            recovery: self
                .recovery
                .as_ref()
                .map(|r| serde_json::to_string(r).expect("recovery"))
                .unwrap_or_default(),
            action_id: self.action_id.clone(),
            action_target: self.action_target.clone(),
            revocation: self.revocation.clone(),
            cleanup: self.cleanup.clone(),
            message: self.message.clone(),
            origin_id: self.origin_id.clone(),
            origin_text: self.origin_text.clone(),
        }
    }
    pub fn begin(
        &mut self,
        command: ManagementCommand,
        kind: IdentityKind,
        id: String,
        password: String,
    ) -> Result<ProviderWork, &'static str> {
        let password = Zeroizing::new(password);
        if !self.configured || self.flight.is_some() {
            return Err("Management unavailable or busy.");
        }
        if self.recovery.is_some() && command != ManagementCommand::Status {
            return Err("Check original action only.");
        }
        let mut target = Target { kind, id };
        let mut after = String::new();
        let mut body = serde_json::json!({"version":2});
        match command {
            ManagementCommand::List | ManagementCommand::Next => {
                if command == ManagementCommand::Next {
                    if self.next.is_empty() {
                        return Err("No next page");
                    }
                    after = self.next.clone();
                }
                self.invalidate();
                body["command"] = "identity_list".into();
                body["limit"] = 64.into();
                body["after"] = if after.is_empty() {
                    serde_json::Value::Null
                } else {
                    after.clone().into()
                };
            }
            ManagementCommand::Detail | ManagementCommand::Prepare => {
                if !target.valid() {
                    return Err("Invalid target");
                }
                self.invalidate();
                body["command"] = if command == ManagementCommand::Detail {
                    "identity_detail"
                } else {
                    "identity_prepare"
                }
                .into();
                body["target"] = serde_json::to_value(&target).expect("target");
            }
            ManagementCommand::Revoke => {
                if !self.can_revoke()
                    || !target.valid()
                    || password.is_empty()
                    || password.len() > 4096
                {
                    return Err("Fresh exact-target review and password required.");
                }
                if self
                    .ticket
                    .as_ref()
                    .expect("ticket")
                    .prepared
                    .identity
                    .target()
                    != target
                {
                    return Err("Target changed");
                }
                let ticket = self.ticket.take().expect("ticket");
                let recovery = Recovery {
                    target: target.clone(),
                    action_id: ticket.prepared.action_id,
                };
                body["command"] = "identity_revoke".into();
                body["target"] = serde_json::to_value(&target).expect("target");
                body["action_id"] = recovery.action_id.clone().into();
                body["ticket"] = ticket.prepared.ticket.into();
                body["password"] = password.to_string().into();
                self.invalidate();
                self.action_id = recovery.action_id.clone();
                self.action_target = target.key();
                self.recovery = Some(recovery);
                self.revocation = "unknown".into();
                self.cleanup = "unknown".into();
            }
            ManagementCommand::Status => {
                let r = self.recovery.as_ref().ok_or("No original action")?;
                target = r.target.clone();
                body["command"] = "identity_status".into();
                body["target"] = serde_json::to_value(&target).expect("target");
                body["action_id"] = r.action_id.clone().into();
            }
            ManagementCommand::Origin => {
                if !valid_id(&target.id) {
                    return Err("Invalid request");
                }
                self.origin_id.clear();
                self.origin_text.clear();
                body["command"] = "request_origin".into();
                body["request_id"] = target.id.clone().into();
            }
        }
        let mut bytes = serde_json::to_vec(&body).map_err(|_| "Invalid body")?;
        for key in ["password", "ticket"] {
            if let Some(serde_json::Value::String(v)) = body.get_mut(key) {
                v.zeroize();
            }
        }
        if bytes.len() > REQUEST_LIMIT {
            bytes.zeroize();
            if command == ManagementCommand::Revoke {
                self.recovery = None;
            }
            return Err("Request too large; not sent");
        }
        self.serial = self.serial.checked_add(1).ok_or("Operation limit")?;
        self.flight = Some(Flight {
            token: self.serial,
            epoch: self.epoch,
            command,
            target,
            after,
            started: Instant::now(),
        });
        self.outcome = ManagementOutcome::None;
        self.message = "Contacting provider…".into();
        Ok(ProviderWork {
            token: self.serial,
            body: bytes,
        })
    }
    pub fn finish(&mut self, token: u32, bytes: &[u8]) {
        if self.flight.as_ref().map(|f| f.token) != Some(token) {
            self.outcome = ManagementOutcome::Stale;
            return;
        }
        let flight = self.flight.take().expect("flight");
        let action = matches!(
            flight.command,
            ManagementCommand::Revoke | ManagementCommand::Status
        );
        if flight.epoch != self.epoch && !action {
            self.outcome = ManagementOutcome::Stale;
            return;
        }
        if let Ok(error) = decode::<ErrorResponse>(bytes) {
            if error.version == 1 {
                self.ticket = None;
                self.outcome = if matches!(error.error, ErrorCode::InvalidRequest) {
                    ManagementOutcome::Unsupported
                } else {
                    ManagementOutcome::Rejected
                };
                if !action {
                    self.invalidate();
                    self.state = if error.error == ErrorCode::Unauthorized {
                        InventoryState::Unauthorized
                    } else {
                        InventoryState::Unavailable
                    };
                }
                if flight.command == ManagementCommand::Revoke && error.error.definite_rejection() {
                    self.recovery = None;
                    self.revocation = "not_recorded".into();
                    self.cleanup = "not_applicable".into();
                    self.message = "Revocation rejected before mutation. A fresh review and password are required.".into();
                    return;
                }
                // Even rejection retains recovery: native pre-send marking may have
                // succeeded. Do not clear an action without action-bound evidence.
                self.message = if action { "Outcome unknown. Check the original action. Revoked clients may need the provider owner's console." } else { "Management unavailable or unauthorized. Enrollment does not grant administration." }.into();
                return;
            }
        }
        if self.accept(&flight, bytes).is_err() {
            if !action {
                self.invalidate();
                self.state = InventoryState::Unavailable;
            }
            self.outcome = ManagementOutcome::Invalid;
            self.message =
                "Unavailable or invalid response. No trust or successful revocation is inferred."
                    .into();
        } else {
            self.outcome = ManagementOutcome::Accepted;
        }
    }
    fn accept(&mut self, f: &Flight, bytes: &[u8]) -> Result<(), &'static str> {
        match f.command {
            ManagementCommand::List | ManagementCommand::Next => {
                let r: Inventory = decode(bytes)?;
                let mut seen = HashSet::new();
                let mut previous = f.after.clone();
                if r.version != 2
                    || r.identities.len() > 64
                    || !valid_hex(&r.provider.fingerprint)
                    || (r.provider.execution_available && !r.provider.execution_configured)
                {
                    return Err("inventory");
                }
                for row in &r.identities {
                    let key = row.target().key();
                    if !row.valid() || !seen.insert(key.clone()) || key <= previous {
                        return Err("row");
                    }
                    previous = key;
                }
                if r.identities.iter().filter(|r| r.this_client).count() > 1
                    || r.next_cursor
                        .as_ref()
                        .is_some_and(|n| r.identities.len() != 64 || *n != previous)
                {
                    return Err("cursor");
                }
                let _session_generation = r.generation; // Not an inventory revision.
                self.identities = r.identities;
                self.next = r.next_cursor.unwrap_or_default();
                self.refreshed = Some(Instant::now());
                self.provider_fingerprint = r.provider.fingerprint;
                self.configured_execution = r.provider.execution_configured;
                self.available_execution = r.provider.execution_available;
                self.state = if self.identities.is_empty() {
                    InventoryState::Empty
                } else {
                    InventoryState::Ready
                };
                self.message = "Provider records · this page is a fresh read, not an atomic multi-page snapshot. Refresh within 30 seconds.".into();
            }
            ManagementCommand::Detail => {
                let r: Detail = decode(bytes)?;
                if r.version != 2 || !r.identity.valid() || r.identity.target() != f.target {
                    return Err("detail");
                }
                let _session_generation = r.generation;
                self.state = if r.identity.trust == IdentityTrust::Revoked {
                    InventoryState::Revoked
                } else {
                    InventoryState::Ready
                };
                self.detail = Some(r.identity);
                self.refreshed = Some(Instant::now());
                self.message =
                    "Identity read from provider. Review consequences before revoking.".into();
            }
            ManagementCommand::Prepare => {
                let r: Prepared = decode(bytes)?;
                if r.version != 2
                    || !r.identity.valid()
                    || r.identity.target() != f.target
                    || r.identity.trust != IdentityTrust::Enabled
                    || !valid_id(&r.action_id)
                    || !valid_hex(&r.ticket)
                    || !(1..=55).contains(&r.valid_for_seconds)
                    || f.started.elapsed() >= Duration::from_secs(r.valid_for_seconds.into())
                {
                    return Err("prepare");
                }
                let _session_generation = r.generation;
                self.detail = Some(r.identity.clone());
                self.refreshed = Some(Instant::now());
                self.ticket = Some(Ticket {
                    prepared: r,
                    started: f.started,
                });
                self.state = InventoryState::Ready;
                self.message = "Fresh password authorizes only this exact revocation. Confirmation expires within 55 seconds.".into();
            }
            ManagementCommand::Revoke | ManagementCommand::Status => {
                let r: Action = decode(bytes)?;
                let expected = self.recovery.as_ref().ok_or("recovery")?;
                if r.version != 2
                    || r.target != expected.target
                    || r.action_id != expected.action_id
                    || !valid_action_facts(&r.revocation, &r.cleanup)
                {
                    return Err("action");
                }
                self.revocation = match r.revocation {
                    Revocation::NotRecorded => "not_recorded",
                    Revocation::Pending => "pending",
                    Revocation::Recorded => "recorded",
                    Revocation::Unknown => "unknown",
                }
                .into();
                self.cleanup = match r.cleanup {
                    Cleanup::Pending => "pending",
                    Cleanup::Complete => "complete",
                    Cleanup::Unknown => "unknown",
                    Cleanup::NotApplicable => "not_applicable",
                }
                .into();
                if r.owner_reconciled {
                    self.recovery = None;
                    self.message = "The provider owner separately confirmed the target revoked and provider-owned cleanup complete. The original action's outcome remains as recorded above; it was not replayed.".into();
                } else if r.revocation == Revocation::NotRecorded
                    && r.cleanup == Cleanup::NotApplicable
                {
                    self.recovery = None;
                    self.message = "The provider confirmed this action made no change. A fresh review is required.".into();
                } else if r.revocation == Revocation::Recorded && r.cleanup == Cleanup::Complete {
                    self.recovery = None;
                    self.message = "Revocation recorded; provider-owned cleanup confirmed. Delivered secrets and consumer programs are not recalled or terminated.".into();
                } else {
                    self.message = "Administrative outcome remains unresolved. Only the original action status can be checked; no command is replayed.".into();
                }
            }
            ManagementCommand::Origin => {
                let r: Origin = decode(bytes)?;
                if r.version != 2 || r.request_id != f.target.id {
                    return Err("origin");
                }
                self.origin_text = if let Some(origin) = r.origin {
                    if origin.kind != IdentityKind::RequesterAgent
                        || !valid_id(&origin.binding_id)
                        || !valid_hex(&origin.fingerprint)
                        || origin.label.is_empty()
                        || origin.label.len() > 128
                        || origin.label.chars().any(char::is_control)
                    {
                        return Err("origin");
                    }
                    let OriginEvidence::SignedOsBinding = origin.evidence;
                    format!("Authenticated requester-agent binding: {}\nBinding ID: {}\nPublic-key SHA-256: {}\nEvidence: signed request and OS binding at admission. This does not establish a physical device.", visible(&origin.label), origin.binding_id, origin.fingerprint)
                } else {
                    "Unavailable: no authenticated origin snapshot for this request. Labels do not prove origin.".into()
                };
                self.origin_id = r.request_id;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    #[test]
    fn ticket_expiry_and_inventory_freshness_retire_authority() {
        let mut s = ManagementSession::default();
        s.configure("").unwrap();
        let id = "A".repeat(43);
        let work = s
            .begin(
                ManagementCommand::Prepare,
                IdentityKind::RequesterAgent,
                id.clone(),
                String::new(),
            )
            .unwrap();
        let body = serde_json::json!({"version":2,"identity":{"kind":"requester_agent","id":id,"label":"Agent","fingerprint":"b".repeat(64),"roles":["request"],"trust":"enabled","this_client":false},"action_id":"C".repeat(43),"ticket":"d".repeat(64),"generation":1,"valid_for_seconds":55});
        s.finish(work.token, &serde_json::to_vec(&body).unwrap());
        assert!(s.snapshot().can_revoke);
        s.ticket.as_mut().unwrap().started = Instant::now() - Duration::from_secs(56);
        assert!(s
            .begin(
                ManagementCommand::Revoke,
                IdentityKind::RequesterAgent,
                id.clone(),
                "synthetic".into()
            )
            .is_err());
        assert!(!s.snapshot().can_revoke);
        s.refreshed = Some(Instant::now() - Duration::from_secs(31));
        assert!(s.snapshot().detail.is_none());
        assert_eq!(s.snapshot().state, InventoryState::Stale);
    }
}
