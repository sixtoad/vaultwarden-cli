//! Durable, OS-bound agent identity and closed administrative projections.

use serde::{Deserialize, Serialize};

use super::provider::{ProviderDiagnostic, ProviderError};
use super::{RequestId, decode_public_key, hex_sha256};

pub const MAX_AGENT_LABEL_LEN: usize = 128;

/// Untrusted human administration input; this is not authentication evidence.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPairing {
    pub label: String,
    pub public_key: String,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentBindingStatus {
    Enabled,
    Revoked,
}

/// Safe human-facing projection. Public verification material stays in storage.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBindingView {
    pub id: String,
    pub label: String,
    pub fingerprint: String,
    pub uid: u32,
    pub gid: u32,
    pub status: AgentBindingStatus,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentBinding {
    pub(crate) id: String,
    pub(crate) label: String,
    pub(crate) public_key: String,
    pub(crate) fingerprint: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) status: AgentBindingStatus,
}

impl AgentBinding {
    pub(crate) fn new(input: AgentPairing, provider_uid: u32) -> Result<Self, ProviderError> {
        let key = decode_public_key(&input.public_key).map_err(|_error| invalid())?;
        let binding = Self {
            id: RequestId::new_random()
                .map_err(|_error| invalid())?
                .as_str()
                .into(),
            label: input.label,
            public_key: input.public_key,
            fingerprint: hex_sha256(key.as_bytes()),
            uid: input.uid,
            gid: input.gid,
            status: AgentBindingStatus::Enabled,
        };
        binding.validate(provider_uid)?;
        Ok(binding)
    }

    pub(crate) fn validate(&self, provider_uid: u32) -> Result<(), ProviderError> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let id = URL_SAFE_NO_PAD
            .decode(&self.id)
            .map_err(|_error| invalid())?;
        let key = decode_public_key(&self.public_key).map_err(|_error| invalid())?;
        if id.len() != 32
            || URL_SAFE_NO_PAD.encode(&id) != self.id
            || !valid_label(&self.label)
            || !valid_os_id(self.uid)
            || !valid_os_id(self.gid)
            || self.uid == provider_uid
            || self.fingerprint != hex_sha256(key.as_bytes())
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Membership and enabled status are prerequisites, never signature proof.
    pub(crate) fn matches_os(&self, uid: u32, groups: &[u32]) -> bool {
        self.status == AgentBindingStatus::Enabled && self.uid == uid && groups.contains(&self.gid)
    }

    pub(crate) fn view(&self) -> AgentBindingView {
        AgentBindingView {
            id: self.id.clone(),
            label: self.label.clone(),
            fingerprint: self.fingerprint.clone(),
            uid: self.uid,
            gid: self.gid,
            status: self.status,
        }
    }

    pub(crate) fn audit(
        &self,
        actor_uid: u32,
        now: u64,
        action: AgentAuditAction,
    ) -> AgentAuditEvent {
        AgentAuditEvent {
            actor_uid,
            binding_id: self.id.clone(),
            label: self.label.clone(),
            fingerprint: self.fingerprint.clone(),
            uid: self.uid,
            gid: self.gid,
            timestamp_unix_seconds: now,
            action,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAuditAction {
    Paired,
    Revoked,
}

/// Closed administrative event, independent from request execution history.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAuditEvent {
    pub actor_uid: u32,
    pub binding_id: String,
    pub label: String,
    pub fingerprint: String,
    pub uid: u32,
    pub gid: u32,
    pub timestamp_unix_seconds: u64,
    pub action: AgentAuditAction,
}

pub(crate) fn validate_registry(
    bindings: &[AgentBinding],
    audit: &[AgentAuditEvent],
    provider_uid: u32,
) -> Result<(), ProviderError> {
    use std::collections::{HashMap, HashSet};
    let mut by_id = HashMap::new();
    let mut keys = HashSet::new();
    let mut labels = HashSet::new();
    for binding in bindings {
        binding.validate(provider_uid)?;
        if by_id.insert(binding.id.as_str(), binding).is_some()
            || !keys.insert(&binding.public_key)
            || (binding.status == AgentBindingStatus::Enabled && !labels.insert(&binding.label))
        {
            return Err(invalid());
        }
    }
    let mut actions = HashMap::new();
    for event in audit {
        let binding = by_id.get(event.binding_id.as_str()).ok_or_else(invalid)?;
        if event != &binding.audit(provider_uid, event.timestamp_unix_seconds, event.action) {
            return Err(invalid());
        }
        let prior = actions.insert(event.binding_id.as_str(), event.action);
        if !matches!(
            (prior, event.action),
            (None, AgentAuditAction::Paired)
                | (Some(AgentAuditAction::Paired), AgentAuditAction::Revoked)
        ) {
            return Err(invalid());
        }
    }
    for binding in bindings {
        let expected = match binding.status {
            AgentBindingStatus::Enabled => AgentAuditAction::Paired,
            AgentBindingStatus::Revoked => AgentAuditAction::Revoked,
        };
        if actions.get(binding.id.as_str()) != Some(&expected) {
            return Err(invalid());
        }
    }
    Ok(())
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_AGENT_LABEL_LEN
        && label
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        && label.bytes().any(|byte| byte.is_ascii_graphic())
}

fn valid_os_id(id: u32) -> bool {
    id != 0 && id != u32::MAX
}

fn invalid() -> ProviderError {
    ProviderError::new(ProviderDiagnostic::InvalidState)
}
