//! The durable recovery marker and the management lifecycle gate, ported
//! from `ProviderSettings.beforeSend`/`settle` and `ManagementTransportGate`
//! (macOS) and their Android port (`RecoveryState`, `ManagementTransportGate`).
//! The marker holds no password, ticket or review.
use super::rules::{parse, valid_hex, valid_request_id};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Management {
    pub kind: String,
    pub id: String,
    pub action_id: String,
}
impl Management {
    pub fn valid(&self) -> bool {
        valid_request_id(&self.action_id)
            && ((self.kind == "approval_client" && valid_hex(&self.id, 64))
                || (self.kind == "requester_agent" && valid_request_id(&self.id)))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recovery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management: Option<Management>,
}
fn keys(map: &Map<String, Value>) -> Vec<&str> {
    let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
    keys.sort_unstable();
    keys
}
fn text<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}
fn target(map: &Map<String, Value>) -> Option<(&str, &str)> {
    let target = map.get("target")?.as_object()?;
    (keys(target) == ["id", "kind"]).then_some(())?;
    Some((text(target, "kind")?, text(target, "id")?))
}
impl Recovery {
    pub fn valid(&self) -> bool {
        self.pending_id.as_deref().is_none_or(valid_request_id)
            && self
                .management
                .as_ref()
                .is_none_or(|m| m.valid() && self.pending_id.is_none())
    }
    pub fn has_pending(&self) -> bool {
        self.pending_id.is_some() || self.management.is_some()
    }
    /// The state to persist BEFORE `body` is sent, or `None` to refuse it.
    pub fn before_send(&self, body: &[u8]) -> Option<Self> {
        let json = parse(body)?;
        let command = text(&json, "command")?;
        let version = json.get("version").and_then(Value::as_u64);
        if let Some(pending) = &self.pending_id {
            if command != "status" || text(&json, "request_id") != Some(pending.as_str()) {
                return None;
            }
        }
        if let Some(m) = &self.management {
            let (kind, id) = target(&json)?;
            if command != "identity_status"
                || version != Some(2)
                || keys(&json) != ["action_id", "command", "target", "version"]
                || kind != m.kind
                || id != m.id
                || text(&json, "action_id") != Some(m.action_id.as_str())
            {
                return None;
            }
        }
        let mut next = self.clone();
        if command == "identity_revoke" {
            let (kind, id) = target(&json)?;
            let marker = Management {
                kind: kind.into(),
                id: id.into(),
                action_id: text(&json, "action_id")?.into(),
            };
            let password = text(&json, "password")?;
            if self.has_pending()
                || keys(&json)
                    != [
                        "action_id",
                        "command",
                        "password",
                        "target",
                        "ticket",
                        "version",
                    ]
                || version != Some(2)
                || !text(&json, "ticket").is_some_and(|t| valid_hex(t, 64))
                || password.is_empty()
                || password.len() > 4096
                || !marker.valid()
            {
                return None;
            }
            next.management = Some(marker);
        }
        if command == "decision" {
            let id = text(&json, "request_id").filter(|id| valid_request_id(id))?;
            next.pending_id = Some(id.into());
        }
        Some(next)
    }
    /// The state after Dart settled `id`, or `None` to refuse.
    pub fn settle(&self, id: &str) -> Option<Self> {
        match (&self.management, &self.pending_id) {
            (Some(m), None) if m.action_id == id => Some(Self::default()),
            (Some(_), _) => None,
            (None, Some(pending)) if pending == id => Some(Self::default()),
            _ => None,
        }
    }
    /// The `managementRecovery` member of the `configuration` reply.
    pub fn management_json(&self) -> String {
        self.management.as_ref().map_or_else(String::new, |m| {
            serde_json::json!({"target":{"kind":m.kind,"id":m.id},"action_id":m.action_id})
                .to_string()
        })
    }
}

/// A ticket prepared in the foreground is usable once, within 55 s, and any
/// lifecycle invalidation discards it.
#[derive(Default)]
pub struct ManagementGate {
    epoch: u64,
    prepared: Option<[String; 4]>,
    deadline: Option<Instant>,
}
fn binding(value: &Map<String, Value>) -> Option<[String; 4]> {
    let (kind, id) = target(value)?;
    let action = text(value, "action_id")?;
    let ticket = text(value, "ticket").filter(|t| valid_hex(t, 64))?;
    let marker = Management {
        kind: kind.into(),
        id: id.into(),
        action_id: action.into(),
    };
    marker
        .valid()
        .then(|| [kind.into(), id.into(), action.into(), ticket.into()])
}
impl ManagementGate {
    pub fn invalidate(&mut self) {
        self.epoch += 1;
        self.prepared = None;
        self.deadline = None;
    }
    /// The epoch to hand to [`Self::finish`], or `None` to refuse the send.
    pub fn begin(&mut self, body: &[u8], foreground: bool, now: Instant) -> Option<u64> {
        let json = parse(body)?;
        match text(&json, "command")? {
            "identity_prepare" => {
                self.invalidate();
                if !foreground {
                    return None;
                }
                self.deadline = Some(now + Duration::from_secs(55));
            }
            "identity_revoke" => {
                let expected = self.prepared.take();
                let expires = self.deadline;
                self.invalidate(); // one send attempt
                if !foreground
                    || expires.is_none_or(|deadline| now >= deadline)
                    || expected.is_none()
                    || binding(&json) != expected
                {
                    return None;
                }
            }
            "identity_list" | "identity_detail" => self.invalidate(),
            _ => {}
        }
        Some(self.epoch)
    }
    /// False refuses the response (it is not handed to Dart).
    pub fn finish(
        &mut self,
        request: &[u8],
        response: &[u8],
        started: u64,
        foreground: bool,
        now: Instant,
    ) -> bool {
        let Some(body) = parse(request) else {
            return false;
        };
        if text(&body, "command") != Some("identity_prepare") {
            return true;
        }
        if !foreground || started != self.epoch || self.deadline.is_none_or(|d| now >= d) {
            return false;
        }
        let Some(mut reply) = parse(response) else {
            return true;
        };
        let (Some(identity), Some(target)) = (
            reply.get("identity").and_then(Value::as_object),
            body.get("target").and_then(Value::as_object),
        ) else {
            return true;
        };
        if reply.get("version").and_then(Value::as_u64) != Some(2)
            || identity.get("kind") != target.get("kind")
            || identity.get("id") != target.get("id")
        {
            return true;
        }
        reply.insert("target".into(), Value::Object(target.clone()));
        self.prepared = binding(&reply);
        true
    }
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
