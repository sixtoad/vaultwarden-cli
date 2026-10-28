//! Frozen v1 wire contract. No provider authority or synthetic proofs live here.
use crate::api::provider::{
    ProviderHistoryEvent, ProviderHistoryOutcome, ProviderReview, ProviderReviewCredential,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const RESPONSE_LIMIT: usize = 1_048_576;
pub const REQUEST_LIMIT: usize = 16_384;
// Match the existing provider policy cardinalities. Literal boundary tests in
// both crates prevent a local constant change from silently widening this view.
const MAX_ARGUMENTS: usize = 32;
const MAX_CREDENTIALS: usize = 16;

pub fn valid_id(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
pub fn valid_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Status {
    Pending {},
    Approved {},
    Denied {},
    Expired {},
    Running {},
    Completed { exit_code: u8 },
    Failed { reason: Failure },
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    ReviewUnavailable,
    ExecutionUnavailable,
    ExecutionRejected,
    ExecutionNonzero,
    ExecutionSignaled,
}
impl Status {
    pub fn summary(&self) -> String {
        // Only closed enum values and exit codes, never provider detail.
        serde_json::to_string(self).expect("status serialization")
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub label: String,
    pub use_type: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub id: String,
    pub requester: String,
    pub operation: String,
    pub effect: String,
    pub target: String,
    pub arguments: Vec<String>,
    pub credentials: Vec<Credential>,
    pub executable_digest: String,
    pub policy_digest: String,
    pub arguments_digest: String,
    pub expires_at_unix_seconds: u64,
    pub one_time: String,
    pub status: Status,
}
impl Review {
    pub fn valid(&self) -> bool {
        valid_id(&self.id)
            && self.arguments.len() <= MAX_ARGUMENTS
            && self.credentials.len() <= MAX_CREDENTIALS
            && [
                &self.executable_digest,
                &self.policy_digest,
                &self.arguments_digest,
            ]
            .into_iter()
            .all(|s| valid_hex(s))
    }
    pub fn projection(&self) -> ProviderReview {
        ProviderReview {
            id: visible(&self.id),
            requester: visible(&self.requester),
            operation: visible(&self.operation),
            effect: visible(&self.effect),
            target: visible(&self.target),
            arguments: self.arguments.iter().map(|value| visible(value)).collect(),
            credentials: self
                .credentials
                .iter()
                .map(|credential| ProviderReviewCredential {
                    label: visible(&credential.label),
                    use_type: visible(&credential.use_type),
                })
                .collect(),
            executable_digest: self.executable_digest.clone(),
            policy_digest: self.policy_digest.clone(),
            arguments_digest: self.arguments_digest.clone(),
            expires_at_unix_seconds: self.expires_at_unix_seconds,
            one_time: visible(&self.one_time),
            status: self.status.summary(),
        }
    }
    pub fn visible(&self) -> String {
        let mut rows = vec![
            format!("Request: {}", visible(&self.id)),
            format!("Requester: {}", visible(&self.requester)),
            format!("Operation: {}", visible(&self.operation)),
            format!("Effect: {}", visible(&self.effect)),
            format!("Target: {}", visible(&self.target)),
            format!("Arguments ({} separate values):", self.arguments.len()),
        ];
        for (i, arg) in self.arguments.iter().enumerate() {
            rows.push(format!("  [{i}] {}", visible(arg)));
        }
        rows.push(format!("Credentials ({}):", self.credentials.len()));
        for credential in &self.credentials {
            rows.push(format!(
                "  label={} use_type={}",
                visible(&credential.label),
                visible(&credential.use_type)
            ));
        }
        rows.extend([
            format!("Executable SHA-256: {}", self.executable_digest),
            format!("Policy SHA-256: {}", self.policy_digest),
            format!("Arguments SHA-256: {}", self.arguments_digest),
            format!("Expires (Unix seconds): {}", self.expires_at_unix_seconds),
            format!("One-time scope: {}", visible(&self.one_time)),
            format!("Status: {}", self.status.summary()),
        ]);
        rows.join("\n")
    }
}

/// Quote every string and escape non-ASCII scalars as well as controls. This
/// deliberately conservative presentation makes invisible/bidi scalars visible.
pub fn visible(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ' '..='~' => out.push(c),
            _ => out.push_str(&format!("\\u{{{:04x}}}", c as u32)),
        }
    }
    out.push('"');
    out
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionResponse {
    pub version: u8,
    pub state: SessionState,
    pub generation: u64,
}
#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SessionState {
    Locked,
    Unlocked,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListResponse {
    pub version: u8,
    pub requests: Vec<String>,
}
impl ListResponse {
    pub fn valid(&self) -> bool {
        self.version == 1
            && self.requests.len() <= 256
            && self.requests.iter().all(|id| valid_id(id))
            && self.requests.iter().collect::<HashSet<_>>().len() == self.requests.len()
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewResponse {
    pub version: u8,
    pub review: Review,
    // deserialize_with means the key must exist, even when its value is null.
    #[serde(deserialize_with = "Option::deserialize")]
    pub ticket: Option<String>,
    pub generation: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResponse {
    pub version: u8,
    pub status: Status,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorResponse {
    pub version: u8,
    pub error: ErrorCode,
}
#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    Unauthorized,
    Unavailable,
    Stale,
    AuthenticationFailed,
    RateLimited,
}
impl ErrorCode {
    pub fn definite_rejection(self) -> bool {
        matches!(
            self,
            Self::InvalidRequest
                | Self::Unauthorized
                | Self::AuthenticationFailed
                | Self::RateLimited
        )
    }
}

pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, &'static str> {
    if bytes.len() > RESPONSE_LIMIT {
        return Err("Provider response exceeded the size limit.");
    }
    serde_json::from_slice(bytes).map_err(|_| "Provider returned an invalid response.")
}

// Keep these in sync with the provider's canonical history limits. The companion
// requests 50; accepting a larger unsolicited result is not pagination.
pub const DEFAULT_HISTORY_LIMIT: usize = 50;
pub const MAX_HISTORY_LIMIT: usize = 200;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryResponse {
    pub version: u8,
    pub history_version: u8,
    #[serde(deserialize_with = "bounded_history")]
    pub events: Vec<HistoryEvent>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEvent {
    pub request_id: String,
    pub operation: String,
    #[serde(deserialize_with = "Option::deserialize")]
    pub at_unix_seconds: Option<u64>,
    pub ordinal: u32,
    pub outcome: ProviderHistoryOutcome,
}
fn bounded_history<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Vec<HistoryEvent>, D::Error> {
    struct Bounded;
    impl<'de> serde::de::Visitor<'de> for Bounded {
        type Value = Vec<HistoryEvent>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("at most 200 history events")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut events = Vec::new();
            while let Some(event) = seq.next_element()? {
                if events.len() == MAX_HISTORY_LIMIT {
                    return Err(serde::de::Error::custom("history limit"));
                }
                events.push(event);
            }
            Ok(events)
        }
    }
    de.deserialize_seq(Bounded)
}
impl HistoryEvent {
    fn key(&self) -> (Option<u64>, &str, u32) {
        (self.at_unix_seconds, &self.request_id, self.ordinal)
    }
    fn valid(&self) -> bool {
        valid_id(&self.request_id)
            && !self.operation.is_empty()
            && self.operation.len() <= 64
            && self.operation.bytes().enumerate().all(|(i, b)| {
                (i == 0 && b.is_ascii_lowercase())
                    || (i > 0
                        && (b.is_ascii_lowercase()
                            || b.is_ascii_digit()
                            || (b == b'-' && self.operation.as_bytes()[i - 1] != b'-')))
            })
            && !self.operation.ends_with('-')
            && (self.at_unix_seconds.is_some()
                || self.outcome == ProviderHistoryOutcome::LegacyUnknown)
    }
    pub fn projection(&self) -> ProviderHistoryEvent {
        ProviderHistoryEvent {
            request_id: self.request_id.clone(),
            operation: self.operation.clone(),
            at_unix_seconds: self.at_unix_seconds,
            ordinal: self.ordinal,
            outcome: self.outcome,
        }
    }
}
impl HistoryResponse {
    pub fn valid(&self, requested: usize) -> bool {
        self.version == 1
            && self.history_version == 1
            && (1..=MAX_HISTORY_LIMIT).contains(&requested)
            && self.events.len() <= requested
            && self.events.iter().all(HistoryEvent::valid)
            && self
                .events
                .windows(2)
                .all(|pair| pair[0].key() > pair[1].key())
            && self
                .events
                .iter()
                .map(|e| (&e.request_id, e.ordinal))
                .collect::<HashSet<_>>()
                .len()
                == self.events.len()
    }
}
