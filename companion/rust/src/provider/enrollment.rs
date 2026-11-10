//! Joining half of guided enrollment v1 (#59) for a companion over pinned
//! mTLS. Same construction as the provider's `access::enrollment::transcript`
//! (HKDF-SHA256 keys, HMAC-SHA256 proofs, SHA-256 transcript hash), pinned to
//! it byte for byte by `companion/fixtures/enrollment-v1.json`. No key
//! agreement: mTLS authenticates both peers; the secret binds human intent.
use super::approval_v2::{base64url, base64url_decode};
use super::protocol::{valid_hex, visible, ErrorCode, ErrorResponse, RESPONSE_LIMIT};
use crate::api::enrollment::{EnrolleeRole, JoinerCommand, JoinerEnd, JoinerPhase, JoinerSnapshot};
use crate::api::provider::ProviderWork;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"vaultwarden-access/enroll/v1\0";
const PREFIX: &str = "vwe1";
const VERSION: u8 = 1;
const MAX_LABEL: usize = 128;

fn field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend((value.len() as u32).to_be_bytes());
    out.extend(value);
}
fn key(secret: &[u8; 32], id: &[u8; 32], purpose: &str) -> Zeroizing<[u8; 32]> {
    let mut info = DOMAIN.to_vec();
    info.extend(purpose.as_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(Some(id), secret)
        .expand(&info, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}
fn hmac(secret: &[u8; 32], id: &[u8; 32], purpose: &str) -> Hmac<Sha256> {
    <Hmac<Sha256> as Mac>::new_from_slice(key(secret, id, purpose).as_ref())
        .expect("HMAC accepts any key length")
}
fn control_message(action: &str, hash: &[u8; 32]) -> Vec<u8> {
    let mut out = DOMAIN.to_vec();
    field(&mut out, action.as_bytes());
    field(&mut out, hash);
    out
}
fn comparison_code(secret: &[u8; 32], id: &[u8; 32], hash: &[u8; 32]) -> String {
    let mut info = DOMAIN.to_vec();
    info.extend(b"comparison-code");
    info.extend(id);
    let mut okm = Zeroizing::new([0u8; 8]);
    hkdf::Hkdf::<Sha256>::new(Some(hash), secret)
        .expand(&info, okm.as_mut())
        .expect("8 bytes is a valid HKDF-SHA256 output length");
    let value = u64::from_be_bytes(*okm) % 100_000_000;
    format!("{:04}-{:04}", value / 10_000, value % 10_000)
}
fn fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    base64url_decode(value)?.try_into().ok()
}
fn unhex32(value: &str) -> Option<[u8; 32]> {
    if !valid_hex(value) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in value.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}
/// The provider's own label rule: trimmed, 1–128 bytes, no control chars.
pub(crate) fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL
        && label.trim() == label
        && !label.chars().any(char::is_control)
}
/// Printable ASCII is shown as is; anything else in Rust-escaped quotes, so
/// look-alike or direction-changing characters cannot hide in a name.
pub(crate) fn display_label(label: &str) -> String {
    if label.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
        label.to_owned()
    } else {
        visible(label)
    }
}

#[derive(Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
enum Kind {
    Agent { label: String, uid: u32, gid: u32 },
    Companion { label: String },
}
#[derive(Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
enum Identity {
    Agent {
        #[allow(dead_code)]
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
        by: String,
    },
    Expired {},
    Aborted {
        reason: String,
    },
    Failed {
        reason: String,
    },
}
#[derive(Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
enum Reply {
    Joined {
        protocol_version: u8,
        invitation_id: String,
        kind: Kind,
        provider_nonce: String,
        provider_mac: String,
        expires_in_seconds: u64,
    },
    State {
        protocol_version: u8,
        invitation_id: String,
        state: State,
    },
    Rejected {
        protocol_version: u8,
        reason: String,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sent {
    Join,
    Status,
    Confirm,
    Decline,
    Cancel,
}

/// Secret material; wiped on drop (every final state drops it).
struct Live {
    id: [u8; 32],
    secret: Zeroizing<[u8; 32]>,
    join_bytes: Vec<u8>,
    join_request: Vec<u8>,
    /// Set once the provider's half verified.
    hash: Option<[u8; 32]>,
}
impl Live {
    fn id_text(&self) -> String {
        base64url(&self.id)
    }
    fn control(&self, action: &str, extra: Option<(&str, &str)>) -> Option<Vec<u8>> {
        let hash = self.hash?;
        let mut mac = hmac(&self.secret, &self.id, "control");
        mac.update(&control_message(action, &hash));
        let mut message = serde_json::json!({
            "purpose": match action {
                "confirm" => "enroll_confirm",
                "status" => "enroll_status",
                _ => "enroll_cancel",
            },
            "protocol_version": VERSION,
            "invitation_id": self.id_text(),
            "mac": base64url(&mac.finalize().into_bytes()),
        });
        if let Some((key, value)) = extra {
            message[key] = value.into();
        }
        Some(envelope(message))
    }
}
fn envelope(message: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"command":"enroll","version":1,"message":message}))
        .expect("enrollment request serialization")
}

#[derive(Default)]
pub struct JoinerSession {
    live: Option<Live>,
    phase: JoinerPhase,
    end: JoinerEnd,
    role: EnrolleeRole,
    label: String,
    code: String,
    deadline: Option<Instant>,
    provider_approved: bool,
    confirmed: bool,
    confirm_lost: bool,
    retryable: bool,
    invitation_id: String,
    enrolled_fingerprint: String,
    token: u32,
    pending: Option<(u32, Sent)>,
}

impl JoinerSession {
    pub fn snapshot(&self) -> JoinerSnapshot {
        JoinerSnapshot {
            phase: self.phase,
            busy: self.pending.is_some(),
            role: self.role,
            label: self.label.clone(),
            comparison_code: self.code.clone(),
            seconds_remaining: self
                .deadline
                .map_or(0, |d| d.saturating_duration_since(Instant::now()).as_secs()),
            provider_approved: self.provider_approved,
            confirmed: self.confirmed,
            end: self.end,
            retryable: self.retryable,
            invitation_id: self.invitation_id.clone(),
            enrolled_fingerprint: self.enrolled_fingerprint.clone(),
        }
    }

    pub fn reset(&mut self) {
        *self = Self {
            token: self.token,
            ..Self::default()
        };
    }

    fn work(&mut self, sent: Sent, body: Vec<u8>) -> ProviderWork {
        self.token = self.token.wrapping_add(1);
        self.pending = Some((self.token, sent));
        self.retryable = false;
        ProviderWork {
            token: self.token,
            body,
        }
    }

    /// Parse `vwe1.<id>.<secret>` and build the join. Nothing is kept on error.
    pub fn join(
        &mut self,
        invitation: &str,
        device_fingerprint: &str,
        provider_pin: &str,
        nonce: [u8; 32],
    ) -> Result<ProviderWork, &'static str> {
        if !matches!(
            self.phase,
            JoinerPhase::Idle | JoinerPhase::Ended | JoinerPhase::Enrolled
        ) || self.pending.is_some()
        {
            return Err("An enrollment is already in progress.");
        }
        let device = unhex32(device_fingerprint).ok_or("This client certificate is not usable.")?;
        let provider = unhex32(provider_pin).ok_or("The provider pin is not usable.")?;
        let mut parts = invitation.trim().split('.');
        let (Some(PREFIX), Some(id), Some(secret), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err("That is not an invitation code (vwe1.…).");
        };
        let id = fixed::<32>(id).ok_or("That is not an invitation code (vwe1.…).")?;
        let secret = Zeroizing::new(
            base64url_decode(secret)
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .ok_or("That is not an invitation code (vwe1.…).")?,
        );
        let mut join_bytes = DOMAIN.to_vec();
        field(&mut join_bytes, b"companion-mtls");
        field(&mut join_bytes, &id);
        field(&mut join_bytes, &device);
        field(&mut join_bytes, &nonce);
        field(&mut join_bytes, &provider);
        let mut mac = hmac(&secret, &id, "join");
        mac.update(&join_bytes);
        let join_request = envelope(serde_json::json!({
            "purpose": "enroll_join",
            "protocol_version": VERSION,
            "invitation_id": base64url(&id),
            "nonce": base64url(&nonce),
            "mac": base64url(&mac.finalize().into_bytes()),
        }));
        self.reset();
        self.invitation_id = base64url(&id);
        self.live = Some(Live {
            id,
            secret,
            join_bytes,
            join_request: join_request.clone(),
            hash: None,
        });
        self.phase = JoinerPhase::Joining;
        Ok(self.work(Sent::Join, join_request))
    }

    pub fn begin(&mut self, command: JoinerCommand) -> Result<ProviderWork, &'static str> {
        if self.pending.is_some() {
            return Err("Waiting for the provider.");
        }
        let live = self.live.as_ref().ok_or("No enrollment in progress.")?;
        let (sent, body) = match (command, self.phase) {
            (JoinerCommand::Retry, JoinerPhase::Joining) => (Sent::Join, live.join_request.clone()),
            (JoinerCommand::Status, JoinerPhase::Compare | JoinerPhase::Waiting) => {
                (Sent::Status, live.control("status", None))
                    .1
                    .map(|b| (Sent::Status, b))
                    .ok_or("No enrollment in progress.")?
            }
            (JoinerCommand::Confirm, JoinerPhase::Compare | JoinerPhase::Waiting) => live
                .control("confirm", None)
                .map(|b| (Sent::Confirm, b))
                .ok_or("No enrollment in progress.")?,
            (JoinerCommand::Decline, JoinerPhase::Compare | JoinerPhase::Waiting) => live
                .control("cancel/code_mismatch", Some(("reason", "code_mismatch")))
                .map(|b| (Sent::Decline, b))
                .ok_or("No enrollment in progress.")?,
            (JoinerCommand::Cancel, JoinerPhase::Compare | JoinerPhase::Waiting) => live
                .control("cancel/cancelled", Some(("reason", "cancelled")))
                .map(|b| (Sent::Cancel, b))
                .ok_or("No enrollment in progress.")?,
            _ => return Err("Not possible in this step."),
        };
        if sent == Sent::Confirm {
            self.confirmed = true;
            self.phase = JoinerPhase::Waiting;
        }
        Ok(self.work(sent, body))
    }

    fn end(&mut self, end: JoinerEnd) {
        self.live = None;
        self.code.clear();
        self.deadline = None;
        self.phase = JoinerPhase::Ended;
        self.end = end;
        self.retryable = false;
    }

    pub fn finish(&mut self, token: u32, response: &[u8]) {
        let Some((pending, sent)) = self.pending else {
            return;
        };
        if pending != token {
            return;
        }
        self.pending = None;
        if self.live.is_none() {
            return;
        }
        if response.is_empty() || response.len() > RESPONSE_LIMIT {
            return self.lost(sent);
        }
        if let Ok(reply) = serde_json::from_slice::<Reply>(response) {
            return self.reply(sent, reply);
        }
        match serde_json::from_slice::<ErrorResponse>(response) {
            Ok(ErrorResponse {
                version: 1,
                error: ErrorCode::Unavailable,
            }) => self.lost(sent),
            Ok(_) | Err(_) => self.end(JoinerEnd::Malformed),
        }
    }

    /// No reply (offline peer) or a transient refusal: nothing is decided.
    fn lost(&mut self, sent: Sent) {
        if sent == Sent::Confirm {
            self.confirm_lost = true;
        }
        self.retryable = true;
    }

    fn reply(&mut self, sent: Sent, reply: Reply) {
        let id = self.invitation_id.clone();
        match reply {
            Reply::Joined {
                protocol_version,
                invitation_id,
                kind,
                provider_nonce,
                provider_mac,
                expires_in_seconds,
            } => {
                if sent != Sent::Join || protocol_version != VERSION || invitation_id != id {
                    return self.end(JoinerEnd::Malformed);
                }
                self.joined(kind, &provider_nonce, &provider_mac, expires_in_seconds);
            }
            Reply::State {
                protocol_version,
                invitation_id,
                state,
            } => {
                if protocol_version != VERSION || invitation_id != id {
                    return self.end(JoinerEnd::Malformed);
                }
                self.state(sent, state);
            }
            Reply::Rejected {
                protocol_version,
                reason,
            } => {
                if protocol_version != VERSION {
                    return self.end(JoinerEnd::Malformed);
                }
                match reason.as_str() {
                    "busy" | "unavailable" => self.lost(sent),
                    "expired" => self.end(JoinerEnd::Expired),
                    "already_used" => self.end(JoinerEnd::AlreadyUsed),
                    "identity_refused" => self.end(JoinerEnd::IdentityRefused),
                    // After a lost confirmation, a forgotten session may
                    // have committed first: the outcome is not known.
                    "invalid_invitation" if self.confirm_lost => {
                        self.end(JoinerEnd::OutcomeUnknown)
                    }
                    "invalid_invitation" => self.end(JoinerEnd::InvalidInvitation),
                    _ => self.end(JoinerEnd::Malformed),
                }
            }
        }
    }

    fn joined(&mut self, kind: Kind, nonce: &str, tag: &str, expires: u64) {
        let (Some(live), Some(nonce), Some(tag)) =
            (self.live.as_mut(), fixed::<32>(nonce), fixed::<32>(tag))
        else {
            return self.end(JoinerEnd::Malformed);
        };
        let mut full = live.join_bytes.clone();
        let (role, label) = match &kind {
            Kind::Agent { label, uid, gid } => {
                field(&mut full, b"agent");
                field(&mut full, label.as_bytes());
                field(&mut full, &uid.to_be_bytes());
                field(&mut full, &gid.to_be_bytes());
                (EnrolleeRole::Agent, label)
            }
            Kind::Companion { label } => {
                field(&mut full, b"companion");
                field(&mut full, label.as_bytes());
                (EnrolleeRole::Companion, label)
            }
        };
        field(&mut full, &nonce);
        let mut mac = hmac(&live.secret, &live.id, "provider");
        mac.update(&full);
        if mac.verify_slice(&tag).is_err() {
            return self.end(JoinerEnd::ProviderNotAuthenticated);
        }
        // Only after the provider proved the secret does the role matter.
        if role != EnrolleeRole::Companion || !valid_label(label) || expires > 1800 {
            return self.end(JoinerEnd::WrongRole);
        }
        let hash: [u8; 32] = Sha256::digest(&full).into();
        live.hash = Some(hash);
        self.code = comparison_code(&live.secret, &live.id, &hash);
        self.label = display_label(label);
        self.role = role;
        self.deadline = Some(Instant::now() + Duration::from_secs(expires));
        self.phase = JoinerPhase::Compare;
    }

    fn state(&mut self, sent: Sent, state: State) {
        if sent == Sent::Join && self.live.as_ref().is_some_and(|l| l.hash.is_none()) {
            // A state before our verified half: only a final one is usable.
            if matches!(
                state,
                State::AwaitingJoin {} | State::AwaitingApprovals { .. }
            ) {
                return self.end(JoinerEnd::Malformed);
            }
        }
        self.confirm_lost = false;
        match state {
            State::AwaitingJoin {} => self.end(JoinerEnd::Malformed),
            State::AwaitingApprovals {
                provider_approved,
                joiner_confirmed,
            } => {
                self.provider_approved = provider_approved;
                if joiner_confirmed {
                    self.confirmed = true;
                    self.phase = JoinerPhase::Waiting;
                }
            }
            State::Enrolled {
                identity: Identity::Companion { fingerprint },
            } if valid_hex(&fingerprint) => {
                self.end(JoinerEnd::None);
                self.phase = JoinerPhase::Enrolled;
                self.enrolled_fingerprint = fingerprint;
            }
            State::Enrolled { .. } => self.end(JoinerEnd::Malformed),
            State::Cancelled { by } => self.end(match by.as_str() {
                "provider" => JoinerEnd::CancelledByProvider,
                "joiner" if sent == Sent::Decline => JoinerEnd::Declined,
                "joiner" => JoinerEnd::Cancelled,
                _ => JoinerEnd::Malformed,
            }),
            State::Expired {} => self.end(JoinerEnd::Expired),
            State::Aborted { reason } => self.end(match reason.as_str() {
                "code_mismatch" => JoinerEnd::CodeMismatch,
                "joiner_reported_mismatch" => JoinerEnd::Declined,
                "duplicate_join" => JoinerEnd::DuplicateJoin,
                "too_many_failures" => JoinerEnd::TooManyFailures,
                _ => JoinerEnd::Malformed,
            }),
            State::Failed { reason } => self.end(match reason.as_str() {
                "identity_refused" => JoinerEnd::IdentityRefused,
                "unavailable" => JoinerEnd::CommitUnavailable,
                _ => JoinerEnd::Malformed,
            }),
        }
    }
}
