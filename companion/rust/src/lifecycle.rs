use crate::api::{Completion, Fixture, Invalidation, Operation, Outcome, Snapshot, Work};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const DOMAIN: &[u8] = b"dev.vaultwarden.companion.synthetic.v1";
const REVIEW_TTL: Duration = Duration::from_secs(55);

pub fn fixture(id: u32) -> Option<Fixture> {
    let (title, detail) = match id {
        1 => (
            "Synthetic request one",
            "Demonstrate a local signature only. No vault, provider or execution.",
        ),
        2 => (
            "Synthetic request two",
            "Demonstrate another fresh signature only. No vault, provider or execution.",
        ),
        _ => return None,
    };
    Some(Fixture {
        id,
        title: title.into(),
        detail: detail.into(),
    })
}

/// Every field is u32-BE length + bytes, in the order below. Integers use fixed
/// big-endian widths inside their field. This is a synthetic protocol, not v2.
pub fn transcript(work: &Work) -> Result<Vec<u8>, String> {
    let fixture = fixture(work.fixture).ok_or("unknown fixture")?;
    if work.nonce.len() != 32 || work.key_id.len() != 32 {
        return Err("invalid binding".into());
    }
    let mut out = Vec::with_capacity(384);
    let fields: [&[u8]; 10] = [
        DOMAIN,
        b"sign",
        &work.fixture.to_be_bytes(),
        fixture.title.as_bytes(),
        fixture.detail.as_bytes(),
        &work.epoch.to_be_bytes(),
        &work.token.to_be_bytes(),
        &work.expires_unix_ms.to_be_bytes(),
        &work.nonce,
        &work.key_id,
    ];
    for field in fields {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    Ok(out)
}

struct Active {
    work: Work,
    invalidated: bool,
    deadline: Instant,
    transcript: Vec<u8>,
}

pub struct Core {
    selected: u32,
    epoch: u32,
    next_token: u32,
    reviewed: Option<(Instant, u64)>,
    key: Option<Vec<u8>>,
    active: Option<Active>,
    verified: u32,
    blocked: u32,
    unsafe_observed: bool,
    outcome: Outcome,
}

impl Default for Core {
    fn default() -> Self {
        Self {
            selected: 1,
            epoch: 0,
            next_token: 0,
            reviewed: None,
            key: None,
            active: None,
            verified: 0,
            blocked: 0,
            unsafe_observed: false,
            outcome: Outcome::Ready,
        }
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(u64::MAX)
}

impl Core {
    pub fn select(&mut self, id: u32) -> Result<(), String> {
        if fixture(id).is_none() {
            return Err("unknown fixture".into());
        }
        self.invalidate(Invalidation::Selection);
        self.selected = id;
        self.reviewed = Some((
            Instant::now() + REVIEW_TTL,
            unix_ms().saturating_add(55_000),
        ));
        self.outcome = Outcome::Ready;
        Ok(())
    }

    pub fn snapshot(&self) -> Snapshot {
        let fresh = !self.unsafe_observed
            && self
                .reviewed
                .is_some_and(|(deadline, wall)| Instant::now() < deadline && unix_ms() < wall);
        Snapshot {
            fixture: fixture(self.selected).expect("selected fixture"),
            busy: self.active.is_some(),
            has_key: self.key.is_some(),
            key_fingerprint: self
                .key
                .as_ref()
                .map(|key| {
                    Sha256::digest(key)
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect()
                })
                .unwrap_or_default(),
            unsafe_observed: self.unsafe_observed,
            can_sign: self.active.is_none() && self.key.is_some() && fresh,
            verified: self.verified,
            blocked_without_interaction: self.blocked,
            outcome: self.outcome,
        }
    }

    pub fn begin(&mut self, operation: Operation) -> Result<Work, String> {
        if self.active.is_some() {
            return Err("native worker still active".into());
        }
        let signing = matches!(operation, Operation::Sign | Operation::NoInteraction);
        if signing && !self.snapshot().can_sign {
            return Err("fresh review and retained key required".into());
        }
        if operation == Operation::Create && self.key.is_some() {
            return Err("delete the existing test key explicitly".into());
        }
        self.next_token = self
            .next_token
            .checked_add(1)
            .ok_or("attempt limit reached")?;
        let mut nonce = vec![0; 32];
        getrandom::fill(&mut nonce).map_err(|_| "random source unavailable")?;
        let (deadline, wall) = if signing {
            self.reviewed.take().ok_or("review required")?
        } else {
            (
                Instant::now() + REVIEW_TTL,
                unix_ms().saturating_add(55_000),
            )
        };
        let work = Work {
            token: self.next_token,
            epoch: self.epoch,
            operation,
            fixture: self.selected,
            expires_unix_ms: wall,
            nonce,
            key_id: self
                .key
                .as_ref()
                .map(|k| Sha256::digest(k).to_vec())
                .unwrap_or(vec![0; 32]),
        };
        let bytes = transcript(&work)?;
        self.active = Some(Active {
            work: work.clone(),
            invalidated: false,
            deadline,
            transcript: bytes,
        });
        Ok(work)
    }

    pub fn invalidate(&mut self, _reason: Invalidation) {
        self.reviewed = None;
        // Never wrap into an old epoch. The monotonic token also cannot wrap.
        self.epoch = self.epoch.saturating_add(1);
        if let Some(active) = &mut self.active {
            active.invalidated = true;
        }
        self.outcome = Outcome::Cancelled;
    }

    pub fn finish(&mut self, token: u32, epoch: u32, completion: Completion) {
        // A forged/stale callback cannot release another worker's admission slot.
        if !self
            .active
            .as_ref()
            .is_some_and(|a| a.work.token == token && a.work.epoch == epoch)
        {
            return;
        }
        let active = self.active.take().expect("matched active worker");
        self.outcome = self.complete(active, completion);
        self.unsafe_observed |= self.outcome == Outcome::Unsafe;
    }

    fn complete(&mut self, active: Active, completion: Completion) -> Outcome {
        let operation = active.work.operation;
        if completion.outcome == Outcome::Unsafe {
            return Outcome::Unsafe;
        }
        // Signing without interaction is unsafe even if cancelled, expired, or
        // malformed; it must never disappear as a benign late callback.
        if operation == Operation::NoInteraction && !completion.signature.is_empty() {
            return Outcome::Unsafe;
        }
        if completion.signature.len() > 72 || completion.public_key.len() > 65 {
            return Outcome::Rejected;
        }
        if operation == Operation::Delete
            && matches!(completion.outcome, Outcome::Deleted | Outcome::MissingKey)
        {
            self.key = None;
            self.verified = 0;
            self.blocked = 0;
            self.reviewed = None;
            return Outcome::Deleted;
        }
        if matches!(
            (operation, completion.outcome),
            (Operation::Create, Outcome::Created) | (Operation::Reopen, Outcome::Reopened)
        ) {
            if completion.public_key.len() != 65
                || completion.public_key.first() != Some(&4)
                || VerifyingKey::from_sec1_bytes(&completion.public_key).is_err()
            {
                return Outcome::Rejected;
            }
            if self
                .key
                .as_ref()
                .is_some_and(|key| key != &completion.public_key)
            {
                return Outcome::Rejected;
            }
            // Preserve a completed create even after cancellation. Reopen can
            // only retain the same identity; a cancelled reopen grants nothing.
            if operation == Operation::Reopen && active.invalidated {
                return Outcome::Cancelled;
            }
            self.key = Some(completion.public_key);
            if operation == Operation::Create {
                self.verified = 0;
                self.blocked = 0;
            }
            return completion.outcome;
        }
        if active.invalidated || active.work.epoch != self.epoch {
            return Outcome::Cancelled;
        }
        if Instant::now() >= active.deadline || unix_ms() >= active.work.expires_unix_ms {
            return Outcome::Expired;
        }
        match (operation, completion.outcome) {
            (Operation::Sign, Outcome::Verified) => {
                // No completion-supplied key or authenticated boolean is trusted.
                if !completion.public_key.is_empty() {
                    return Outcome::Rejected;
                }
                let Some(key) = self
                    .key
                    .as_ref()
                    .and_then(|k| VerifyingKey::from_sec1_bytes(k).ok())
                else {
                    return Outcome::Rejected;
                };
                let Ok(signature) = Signature::from_der(&completion.signature) else {
                    return Outcome::Rejected;
                };
                if key.verify(&active.transcript, &signature).is_err() {
                    return Outcome::Rejected;
                }
                self.verified = self.verified.saturating_add(1);
                Outcome::Verified
            }
            (Operation::NoInteraction, Outcome::InteractionRequired) => {
                self.blocked = self.blocked.saturating_add(1);
                Outcome::InteractionRequired
            }
            (
                _,
                Outcome::Cancelled | Outcome::Unavailable | Outcome::MissingKey | Outcome::Failed,
            ) => completion.outcome,
            _ => Outcome::Rejected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};

    #[test]
    fn expiry_checks_both_monotonic_and_wall_deadlines() {
        for monotonic in [true, false] {
            let mut core = Core::default();
            let key = SigningKey::from_slice(&[1; 32]).unwrap();
            core.key = Some(
                key.verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
            );
            core.select(1).unwrap();
            let work = core.begin(Operation::Sign).unwrap();
            let signature: Signature = key.sign(&transcript(&work).unwrap());
            let active = core.active.as_mut().unwrap();
            if monotonic {
                active.deadline = Instant::now();
            } else {
                active.work.expires_unix_ms = 0;
            }
            core.finish(
                work.token,
                work.epoch,
                Completion {
                    outcome: Outcome::Verified,
                    public_key: vec![],
                    signature: signature.to_der().as_bytes().to_vec(),
                },
            );
            assert_eq!(core.snapshot().outcome, Outcome::Expired);
            assert_eq!(core.snapshot().verified, 0);
        }
    }
}
