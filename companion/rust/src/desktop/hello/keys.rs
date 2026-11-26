//! The `approvalKey` channel contract (`docs/mobile-clients.md` section 2) for
//! the Windows Hello key: read, create, delete, sign and cancel, with the
//! macOS/Android admission gate (one signature at a time, strictly
//! increasing tokens per session). The authenticator is a trait so the
//! contract runs in tests with a software key; Windows supplies WebAuthn.
use super::admit::{admits, Binding, Purpose};
use super::attested;
use crate::desktop::identity::{hex, unhex};
use crate::provider::{approval_v2 as v2, key_class};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

/// `KeyOutcome` names (Dart `approval_key.dart`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Present,
    Absent,
    Created,
    Deleted,
    Signed,
    Invalidated,
    Cancelled,
    Unavailable,
    Refused,
    Failed,
    Unsafe,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub outcome: Outcome,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    /// Only with `Signed`: the 37-byte authenticator data of the assertion.
    pub authenticator_data: Vec<u8>,
}
impl Reply {
    fn of(outcome: Outcome) -> Self {
        Self::with_key(outcome, Vec::new())
    }
    fn with_key(outcome: Outcome, public_key: Vec<u8>) -> Self {
        Self {
            outcome,
            public_key,
            signature: Vec::new(),
            authenticator_data: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Cancelled,
    /// The credential no longer exists (Windows Hello was reset).
    NotFound,
    Unavailable,
    Failed,
}
pub type CancelId = [u8; 16];
pub trait Authenticator: Send + Sync {
    /// A user-verifying platform authenticator is available now.
    fn available(&self) -> bool;
    /// MakeCredential for `user`; the created credential's authenticator data.
    fn create(&self, user: &[u8; 32]) -> Result<Vec<u8>, Failure>;
    /// GetAssertion with `credential` over `client_data`: (authenticator data, DER signature).
    fn assert(
        &self,
        credential: &[u8],
        client_data: &[u8],
        cancel: Option<CancelId>,
    ) -> Result<(Vec<u8>, Vec<u8>), Failure>;
    fn cancellation(&self) -> Option<CancelId>;
    fn cancel(&self, id: CancelId);
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    credential: String,
    public_key: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    version: u8,
    keys: BTreeMap<String, Entry>,
}

#[derive(Default)]
struct Gate {
    session: String,
    last: u32,
    active: Option<(String, u32, Option<CancelId>)>,
}

pub struct Keys<A: Authenticator> {
    authenticator: A,
    directory: PathBuf,
    gate: Mutex<Gate>,
}
const FILE: &str = "approval-keys-v1.json";
/// (credential id, 65-byte public key).
type Stored = (Vec<u8>, Vec<u8>);

impl<A: Authenticator> Keys<A> {
    pub fn new(authenticator: A, directory: PathBuf) -> Self {
        Self {
            authenticator,
            directory,
            gate: Mutex::new(Gate::default()),
        }
    }
    pub fn available(&self) -> bool {
        self.authenticator.available()
    }
    fn idle(&self) -> bool {
        self.gate.lock().is_ok_and(|g| g.active.is_none())
    }
    fn load(&self) -> Option<File> {
        let path = self.directory.join(FILE);
        match std::fs::read(&path) {
            Ok(bytes) if bytes.len() <= 65_536 => {
                let file: File = serde_json::from_slice(&bytes).ok()?;
                (file.version == 1).then_some(file)
            }
            Ok(_) => None,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(File {
                version: 1,
                keys: BTreeMap::new(),
            }),
            Err(_) => None,
        }
    }
    fn save(&self, file: &File) -> bool {
        serde_json::to_vec(file).is_ok_and(|bytes| {
            crate::desktop::store::write_private(
                &self.directory,
                &self.directory.join(FILE),
                &bytes,
            )
            .is_ok()
        })
    }
    /// The stored (credential id, public key) for `binding`.
    fn entry(&self, binding: &Binding) -> Result<Option<Stored>, Outcome> {
        let file = self.load().ok_or(Outcome::Failed)?;
        let Some(entry) = file.keys.get(&binding.alias()) else {
            return Ok(None);
        };
        let pair = unhex(&entry.credential).zip(unhex(&entry.public_key));
        match pair {
            Some((id, key)) if !id.is_empty() && v2::valid_public_key(&key) => Ok(Some((id, key))),
            _ => Err(Outcome::Unsafe),
        }
    }
    pub fn read(&self, binding: &Binding) -> Reply {
        if !self.idle() {
            return Reply::of(Outcome::Failed);
        }
        match self.entry(binding) {
            Ok(Some((_, key))) => Reply::with_key(Outcome::Present, key),
            Ok(None) => Reply::of(Outcome::Absent),
            Err(outcome) => Reply::of(outcome),
        }
    }
    pub fn create(&self, binding: &Binding) -> Reply {
        if !self.idle() {
            return Reply::of(Outcome::Failed);
        }
        match self.entry(binding) {
            Ok(None) => {}
            Ok(Some(_)) => return Reply::of(Outcome::Refused),
            Err(outcome) => return Reply::of(outcome),
        }
        if !self.authenticator.available() {
            return Reply::of(Outcome::Unavailable);
        }
        let user = v2::hex32(&binding.alias()).unwrap_or([0; 32]);
        let data = match self.authenticator.create(&user) {
            Ok(data) => data,
            Err(failure) => return Reply::of(outcome_of(failure)),
        };
        let Some(credential) = attested::parse(&data) else {
            return Reply::of(Outcome::Unsafe);
        };
        let Some(mut file) = self.load() else {
            return Reply::of(Outcome::Failed);
        };
        file.keys.insert(
            binding.alias(),
            Entry {
                credential: hex(&credential.id),
                public_key: hex(&credential.public_key),
            },
        );
        if !self.save(&file) {
            return Reply::of(Outcome::Failed);
        }
        Reply::with_key(Outcome::Created, credential.public_key)
    }
    /// Forgets the credential for this binding. Windows Hello keeps the
    /// platform credential itself until the user removes it in Settings
    /// (spec D-6); it is never used again by this app.
    pub fn delete(&self, binding: &Binding) -> Reply {
        if !self.idle() {
            return Reply::of(Outcome::Failed);
        }
        let Some(mut file) = self.load() else {
            return Reply::of(Outcome::Failed);
        };
        if file.keys.remove(&binding.alias()).is_some() && !self.save(&file) {
            return Reply::of(Outcome::Failed);
        }
        Reply::of(Outcome::Deleted)
    }
    pub fn sign(
        &self,
        binding: &Binding,
        session: &str,
        token: u32,
        purpose: Purpose,
        transcript: &[u8],
    ) -> Reply {
        let (credential, key) = match self.entry(binding) {
            Ok(Some(pair)) => pair,
            Ok(None) => return Reply::of(Outcome::Absent),
            Err(outcome) => return Reply::of(outcome),
        };
        if !admits(transcript, purpose, binding, &key) {
            return Reply::of(Outcome::Refused);
        }
        if !self.authenticator.available() {
            return Reply::of(Outcome::Unavailable);
        }
        let cancel = self.authenticator.cancellation();
        if !self.begin(session, token, cancel) {
            return Reply::of(Outcome::Failed);
        }
        let result =
            self.authenticator
                .assert(&credential, &key_class::client_data(transcript), cancel);
        self.finish(session, token);
        let (data, signature) = match result {
            Ok(pair) => pair,
            Err(failure) => return Reply::of(outcome_of(failure)),
        };
        if !key_class::valid_authenticator_data(&data) {
            return Reply::of(Outcome::Unsafe);
        }
        let verified = key_class::signed_message(transcript, &data)
            .is_some_and(|message| v2::verify(&key, &message, &signature));
        if !verified {
            return Reply::of(Outcome::Failed);
        }
        Reply {
            outcome: Outcome::Signed,
            public_key: key,
            signature,
            authenticator_data: data,
        }
    }
    fn begin(&self, session: &str, token: u32, cancel: Option<CancelId>) -> bool {
        let Ok(mut gate) = self.gate.lock() else {
            return false;
        };
        if gate.active.is_some() || !crate::desktop::rules::valid_hex(session, 32) || token == 0 {
            return false;
        }
        if gate.session != session {
            gate.session = session.into();
            gate.last = 0;
        }
        if token <= gate.last {
            return false;
        }
        gate.last = token;
        gate.active = Some((session.into(), token, cancel));
        true
    }
    fn finish(&self, session: &str, token: u32) {
        if let Ok(mut gate) = self.gate.lock() {
            if gate
                .active
                .as_ref()
                .is_some_and(|(s, t, _)| s == session && *t == token)
            {
                gate.active = None;
            }
        }
    }
    /// Cancels only the open signature of this session and token.
    pub fn cancel(&self, session: &str, token: u32) {
        let id = self.gate.lock().ok().and_then(|gate| match &gate.active {
            Some((s, t, id)) if s == session && *t == token => *id,
            _ => None,
        });
        if let Some(id) = id {
            self.authenticator.cancel(id);
        }
    }
}
fn outcome_of(failure: Failure) -> Outcome {
    match failure {
        Failure::Cancelled => Outcome::Cancelled,
        Failure::NotFound => Outcome::Invalidated,
        Failure::Unavailable => Outcome::Unavailable,
        Failure::Failed => Outcome::Failed,
    }
}

#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;
