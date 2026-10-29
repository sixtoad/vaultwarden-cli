use crate::lifecycle::Core;
use std::sync::{Mutex, OnceLock};
pub mod installation;
pub mod provider;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Create,
    Reopen,
    Delete,
    Sign,
    NoInteraction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ready,
    Created,
    Reopened,
    Deleted,
    Verified,
    InteractionRequired,
    Cancelled,
    Expired,
    Unavailable,
    MissingKey,
    Failed,
    Unsafe,
    Rejected,
    Busy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalidation {
    Cancel,
    Selection,
    Sleep,
    Close,
}

/// Only these two built-in requests exist. There is no provider or arbitrary payload API.
#[derive(Clone, Debug)]
pub struct Fixture {
    pub id: u32,
    pub title: String,
    pub detail: String,
}

#[derive(Clone, Debug)]
pub struct Work {
    pub token: u32,
    pub epoch: u32,
    pub operation: Operation,
    pub fixture: u32,
    pub expires_unix_ms: u64,
    pub nonce: Vec<u8>,
    pub key_id: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Completion {
    pub outcome: Outcome,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub fixture: Fixture,
    pub busy: bool,
    pub has_key: bool,
    pub key_fingerprint: String,
    pub unsafe_observed: bool,
    pub can_sign: bool,
    pub verified: u32,
    pub blocked_without_interaction: u32,
    pub outcome: Outcome,
}

fn core() -> &'static Mutex<Core> {
    static CORE: OnceLock<Mutex<Core>> = OnceLock::new();
    CORE.get_or_init(|| Mutex::new(Core::default()))
}

#[flutter_rust_bridge::frb(sync)]
pub fn snapshot() -> Snapshot {
    core().lock().expect("core mutex poisoned").snapshot()
}

#[flutter_rust_bridge::frb(sync)]
pub fn select_fixture(id: u32) -> Result<Snapshot, String> {
    let mut core = core().lock().map_err(|_| "core unavailable")?;
    core.select(id)?;
    Ok(core.snapshot())
}

#[flutter_rust_bridge::frb(sync)]
pub fn begin(operation: Operation) -> Result<Work, String> {
    core()
        .lock()
        .map_err(|_| "core unavailable")?
        .begin(operation)
}

#[flutter_rust_bridge::frb(sync)]
pub fn invalidate(reason: Invalidation) -> Snapshot {
    let mut core = core().lock().expect("core mutex poisoned");
    core.invalidate(reason);
    core.snapshot()
}

#[flutter_rust_bridge::frb(sync)]
pub fn finish(token: u32, epoch: u32, completion: Completion) -> Snapshot {
    let mut core = core().lock().expect("core mutex poisoned");
    core.finish(token, epoch, completion);
    core.snapshot()
}
