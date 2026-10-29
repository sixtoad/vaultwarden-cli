//! Administrator-installed immutable service identity. No environment fallback.
use super::platform;
use crate::access::ports::ExecutionError;
use serde::Deserialize;
use std::{io::Read, os::unix::fs::MetadataExt, path::Path};
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identities {
    pub provider_uid: u32,
    pub provider_uuid: String,
    pub operator_uid: u32,
    pub operator_uuid: String,
    pub human_gid: u32,
    pub agent_gid: u32,
    pub human_socket_dir: std::path::PathBuf,
    pub ssh_runtime_dir: std::path::PathBuf,
}
unsafe extern "C" {
    fn mbr_uid_to_uuid(uid: libc::uid_t, uuid: *mut u8) -> libc::c_int;
}
#[cfg(test)]
thread_local! {pub(crate) static TEST_ACCOUNT_UUID: std::cell::RefCell<Option<(u32, Option<String>)>>=const{std::cell::RefCell::new(None)};}
pub(crate) fn uuid(uid: u32) -> Result<String, ExecutionError> {
    #[cfg(test)]
    if let Some((_, value)) = TEST_ACCOUNT_UUID
        .with(|value| value.borrow().clone())
        .filter(|(id, _)| *id == uid)
    {
        return value.ok_or(ExecutionError::Unavailable);
    }
    let mut account: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0u8; 65536];
    if unsafe {
        libc::getpwuid_r(
            uid,
            &mut account,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    } != 0
        || result.is_null()
        || account.pw_uid != uid
    {
        return Err(ExecutionError::Unavailable);
    }
    let mut value = [0u8; 16];
    if unsafe { mbr_uid_to_uuid(uid, value.as_mut_ptr()) } != 0 {
        return Err(ExecutionError::Unavailable);
    }
    Ok(value.iter().map(|b| format!("{b:02x}")).collect())
}
#[cfg(test)]
thread_local! {pub(crate) static TEST_IDENTITIES: std::cell::RefCell<Option<Identities>>=const{std::cell::RefCell::new(None)};}
pub(crate) fn load() -> Result<Identities, ExecutionError> {
    #[cfg(test)]
    if let Some(value) = TEST_IDENTITIES.with(|value| value.borrow().clone()) {
        return Ok(value);
    }
    let file = platform::open_no_writers(
        Path::new("/Library/VaultwardenAccess/native-identities.json"),
        true,
    )?;
    let m = file
        .metadata()
        .map_err(|_error| ExecutionError::UnsafePath)?;
    if !m.is_file() || m.nlink() != 1 || m.len() > 4096 {
        return Err(ExecutionError::UnsafePath);
    }
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_error| ExecutionError::UnsafePath)?;
    let value: Identities =
        serde_json::from_slice(&bytes).map_err(|_error| ExecutionError::UnsafePath)?;
    if value.provider_uid == 0
        || value.operator_uid == 0
        || value.provider_uid == value.operator_uid
        || value.human_gid == 0
        || value.agent_gid == 0
        || value.human_gid == value.agent_gid
        || uuid(value.provider_uid)? != value.provider_uuid
        || uuid(value.operator_uid)? != value.operator_uuid
        || !value.human_socket_dir.is_absolute()
        || !value.ssh_runtime_dir.is_absolute()
    {
        return Err(ExecutionError::UnsafePath);
    }
    Ok(value)
}
