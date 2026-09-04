//! Provider-owned, permission-checked lifecycle state.
//!
//! This deliberately small file adapter is a foundation, not the eventual
//! request database. It is the only writer for its JSON document and validates
//! the complete layout before every read and write.

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::{
    fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};
use std::path::{Path, PathBuf};

use super::provider::{ProviderDiagnostic, ProviderError};

const STATE_FILE: &str = "provider-state.json";
const STATE_SCHEMA_VERSION: u8 = 1;
const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

/// The redacted state stored by the provider. It intentionally contains no
/// session, backend, secret, command, or credential data.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderState {
    pub schema_version: u8,
    pub lifecycle_epoch: u64,
    pub pairings: Vec<String>,
    pub operations: Vec<String>,
    pub requests: Vec<RequestRecord>,
}

impl ProviderState {
    fn initial() -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            lifecycle_epoch: 0,
            pairings: Vec::new(),
            operations: Vec::new(),
            requests: Vec::new(),
        }
    }

    fn validate(&self) -> Result<(), ProviderError> {
        if self.schema_version != STATE_SCHEMA_VERSION {
            return Err(ProviderError::new(ProviderDiagnostic::InvalidState));
        }
        Ok(())
    }
}

/// A future request record can only survive a lifecycle boundary if it is
/// terminal. This type is public to allow future provider-owned application
/// code to use the same durable transition model.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestRecord {
    pub id: String,
    pub status: RequestLifecycleStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestLifecycleStatus {
    Pending,
    Approved,
    Running,
    Invalidated,
    Completed,
    Failed,
}

impl RequestLifecycleStatus {
    fn is_unexecuted(self) -> bool {
        matches!(self, Self::Pending | Self::Approved | Self::Running)
    }
}

/// A one-writer adapter for the provider's private state root.
#[derive(Debug)]
pub struct ProviderStore {
    root: PathBuf,
    owner_uid: u32,
    // Held for the store lifetime so a second provider process cannot become
    // a concurrent writer for this document.
    _state_lock: Option<File>,
}

impl ProviderStore {
    /// Open an initialized state root or create a complete new root beneath a
    /// safe, existing parent. Existing roots are never repaired.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, ProviderError> {
        Self::open_for_owner(root.into(), current_uid())
    }

    fn open_for_owner(root: PathBuf, owner_uid: u32) -> Result<Self, ProviderError> {
        let layout = Self {
            root,
            owner_uid,
            _state_lock: None,
        };
        if !layout.root.exists() {
            layout.create_initial_layout()?;
        }
        layout.validate_layout()?;
        let state_lock = open_existing(&layout.state_path(), true)?;
        validate_open_file(&state_lock, PRIVATE_FILE_MODE, layout.owner_uid)?;
        try_lock_exclusive(&state_lock)?;
        let store = Self {
            root: layout.root,
            owner_uid: layout.owner_uid,
            _state_lock: Some(state_lock),
        };
        store.read_state().map(|_| store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn read_state(&self) -> Result<ProviderState, ProviderError> {
        self.validate_layout()?;
        let mut file = open_existing(&self.state_path(), false)?;
        validate_open_file(&file, PRIVATE_FILE_MODE, self.owner_uid)?;
        let mut raw = String::new();
        file.read_to_string(&mut raw)
            .map_err(|_| ProviderError::new(ProviderDiagnostic::InvalidState))?;
        let state: ProviderState = serde_json::from_str(&raw)
            .map_err(|_| ProviderError::new(ProviderDiagnostic::InvalidState))?;
        state.validate()?;
        Ok(state)
    }

    /// Replace the complete state document after validating the existing
    /// trusted layout. The file descriptor is synced before success returns.
    pub fn write_state(&mut self, state: &ProviderState) -> Result<(), ProviderError> {
        state.validate()?;
        self.validate_layout()?;
        let encoded = serde_json::to_vec(state)
            .map_err(|_| ProviderError::new(ProviderDiagnostic::PersistenceFailure))?;
        let mut file = open_existing(&self.state_path(), true)?;
        validate_open_file(&file, PRIVATE_FILE_MODE, self.owner_uid)?;
        file.set_len(0)
            .map_err(|_| ProviderError::new(ProviderDiagnostic::PersistenceFailure))?;
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|_| ProviderError::new(ProviderDiagnostic::PersistenceFailure))?;
        Ok(())
    }

    /// Advance the epoch and invalidate every non-terminal request before an
    /// in-memory provider can be exposed.
    pub fn invalidate_unexecuted(&mut self) -> Result<ProviderState, ProviderError> {
        let mut state = self.read_state()?;
        state.lifecycle_epoch = state
            .lifecycle_epoch
            .checked_add(1)
            .ok_or_else(|| ProviderError::new(ProviderDiagnostic::PersistenceFailure))?;
        for request in &mut state.requests {
            if request.status.is_unexecuted() {
                request.status = RequestLifecycleStatus::Invalidated;
            }
        }
        self.write_state(&state)?;
        Ok(state)
    }

    fn state_path(&self) -> PathBuf {
        self.root.join(STATE_FILE)
    }

    fn create_initial_layout(&self) -> Result<(), ProviderError> {
        let parent = self
            .root
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| ProviderError::new(ProviderDiagnostic::UnsafeState))?;
        validate_dir(parent, self.owner_uid, false)?;
        fs::create_dir(&self.root)
            .map_err(|_| ProviderError::new(ProviderDiagnostic::UnsafeState))?;
        fs::set_permissions(&self.root, fs::Permissions::from_mode(PRIVATE_DIR_MODE))
            .map_err(|_| ProviderError::new(ProviderDiagnostic::PersistenceFailure))?;
        validate_dir(&self.root, self.owner_uid, true)?;

        let initial = serde_json::to_vec(&ProviderState::initial())
            .map_err(|_| ProviderError::new(ProviderDiagnostic::PersistenceFailure))?;
        let state_path = self.state_path();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&state_path)
            .map_err(|_| ProviderError::new(ProviderDiagnostic::PersistenceFailure))?;
        file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
            .map_err(|_| ProviderError::new(ProviderDiagnostic::PersistenceFailure))?;
        file.write_all(&initial)
            .and_then(|()| file.sync_all())
            .map_err(|_| ProviderError::new(ProviderDiagnostic::PersistenceFailure))?;
        Ok(())
    }

    fn validate_layout(&self) -> Result<(), ProviderError> {
        validate_dir(&self.root, self.owner_uid, true)?;
        validate_regular_file(&self.state_path(), PRIVATE_FILE_MODE, self.owner_uid)
    }
}

fn current_uid() -> u32 {
    // Linux-first provider storage has an explicit owner identity check.
    unsafe { libc::geteuid() }
}

fn try_lock_exclusive(file: &File) -> Result<(), ProviderError> {
    // `fs4` 1.1 does not expose advisory file locking. The provider is
    // Linux-first, so use the kernel's non-blocking advisory lock directly.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        Ok(())
    } else {
        Err(ProviderError::new(ProviderDiagnostic::PersistenceFailure))
    }
}

fn validate_dir(
    path: &Path,
    owner_uid: u32,
    exact_private_mode: bool,
) -> Result<(), ProviderError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ProviderError::new(ProviderDiagnostic::UnsafeState))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != owner_uid {
        return Err(ProviderError::new(ProviderDiagnostic::UnsafeState));
    }
    let mode = metadata.mode() & 0o777;
    let acceptable = if exact_private_mode {
        mode == PRIVATE_DIR_MODE
    } else {
        mode & 0o022 == 0
    };
    if !acceptable {
        return Err(ProviderError::new(ProviderDiagnostic::UnsafeState));
    }
    Ok(())
}

fn validate_regular_file(
    path: &Path,
    required_mode: u32,
    owner_uid: u32,
) -> Result<(), ProviderError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ProviderError::new(ProviderDiagnostic::InvalidState))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != required_mode
    {
        return Err(ProviderError::new(ProviderDiagnostic::UnsafeState));
    }
    Ok(())
}

fn open_existing(path: &Path, write: bool) -> Result<File, ProviderError> {
    let mut options = OpenOptions::new();
    options
        .read(!write)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW);
    options.open(path).map_err(|_| {
        ProviderError::new(if write {
            ProviderDiagnostic::PersistenceFailure
        } else {
            ProviderDiagnostic::InvalidState
        })
    })
}

fn validate_open_file(
    file: &File,
    required_mode: u32,
    owner_uid: u32,
) -> Result<(), ProviderError> {
    let metadata = file
        .metadata()
        .map_err(|_| ProviderError::new(ProviderDiagnostic::PersistenceFailure))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != required_mode
    {
        return Err(ProviderError::new(ProviderDiagnostic::UnsafeState));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::tempdir;

    fn assert_diagnostic<T: std::fmt::Debug>(
        result: Result<T, ProviderError>,
        expected: ProviderDiagnostic,
    ) {
        assert_eq!(result.unwrap_err().diagnostic(), expected);
    }

    #[test]
    fn rejects_an_unsupported_state_schema_before_exposing_provider_state() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("provider");
        let store = ProviderStore::open(&root).unwrap();
        let mut state = store.read_state().unwrap();
        state.schema_version = STATE_SCHEMA_VERSION + 1;
        let state_path = store.state_path();
        drop(store);

        fs::write(state_path, serde_json::to_vec(&state).unwrap()).unwrap();
        assert_diagnostic(ProviderStore::open(root), ProviderDiagnostic::InvalidState);
    }

    #[test]
    fn rejects_a_second_provider_writer() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("provider");
        let _first = ProviderStore::open(&root).unwrap();

        assert_diagnostic(
            ProviderStore::open(root),
            ProviderDiagnostic::PersistenceFailure,
        );
    }

    #[test]
    fn directory_validator_rejects_each_unsafe_root_condition() {
        let temp = tempdir().unwrap();
        let owner_uid = current_uid();
        let real_dir = temp.path().join("real");
        fs::create_dir(&real_dir).unwrap();
        fs::set_permissions(&real_dir, fs::Permissions::from_mode(PRIVATE_DIR_MODE)).unwrap();
        let symlink_dir = temp.path().join("symlink");
        symlink(&real_dir, &symlink_dir).unwrap();
        let regular_file = temp.path().join("file");
        fs::write(&regular_file, b"not a directory").unwrap();
        fs::set_permissions(&regular_file, fs::Permissions::from_mode(PRIVATE_DIR_MODE)).unwrap();

        assert_diagnostic(
            validate_dir(&symlink_dir, owner_uid, true),
            ProviderDiagnostic::UnsafeState,
        );
        assert_diagnostic(
            validate_dir(&regular_file, owner_uid, true),
            ProviderDiagnostic::UnsafeState,
        );
        assert_diagnostic(
            validate_dir(&real_dir, owner_uid.wrapping_add(1), true),
            ProviderDiagnostic::UnsafeState,
        );
    }

    #[test]
    fn regular_file_validator_rejects_each_unsafe_state_condition() {
        let temp = tempdir().unwrap();
        let owner_uid = current_uid();
        let safe_file = temp.path().join("safe-state");
        fs::write(&safe_file, b"{}").unwrap();
        fs::set_permissions(&safe_file, fs::Permissions::from_mode(PRIVATE_FILE_MODE)).unwrap();
        let symlink_file = temp.path().join("symlink-state");
        symlink(&safe_file, &symlink_file).unwrap();
        let directory = temp.path().join("state-directory");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(PRIVATE_FILE_MODE)).unwrap();

        assert_diagnostic(
            validate_regular_file(&symlink_file, PRIVATE_FILE_MODE, owner_uid),
            ProviderDiagnostic::UnsafeState,
        );
        assert_diagnostic(
            validate_regular_file(&directory, PRIVATE_FILE_MODE, owner_uid),
            ProviderDiagnostic::UnsafeState,
        );
        assert_diagnostic(
            validate_regular_file(&safe_file, PRIVATE_FILE_MODE, owner_uid.wrapping_add(1)),
            ProviderDiagnostic::UnsafeState,
        );
        fs::set_permissions(&safe_file, fs::Permissions::from_mode(0o640)).unwrap();
        assert_diagnostic(
            validate_regular_file(&safe_file, PRIVATE_FILE_MODE, owner_uid),
            ProviderDiagnostic::UnsafeState,
        );
    }

    #[test]
    fn open_file_validator_rejects_unsafe_descriptors() {
        let temp = tempdir().unwrap();
        let owner_uid = current_uid();
        let state_path = temp.path().join("state");
        fs::write(&state_path, b"{}").unwrap();
        fs::set_permissions(&state_path, fs::Permissions::from_mode(PRIVATE_FILE_MODE)).unwrap();
        let file = File::open(&state_path).unwrap();

        assert_diagnostic(
            validate_open_file(&file, PRIVATE_FILE_MODE, owner_uid.wrapping_add(1)),
            ProviderDiagnostic::UnsafeState,
        );
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_diagnostic(
            validate_open_file(&file, PRIVATE_FILE_MODE, owner_uid),
            ProviderDiagnostic::UnsafeState,
        );

        let directory = File::open(temp.path()).unwrap();
        assert_diagnostic(
            validate_open_file(&directory, PRIVATE_FILE_MODE, owner_uid),
            ProviderDiagnostic::UnsafeState,
        );
    }

    #[test]
    fn rejects_wrong_owner_without_deserializing_state() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("provider");
        let store = ProviderStore::open(&root).unwrap();
        let other_uid = current_uid().wrapping_add(1);
        let result = ProviderStore::open_for_owner(root, other_uid);
        assert_eq!(
            result.unwrap_err().diagnostic(),
            ProviderDiagnostic::UnsafeState
        );
        drop(store);
    }
}
