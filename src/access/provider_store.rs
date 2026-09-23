//! Hardened, provider-owned state persistence.
//!
//! The lock file has a stable inode for its full lifetime. State is written to
//! a private new file, synced, atomically renamed, then the directory is
//! synced, so a failed replacement cannot advance in-memory authority.

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::{
    fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};
use std::path::{Path, PathBuf};

use super::policy::{ApprovedImage, OperationPolicy};
use super::provider::{ProviderDiagnostic, ProviderError};

const STATE_FILE: &str = "provider-state.json";
const LOCK_FILE: &str = ".provider-state.lock";
const TEMP_FILE: &str = ".provider-state.json.new";
const STATE_SCHEMA_VERSION: u8 = 1;
const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderState {
    pub(crate) schema_version: u8,
    pub(crate) lifecycle_epoch: u64,
    pub(crate) pairings: Vec<String>,
    #[serde(default)]
    pub(crate) approved_images: Vec<ApprovedImage>,
    pub(crate) operations: Vec<OperationPolicy>,
    pub(crate) requests: Vec<RequestRecord>,
}

impl ProviderState {
    fn initial() -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            lifecycle_epoch: 0,
            pairings: Vec::new(),
            approved_images: Vec::new(),
            operations: Vec::new(),
            requests: Vec::new(),
        }
    }
    pub(crate) fn validate(&self) -> Result<(), ProviderError> {
        if self.schema_version != STATE_SCHEMA_VERSION {
            return Err(error(ProviderDiagnostic::InvalidState));
        }
        let mut image_ids: Vec<&str> = self.approved_images.iter().map(ApprovedImage::id).collect();
        image_ids.sort_unstable();
        if image_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(error(ProviderDiagnostic::InvalidState));
        }
        for image in &self.approved_images {
            image
                .validate_integrity()
                .map_err(|_| error(ProviderDiagnostic::InvalidState))?;
        }
        let mut operation_ids: Vec<&str> =
            self.operations.iter().map(OperationPolicy::id).collect();
        operation_ids.sort_unstable();
        if operation_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(error(ProviderDiagnostic::InvalidState));
        }
        for policy in &self.operations {
            policy
                .validate_integrity()
                .map_err(|_| error(ProviderDiagnostic::InvalidState))?;
            let Some(image) = self
                .approved_images
                .iter()
                .find(|image| image.id() == policy.image_id())
            else {
                return Err(error(ProviderDiagnostic::InvalidState));
            };
            if !policy.image_matches(image) {
                return Err(error(ProviderDiagnostic::InvalidState));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestRecord {
    pub(crate) id: String,
    pub(crate) status: RequestLifecycleStatus,
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RequestLifecycleStatus {
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

#[derive(Debug)]
pub(crate) struct ProviderStore {
    root: PathBuf,
    owner_uid: u32,
    poisoned: bool,
    _writer_lock: File,
}

impl ProviderStore {
    pub(crate) fn open(root: impl Into<PathBuf>) -> Result<Self, ProviderError> {
        Self::open_for_owner(root.into(), current_uid())
    }
    fn open_for_owner(root: PathBuf, owner_uid: u32) -> Result<Self, ProviderError> {
        if !root.exists() {
            create_initial_layout(&root, owner_uid)?;
        }
        validate_layout(&root, owner_uid)?;
        let lock = open_existing(&root.join(LOCK_FILE), true)?;
        validate_open_file(&lock, PRIVATE_FILE_MODE, owner_uid)?;
        try_lock_exclusive(&lock)?;
        let store = Self {
            root,
            owner_uid,
            poisoned: false,
            _writer_lock: lock,
        };
        store.read_state().map(|_| store)
    }
    pub(crate) fn read_state(&self) -> Result<ProviderState, ProviderError> {
        self.ensure_healthy()?;
        validate_layout(&self.root, self.owner_uid)?;
        let mut file = open_existing(&self.state_path(), false)?;
        validate_open_file(&file, PRIVATE_FILE_MODE, self.owner_uid)?;
        let mut raw = String::new();
        file.read_to_string(&mut raw)
            .map_err(|_| error(ProviderDiagnostic::InvalidState))?;
        let state: ProviderState =
            serde_json::from_str(&raw).map_err(|_| error(ProviderDiagnostic::InvalidState))?;
        state.validate()?;
        Ok(state)
    }
    pub(crate) fn write_state(&mut self, state: &ProviderState) -> Result<(), ProviderError> {
        self.ensure_healthy()?;
        state.validate()?;
        validate_layout(&self.root, self.owner_uid)?;
        let encoded =
            serde_json::to_vec(state).map_err(|_| error(ProviderDiagnostic::PersistenceFailure))?;
        let temporary = self.temp_path();
        remove_stale_private_temp(&temporary, self.owner_uid)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|_| error(ProviderDiagnostic::PersistenceFailure))?;
        if file
            .set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
            .and_then(|()| file.write_all(&encoded))
            .and_then(|()| file.sync_all())
            .is_err()
        {
            let _ = fs::remove_file(&temporary);
            return Err(error(ProviderDiagnostic::PersistenceFailure));
        }
        if let Err(err) = validate_open_file(&file, PRIVATE_FILE_MODE, self.owner_uid) {
            let _ = fs::remove_file(&temporary);
            return Err(err);
        }
        fs::rename(&temporary, self.state_path())
            .map_err(|_| error(ProviderDiagnostic::PersistenceFailure))?;
        if sync_directory(&self.root).is_err() {
            self.poisoned = true;
            return Err(error(ProviderDiagnostic::PersistenceFailure));
        }
        Ok(())
    }
    pub(crate) fn invalidate_unexecuted(&mut self) -> Result<ProviderState, ProviderError> {
        let mut state = self.read_state()?;
        state.lifecycle_epoch = state
            .lifecycle_epoch
            .checked_add(1)
            .ok_or_else(|| error(ProviderDiagnostic::PersistenceFailure))?;
        for request in &mut state.requests {
            if request.status.is_unexecuted() {
                request.status = RequestLifecycleStatus::Invalidated;
            }
        }
        self.write_state(&state)?;
        Ok(state)
    }
    pub(crate) fn upsert_operation(
        &mut self,
        state: &ProviderState,
        operation: OperationPolicy,
    ) -> Result<ProviderState, ProviderError> {
        state.validate()?;
        let mut updated = state.clone();
        if let Some(existing) = updated
            .operations
            .iter_mut()
            .find(|existing| existing.id() == operation.id())
        {
            *existing = operation;
        } else {
            updated.operations.push(operation);
        }
        updated.validate()?;
        self.write_state(&updated)?;
        Ok(updated)
    }
    fn state_path(&self) -> PathBuf {
        self.root.join(STATE_FILE)
    }
    fn temp_path(&self) -> PathBuf {
        self.root.join(TEMP_FILE)
    }
    #[cfg(test)]
    pub(crate) fn poison_for_test(&mut self) {
        self.poisoned = true;
    }
    fn ensure_healthy(&self) -> Result<(), ProviderError> {
        if self.poisoned {
            Err(error(ProviderDiagnostic::UnsafeState))
        } else {
            Ok(())
        }
    }
}

fn error(diagnostic: ProviderDiagnostic) -> ProviderError {
    ProviderError::new(diagnostic)
}
fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}
fn try_lock_exclusive(file: &File) -> Result<(), ProviderError> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(())
    } else {
        Err(error(ProviderDiagnostic::PersistenceFailure))
    }
}
fn create_initial_layout(root: &Path, owner_uid: u32) -> Result<(), ProviderError> {
    let parent = root
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| error(ProviderDiagnostic::UnsafeState))?;
    validate_dir(parent, owner_uid, false)?;
    fs::create_dir(root).map_err(|_| error(ProviderDiagnostic::UnsafeState))?;
    fs::set_permissions(root, fs::Permissions::from_mode(PRIVATE_DIR_MODE))
        .map_err(|_| error(ProviderDiagnostic::PersistenceFailure))?;
    validate_dir(root, owner_uid, true)?;
    let lock_path = root.join(LOCK_FILE);
    let lock = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
        .map_err(|_| error(ProviderDiagnostic::PersistenceFailure))?;
    lock.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .and_then(|()| lock.sync_all())
        .map_err(|_| error(ProviderDiagnostic::PersistenceFailure))?;
    write_initial_state(root, owner_uid)
}
fn write_initial_state(root: &Path, owner_uid: u32) -> Result<(), ProviderError> {
    let state = ProviderState::initial();
    let encoded =
        serde_json::to_vec(&state).map_err(|_| error(ProviderDiagnostic::PersistenceFailure))?;
    let temporary = root.join(TEMP_FILE);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|_| error(ProviderDiagnostic::PersistenceFailure))?;
    file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .and_then(|()| file.write_all(&encoded))
        .and_then(|()| file.sync_all())
        .map_err(|_| error(ProviderDiagnostic::PersistenceFailure))?;
    validate_open_file(&file, PRIVATE_FILE_MODE, owner_uid)?;
    fs::rename(&temporary, root.join(STATE_FILE))
        .map_err(|_| error(ProviderDiagnostic::PersistenceFailure))?;
    sync_directory(root)
}
fn sync_directory(root: &Path) -> Result<(), ProviderError> {
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| error(ProviderDiagnostic::PersistenceFailure))
}
fn remove_stale_private_temp(path: &Path, owner_uid: u32) -> Result<(), ProviderError> {
    if path.exists() {
        validate_regular_file(path, PRIVATE_FILE_MODE, owner_uid)?;
        fs::remove_file(path).map_err(|_| error(ProviderDiagnostic::PersistenceFailure))?;
    }
    Ok(())
}
fn validate_layout(root: &Path, owner_uid: u32) -> Result<(), ProviderError> {
    validate_dir(root, owner_uid, true)?;
    validate_regular_file(&root.join(STATE_FILE), PRIVATE_FILE_MODE, owner_uid)?;
    validate_regular_file(&root.join(LOCK_FILE), PRIVATE_FILE_MODE, owner_uid)
}
fn validate_dir(
    path: &Path,
    owner_uid: u32,
    exact_private_mode: bool,
) -> Result<(), ProviderError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| error(ProviderDiagnostic::UnsafeState))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_uid
        || if exact_private_mode {
            metadata.mode() & 0o777 != PRIVATE_DIR_MODE
        } else {
            metadata.mode() & 0o022 != 0
        }
    {
        Err(error(ProviderDiagnostic::UnsafeState))
    } else {
        Ok(())
    }
}
fn validate_regular_file(path: &Path, mode: u32, owner_uid: u32) -> Result<(), ProviderError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| error(ProviderDiagnostic::InvalidState))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != mode
    {
        Err(error(ProviderDiagnostic::UnsafeState))
    } else {
        Ok(())
    }
}
fn open_existing(path: &Path, write: bool) -> Result<File, ProviderError> {
    let mut options = OpenOptions::new();
    options
        .read(!write)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW);
    options.open(path).map_err(|_| {
        error(if write {
            ProviderDiagnostic::PersistenceFailure
        } else {
            ProviderDiagnostic::InvalidState
        })
    })
}
fn validate_open_file(file: &File, mode: u32, owner_uid: u32) -> Result<(), ProviderError> {
    let metadata = file
        .metadata()
        .map_err(|_| error(ProviderDiagnostic::PersistenceFailure))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != mode
    {
        Err(error(ProviderDiagnostic::UnsafeState))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::policy::{
        ApprovedImage, ArgumentSpec, CredentialUse, LoginCredentialDraft, LoginField,
        LoginFieldMapping, OperationPolicyDraft, test_approved_image,
    };
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn temp() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }
    fn operation(image: &ApprovedImage, target: &str) -> OperationPolicy {
        OperationPolicy::from_draft(
            OperationPolicyDraft {
                id: "deploy-homelab".into(),
                description: "Deploy homelab".into(),
                image_id: image.id().into(),
                targets: vec![target.into()],
                arguments: vec![ArgumentSpec::Target],
                credentials: vec![LoginCredentialDraft {
                    item_id: "11111111-1111-1111-1111-111111111111".into(),
                    label: "deployment login".into(),
                    use_type: CredentialUse::Login,
                    field_mappings: vec![LoginFieldMapping {
                        field: LoginField::Password,
                        environment: "DEPLOY_PASSWORD".into(),
                    }],
                }],
            },
            image,
        )
        .unwrap()
    }
    #[test]
    fn state_and_stable_lock_are_private() {
        let temp = temp();
        let root = temp.path().join("provider");
        let _store = ProviderStore::open(&root).unwrap();
        assert_eq!(
            fs::metadata(root.join(LOCK_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            PRIVATE_FILE_MODE
        );
        assert_eq!(
            fs::metadata(root.join(STATE_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            PRIVATE_FILE_MODE
        );
    }
    #[test]
    fn empty_legacy_v1_state_loads_with_an_empty_image_registry() {
        let temp = temp();
        let root = temp.path().join("provider");
        let store = ProviderStore::open(&root).unwrap();
        drop(store);
        fs::write(
            root.join(STATE_FILE),
            br#"{"schema_version":1,"lifecycle_epoch":0,"pairings":[],"operations":[],"requests":[]}"#,
        )
        .unwrap();
        fs::set_permissions(
            root.join(STATE_FILE),
            fs::Permissions::from_mode(PRIVATE_FILE_MODE),
        )
        .unwrap();
        assert!(ProviderStore::open(&root).is_ok());
    }
    #[test]
    fn replacement_preserves_a_complete_state_and_lock_excludes_second_writer() {
        let temp = temp();
        let root = temp.path().join("provider");
        let mut store = ProviderStore::open(&root).unwrap();
        let mut state = store.read_state().unwrap();
        state.lifecycle_epoch = 9;
        store.write_state(&state).unwrap();
        assert_eq!(store.read_state().unwrap().lifecycle_epoch, 9);
        assert_eq!(
            ProviderStore::open(&root).unwrap_err().diagnostic(),
            ProviderDiagnostic::PersistenceFailure
        );
    }
    #[test]
    fn symlinked_lock_or_state_fails_closed() {
        let temp = temp();
        let root = temp.path().join("provider");
        let store = ProviderStore::open(&root).unwrap();
        drop(store);
        let outside = temp.path().join("outside");
        fs::write(&outside, b"x").unwrap();
        fs::remove_file(root.join(LOCK_FILE)).unwrap();
        symlink(&outside, root.join(LOCK_FILE)).unwrap();
        assert_eq!(
            ProviderStore::open(&root).unwrap_err().diagnostic(),
            ProviderDiagnostic::UnsafeState
        );
    }

    #[test]
    fn state_validation_rejects_bad_versions_duplicate_ids_and_unbound_operations() {
        let temp = temp();
        let image = test_approved_image(temp.path(), "deploy-image");
        let policy = operation(&image, "staging");

        let mut invalid = ProviderState::initial();
        invalid.schema_version = STATE_SCHEMA_VERSION + 1;
        assert_eq!(
            invalid.validate().unwrap_err().diagnostic(),
            ProviderDiagnostic::InvalidState
        );

        let mut invalid = ProviderState::initial();
        invalid.approved_images = vec![image.clone(), image.clone()];
        assert_eq!(
            invalid.validate().unwrap_err().diagnostic(),
            ProviderDiagnostic::InvalidState
        );

        let mut invalid = ProviderState::initial();
        invalid.approved_images.push(image.clone());
        invalid.operations = vec![policy.clone(), policy];
        assert_eq!(
            invalid.validate().unwrap_err().diagnostic(),
            ProviderDiagnostic::InvalidState
        );

        let mut invalid = ProviderState::initial();
        invalid.operations.push(operation(&image, "staging"));
        assert_eq!(
            invalid.validate().unwrap_err().diagnostic(),
            ProviderDiagnostic::InvalidState
        );
    }

    #[test]
    fn invalidation_changes_only_unexecuted_request_lifecycle_states() {
        let temp = temp();
        let root = temp.path().join("provider");
        let mut store = ProviderStore::open(&root).unwrap();
        let mut state = store.read_state().unwrap();
        state.requests = vec![
            RequestRecord {
                id: "pending".into(),
                status: RequestLifecycleStatus::Pending,
            },
            RequestRecord {
                id: "approved".into(),
                status: RequestLifecycleStatus::Approved,
            },
            RequestRecord {
                id: "running".into(),
                status: RequestLifecycleStatus::Running,
            },
            RequestRecord {
                id: "invalidated".into(),
                status: RequestLifecycleStatus::Invalidated,
            },
            RequestRecord {
                id: "completed".into(),
                status: RequestLifecycleStatus::Completed,
            },
            RequestRecord {
                id: "failed".into(),
                status: RequestLifecycleStatus::Failed,
            },
        ];
        store.write_state(&state).unwrap();

        let updated = store.invalidate_unexecuted().unwrap();
        assert_eq!(updated.lifecycle_epoch, 1);
        assert_eq!(
            updated
                .requests
                .iter()
                .map(|request| request.status)
                .collect::<Vec<_>>(),
            vec![
                RequestLifecycleStatus::Invalidated,
                RequestLifecycleStatus::Invalidated,
                RequestLifecycleStatus::Invalidated,
                RequestLifecycleStatus::Invalidated,
                RequestLifecycleStatus::Completed,
                RequestLifecycleStatus::Failed,
            ]
        );
    }

    #[test]
    fn upsert_replaces_only_the_matching_operation_id() {
        let temp = temp();
        let root = temp.path().join("provider");
        let mut store = ProviderStore::open(&root).unwrap();
        let image = test_approved_image(temp.path(), "deploy-image");
        let mut state = store.read_state().unwrap();
        state.approved_images.push(image.clone());
        store.write_state(&state).unwrap();

        let first = operation(&image, "staging");
        let state = store.upsert_operation(&state, first.clone()).unwrap();
        let replacement = operation(&image, "production");
        let updated = store.upsert_operation(&state, replacement.clone()).unwrap();
        assert_eq!(updated.operations, vec![replacement]);
        assert_ne!(updated.operations[0].revision(), first.revision());
        assert_eq!(store.read_state().unwrap(), updated);
    }

    #[test]
    fn persistence_helpers_fail_closed_for_invalid_sync_or_stale_temp() {
        let temp = temp();
        assert_eq!(
            sync_directory(&temp.path().join("missing"))
                .unwrap_err()
                .diagnostic(),
            ProviderDiagnostic::PersistenceFailure
        );

        let stale = temp.path().join(TEMP_FILE);
        fs::write(&stale, b"old state").unwrap();
        fs::set_permissions(&stale, fs::Permissions::from_mode(PRIVATE_FILE_MODE)).unwrap();
        remove_stale_private_temp(&stale, current_uid()).unwrap();
        assert!(!stale.exists());

        let outside = temp.path().join("outside");
        fs::write(&outside, b"outside").unwrap();
        symlink(&outside, &stale).unwrap();
        assert_eq!(
            remove_stale_private_temp(&stale, current_uid())
                .unwrap_err()
                .diagnostic(),
            ProviderDiagnostic::UnsafeState
        );
    }

    #[test]
    fn post_rename_durability_failure_poisoning_blocks_stale_state_use() {
        let temp = temp();
        let root = temp.path().join("provider");
        let mut store = ProviderStore::open(&root).unwrap();
        store.poison_for_test();
        assert_eq!(
            store.read_state().unwrap_err().diagnostic(),
            ProviderDiagnostic::UnsafeState
        );
        assert_eq!(
            store
                .write_state(&ProviderState::initial())
                .unwrap_err()
                .diagnostic(),
            ProviderDiagnostic::UnsafeState
        );
    }

    #[test]
    fn directory_and_file_validation_reject_every_unsafe_shape() {
        let temp = temp();
        let directory = temp.path().join("directory");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(PRIVATE_DIR_MODE)).unwrap();
        let regular = temp.path().join("regular");
        fs::write(&regular, b"state").unwrap();
        fs::set_permissions(&regular, fs::Permissions::from_mode(PRIVATE_DIR_MODE)).unwrap();
        let link = temp.path().join("link");
        symlink(&regular, &link).unwrap();

        for (path, exact_private_mode) in [(&regular, true), (&link, true), (&directory, true)] {
            assert!(validate_dir(path, current_uid() + 1, exact_private_mode).is_err());
        }
        assert!(validate_dir(&regular, current_uid(), true).is_err());
        assert!(validate_dir(&link, current_uid(), true).is_err());
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_dir(&directory, current_uid(), true).is_err());
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(validate_dir(&directory, current_uid(), false).is_err());

        assert!(validate_regular_file(&link, PRIVATE_FILE_MODE, current_uid()).is_err());
        fs::set_permissions(&regular, fs::Permissions::from_mode(PRIVATE_FILE_MODE)).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(PRIVATE_FILE_MODE)).unwrap();
        assert!(validate_regular_file(&directory, PRIVATE_FILE_MODE, current_uid()).is_err());
        assert!(validate_regular_file(&regular, PRIVATE_FILE_MODE, current_uid() + 1).is_err());
        fs::set_permissions(&regular, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate_regular_file(&regular, PRIVATE_FILE_MODE, current_uid()).is_err());
    }

    #[test]
    fn opened_handles_are_revalidated_as_regular_private_owner_files() {
        let temp = temp();
        let regular = temp.path().join("regular");
        fs::write(&regular, b"state").unwrap();
        fs::set_permissions(&regular, fs::Permissions::from_mode(PRIVATE_FILE_MODE)).unwrap();
        let file = File::open(&regular).unwrap();
        assert!(validate_open_file(&file, PRIVATE_FILE_MODE, current_uid() + 1).is_err());
        fs::set_permissions(&regular, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate_open_file(&file, PRIVATE_FILE_MODE, current_uid()).is_err());

        let directory = File::open(temp.path()).unwrap();
        assert!(validate_open_file(&directory, PRIVATE_FILE_MODE, current_uid()).is_err());
    }
}
