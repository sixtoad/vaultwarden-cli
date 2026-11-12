//! File-backed provider secret store for the native macOS provider.
//!
//! The installed provider runs as a hidden service account (home `/var/empty`)
//! without a login session or default Keychain, so the OS keyring store cannot
//! hold its bootstrap client secret or revocable session. This store keeps those
//! two records in `<state root>/secrets/`, next to the provider's TLS key, under
//! the same trust: provider-owned `0700` directories, provider-owned `0600`
//! single-link regular files, no-follow descriptor-relative access, atomic
//! replacement and `fsync`. Root can read it, as root could read a System
//! keychain. It implements the `keyring-core` store API, so callers keep the
//! keyring semantics: an absent record is `NoEntry`; anything unsafe or
//! unreadable is an error and fails closed. It is installed only by the native
//! macOS provider and compiled only on macOS; Linux keeps the Secret Service store.
use keyring_core::{
    Credential, Entry, Error, Result,
    api::{CredentialApi, CredentialPersistence, CredentialStoreApi},
};
use std::{
    collections::HashMap,
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        io::{AsRawFd, FromRawFd},
    },
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

/// Directory, inside the provider state root, that holds the secret records.
pub const SECRETS_DIRECTORY: &str = "secrets";
/// Upper bound for one record; the session record is a few hundred bytes.
const MAX_SECRET_BYTES: usize = 64 * 1024;

/// A `keyring-core` store rooted at an existing, provider-owned `0700` state root.
#[derive(Debug, Clone)]
pub struct ProviderSecretFileStore {
    state_root: PathBuf,
}

impl ProviderSecretFileStore {
    /// The state root must be absolute; it is validated on every operation, not here.
    pub fn new(state_root: &Path) -> Result<Self> {
        if !state_root.is_absolute() {
            return Err(Error::Invalid(
                "state_root".into(),
                "must be an absolute path".into(),
            ));
        }
        Ok(Self {
            state_root: state_root.to_path_buf(),
        })
    }

    /// Make this store the process default, so every provider keyring entry uses it.
    pub fn install_default(state_root: &Path) -> Result<()> {
        keyring_core::set_default_store(Arc::new(Self::new(state_root)?));
        Ok(())
    }

    /// Path of the record for `service`/`account`, for diagnostics and documentation.
    pub fn record_path(&self, service: &str, account: &str) -> Result<PathBuf> {
        Ok(self
            .state_root
            .join(SECRETS_DIRECTORY)
            .join(record_name(service, account)?))
    }
}

/// `<service>.<account>`, restricted to a conservative character set.
fn record_name(service: &str, account: &str) -> Result<String> {
    let valid = |value: &str| {
        !value.is_empty()
            && value.len() <= 64
            && !value.starts_with('.')
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if !valid(service) || !valid(account) {
        return Err(Error::Invalid(
            "service/account".into(),
            "only [A-Za-z0-9_-]{1,64} names are stored".into(),
        ));
    }
    Ok(format!("{service}.{account}"))
}

fn unsafe_state(what: &str) -> Error {
    Error::NoStorageAccess(format!("unsafe provider secret store: {what}").into())
}
fn io_failure(what: &str, error: &std::io::Error) -> Error {
    Error::PlatformFailure(format!("provider secret store {what}: {error}").into())
}
fn last_os_error() -> std::io::Error {
    std::io::Error::last_os_error()
}
fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

fn no_acl_grants(file: &File) -> Result<()> {
    crate::adapters::native::platform::no_acl(file).map_err(|_error| unsafe_state("ACL grant"))
}

/// Remedy for a directory the running user does not own (typically root or the operator).
const RUN_AS_PROVIDER: &str =
    "run as the provider account (with the installer defaults: `sudo -u _vwaccess`)";

fn private_directory(file: &File, what: &str) -> Result<()> {
    no_acl_grants(file)?;
    let metadata = file
        .metadata()
        .map_err(|error| io_failure("metadata", &error))?;
    if !metadata.is_dir() {
        return Err(unsafe_state(&format!("{what} is not a directory")));
    }
    if metadata.uid() != euid() {
        return Err(unsafe_state(&format!(
            "{what} not owned by the running user; {RUN_AS_PROVIDER}"
        )));
    }
    if metadata.mode() & 0o7777 != 0o700 {
        return Err(unsafe_state(&format!("{what} must be mode 0700")));
    }
    Ok(())
}

/// Explain why the state root failed the ancestry check, without weakening it:
/// this only runs after the check refused, and only chooses the message.
fn state_root_refusal(state_root: &Path) -> Error {
    match open_at(
        None,
        std::os::unix::ffi::OsStrExt::as_bytes(state_root.as_os_str()),
        libc::O_RDONLY | libc::O_DIRECTORY,
    ) {
        Err(error) if error.raw_os_error() == Some(libc::EACCES) => unsafe_state(&format!(
            "state directory not accessible to the running user; {RUN_AS_PROVIDER}"
        )),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
            unsafe_state("state directory does not exist")
        }
        Ok(file) if file.metadata().is_ok_and(|m| m.uid() != euid()) => unsafe_state(&format!(
            "state directory not owned by the running user; {RUN_AS_PROVIDER}"
        )),
        _ => unsafe_state(
            "state directory or an ancestor is a symlink, carries an ACL grant or is writable by another account",
        ),
    }
}

/// Crash leftovers of `write`: `.<record>.<24 lowercase hex>.tmp`, exactly.
fn is_temporary_name(name: &[u8]) -> bool {
    let Some(inner) = name
        .strip_prefix(b".")
        .and_then(|rest| rest.strip_suffix(b".tmp"))
    else {
        return false;
    };
    let Some(split) = inner.iter().rposition(|b| *b == b'.') else {
        return false;
    };
    let (record, random) = (&inner[..split], &inner[split + 1..]);
    let Some(dot) = record.iter().position(|b| *b == b'.') else {
        return false;
    };
    let (service, account) = (
        std::str::from_utf8(&record[..dot]),
        std::str::from_utf8(&record[dot + 1..]),
    );
    random.len() == 24
        && random
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        && matches!((service, account), (Ok(service), Ok(account)) if record_name(service, account).is_ok())
}

/// A temporary younger than this may belong to a concurrent writer.
const STALE_TEMPORARY_SECONDS: i64 = 60;

/// Best effort: remove crash-leftover temporaries that match the exact name
/// pattern and are euid-owned, single-link, `0600` regular files older than a
/// minute. Never follows links; anything else is left untouched.
fn sweep_stale_temporaries(directory: &File) {
    let names = {
        let fd = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            return;
        }
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            unsafe { libc::close(fd) };
            return;
        }
        unsafe { libc::rewinddir(stream) };
        let mut names = Vec::new();
        loop {
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                break;
            }
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            if is_temporary_name(name.to_bytes()) {
                names.push(name.to_owned());
            }
        }
        unsafe { libc::closedir(stream) };
        names
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        });
    for name in names {
        let Ok(Some(stat)) = stat_at(directory, &name) else {
            continue;
        };
        if private_stat(&stat).is_ok() && now - stat.st_mtime >= STALE_TEMPORARY_SECONDS {
            unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
        }
    }
}

fn private_record(metadata: &std::fs::Metadata) -> Result<()> {
    if !metadata.file_type().is_file()
        || metadata.uid() != euid()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(unsafe_state(
            "record must be a provider-owned single-link 0600 regular file",
        ));
    }
    Ok(())
}

fn c_name(name: &str) -> Result<CString> {
    CString::new(name).map_err(|_error| Error::Invalid("name".into(), "contains NUL".into()))
}

fn open_at(parent: Option<&File>, path: &[u8], flags: libc::c_int) -> std::io::Result<File> {
    let path = CString::new(path)
        .map_err(|_error| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let flags = flags | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = unsafe {
        match parent {
            Some(parent) => libc::openat(parent.as_raw_fd(), path.as_ptr(), flags),
            None => libc::open(path.as_ptr(), flags),
        }
    };
    if fd < 0 {
        Err(last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

/// `lstat` of one name inside `parent`; `None` when it does not exist.
fn stat_at(parent: &File, name: &CString) -> Result<Option<libc::stat>> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(Some(stat));
    }
    let error = last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(None)
    } else {
        Err(io_failure("stat", &error))
    }
}

fn private_stat(stat: &libc::stat) -> Result<()> {
    if (u32::from(stat.st_mode) & u32::from(libc::S_IFMT)) != u32::from(libc::S_IFREG)
        || stat.st_uid != euid()
        || u32::from(stat.st_mode) & 0o7777 != 0o600
        || u64::from(stat.st_nlink) != 1
    {
        return Err(unsafe_state(
            "record must be a provider-owned single-link 0600 regular file",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct SecretRecord {
    state_root: PathBuf,
    service: String,
    account: String,
    name: String,
}

impl SecretRecord {
    /// Open and validate the state root. On macOS the whole ancestry must have
    /// no untrusted writers, as the provider state store requires.
    fn root(&self) -> Result<File> {
        let root = crate::adapters::native::platform::open_no_writers(&self.state_root, false)
            .map_err(|_error| state_root_refusal(&self.state_root))?;
        private_directory(&root, "state directory")?;
        Ok(root)
    }

    /// The secrets directory; `None` when absent and `create` is false.
    fn directory(&self, create: bool) -> Result<Option<(File, File)>> {
        let root = self.root()?;
        let name = c_name(SECRETS_DIRECTORY)?;
        if create && unsafe { libc::mkdirat(root.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            let error = last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(io_failure("create directory", &error));
            }
        } else if create {
            // The new entry must survive a crash before any record is renamed into it.
            root.sync_all()
                .map_err(|error| io_failure("sync state root", &error))?;
        }
        match open_at(
            Some(&root),
            SECRETS_DIRECTORY.as_bytes(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        ) {
            Ok(directory) => {
                private_directory(&directory, "secrets directory")?;
                sweep_stale_temporaries(&directory);
                Ok(Some((root, directory)))
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) && !create => Ok(None),
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                Err(unsafe_state("secrets directory is a symlink"))
            }
            Err(error) => Err(io_failure("open directory", &error)),
        }
    }

    fn read(&self) -> Result<Zeroizing<Vec<u8>>> {
        let Some((_root, directory)) = self.directory(false)? else {
            return Err(Error::NoEntry);
        };
        let mut file = match open_at(
            Some(&directory),
            self.name.as_bytes(),
            libc::O_RDONLY | libc::O_NONBLOCK,
        ) {
            Ok(file) => file,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Err(Error::NoEntry),
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                return Err(unsafe_state("record is a symlink"));
            }
            Err(error) => return Err(io_failure("open record", &error)),
        };
        no_acl_grants(&file)?;
        let metadata = file
            .metadata()
            .map_err(|error| io_failure("metadata", &error))?;
        private_record(&metadata)?;
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file)
            .take(MAX_SECRET_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io_failure("read record", &error))?;
        if bytes.len() > MAX_SECRET_BYTES {
            return Err(Error::TooLong(self.name.clone(), MAX_SECRET_BYTES as u32));
        }
        Ok(bytes)
    }

    fn write(&self, secret: &[u8]) -> Result<()> {
        if secret.len() > MAX_SECRET_BYTES {
            return Err(Error::TooLong(self.name.clone(), MAX_SECRET_BYTES as u32));
        }
        let Some((_root, directory)) = self.directory(true)? else {
            return Err(unsafe_state("secrets directory missing"));
        };
        let target = c_name(&self.name)?;
        // Never replace something that is not one of our own records.
        if let Some(existing) = stat_at(&directory, &target)? {
            private_stat(&existing)?;
        }
        let mut random = [0u8; 12];
        getrandom::fill(&mut random)
            .map_err(|error| Error::PlatformFailure(format!("random: {error}").into()))?;
        let temporary_name = format!(
            ".{}.{}.tmp",
            self.name,
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let temporary = c_name(&temporary_name)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io_failure("create record", &last_os_error()));
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let written = (|| {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|error| io_failure("chmod record", &error))?;
            private_record(
                &file
                    .metadata()
                    .map_err(|error| io_failure("metadata", &error))?,
            )?;
            no_acl_grants(&file)?;
            file.write_all(secret)
                .map_err(|error| io_failure("write record", &error))?;
            file.sync_all()
                .map_err(|error| io_failure("sync record", &error))?;
            if unsafe {
                libc::renameat(
                    directory.as_raw_fd(),
                    temporary.as_ptr(),
                    directory.as_raw_fd(),
                    target.as_ptr(),
                )
            } != 0
            {
                return Err(io_failure("replace record", &last_os_error()));
            }
            Ok(())
        })();
        if written.is_err() {
            unsafe { libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0) };
            return written;
        }
        directory
            .sync_all()
            .map_err(|error| io_failure("sync directory", &error))
    }

    fn delete(&self) -> Result<()> {
        let Some((_root, directory)) = self.directory(false)? else {
            return Err(Error::NoEntry);
        };
        let target = c_name(&self.name)?;
        let Some(existing) = stat_at(&directory, &target)? else {
            return Err(Error::NoEntry);
        };
        private_stat(&existing)?;
        if unsafe { libc::unlinkat(directory.as_raw_fd(), target.as_ptr(), 0) } != 0 {
            let error = last_os_error();
            return if error.raw_os_error() == Some(libc::ENOENT) {
                Err(Error::NoEntry)
            } else {
                Err(io_failure("delete record", &error))
            };
        }
        directory
            .sync_all()
            .map_err(|error| io_failure("sync directory", &error))
    }
}

impl CredentialApi for SecretRecord {
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        self.write(secret)
    }
    fn get_secret(&self) -> Result<Vec<u8>> {
        // keyring-core returns an owned Vec; our buffer is zeroized on drop.
        self.read().map(|bytes| bytes.to_vec())
    }
    fn delete_credential(&self) -> Result<()> {
        self.delete()
    }
    fn get_credential(&self) -> Result<Option<Arc<Credential>>> {
        self.read().map(|_bytes| None)
    }
    fn get_specifiers(&self) -> Option<(String, String)> {
        Some((self.service.clone(), self.account.clone()))
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl CredentialStoreApi for ProviderSecretFileStore {
    fn vendor(&self) -> String {
        "vaultwarden-cli provider secret file store".into()
    }
    fn id(&self) -> String {
        self.state_root.display().to_string()
    }
    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        if modifiers.is_some_and(|modifiers| !modifiers.is_empty()) {
            return Err(Error::NotSupportedByStore(
                "the provider secret file store takes no modifiers".into(),
            ));
        }
        Ok(Entry::new_with_credential(Arc::new(SecretRecord {
            state_root: self.state_root.clone(),
            service: service.into(),
            account: user.into(),
            name: record_name(service, user)?,
        })))
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::UntilDelete
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::session::{BOOTSTRAP_ACCOUNT, KEYRING_SERVICE, SESSION_ACCOUNT};

    fn private_root() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = dir.path().join("state");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        (dir, root)
    }
    fn entry(root: &Path, account: &str) -> Entry {
        ProviderSecretFileStore::new(root)
            .unwrap()
            .build(KEYRING_SERVICE, account, None)
            .unwrap()
    }
    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    #[test]
    fn first_start_has_no_entry_and_creates_nothing() {
        let (_dir, root) = private_root();
        for account in [BOOTSTRAP_ACCOUNT, SESSION_ACCOUNT] {
            assert!(matches!(
                entry(&root, account).get_password(),
                Err(Error::NoEntry)
            ));
            assert!(matches!(
                entry(&root, account).delete_credential(),
                Err(Error::NoEntry)
            ));
            assert!(matches!(
                entry(&root, account).get_credential(),
                Err(Error::NoEntry)
            ));
        }
        assert!(!root.join(SECRETS_DIRECTORY).exists());
        std::fs::create_dir(root.join(SECRETS_DIRECTORY)).unwrap();
        std::fs::set_permissions(
            root.join(SECRETS_DIRECTORY),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(matches!(
            entry(&root, SESSION_ACCOUNT).get_password(),
            Err(Error::NoEntry)
        ));
    }

    #[test]
    fn round_trip_replaces_atomically_with_private_modes_and_deletes() {
        let (_dir, root) = private_root();
        let session = entry(&root, SESSION_ACCOUNT);
        session.set_password("first-session").unwrap();
        assert_eq!(session.get_password().unwrap(), "first-session");
        let path = ProviderSecretFileStore::new(&root)
            .unwrap()
            .record_path(KEYRING_SERVICE, SESSION_ACCOUNT)
            .unwrap();
        assert_eq!(mode(&root.join(SECRETS_DIRECTORY)), 0o700);
        assert_eq!(mode(&path), 0o600);
        session.set_password("second-session").unwrap();
        assert_eq!(
            entry(&root, SESSION_ACCOUNT).get_password().unwrap(),
            "second-session"
        );
        // Only the record remains: no temporary file survives a replacement.
        let names: Vec<_> = std::fs::read_dir(root.join(SECRETS_DIRECTORY))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            names,
            [std::ffi::OsString::from(
                "vaultwarden-accessd.revocable-session"
            )]
        );
        // Records are independent; deleting the session preserves bootstrap.
        entry(&root, BOOTSTRAP_ACCOUNT)
            .set_password("client-secret")
            .unwrap();
        session.delete_credential().unwrap();
        assert!(matches!(session.get_password(), Err(Error::NoEntry)));
        assert!(matches!(session.delete_credential(), Err(Error::NoEntry)));
        assert_eq!(
            entry(&root, BOOTSTRAP_ACCOUNT).get_password().unwrap(),
            "client-secret"
        );
    }

    #[test]
    fn unsafe_modes_links_and_names_are_refused_without_following() {
        let (dir, root) = private_root();
        let record = entry(&root, SESSION_ACCOUNT);
        record.set_password("sentinel").unwrap();
        let path = root
            .join(SECRETS_DIRECTORY)
            .join("vaultwarden-accessd.revocable-session");
        for unsafe_mode in [0o644, 0o640, 0o400, 0o700] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(unsafe_mode)).unwrap();
            assert!(record.get_password().is_err(), "read mode {unsafe_mode:o}");
            assert!(!matches!(record.get_password(), Err(Error::NoEntry)));
            assert!(
                record.set_password("x").is_err(),
                "replace mode {unsafe_mode:o}"
            );
            assert!(
                record.delete_credential().is_err(),
                "delete mode {unsafe_mode:o}"
            );
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(record.get_password().unwrap(), "sentinel");
        // A second hard link (e.g. into an agent-readable place) is refused.
        let link = dir.path().join("copy");
        std::fs::hard_link(&path, &link).unwrap();
        assert!(record.get_password().is_err());
        assert!(record.set_password("x").is_err());
        assert!(record.delete_credential().is_err());
        std::fs::remove_file(&link).unwrap();
        // A symlinked record is never followed, written through or removed as data.
        let outside = dir.path().join("outside");
        std::fs::write(&outside, "outside").unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        assert!(record.get_password().is_err());
        assert!(record.set_password("x").is_err());
        assert!(record.delete_credential().is_err());
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "outside");
        std::fs::remove_file(&path).unwrap();
        // Unsafe secrets directory and state root.
        let secrets = root.join(SECRETS_DIRECTORY);
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(record.get_password().is_err());
        assert!(record.set_password("x").is_err());
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir(&secrets).unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &secrets).unwrap();
        assert!(record.get_password().is_err());
        assert!(record.set_password("x").is_err());
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
        std::fs::remove_file(&secrets).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(record.get_password().is_err());
        assert!(record.set_password("x").is_err());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        record.set_password("restored").unwrap();
        assert_eq!(record.get_password().unwrap(), "restored");
        // Names that could escape or hide are invalid, not absent.
        let store = ProviderSecretFileStore::new(&root).unwrap();
        for (service, account) in [("../x", "y"), ("x", "a/b"), ("x", ".hidden"), ("", "y")] {
            assert!(matches!(
                store.build(service, account, None),
                Err(Error::Invalid(..))
            ));
        }
        assert!(ProviderSecretFileStore::new(Path::new("relative")).is_err());
    }

    #[test]
    fn foreign_or_inaccessible_state_roots_name_the_provider_account_remedy() {
        if euid() == 0 {
            eprintln!("skipping: root owns and can open every directory");
            return;
        }
        let message = |root: &Path| match entry(root, SESSION_ACCOUNT).get_password() {
            Err(error @ Error::NoStorageAccess(_)) => error.to_string(),
            other => panic!("{}: {other:?}", root.display()),
        };
        // A root-owned directory (as `sudo` without `-u _vwaccess` would meet).
        let foreign = message(Path::new("/usr"));
        assert!(
            foreign.contains("not owned by the running user") && foreign.contains(RUN_AS_PROVIDER),
            "{foreign}"
        );
        // A directory the running user cannot open at all.
        let (_dir, root) = private_root();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o000)).unwrap();
        let closed = message(&root);
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            closed.contains("not accessible to the running user")
                && closed.contains(RUN_AS_PROVIDER),
            "{closed}"
        );
    }

    #[test]
    fn crash_leftover_temporaries_are_swept_and_nothing_else() {
        let (dir, root) = private_root();
        let record = entry(&root, SESSION_ACCOUNT);
        record.set_password("first").unwrap();
        let secrets = root.join(SECRETS_DIRECTORY);
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        let leftover = |name: &str, age: Option<std::time::SystemTime>| {
            let path = secrets.join(name);
            std::fs::write(&path, "partial").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            if let Some(time) = age {
                File::options()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_modified(time)
                    .unwrap();
            }
            path
        };
        let hex = "0123456789abcdef01234567";
        let stale = leftover(
            &format!(".vaultwarden-accessd.revocable-session.{hex}.tmp"),
            Some(old),
        );
        let stale_bootstrap = leftover(
            &format!(".vaultwarden-accessd.bootstrap-client-secret.{hex}.tmp"),
            Some(old),
        );
        // A writer's in-flight temporary (recent) is never taken from under it.
        let fresh = leftover(
            &format!(".vaultwarden-accessd.revocable-session.{hex}.tmp").replace("0123", "fedc"),
            None,
        );
        // Near misses of the exact pattern are not ours.
        let kept: Vec<PathBuf> = [
            ".vaultwarden-accessd.revocable-session.0123.tmp",
            ".vaultwarden-accessd.revocable-session.0123456789abcdefg1234567.tmp",
            ".vaultwarden-accessd.revocable-session.0123456789abcdef01234567.tmp.bak",
            "vaultwarden-accessd.revocable-session.0123456789abcdef01234567.tmp",
            ".vaultwarden-accessd..0123456789abcdef01234567.tmp",
            ".tmp",
        ]
        .iter()
        .map(|name| leftover(name, Some(old)))
        .collect();
        // A matching name with a second link, a wrong mode or as a symlink is left alone.
        let linked = leftover(&format!(".vaultwarden-accessd.a.{hex}.tmp"), Some(old));
        std::fs::hard_link(&linked, dir.path().join("second-link")).unwrap();
        let wide = leftover(&format!(".vaultwarden-accessd.b.{hex}.tmp"), Some(old));
        std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o644)).unwrap();
        let outside = dir.path().join("outside");
        std::fs::write(&outside, "outside").unwrap();
        let symlink = secrets.join(format!(".vaultwarden-accessd.c.{hex}.tmp"));
        std::os::unix::fs::symlink(&outside, &symlink).unwrap();
        // Opening the store for a read sweeps; the record itself is untouched.
        assert_eq!(record.get_password().unwrap(), "first");
        assert!(!stale.exists());
        assert!(!stale_bootstrap.exists());
        for path in kept.iter().chain([&fresh, &linked, &wide]) {
            assert!(path.exists(), "{}", path.display());
        }
        assert!(std::fs::symlink_metadata(&symlink).is_ok());
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "outside");
        // A write sweeps too.
        let again = leftover(
            &format!(".vaultwarden-accessd.revocable-session.{hex}.tmp"),
            Some(old),
        );
        record.set_password("second").unwrap();
        assert!(!again.exists());
        assert_eq!(record.get_password().unwrap(), "second");
    }

    #[test]
    fn provider_keyring_uses_installed_store_and_startup_clear_tolerates_empty_store() {
        let _guard = crate::KEYRING_TEST_LOCK.lock().unwrap();
        let previous = keyring_core::unset_default_store();
        let (_dir, root) = private_root();
        ProviderSecretFileStore::install_default(&root).unwrap();
        // Startup on a fresh install: nothing stored, nothing created, no failure.
        assert_eq!(crate::adapters::session::clear_persisted_session(), Ok(()));
        assert!(!root.join(SECRETS_DIRECTORY).exists());
        assert_eq!(
            crate::adapters::session::store_bootstrap_secret(
                &crate::access::ports::SensitiveString::new("provisioned".into())
            ),
            Ok(())
        );
        entry(&root, SESSION_ACCOUNT)
            .set_password("stale-session")
            .unwrap();
        assert_eq!(crate::adapters::session::clear_persisted_session(), Ok(()));
        assert!(matches!(
            entry(&root, SESSION_ACCOUNT).get_password(),
            Err(Error::NoEntry)
        ));
        assert_eq!(
            entry(&root, BOOTSTRAP_ACCOUNT).get_password().unwrap(),
            "provisioned"
        );
        // An unsafe store fails startup closed instead of being ignored.
        entry(&root, SESSION_ACCOUNT)
            .set_password("stale-session")
            .unwrap();
        std::fs::set_permissions(
            root.join(SECRETS_DIRECTORY)
                .join("vaultwarden-accessd.revocable-session"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(crate::adapters::session::clear_persisted_session().is_err());
        keyring_core::unset_default_store();
        if let Some(previous) = previous {
            keyring_core::set_default_store(previous);
        }
    }
}
