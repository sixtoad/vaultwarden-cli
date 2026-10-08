//! Provider-private SSH files. No destructor deletes material; reap evidence is mandatory.
use crate::access::{
    policy::SshOperation,
    ports::{CleanupEvidence, ExecutionError, SensitiveString, SshMaterial},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
};

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_FAIL_REMOVE: std::cell::Cell<bool> = const {std::cell::Cell::new(false)};
    static TEST_FAIL_CREATE_AFTER: std::cell::Cell<Option<usize>> = const {std::cell::Cell::new(None)};
    static TEST_FAIL_REMOVE_AFTER: std::cell::Cell<Option<usize>> = const {std::cell::Cell::new(None)};
    static TEST_FAULT: std::cell::Cell<Option<Fault>> = const {std::cell::Cell::new(None)};
    static TEST_FAULT_HIT: std::cell::Cell<bool> = const {std::cell::Cell::new(false)};
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    RequestSync,
    RequestOpen,
    RequestMetadata,
    PartialWrite,
    FileSync,
    CreateParentSync,
    RemoveDirectory,
    RemoveFileSync,
    RemoveDirectorySync,
}
#[cfg(test)]
fn test_fault(point: Fault) -> Result<(), ExecutionError> {
    if TEST_FAULT.with(|fault| fault.get() == Some(point)) {
        TEST_FAULT_HIT.with(|hit| hit.set(true));
        return Err(ExecutionError::UnsafePath);
    }
    Ok(())
}

fn failure<T>(_: T) -> ExecutionError {
    ExecutionError::UnsafePath
}
fn name(value: &std::ffi::OsStr) -> Result<CString, ExecutionError> {
    CString::new(value.as_bytes()).map_err(failure)
}
fn open_at(parent: &File, leaf: &str, directory: bool) -> Result<File, ExecutionError> {
    let leaf = name(leaf.as_ref())?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK
                | if directory { libc::O_DIRECTORY } else { 0 },
        )
    };
    if fd < 0 {
        return Err(ExecutionError::UnsafePath);
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn private(file: &File, directory: bool) -> Result<(), ExecutionError> {
    let m = file.metadata().map_err(failure)?;
    if m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
        || if directory {
            !m.is_dir()
        } else {
            !m.is_file() || m.nlink() != 1
        }
    {
        return Err(ExecutionError::UnsafePath);
    }
    Ok(())
}
/// Descriptor walk rejects symlinks, unsafe ancestors, relative/dot spelling and writable shared roots.
pub(crate) fn directory(path: &Path, require_private: bool) -> Result<File, ExecutionError> {
    if !path.is_absolute()
        || path
            .as_os_str()
            .as_bytes()
            .split(|b| *b == b'/')
            .any(|s| s == b"." || s == b"..")
    {
        return Err(ExecutionError::UnsafePath);
    }
    let fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(ExecutionError::UnsafePath);
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => {
                let part = part.to_str().ok_or(ExecutionError::UnsafePath)?;
                file = open_at(&file, part, true)?;
            }
            _ => return Err(ExecutionError::UnsafePath),
        }
        let m = file.metadata().map_err(failure)?;
        if !m.is_dir()
            || (m.uid() != 0 && m.uid() != unsafe { libc::geteuid() })
            || m.mode() & 0o7022 != 0
        {
            return Err(ExecutionError::UnsafePath);
        }
    }
    if require_private {
        private(&file, true)?;
    }
    Ok(file)
}
fn ensure_directory(parent: &File, leaf: &str) -> Result<File, ExecutionError> {
    let encoded = name(leaf.as_ref())?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), encoded.as_ptr(), 0o700) } != 0
        && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
    {
        return Err(ExecutionError::UnsafePath);
    }
    let result = open_at(parent, leaf, true)?;
    private(&result, true)?;
    parent.sync_all().map_err(failure)?;
    Ok(result)
}
fn create(parent: &File, leaf: &str, bytes: &[u8]) -> Result<(), ExecutionError> {
    #[cfg(test)]
    if TEST_FAIL_CREATE_AFTER.with(|remaining| match remaining.get() {
        Some(0) => true,
        Some(n) => {
            remaining.set(Some(n - 1));
            false
        }
        None => false,
    }) {
        return Err(ExecutionError::UnsafePath);
    }
    let encoded = name(leaf.as_ref())?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            encoded.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(ExecutionError::UnsafePath);
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    private(&file, false)?;
    #[cfg(test)]
    if TEST_FAULT.with(|fault| fault.get() == Some(Fault::PartialWrite)) {
        file.write_all(&bytes[..bytes.len() / 2]).map_err(failure)?;
        test_fault(Fault::PartialWrite)?;
    }
    file.write_all(bytes).map_err(failure)?;
    #[cfg(test)]
    test_fault(Fault::FileSync)?;
    file.sync_all().map_err(failure)?;
    #[cfg(test)]
    test_fault(Fault::CreateParentSync)?;
    parent.sync_all().map_err(failure)
}
fn entries(file: &File) -> Result<Vec<String>, ExecutionError> {
    std::fs::read_dir(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(failure)?
        .map(|entry| {
            entry
                .map_err(failure)?
                .file_name()
                .into_string()
                .map_err(failure)
        })
        .collect()
}
fn same(parent: &File, leaf: &str, file: &File, directory: bool) -> Result<(), ExecutionError> {
    let current = open_at(parent, leaf, directory)?;
    private(&current, directory)?;
    let a = file.metadata().map_err(failure)?;
    let b = current.metadata().map_err(failure)?;
    if a.dev() != b.dev() || a.ino() != b.ino() {
        return Err(ExecutionError::UnsafePath);
    }
    Ok(())
}
fn remove(parent: &File, leaf: &str, directory: bool) -> Result<(), ExecutionError> {
    #[cfg(test)]
    if TEST_FAIL_REMOVE.with(|fail| fail.get()) {
        return Err(ExecutionError::CleanupUncertain);
    }
    #[cfg(test)]
    {
        if TEST_FAIL_REMOVE_AFTER.with(|remaining| match remaining.get() {
            Some(0) => true,
            Some(n) => {
                remaining.set(Some(n - 1));
                false
            }
            None => false,
        }) {
            return Err(ExecutionError::CleanupUncertain);
        }
        if directory {
            test_fault(Fault::RemoveDirectory)?;
        }
    }
    let leaf = name(leaf.as_ref())?;
    if unsafe {
        libc::unlinkat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            if directory { libc::AT_REMOVEDIR } else { 0 },
        )
    } != 0
    {
        return Err(ExecutionError::CleanupUncertain);
    }
    #[cfg(test)]
    test_fault(if directory {
        Fault::RemoveDirectorySync
    } else {
        Fault::RemoveFileSync
    })?;
    parent.sync_all().map_err(failure)
}
fn cleanup(parent: &File, leaf: &str, dir: &File) -> Result<(), ExecutionError> {
    same(parent, leaf, dir, true)?;
    // Validate the entire set before deleting anything. Unknown objects are never removed.
    let names = entries(dir)?;
    let mut checked = Vec::new();
    for leaf in names {
        if !["identity", "known_hosts"].contains(&leaf.as_str()) {
            return Err(ExecutionError::CleanupUncertain);
        }
        let file = open_at(dir, &leaf, false)?;
        private(&file, false)?;
        checked.push((leaf, file));
    }
    for (leaf, file) in checked {
        same(dir, &leaf, &file, false)?;
        remove(dir, &leaf, false)?;
    }
    same(parent, leaf, dir, true)?;
    remove(parent, leaf, true)
}
fn request_name(value: &str) -> bool {
    value.len() == 36
        && value.starts_with("req-")
        && value[4..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Called only after manager recovery under the provider's writer lock.
pub fn recover(root: &Path) -> Result<(), ExecutionError> {
    let root = directory(root, true)?;
    let requests = ensure_directory(&root, "requests")?;
    for leaf in entries(&requests)? {
        if !request_name(&leaf) {
            return Err(ExecutionError::CleanupUncertain);
        }
        let dir = open_at(&requests, &leaf, true)?;
        private(&dir, true)?;
        cleanup(&requests, &leaf, &dir)?;
    }
    Ok(())
}
/// Create the dedicated private namespace. Its path comes only from daemon composition.
pub fn initialize(state_root: &Path) -> Result<PathBuf, ExecutionError> {
    let root = directory(state_root, true)?;
    let ssh = ensure_directory(&root, "ssh")?;
    let _requests = ensure_directory(&ssh, "requests")?;
    Ok(state_root.join("ssh"))
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostKey {
    host: String,
    port: u16,
    key: String,
}
fn host_key(root: &File, ssh: &SshOperation) -> Result<String, ExecutionError> {
    let mut file = open_at(root, "host_keys.json", false)?;
    private(&file, false)?;
    if file.metadata().map_err(failure)?.len() > 1024 * 1024 {
        return Err(ExecutionError::InvalidArguments);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(failure)?;
    if bytes.len() > 1024 * 1024 {
        return Err(ExecutionError::InvalidArguments);
    }
    let keys: Vec<HostKey> = serde_json::from_slice(&bytes).map_err(failure)?;
    let matches: Vec<_> = keys
        .iter()
        .filter(|key| key.host == ssh.destination.host && key.port == ssh.destination.port)
        .collect();
    if matches.len() != 1 {
        return Err(ExecutionError::InvalidArguments);
    }
    let key = &matches[0].key;
    let parts: Vec<_> = key.split(' ').collect();
    if parts.len() != 2
        || ![
            "ssh-ed25519",
            "ssh-rsa",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ]
        .contains(&parts[0])
    {
        return Err(ExecutionError::InvalidArguments);
    }
    let decoded = STANDARD.decode(parts[1]).map_err(failure)?;
    let length = decoded.get(..4).ok_or(ExecutionError::InvalidArguments)?;
    let length = u32::from_be_bytes(length.try_into().map_err(failure)?) as usize;
    if decoded.get(4..4 + length) != Some(parts[0].as_bytes()) || decoded.len() <= 4 + length + 4 {
        return Err(ExecutionError::InvalidArguments);
    }
    if format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(Sha256::digest(&decoded))
    ) != ssh.destination.host_fingerprint
    {
        return Err(ExecutionError::DigestMismatch);
    }
    let destination = if ssh.destination.port == 22 {
        ssh.destination.host.clone()
    } else {
        format!("[{}]:{}", ssh.destination.host, ssh.destination.port)
    };
    Ok(format!("{destination} {key}\n"))
}
/// Explicit resource ownership. Leaving this scope preserves the directory on disk.
pub(crate) struct Material {
    parent: File,
    dir: File,
    leaf: String,
    finished: bool,
}
impl SshMaterial for Material {
    fn install_key(&mut self, key: SensitiveString) -> Result<(), ExecutionError> {
        if key.expose().is_empty() || key.expose().len() > 64 * 1024 || key.expose().contains('\0')
        {
            return Err(ExecutionError::InvalidArguments);
        }
        create(&self.dir, "identity", key.expose().as_bytes())
    }
    fn finalize(&mut self, evidence: CleanupEvidence) -> Result<(), ExecutionError> {
        if evidence == CleanupEvidence::Uncertain {
            return Err(ExecutionError::CleanupUncertain);
        }
        if !self.finished {
            cleanup(&self.parent, &self.leaf, &self.dir)?;
            self.finished = true;
        }
        Ok(())
    }
}
pub(crate) fn prepare(
    root: &Path,
    ssh: &SshOperation,
) -> Result<(Material, Vec<String>, File), ExecutionError> {
    let cwd = directory(Path::new(&ssh.working_directory), false)?;
    let private_root = directory(root, true)?;
    let known_hosts = host_key(&private_root, ssh)?;
    let parent = open_at(&private_root, "requests", true)?;
    private(&parent, true)?;
    // A residual is a durable interlock, including after an unsuccessful earlier cleanup.
    if !entries(&parent)?.is_empty() {
        return Err(ExecutionError::CleanupUncertain);
    }
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(failure)?;
    let leaf = format!(
        "req-{}",
        nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let encoded = name(leaf.as_ref())?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), encoded.as_ptr(), 0o700) } != 0 {
        return Err(ExecutionError::UnsafePath);
    }
    // Until Material owns the directory, any failure leaves a residual that must
    // close admission immediately as well as after restart.
    let dir = (|| {
        #[cfg(test)]
        test_fault(Fault::RequestSync)?;
        parent.sync_all().map_err(failure)?;
        #[cfg(test)]
        test_fault(Fault::RequestOpen)?;
        let dir = open_at(&parent, &leaf, true)?;
        #[cfg(test)]
        test_fault(Fault::RequestMetadata)?;
        private(&dir, true)?;
        Ok::<_, ExecutionError>(dir)
    })()
    .map_err(|_error| ExecutionError::CleanupUncertain)?;
    let mut material = Material {
        parent,
        dir,
        leaf,
        finished: false,
    };
    let request = root.join("requests").join(&material.leaf);
    let result = (|| {
        let path = request.to_str().ok_or(ExecutionError::UnsafePath)?;
        if path
            .bytes()
            .any(|b| b.is_ascii_control() || matches!(b, b'"' | b'\\' | b'%' | b'$'))
        {
            return Err(ExecutionError::UnsafePath);
        }
        create(&material.dir, "known_hosts", known_hosts.as_bytes())?;
        let mut argv = vec!["-F".into(), "/dev/null".into()];
        for option in [
            format!("IdentityFile=\"{path}/identity\""),
            format!("UserKnownHostsFile=\"{path}/known_hosts\""),
            "CertificateFile=none".into(),
            "IdentityAgent=none".into(),
            "IdentitiesOnly=yes".into(),
            "GlobalKnownHostsFile=/dev/null".into(),
            "StrictHostKeyChecking=yes".into(),
            "UpdateHostKeys=no".into(),
            "VerifyHostKeyDNS=no".into(),
            "CheckHostIP=no".into(),
            "BatchMode=yes".into(),
            "PreferredAuthentications=publickey".into(),
            "PasswordAuthentication=no".into(),
            "KbdInteractiveAuthentication=no".into(),
            "ForwardAgent=no".into(),
            "ForwardX11=no".into(),
            "ClearAllForwardings=yes".into(),
            "ProxyCommand=none".into(),
            "ProxyJump=none".into(),
            "PermitLocalCommand=no".into(),
            "ControlMaster=no".into(),
            "ControlPath=none".into(),
            "RequestTTY=no".into(),
            "EscapeChar=none".into(),
            "LogLevel=QUIET".into(),
        ] {
            argv.push("-o".into());
            argv.push(option);
        }
        argv.extend([
            "-p".into(),
            ssh.destination.port.to_string(),
            "-l".into(),
            ssh.destination.user.clone(),
            "--".into(),
            ssh.destination.host.clone(),
            ssh.destination.resource_path.clone(),
        ]);
        Ok(argv)
    })();
    match result {
        Ok(argv) => Ok((material, argv, cwd)),
        Err(error) => match material.finalize(CleanupEvidence::NotStarted) {
            Ok(()) => Err(error),
            Err(_) => Err(ExecutionError::CleanupUncertain),
        },
    }
}

#[cfg(test)]
pub(crate) fn fixture(root: &Path) -> (SshOperation, String) {
    use crate::access::policy::{CredentialUse, SshCredential, SshDestination};
    use std::os::unix::fs::PermissionsExt;
    fn field(bytes: &mut Vec<u8>, value: &[u8]) {
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value);
    }
    let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let public = key.verifying_key().to_bytes();
    let mut host = Vec::new();
    field(&mut host, b"ssh-ed25519");
    field(&mut host, &public);
    let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&host)));
    let mut bytes = b"openssh-key-v1\0".to_vec();
    field(&mut bytes, b"none");
    field(&mut bytes, b"none");
    field(&mut bytes, b"");
    bytes.extend_from_slice(&1u32.to_be_bytes());
    field(&mut bytes, &host);
    let mut private = vec![0u8; 8];
    field(&mut private, b"ssh-ed25519");
    field(&mut private, &public);
    let mut secret = vec![42u8; 32];
    secret.extend_from_slice(&public);
    field(&mut private, &secret);
    field(&mut private, b"ssh-private-key-sentinel");
    let padding = 8 - private.len() % 8;
    private.extend(1..=padding as u8);
    field(&mut bytes, &private);
    let private = format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
        STANDARD.encode(bytes)
    );
    let ssh = SshOperation {
        credential: SshCredential {
            item_id: "11111111-1111-1111-1111-111111111111".into(),
            label: "Synthetic".into(),
            use_type: CredentialUse::Ssh,
        },
        working_directory: root.to_string_lossy().into_owned(),
        destination: SshDestination {
            host: "backup.example.test".into(),
            port: 2222,
            user: "backup".into(),
            resource_path: "/srv/archive".into(),
            host_fingerprint: fingerprint,
        },
    };
    let material_root = initialize(root).unwrap();
    std::fs::write(material_root.join("host_keys.json"), serde_json::to_vec(&serde_json::json!([{"host":ssh.destination.host,"port":2222,"key":format!("ssh-ed25519 {}",STANDARD.encode(host))}])).unwrap()).unwrap();
    std::fs::set_permissions(
        material_root.join("host_keys.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    (ssh, private)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn setup() -> (tempfile::TempDir, SshOperation, String) {
        let root = tempfile::tempdir().unwrap();
        let (ssh, key) = fixture(root.path());
        (root, ssh, key)
    }
    #[test]
    fn ssh_creation_modes_are_private_with_permissive_umask() {
        const CHILD: &str = "VW_SSH_UMASK_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "adapters::ssh_material::tests::ssh_creation_modes_are_private_with_permissive_umask", "--test-threads=1", "--nocapture"])
                .env(CHILD,"1").output().unwrap();
            assert!(
                output.status.success(),
                "isolated permissive-umask creation test failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        // Establish the already-private provider root before changing creation policy.
        let root = tempfile::tempdir().unwrap();
        // Process isolated: never weaken the parallel test runner's global umask.
        unsafe { libc::umask(0) };
        let (ssh, key) = fixture(root.path());
        let (mut material, _, _) = prepare(&root.path().join("ssh"), &ssh).unwrap();
        material.install_key(SensitiveString::new(key)).unwrap();
        let request = root.path().join("ssh/requests").join(&material.leaf);
        for dir in [
            root.path().join("ssh"),
            root.path().join("ssh/requests"),
            request.clone(),
        ] {
            let meta = std::fs::symlink_metadata(dir).unwrap();
            assert!(meta.is_dir());
            assert_eq!(meta.mode() & 0o7777, 0o700);
            assert_eq!(meta.uid(), unsafe { libc::geteuid() });
        }
        for name in ["identity", "known_hosts"] {
            let meta = std::fs::symlink_metadata(request.join(name)).unwrap();
            assert!(meta.is_file());
            assert_eq!(meta.mode() & 0o7777, 0o600);
            assert_eq!(meta.nlink(), 1);
            assert_eq!(meta.uid(), unsafe { libc::geteuid() });
        }
        material.finalize(CleanupEvidence::NotStarted).unwrap();
    }
    #[test]
    fn ssh_exclusive_install_preserves_existing_key_and_replacement_inodes() {
        let (root, ssh, key) = setup();
        let (mut material, _, _) = prepare(&root.path().join("ssh"), &ssh).unwrap();
        material
            .install_key(SensitiveString::new(key.clone()))
            .unwrap();
        let request = root.path().join("ssh/requests").join(&material.leaf);
        assert!(
            material
                .install_key(SensitiveString::new("replacement-key-sentinel".into()))
                .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(request.join("identity")).unwrap(),
            key
        );
        let retained = open_at(&material.dir, "identity", false).unwrap();
        std::fs::rename(request.join("identity"), request.join("saved-identity")).unwrap();
        create(&material.dir, "identity", b"replacement-file-sentinel").unwrap();
        assert!(
            same(&material.dir, "identity", &retained, false).is_err(),
            "valid replacement metadata cannot substitute another inode"
        );
        assert_eq!(
            std::fs::read(request.join("identity")).unwrap(),
            b"replacement-file-sentinel"
        );
        assert_eq!(
            std::fs::read_to_string(request.join("saved-identity")).unwrap(),
            key
        );
        std::fs::remove_file(request.join("identity")).unwrap();
        std::fs::rename(request.join("saved-identity"), request.join("identity")).unwrap();
        let moved = root.path().join("ssh/requests/moved-original");
        std::fs::rename(&request, &moved).unwrap();
        std::fs::create_dir(&request).unwrap();
        std::fs::set_permissions(&request, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(request.join("unrelated"), b"replacement-directory-sentinel").unwrap();
        assert!(
            material.finalize(CleanupEvidence::Reaped).is_err(),
            "cleanup must reject a replacement directory before removing original files"
        );
        assert_eq!(
            std::fs::read_to_string(moved.join("identity")).unwrap(),
            key
        );
        assert_eq!(
            std::fs::read(request.join("unrelated")).unwrap(),
            b"replacement-directory-sentinel"
        );
        std::fs::remove_file(request.join("unrelated")).unwrap();
        std::fs::remove_dir(&request).unwrap();
        std::fs::rename(&moved, &request).unwrap();
        material.finalize(CleanupEvidence::Reaped).unwrap();
    }
    #[test]
    #[ignore = "requires subordinate UID/GID mappings and unshare; invoked explicitly by systemd verification script"]
    fn distinct_agent_principals_cannot_read_live_provider_material() {
        if std::env::var_os("VW_SSH_FOREIGN_OWNER_CHILD").is_some() {
            use std::os::fd::AsFd;
            let maps = std::fs::read_to_string("/proc/self/uid_map").unwrap();
            let ranges: Vec<Vec<u64>> = maps
                .lines()
                .map(|line| {
                    line.split_whitespace()
                        .map(|value| value.parse().unwrap())
                        .collect()
                })
                .collect();
            assert!(ranges.iter().all(|range| range.len() == 3 && range[1] != 0));
            assert!(
                ranges
                    .iter()
                    .any(|range| range[0] <= 8 && 8 - range[0] < range[2])
            );
            let file = File::from(std::io::stdin().as_fd().try_clone_to_owned().unwrap());
            let meta = file.metadata().unwrap();
            assert!(meta.is_file());
            assert_eq!(meta.mode() & 0o7777, 0o600);
            assert_eq!(meta.nlink(), 1);
            assert_eq!(meta.uid(), 0);
            private(&file, false).unwrap();
            assert_eq!(unsafe { libc::setgroups(0, std::ptr::null()) }, 0);
            assert_eq!(unsafe { libc::setgid(8) }, 0);
            assert_eq!(unsafe { libc::setuid(8) }, 0);
            assert_ne!(file.metadata().unwrap().uid(), unsafe { libc::geteuid() });
            assert!(
                private(&file, false).is_err(),
                "a valid 0600 regular single-link file must still reject its foreign owner"
            );
            return;
        }
        assert_ne!(
            unsafe { libc::geteuid() },
            0,
            "never run the provider fixture as host root"
        );
        let (root, ssh, key) = setup();
        let (mut material, _, _) = prepare(&root.path().join("ssh"), &ssh).unwrap();
        material.install_key(SensitiveString::new(key)).unwrap();
        let request = root.path().join("ssh/requests").join(&material.leaf);
        let script = r#"import os,sys
uid=int(sys.argv[1])
maps=[list(map(int,line.split())) for line in open('/proc/self/uid_map')]
assert all(outer != 0 for inner,outer,count in maps)
assert any(inner <= uid < inner+count for inner,outer,count in maps)
os.setgroups([])
os.setgid(uid)
os.setuid(uid)
for leaf in ['identity','known_hosts']:
    try:
        fd=os.open(os.path.join(sys.argv[2],leaf),os.O_RDONLY)
    except PermissionError:
        continue
    else:
        os.close(fd)
        sys.exit(2)
"#;
        for uid in [8, 10] {
            let status = std::process::Command::new("unshare")
                .args([
                    "--user",
                    "--map-auto",
                    "--map-root-user",
                    "--fork",
                    "python3",
                    "-c",
                    script,
                    &uid.to_string(),
                ])
                .arg(&request)
                .status()
                .unwrap();
            assert!(
                status.success(),
                "distinct mapped UID {uid} must receive EACCES for both material files"
            );
        }
        let output=std::process::Command::new("unshare")
            .args(["--user","--map-auto","--map-root-user","--fork"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact","adapters::ssh_material::tests::distinct_agent_principals_cannot_read_live_provider_material","--ignored","--test-threads=1","--nocapture"])
            .env("VW_SSH_FOREIGN_OWNER_CHILD","1")
            .stdin(std::process::Stdio::from(open_at(&material.dir,"identity",false).unwrap()))
            .output().unwrap();
        assert!(
            output.status.success(),
            "foreign-owner descriptor oracle failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        material.finalize(CleanupEvidence::Reaped).unwrap();
        assert!(!request.exists());
    }
    #[test]
    fn partial_setup_is_cleaned_and_unlink_failure_survives_restart_until_recovery() {
        for failure_at in [0, 1] {
            let (root, ssh, key) = setup();
            let material_root = root.path().join("ssh");
            TEST_FAIL_CREATE_AFTER.with(|fail| fail.set(Some(failure_at)));
            let result = prepare(&material_root, &ssh);
            if failure_at == 0 {
                assert!(result.is_err());
            } else {
                let (mut material, _, _) = result.unwrap();
                assert!(material.install_key(SensitiveString::new(key)).is_err());
                material.finalize(CleanupEvidence::NotStarted).unwrap();
            }
            TEST_FAIL_CREATE_AFTER.with(|fail| fail.set(None));
            assert_eq!(
                std::fs::read_dir(material_root.join("requests"))
                    .unwrap()
                    .count(),
                0
            );
        }
        let (root, ssh, key) = setup();
        let material_root = root.path().join("ssh");
        let (mut material, _, _) = prepare(&material_root, &ssh).unwrap();
        material.install_key(SensitiveString::new(key)).unwrap();
        let request = material_root.join("requests").join(&material.leaf);
        TEST_FAIL_REMOVE.with(|fail| fail.set(true));
        assert!(material.finalize(CleanupEvidence::Reaped).is_err());
        drop(material);
        assert!(request.join("identity").exists());
        assert!(prepare(&material_root, &ssh).is_err());
        assert!(recover(&material_root).is_err());
        TEST_FAIL_REMOVE.with(|fail| fail.set(false));
        recover(&material_root).unwrap();
        assert!(!request.exists());
    }
    fn arm_fault(fault: Option<Fault>) {
        TEST_FAULT.with(|value| value.set(fault));
        TEST_FAULT_HIT.with(|hit| hit.set(false));
    }
    fn assert_recovered_and_reusable(root: &Path, ssh: &SshOperation) {
        recover(root).unwrap();
        assert_eq!(std::fs::read_dir(root.join("requests")).unwrap().count(), 0);
        let (mut material, _, _) = prepare(root, ssh).unwrap();
        material.finalize(CleanupEvidence::NotStarted).unwrap();
    }
    #[test]
    fn ssh_post_mkdir_failures_report_uncertain_and_interlock_until_recovery() {
        for fault in [
            Fault::RequestSync,
            Fault::RequestOpen,
            Fault::RequestMetadata,
        ] {
            let (root, ssh, _) = setup();
            let material_root = root.path().join("ssh");
            arm_fault(Some(fault));
            assert!(
                matches!(
                    prepare(&material_root, &ssh),
                    Err(ExecutionError::CleanupUncertain)
                ),
                "{fault:?}"
            );
            assert!(TEST_FAULT_HIT.with(|hit| hit.get()), "{fault:?}");
            let residuals: Vec<_> = std::fs::read_dir(material_root.join("requests"))
                .unwrap()
                .collect();
            assert_eq!(residuals.len(), 1);
            let request = residuals[0].as_ref().unwrap().path();
            assert_eq!(std::fs::read_dir(&request).unwrap().count(), 0);
            assert!(matches!(
                prepare(&material_root, &ssh),
                Err(ExecutionError::CleanupUncertain)
            ));
            arm_fault(None);
            assert_recovered_and_reusable(&material_root, &ssh);
            assert!(!request.exists());
        }
    }
    #[test]
    fn ssh_partial_writes_and_create_sync_failures_are_cleaned_or_interlocked() {
        for fault in [
            Fault::PartialWrite,
            Fault::FileSync,
            Fault::CreateParentSync,
        ] {
            for identity in [false, true] {
                for cleanup_fails in [false, true] {
                    let (root, ssh, key) = setup();
                    let material_root = root.path().join("ssh");
                    if identity {
                        let (mut material, _, _) = prepare(&material_root, &ssh).unwrap();
                        arm_fault(Some(fault));
                        assert!(
                            material
                                .install_key(SensitiveString::new(key.clone()))
                                .is_err()
                        );
                        assert!(TEST_FAULT_HIT.with(|hit| hit.get()));
                        let request = material_root.join("requests").join(&material.leaf);
                        let written = std::fs::read(request.join("identity")).unwrap();
                        let expected = if fault == Fault::PartialWrite {
                            &key.as_bytes()[..key.len() / 2]
                        } else {
                            key.as_bytes()
                        };
                        assert_eq!(written, expected, "{fault:?}");
                        TEST_FAIL_REMOVE.with(|fail| fail.set(cleanup_fails));
                        assert_eq!(
                            material.finalize(CleanupEvidence::NotStarted).is_err(),
                            cleanup_fails
                        );
                        drop(material);
                    } else {
                        arm_fault(Some(fault));
                        TEST_FAIL_REMOVE.with(|fail| fail.set(cleanup_fails));
                        let result = prepare(&material_root, &ssh);
                        assert!(TEST_FAULT_HIT.with(|hit| hit.get()));
                        assert!(
                            matches!(result, Err(error) if error == if cleanup_fails { ExecutionError::CleanupUncertain } else { ExecutionError::UnsafePath })
                        );
                    }
                    arm_fault(None);
                    let count = std::fs::read_dir(material_root.join("requests"))
                        .unwrap()
                        .count();
                    assert_eq!(count, usize::from(cleanup_fails));
                    if cleanup_fails {
                        assert!(matches!(
                            prepare(&material_root, &ssh),
                            Err(ExecutionError::CleanupUncertain)
                        ));
                        assert!(recover(&material_root).is_err());
                    }
                    TEST_FAIL_REMOVE.with(|fail| fail.set(false));
                    assert_recovered_and_reusable(&material_root, &ssh);
                }
            }
        }
    }
    #[test]
    fn ssh_cleanup_failure_after_unlink_or_directory_removal_recovers_safely() {
        for fault in [
            None,
            Some(Fault::RemoveFileSync),
            Some(Fault::RemoveDirectory),
            Some(Fault::RemoveDirectorySync),
        ] {
            let (root, ssh, key) = setup();
            let material_root = root.path().join("ssh");
            let (mut material, _, _) = prepare(&material_root, &ssh).unwrap();
            material.install_key(SensitiveString::new(key)).unwrap();
            let request = material_root.join("requests").join(&material.leaf);
            arm_fault(fault);
            if fault.is_none() {
                TEST_FAIL_REMOVE_AFTER.with(|remaining| remaining.set(Some(1)));
            }
            assert!(material.finalize(CleanupEvidence::Reaped).is_err());
            if fault.is_some() {
                assert!(TEST_FAULT_HIT.with(|hit| hit.get()));
            }
            drop(material);
            if fault == Some(Fault::RemoveDirectorySync) {
                // Both files and the request directory were removed before sync failed.
                assert!(!request.exists());
            } else {
                let remaining = std::fs::read_dir(&request).unwrap().count();
                assert_eq!(
                    remaining,
                    if fault == Some(Fault::RemoveDirectory) {
                        0
                    } else {
                        1
                    }
                );
                assert!(matches!(
                    prepare(&material_root, &ssh),
                    Err(ExecutionError::CleanupUncertain)
                ));
                assert!(recover(&material_root).is_err());
                assert!(request.exists());
            }
            arm_fault(None);
            TEST_FAIL_REMOVE_AFTER.with(|remaining| remaining.set(None));
            assert_recovered_and_reusable(&material_root, &ssh);
        }
    }
    #[test]
    fn material_is_private_pinned_and_only_explicitly_removed_after_reap() {
        let (root, ssh, key) = setup();
        let (mut material, argv, cwd) = prepare(&root.path().join("ssh"), &ssh).unwrap();
        material
            .install_key(SensitiveString::new(key.clone()))
            .unwrap();
        assert_eq!(
            cwd.metadata().unwrap().ino(),
            std::fs::metadata(root.path()).unwrap().ino()
        );
        assert_eq!(entries(&material.dir).unwrap().len(), 2);
        for name in ["identity", "known_hosts"] {
            private(&open_at(&material.dir, name, false).unwrap(), false).unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(
                root.path()
                    .join("ssh/requests")
                    .join(&material.leaf)
                    .join("identity")
            )
            .unwrap(),
            key
        );
        for required in [
            "StrictHostKeyChecking=yes",
            "IdentityAgent=none",
            "GlobalKnownHostsFile=/dev/null",
            "ProxyCommand=none",
            "ForwardAgent=no",
            "ControlPath=none",
        ] {
            assert!(argv.iter().any(|arg| arg == required), "{required}");
        }
        assert_eq!(&argv[..2], ["-F", "/dev/null"]);
        assert_eq!(
            &argv[argv.len() - 7..],
            [
                "-p",
                "2222",
                "-l",
                "backup",
                "--",
                "backup.example.test",
                "/srv/archive"
            ]
        );
        let path = root.path().join("ssh/requests").join(&material.leaf);
        assert!(material.finalize(CleanupEvidence::Uncertain).is_err());
        assert!(path.join("identity").exists());
        assert!(matches!(
            prepare(&root.path().join("ssh"), &ssh),
            Err(ExecutionError::CleanupUncertain)
        ));
        material.finalize(CleanupEvidence::Reaped).unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn drop_preserves_residual_until_ordered_recovery() {
        let (root, ssh, key) = setup();
        let material_root = root.path().join("ssh");
        let (mut material, _, _) = prepare(&material_root, &ssh).unwrap();
        material.install_key(SensitiveString::new(key)).unwrap();
        let path = material_root.join("requests").join(&material.leaf);
        drop(material);
        assert!(path.join("identity").exists());
        assert!(prepare(&material_root, &ssh).is_err());
        recover(&material_root).unwrap();
        assert!(!path.exists());
        let (mut next, _, _) = prepare(&material_root, &ssh).unwrap();
        next.finalize(CleanupEvidence::NotStarted).unwrap();
    }
    #[test]
    fn unknown_objects_and_links_poison_cleanup_and_are_never_removed() {
        for attack in ["unknown", "symlink", "hardlink", "mode"] {
            let (root, ssh, key) = setup();
            let material_root = root.path().join("ssh");
            let (mut material, _, _) = prepare(&material_root, &ssh).unwrap();
            material.install_key(SensitiveString::new(key)).unwrap();
            let path = material_root.join("requests").join(&material.leaf);
            let unrelated = root.path().join("unrelated");
            std::fs::write(&unrelated, b"preserve unrelated").unwrap();
            match attack {
                "unknown" => std::fs::write(path.join("unrelated"), b"preserve unknown").unwrap(),
                "symlink" => {
                    std::fs::remove_file(path.join("identity")).unwrap();
                    symlink(&unrelated, path.join("identity")).unwrap();
                }
                "hardlink" => {
                    std::fs::remove_file(path.join("identity")).unwrap();
                    std::fs::hard_link(&unrelated, path.join("identity")).unwrap();
                }
                _ => std::fs::set_permissions(
                    path.join("identity"),
                    std::fs::Permissions::from_mode(0o644),
                )
                .unwrap(),
            }
            assert!(
                material.finalize(CleanupEvidence::Reaped).is_err(),
                "{attack}"
            );
            assert!(path.exists());
            assert!(recover(&material_root).is_err());
            assert!(prepare(&material_root, &ssh).is_err());
            assert_eq!(std::fs::read(&unrelated).unwrap(), b"preserve unrelated");
        }
    }
    #[test]
    fn wrong_pin_missing_key_and_destination_fail_before_request_files() {
        for change in [
            "pin",
            "host",
            "port",
            "missing",
            "duplicate",
            "mode",
            "symlink",
        ] {
            let (root, mut ssh, _) = setup();
            let material_root = root.path().join("ssh");
            let hosts = material_root.join("host_keys.json");
            match change {
                "pin" => ssh.destination.host_fingerprint = "SHA256:wrong".into(),
                "host" => ssh.destination.host = "other.example.test".into(),
                "port" => ssh.destination.port = 22,
                "missing" => std::fs::remove_file(&hosts).unwrap(),
                "duplicate" => {
                    let keys: Vec<serde_json::Value> =
                        serde_json::from_slice(&std::fs::read(&hosts).unwrap()).unwrap();
                    std::fs::write(
                        &hosts,
                        serde_json::to_vec(&vec![&keys[0], &keys[0]]).unwrap(),
                    )
                    .unwrap();
                }
                "mode" => std::fs::set_permissions(&hosts, std::fs::Permissions::from_mode(0o644))
                    .unwrap(),
                _ => {
                    std::fs::rename(&hosts, root.path().join("host-backup")).unwrap();
                    symlink(root.path().join("host-backup"), &hosts).unwrap();
                }
            }
            assert!(prepare(&material_root, &ssh).is_err(), "{change}");
            assert_eq!(
                std::fs::read_dir(material_root.join("requests"))
                    .unwrap()
                    .count(),
                0
            );
        }
    }
    #[test]
    fn directory_walk_rejects_symlinks_dot_components_and_shared_ancestry() {
        let (root, mut ssh, _) = setup();
        let material_root = root.path().join("ssh");
        let alias = root.path().join("alias");
        symlink(root.path(), &alias).unwrap();
        for path in [
            alias,
            root.path().join("../"),
            PathBuf::from("/tmp"),
            PathBuf::from("relative"),
        ] {
            ssh.working_directory = path.to_string_lossy().into_owned();
            assert!(prepare(&material_root, &ssh).is_err());
        }
    }
    #[test]
    fn key_input_rejects_empty_nul_and_excess_size_without_writing() {
        let (root, ssh, _) = setup();
        for bad in [String::new(), "secret\0sentinel".into(), "x".repeat(65537)] {
            let (mut material, _, _) = prepare(&root.path().join("ssh"), &ssh).unwrap();
            assert!(material.install_key(SensitiveString::new(bad)).is_err());
            assert!(!entries(&material.dir).unwrap().contains(&"identity".into()));
            material.finalize(CleanupEvidence::NotStarted).unwrap();
        }
    }
    #[test]
    fn port_22_uses_standard_host_token_and_no_tofu() {
        let (root, mut ssh, _) = setup();
        ssh.destination.port = 22;
        let hosts = root.path().join("ssh/host_keys.json");
        let text = std::fs::read_to_string(&hosts)
            .unwrap()
            .replace("2222", "22");
        std::fs::write(hosts, text).unwrap();
        let (mut material, _, _) = prepare(&root.path().join("ssh"), &ssh).unwrap();
        let mut text = String::new();
        open_at(&material.dir, "known_hosts", false)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert!(text.starts_with("backup.example.test ssh-ed25519 "));
        material.finalize(CleanupEvidence::NotStarted).unwrap();
    }
}
