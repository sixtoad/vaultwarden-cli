//! Offline, provider-owned companion enrollment. This is separate from agent pairings.
use crate::access::{approval_v2, ports::SessionError};
use rustls::pki_types::{CertificateDer, UnixTime, pem::PemObject};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::Path,
    sync::Arc,
};
use zeroize::Zeroizing;

pub const STORE_FILE: &str = "companion-identities.json";
const MAX_IDENTITIES: usize = 64;
/// Retired biometric key ids. When the list is full, NEW enrollments (first
/// enrollment and re-enrollment) are refused, so no key id is ever forgotten
/// to make room for an enrollment. A revocation is never refused for the
/// bound: it forgets the OLDEST retired id instead. Forgetting cannot reopen
/// that key while the list stays full (enrollment is refused), and every
/// enrollment needs the device certificate, a fresh password and proof of
/// possession anyway, so a forgotten id grants nothing a fresh key would not.
/// 256 ids (about 17 KiB) keep the registry well under its 64 KiB read limit.
const MAX_RETIRED_KEYS: usize = 256;
/// Touch ID key-management audit entries kept (oldest dropped first).
const MAX_BIOMETRIC_AUDIT: usize = 64;
/// The registry reader refuses larger files; never write one.
const MAX_REGISTRY_BYTES: usize = 65536;
/// Highest registry format this provider reads. Writers emit the lowest
/// version that represents the content: version 2 (byte-compatible with the
/// previous release) unless Touch ID state or audit exists, then version 3.
const REGISTRY_VERSION: u8 = 3;
const STOPPED_PROVIDER_ATTEMPTS: u32 = 50;
const STOPPED_PROVIDER_RETRY: std::time::Duration = std::time::Duration::from_millis(10);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolledCompanion {
    pub fingerprint: String,
    pub label: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    version: u8,
    identities: Vec<EnrolledCompanion>,
    #[serde(default)]
    revoked: Vec<EnrolledCompanion>,
    #[serde(default)]
    administrators: Vec<String>,
    #[serde(default)]
    audit: Vec<IdentityAudit>,
    /// v3: at most one production approval key per enabled approval client.
    /// Omitted when empty so a version 2 write stays readable by an older binary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    biometric: Vec<BiometricEnrollment>,
    /// v3: key ids replaced by re-enrollment, revoked, or removed with their
    /// device. Never accepted again for approval or enrollment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    retired_biometric_keys: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BiometricEnrollment {
    fingerprint: String,
    key_id: String,
    /// Unpadded base64url of the 65-byte uncompressed SEC1 P-256 point.
    public_key: String,
    enrolled_generation: u64,
}
impl BiometricEnrollment {
    fn decoded(&self) -> Option<Vec<u8>> {
        use base64::Engine;
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&self.public_key)
            .ok()?;
        (approval_v2::valid_public_key(&key) && approval_v2::key_id(&key) == self.key_id)
            .then_some(key)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityAudit {
    /// The approval client acted on.
    fingerprint: String,
    /// `local_owner` or the acting approval client's fingerprint.
    actor: String,
    action: IdentityAction,
    /// v3, Touch ID actions only: the key enrolled or revoked. Absent in
    /// older records, which stay readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IdentityAction {
    GrantedAdministrator,
    Revoked,
    BiometricEnrolled,
    BiometricRevoked,
}
impl IdentityAction {
    fn biometric(self) -> bool {
        matches!(self, Self::BiometricEnrolled | Self::BiometricRevoked)
    }
}

fn unavailable<T>(_: T) -> SessionError {
    SessionError::BackendUnavailable
}

pub(crate) fn private_directory(path: &Path) -> Result<(), SessionError> {
    if !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
        || path
            .as_os_str()
            .as_encoded_bytes()
            .split(|b| *b == b'/')
            .any(|part| part == b"." || part == b"..")
    {
        return Err(SessionError::BackendUnavailable);
    }
    let owner = unsafe { libc::geteuid() };
    for ancestor in path.ancestors() {
        let meta = std::fs::symlink_metadata(ancestor).map_err(unavailable)?;
        if !meta.is_dir() || (meta.uid() != owner && meta.uid() != 0) {
            return Err(SessionError::BackendUnavailable);
        }
        if ancestor == path {
            if meta.uid() != owner || meta.mode() & 0o7777 != 0o700 {
                return Err(SessionError::BackendUnavailable);
            }
        } else if meta.mode() & 0o022 != 0 && !(meta.uid() == 0 && meta.mode() & 0o1000 != 0) {
            return Err(SessionError::BackendUnavailable);
        }
    }
    Ok(())
}

fn private_open(path: &Path, write: bool) -> Result<File, SessionError> {
    #[cfg(target_os = "macos")]
    let _checked = super::native::platform::open_no_writers(path, false)
        .map_err(|_error| SessionError::BackendUnavailable)?;
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(unavailable)?;
    #[cfg(target_os = "macos")]
    super::native::platform::no_acl(&file).map_err(|_error| SessionError::BackendUnavailable)?;
    let meta = file.metadata().map_err(unavailable)?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
    {
        return Err(SessionError::BackendUnavailable);
    }
    Ok(file)
}
pub(crate) fn private_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, SessionError> {
    let file = private_open(path, false)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(65537)
        .read_to_end(&mut bytes)
        .map_err(unavailable)?;
    if bytes.len() > 65536 {
        return Err(SessionError::BackendUnavailable);
    }
    Ok(bytes)
}
pub(crate) fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
pub(crate) fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn certificate_fingerprint(path: &Path) -> Result<String, SessionError> {
    let bytes = private_file(path)?;
    let cert = CertificateDer::from_pem_slice(&bytes).map_err(unavailable)?;
    Ok(fingerprint(&cert))
}
pub(crate) fn verifier(
    ca: &Path,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>, SessionError> {
    crate::install_rustls_crypto_provider();
    let bytes = private_file(ca)?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&bytes) {
        roots.add(cert.map_err(unavailable)?).map_err(unavailable)?;
    }
    rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(unavailable)
}
fn registry(path: &Path) -> Result<Registry, SessionError> {
    private_directory(path.parent().ok_or(SessionError::BackendUnavailable)?)?;
    let bytes = private_file(path)?;
    let registry: Registry = serde_json::from_slice(&bytes).map_err(unavailable)?;
    let mut seen = std::collections::HashSet::new();
    let mut admins = std::collections::HashSet::new();
    if !matches!(registry.version, 1..=REGISTRY_VERSION)
        || (registry.version == 1
            && (!registry.revoked.is_empty()
                || !registry.administrators.is_empty()
                || !registry.audit.is_empty()))
        || registry.identities.len() + registry.revoked.len() > MAX_IDENTITIES
        || registry
            .identities
            .iter()
            .chain(&registry.revoked)
            .any(|entry| {
                !valid_fingerprint(&entry.fingerprint)
                    || !seen.insert(&entry.fingerprint)
                    || !valid_label(&entry.label)
            })
        || registry.administrators.iter().any(|fp| {
            !admins.insert(fp) || !registry.identities.iter().any(|i| &i.fingerprint == fp)
        })
        || registry
            .audit
            .iter()
            .filter(|e| !e.action.biometric())
            .count()
            > MAX_IDENTITIES * 2
        || registry
            .audit
            .iter()
            .filter(|e| e.action.biometric())
            .count()
            > MAX_BIOMETRIC_AUDIT
        || registry.audit.iter().any(|e| {
            !valid_fingerprint(&e.fingerprint)
                || (e.actor != "local_owner" && !valid_fingerprint(&e.actor))
                || e.action.biometric() != e.key_id.is_some()
                || e.key_id.as_ref().is_some_and(|id| !valid_fingerprint(id))
        })
        || !valid_biometric(&registry)
    {
        return Err(SessionError::BackendUnavailable);
    }
    Ok(registry)
}
fn valid_biometric(registry: &Registry) -> bool {
    if registry.version < 3 {
        return registry.biometric.is_empty()
            && registry.retired_biometric_keys.is_empty()
            && !registry.audit.iter().any(|e| e.action.biometric());
    }
    let mut devices = std::collections::HashSet::new();
    let mut keys = std::collections::HashSet::new();
    registry.retired_biometric_keys.len() <= MAX_RETIRED_KEYS
        && registry
            .retired_biometric_keys
            .iter()
            .all(|id| valid_fingerprint(id) && keys.insert(id.as_str()))
        && registry.biometric.iter().all(|entry| {
            devices.insert(entry.fingerprint.as_str())
                && keys.insert(entry.key_id.as_str())
                && registry
                    .identities
                    .iter()
                    .any(|identity| identity.fingerprint == entry.fingerprint)
                && entry.decoded().is_some()
        })
}
/// The current production approval key of an ENABLED approval client.
pub(crate) fn biometric_key(
    path: &Path,
    fingerprint: &str,
) -> Result<Option<approval_v2::EnrolledKey>, SessionError> {
    let registry = registry(path)?;
    if !registry
        .identities
        .iter()
        .any(|identity| identity.fingerprint == fingerprint)
    {
        return Ok(None);
    }
    Ok(registry
        .biometric
        .iter()
        .find(|entry| entry.fingerprint == fingerprint)
        .and_then(|entry| {
            Some(approval_v2::EnrolledKey {
                key_id: entry.key_id.clone(),
                public_key: entry.decoded()?,
            })
        }))
}
/// Caller holds the companion identity commit gate. Atomically replaces the
/// device's key; the previous key id is retired permanently in the same write.
pub(crate) fn enroll_biometric_online(
    root: &Path,
    fingerprint: &str,
    public_key: &[u8],
    generation: u64,
) -> Result<String, SessionError> {
    use base64::Engine;
    if !approval_v2::valid_public_key(public_key) {
        return Err(SessionError::InvalidRequest);
    }
    let key_id = approval_v2::key_id(public_key);
    let mut registry = registry(&root.join(STORE_FILE))?;
    if !registry
        .identities
        .iter()
        .any(|identity| identity.fingerprint == fingerprint)
        || registry.retired_biometric_keys.contains(&key_id)
        || registry
            .biometric
            .iter()
            .any(|entry| entry.key_id == key_id)
    {
        return Err(SessionError::InvalidRequest);
    }
    // Full: refuse every new enrollment rather than forget a retired id.
    if registry.retired_biometric_keys.len() >= MAX_RETIRED_KEYS {
        return Err(SessionError::BackendUnavailable);
    }
    retire_biometric(&mut registry, fingerprint);
    registry.biometric.push(BiometricEnrollment {
        fingerprint: fingerprint.into(),
        key_id: key_id.clone(),
        public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key),
        enrolled_generation: generation,
    });
    biometric_audit(
        &mut registry,
        fingerprint,
        fingerprint,
        IdentityAction::BiometricEnrolled,
        &key_id,
    );
    persist_registry(root, registry)?;
    Ok(key_id)
}
/// Caller holds the companion identity commit gate. Disables Touch ID for the
/// device (the device stays enrolled); the key id is retired permanently.
/// `actor` is the device itself or an administrator.
pub(crate) fn revoke_biometric_online(
    root: &Path,
    fingerprint: &str,
    actor: &str,
) -> Result<Option<String>, SessionError> {
    let mut registry = registry(&root.join(STORE_FILE))?;
    let retired = retire_biometric(&mut registry, fingerprint);
    if let Some(key_id) = &retired {
        forget_oldest_retired(&mut registry);
        biometric_audit(
            &mut registry,
            fingerprint,
            actor,
            IdentityAction::BiometricRevoked,
            key_id,
        );
        persist_revocation(root, registry)?;
    }
    Ok(retired)
}
fn retire_biometric(registry: &mut Registry, fingerprint: &str) -> Option<String> {
    let position = registry
        .biometric
        .iter()
        .position(|entry| entry.fingerprint == fingerprint)?;
    let old = registry.biometric.swap_remove(position);
    registry.retired_biometric_keys.push(old.key_id.clone());
    Some(old.key_id)
}
/// A full retired list never blocks a revocation (see MAX_RETIRED_KEYS).
fn forget_oldest_retired(registry: &mut Registry) {
    let excess = registry
        .retired_biometric_keys
        .len()
        .saturating_sub(MAX_RETIRED_KEYS);
    registry.retired_biometric_keys.drain(..excess);
}
fn biometric_audit(
    registry: &mut Registry,
    fingerprint: &str,
    actor: &str,
    action: IdentityAction,
    key_id: &str,
) {
    registry.audit.push(IdentityAudit {
        fingerprint: fingerprint.into(),
        actor: actor.into(),
        action,
        key_id: Some(key_id.into()),
    });
    if registry
        .audit
        .iter()
        .filter(|e| e.action.biometric())
        .count()
        > MAX_BIOMETRIC_AUDIT
        && let Some(oldest) = registry.audit.iter().position(|e| e.action.biometric())
    {
        registry.audit.remove(oldest);
    }
}
pub(crate) fn enrolled(path: &Path) -> Result<Vec<EnrolledCompanion>, SessionError> {
    Ok(registry(path)?.identities)
}
pub(crate) fn management_records(
    path: &Path,
) -> Result<Vec<(EnrolledCompanion, bool, bool)>, SessionError> {
    let registry = registry(path)?;
    let mut result = registry
        .identities
        .into_iter()
        .map(|entry| {
            let admin = registry.administrators.contains(&entry.fingerprint);
            (entry, false, admin)
        })
        .collect::<Vec<_>>();
    result.extend(
        registry
            .revoked
            .into_iter()
            .map(|entry| (entry, true, false)),
    );
    Ok(result)
}
/// Current key id per enabled approval client.
pub(crate) fn biometric_key_ids(
    path: &Path,
) -> Result<std::collections::HashMap<String, String>, SessionError> {
    Ok(registry(path)?
        .biometric
        .into_iter()
        .map(|entry| (entry.fingerprint, entry.key_id))
        .collect())
}
pub(crate) fn administrator(path: &Path, fingerprint: &str) -> bool {
    registry(path).is_ok_and(|r| r.administrators.iter().any(|fp| fp == fingerprint))
}
/// Explicit local-owner grant. Enrollment alone never grants administration.
pub fn grant_administrator(root: &Path, fingerprint: &str) -> Result<(), SessionError> {
    let _lock = stopped_provider(root)?;
    let mut registry = registry(&root.join(STORE_FILE))?;
    if !registry
        .identities
        .iter()
        .any(|i| i.fingerprint == fingerprint)
    {
        return Err(SessionError::InvalidRequest);
    }
    if !registry.administrators.iter().any(|fp| fp == fingerprint) {
        registry.administrators.push(fingerprint.into());
        registry.audit.push(IdentityAudit {
            fingerprint: fingerprint.into(),
            actor: "local_owner".into(),
            action: IdentityAction::GrantedAdministrator,
            key_id: None,
        });
        persist_registry(root, registry)?;
    }
    Ok(())
}
/// Caller holds the companion management gate; offline writers require stopped provider.
pub(crate) fn revoke_online(
    root: &Path,
    fingerprint: &str,
    actor: &str,
) -> Result<(), SessionError> {
    let mut registry = registry(&root.join(STORE_FILE))?;
    if registry
        .revoked
        .iter()
        .any(|entry| entry.fingerprint == fingerprint)
    {
        return Ok(());
    }
    let position = registry
        .identities
        .iter()
        .position(|entry| entry.fingerprint == fingerprint)
        .ok_or(SessionError::InvalidRequest)?;
    let entry = registry.identities.remove(position);
    registry.revoked.push(entry);
    registry.administrators.retain(|fp| fp != fingerprint);
    // Device revocation removes its approval key in the same atomic write.
    // A full retired list never blocks revocation (see MAX_RETIRED_KEYS).
    retire_biometric(&mut registry, fingerprint);
    forget_oldest_retired(&mut registry);
    registry.audit.push(IdentityAudit {
        fingerprint: fingerprint.into(),
        actor: actor.into(),
        action: IdentityAction::Revoked,
        key_id: None,
    });
    persist_revocation(root, registry)
}
fn valid_label(label: &str) -> bool {
    !label.is_empty() && label.len() <= 128 && !label.chars().any(char::is_control)
}
fn stopped_provider(root: &Path) -> Result<File, SessionError> {
    private_directory(root)?;
    let lock = private_open(&root.join(".provider-state.lock"), true)?;
    // A child spawned between our open and its exec briefly shares the lock;
    // a running provider holds it far longer than this bounded wait.
    for _ in 0..STOPPED_PROVIDER_ATTEMPTS {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(lock);
        }
        std::thread::sleep(STOPPED_PROVIDER_RETRY);
    }
    Err(SessionError::BackendUnavailable)
}
fn read_or_initial(root: &Path) -> Result<Registry, SessionError> {
    let path = root.join(STORE_FILE);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Registry {
            version: REGISTRY_VERSION,
            identities: Vec::new(),
            revoked: Vec::new(),
            administrators: Vec::new(),
            audit: Vec::new(),
            biometric: Vec::new(),
            retired_biometric_keys: Vec::new(),
        }),
        _ => registry(&path),
    }
}
#[cfg(all(test, target_os = "linux"))]
fn persist(root: &Path, identities: Vec<EnrolledCompanion>) -> Result<(), SessionError> {
    persist_registry(
        root,
        Registry {
            version: REGISTRY_VERSION,
            identities,
            revoked: Vec::new(),
            administrators: Vec::new(),
            audit: Vec::new(),
            biometric: Vec::new(),
            retired_biometric_keys: Vec::new(),
        },
    )
}
/// A revocation is never refused for size: if the file would exceed the read
/// limit, the oldest Touch ID audit entries and then the oldest retired key
/// ids are forgotten first (see MAX_RETIRED_KEYS for why that is safe).
fn persist_revocation(root: &Path, mut registry: Registry) -> Result<(), SessionError> {
    while serialize(&mut registry)?.len() > MAX_REGISTRY_BYTES {
        if let Some(oldest) = registry.audit.iter().position(|e| e.action.biometric()) {
            registry.audit.remove(oldest);
        } else if !registry.retired_biometric_keys.is_empty() {
            registry.retired_biometric_keys.remove(0);
        } else {
            break;
        }
    }
    persist_registry(root, registry)
}
fn serialize(registry: &mut Registry) -> Result<Vec<u8>, SessionError> {
    registry.version = if registry.biometric.is_empty()
        && registry.retired_biometric_keys.is_empty()
        && !registry.audit.iter().any(|e| e.action.biometric())
    {
        2
    } else {
        3
    };
    serde_json::to_vec(registry).map_err(unavailable)
}
fn persist_registry(root: &Path, mut registry: Registry) -> Result<(), SessionError> {
    let bytes = serialize(&mut registry)?;
    if bytes.len() > MAX_REGISTRY_BYTES {
        return Err(SessionError::BackendUnavailable);
    }
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(unavailable)?;
    let temporary = root.join(format!(".companion-{}.new", fingerprint(&nonce)));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(unavailable)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(unavailable)?;
        std::fs::rename(&temporary, root.join(STORE_FILE)).map_err(unavailable)?;
        File::open(root)
            .and_then(|dir| dir.sync_all())
            .map_err(unavailable)
    })();
    if result.is_err() {
        let _ignored = std::fs::remove_file(&temporary);
    }
    result
}
/// Requires an initialized provider directory and a stopped provider. Only a
/// CA-valid client leaf with an explicit trusted-console label can be enrolled.
pub fn enroll(
    root: &Path,
    certificate: &Path,
    client_ca: &Path,
    label: &str,
) -> Result<String, SessionError> {
    if !valid_label(label) {
        return Err(SessionError::InvalidRequest);
    }
    let _lock = stopped_provider(root)?;
    let bytes = private_file(certificate)?;
    let chain = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(unavailable)?;
    let leaf = chain.first().ok_or(SessionError::InvalidRequest)?;
    verifier(client_ca)?
        .verify_client_cert(leaf, &chain[1..], UnixTime::now())
        .map_err(unavailable)?;
    let fingerprint = fingerprint(leaf);
    let mut registry = read_or_initial(root)?;
    if registry
        .identities
        .iter()
        .chain(&registry.revoked)
        .any(|entry| entry.fingerprint == fingerprint)
        || registry.identities.len() + registry.revoked.len() >= MAX_IDENTITIES
    {
        return Err(SessionError::InvalidRequest);
    }
    registry.identities.push(EnrolledCompanion {
        fingerprint: fingerprint.clone(),
        label: label.into(),
    });
    persist_registry(root, registry)?;
    Ok(fingerprint)
}
pub fn revoke(root: &Path, fingerprint: &str) -> Result<(), SessionError> {
    if !valid_fingerprint(fingerprint) {
        return Err(SessionError::InvalidRequest);
    }
    let _lock = stopped_provider(root)?;
    revoke_online(root, fingerprint, "local_owner")
}
pub fn list(root: &Path) -> Result<Vec<EnrolledCompanion>, SessionError> {
    enrolled(&root.join(STORE_FILE))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.path().join(".provider-state.lock"))
            .unwrap();
        root
    }
    #[test]
    fn companion_identity_private_atomic_closed_store_and_revocation() {
        let root = root();
        let fp = "a".repeat(64);
        persist(
            root.path(),
            vec![EnrolledCompanion {
                fingerprint: fp.clone(),
                label: "Mac".into(),
            }],
        )
        .unwrap();
        assert_eq!(list(root.path()).unwrap()[0].fingerprint, fp);
        assert_eq!(
            std::fs::metadata(root.path().join(STORE_FILE))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        let lock = stopped_provider(root.path()).unwrap();
        assert!(revoke(root.path(), &fp).is_err());
        drop(lock);
        revoke(root.path(), &fp).unwrap();
        assert!(list(root.path()).unwrap().is_empty());
        std::fs::write(
            root.path().join(STORE_FILE),
            b"{\"version\":1,\"identities\":[],\"extra\":true}",
        )
        .unwrap();
        assert!(list(root.path()).is_err());
    }
    #[test]
    fn companion_identity_rejects_symlink_hardlink_and_public_file() {
        let root = root();
        let path = root.path().join("file");
        std::fs::write(&path, "public").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(private_file(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(private_file(&path).is_ok());
        let other = root.path().join("other");
        std::os::unix::fs::symlink(&path, &other).unwrap();
        assert!(private_file(&other).is_err());
        std::fs::remove_file(&other).unwrap();
        std::fs::hard_link(&path, &other).unwrap();
        assert!(private_file(&path).is_err());
    }
    #[test]
    fn companion_identity_enrollment_requires_valid_client_chain_and_stopped_provider() {
        let root = root();
        let write = |name, bytes: &[u8]| {
            let path = root.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            path
        };
        let ca = write("ca.pem", include_bytes!("../../tests/companion-tls/ca.pem"));
        let cert = write(
            "client.pem",
            include_bytes!("../../tests/companion-tls/client.pem"),
        );
        let wrong = write(
            "wrong.pem",
            include_bytes!("../../tests/fixtures/provider-tls/replacement.pem"),
        );
        assert!(enroll(root.path(), &wrong, &ca, "Wrong CA").is_err());
        let lock = stopped_provider(root.path()).unwrap();
        assert!(enroll(root.path(), &cert, &ca, "Mac").is_err());
        drop(lock);
        let fp = enroll(root.path(), &cert, &ca, "Mac").unwrap();
        assert_eq!(fp, certificate_fingerprint(&cert).unwrap());
        assert!(enroll(root.path(), &cert, &ca, "Duplicate").is_err());
        revoke(root.path(), &fp).unwrap();
        assert!(list(root.path()).unwrap().is_empty());
    }
    #[test]
    fn companion_identity_rejects_unsafe_ancestors_fifo_and_duplicate_entries() {
        let root = root();
        let child = root.path().join("child");
        std::fs::create_dir(&child).unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(private_directory(&child).is_ok());
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(private_directory(&child).is_err());
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&child, &link).unwrap();
        assert!(private_directory(&link).is_err());
        assert!(private_directory(&root.path().join("./child")).is_err());
        let fifo = root.path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(private_file(&fifo).is_err());
        let entries = vec![
            EnrolledCompanion {
                fingerprint: "a".repeat(64),
                label: "One".into(),
            },
            EnrolledCompanion {
                fingerprint: "a".repeat(64),
                label: "Two".into(),
            },
        ];
        persist(root.path(), entries).unwrap();
        assert!(list(root.path()).is_err());
    }
    #[test]
    fn explicit_admin_grant_is_default_denied_and_revocation_is_permanent() {
        let root = root();
        let fp = "a".repeat(64);
        persist(
            root.path(),
            vec![
                EnrolledCompanion {
                    fingerprint: fp.clone(),
                    label: "Duplicate label".into(),
                },
                EnrolledCompanion {
                    fingerprint: "b".repeat(64),
                    label: "Duplicate label".into(),
                },
            ],
        )
        .unwrap();
        let path = root.path().join(STORE_FILE);
        assert!(!administrator(&path, &fp));
        assert!(grant_administrator(root.path(), &"c".repeat(64)).is_err());
        grant_administrator(root.path(), &fp).unwrap();
        assert!(administrator(&path, &fp));
        revoke(root.path(), &fp).unwrap();
        assert!(!administrator(&path, &fp));
        assert!(grant_administrator(root.path(), &fp).is_err());
        assert_eq!(list(root.path()).unwrap()[0].fingerprint, "b".repeat(64));
        let records = management_records(&path).unwrap();
        assert!(
            records
                .iter()
                .any(|(entry, revoked, admin)| entry.fingerprint == fp && *revoked && !admin)
        );
        let registry = registry(&path).unwrap();
        assert_eq!(registry.audit.len(), 2);
    }
    #[test]
    fn stopped_provider_waits_out_a_transient_lock_holder() {
        // A child spawned by another thread inherits the lock until it execs.
        let root = root();
        let held = stopped_provider(root.path()).unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            drop(held);
        });
        assert!(stopped_provider(root.path()).is_ok());
        release.join().unwrap();
    }
}
