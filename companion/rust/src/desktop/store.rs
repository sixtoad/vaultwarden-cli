//! The saved desktop provider configuration (desktop-approval-spec D-3):
//! endpoint, provider CA (DER), leaf pin, the protected client identity and
//! the recovery marker; no password, ticket or review. One JSON file, written
//! atomically with mode 0600 in a 0700 directory (Unix).
use super::identity::{hex, unhex, ClientIdentity};
use super::recovery::Recovery;
use super::rules::{valid_hex, Endpoint};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const FILE: &str = "configuration-v1.json";
const MAX_FILE: u64 = 262_144;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    Unreadable,
    Invalid,
    IdentityUnavailable,
}
impl StoreError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Unreadable => "provider_configuration_unreadable",
            Self::Invalid => "provider_configuration_invalid",
            Self::IdentityUnavailable => "provider_identity_unavailable",
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    version: u8,
    endpoint: String,
    ca: String,
    pin: String,
    /// `super::protect` over the identity JSON, hex.
    identity: String,
    #[serde(default)]
    recovery: Recovery,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityWire {
    key: String,
    chain: Vec<String>,
}

pub struct Saved {
    pub endpoint: Endpoint,
    pub ca: Vec<u8>,
    pub pin: String,
    pub identity: ClientIdentity,
    pub recovery: Recovery,
}

pub struct Store {
    directory: PathBuf,
}
impl Store {
    pub fn new(directory: PathBuf) -> Self {
        Self { directory }
    }
    /// `%APPDATA%\dev.vaultwarden.companionSlice\provider` on Windows,
    /// `$XDG_CONFIG_HOME` (else `~/.config`)`/dev.vaultwarden.companionSlice/provider`
    /// elsewhere. Only absolute bases are used.
    pub fn default_directory() -> Option<PathBuf> {
        let env = |key: &str| {
            std::env::var_os(key)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
        };
        let base = if cfg!(windows) {
            env("APPDATA")?
        } else {
            env("XDG_CONFIG_HOME").or_else(|| env("HOME").map(|h| h.join(".config")))?
        };
        Some(base.join("dev.vaultwarden.companionSlice").join("provider"))
    }
    fn file(&self) -> PathBuf {
        self.directory.join(FILE)
    }
    pub fn exists(&self) -> bool {
        self.file().exists()
    }
    pub fn load(&self) -> Result<Saved, StoreError> {
        use std::io::Read;
        let mut bytes = Zeroizing::new(Vec::new());
        std::fs::File::open(self.file())
            .and_then(|f| f.take(MAX_FILE + 1).read_to_end(&mut bytes))
            .map_err(|_| StoreError::Unreadable)?;
        if bytes.len() as u64 > MAX_FILE {
            return Err(StoreError::Invalid);
        }
        let wire: Wire = serde_json::from_slice(&bytes).map_err(|_| StoreError::Invalid)?;
        let endpoint = Endpoint::parse(&wire.endpoint).ok_or(StoreError::Invalid)?;
        let ca = unhex(&wire.ca).filter(|c| !c.is_empty() && c.len() <= super::identity::MAX_CA);
        if wire.version != 1 || !valid_hex(&wire.pin, 64) || !wire.recovery.valid() {
            return Err(StoreError::Invalid);
        }
        let ca = ca.ok_or(StoreError::Invalid)?;
        let identity =
            Self::open_identity(&wire.identity).ok_or(StoreError::IdentityUnavailable)?;
        Ok(Saved {
            endpoint,
            ca,
            pin: wire.pin,
            identity,
            recovery: wire.recovery,
        })
    }
    fn open_identity(sealed: &str) -> Option<ClientIdentity> {
        let plain = super::protect::unprotect(&unhex(sealed)?)?;
        let wire: IdentityWire = serde_json::from_slice(&plain).ok()?;
        let key = Zeroizing::new(unhex(&wire.key)?);
        let chain = wire
            .chain
            .iter()
            .map(|c| unhex(c))
            .collect::<Option<Vec<_>>>()?;
        (!key.is_empty() && !chain.is_empty() && chain.len() <= 8)
            .then_some(ClientIdentity { key, chain })
    }
    pub fn save(&self, saved: &Saved) -> Result<(), StoreError> {
        let identity = Zeroizing::new(
            serde_json::to_vec(&IdentityWire {
                key: hex(&saved.identity.key),
                chain: saved.identity.chain.iter().map(|c| hex(c)).collect(),
            })
            .map_err(|_| StoreError::Invalid)?,
        );
        let sealed = super::protect::protect(&identity).ok_or(StoreError::IdentityUnavailable)?;
        let bytes = Zeroizing::new(
            serde_json::to_vec(&Wire {
                version: 1,
                endpoint: saved.endpoint.url(),
                ca: hex(&saved.ca),
                pin: saved.pin.clone(),
                identity: hex(&sealed),
                recovery: saved.recovery.clone(),
            })
            .map_err(|_| StoreError::Invalid)?,
        );
        write_private(&self.directory, &self.file(), &bytes).map_err(|_| StoreError::Unreadable)
    }
    /// Persist only a new recovery marker over the loaded configuration.
    pub fn save_recovery(&self, mut saved: Saved, recovery: Recovery) -> Result<(), StoreError> {
        saved.recovery = recovery;
        self.save(&saved)
    }
}

pub(crate) fn write_private(directory: &Path, file: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(directory)?;
    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(std::io::ErrorKind::InvalidInput)?;
    let temporary = directory.join(format!(".{name}.{}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = options.open(&temporary).and_then(|mut f| {
        f.write_all(bytes)?;
        f.sync_all()
    });
    match result.and_then(|()| std::fs::rename(&temporary, file)) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            Err(error)
        }
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
