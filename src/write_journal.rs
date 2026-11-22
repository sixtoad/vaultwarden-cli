//! Durable metadata only. An uncertain attempt is never replayed.
use crate::secret_storage::{Destination, WriteReceipt, WriteStatus};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WriteJournal {
    pub server: String,
    pub destination: Destination,
    pub fields: Vec<String>,
    pub receipt: WriteReceipt,
    /// Present only for an update; create journals serialize exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update: Option<UpdateRecord>,
}
/// The item and the revision a human reviewed for one update attempt.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpdateRecord {
    pub item_id: String,
    pub expected_revision: String,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, byte| {
        use std::fmt::Write;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
        output
    })
}
/// Scheme and host compare case-insensitively; the path and a trailing slash do not matter.
fn normalized_server(server: &str) -> String {
    let server = server.trim_end_matches('/');
    match server.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            format!(
                "{}://{}{path}",
                scheme.to_ascii_lowercase(),
                authority.to_ascii_lowercase()
            )
        }
        None => server.to_owned(),
    }
}
/// Held while one update of an item runs; released when dropped.
pub struct UpdateLock {
    _file: File,
}
impl WriteJournal {
    /// Every update attempt for one server and item shares this file-name prefix.
    #[must_use]
    pub fn update_prefix(server: &str, item_id: &str) -> String {
        let server = normalized_server(server);
        format!(
            "update-{}-",
            hex(&Sha256::digest(format!("{server}\0{item_id}")))
        )
    }
    /// Refuses a new update while an earlier attempt for the item is uncertain.
    /// # Errors
    /// Returns an error when such an attempt exists or a journal cannot be read.
    pub fn ensure_no_uncertain_update(root: &Path, server: &str, item_id: &str) -> Result<()> {
        let prefix = Self::update_prefix(server, item_id);
        let entries = match fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let name = entry?.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(&prefix) && name.ends_with(".json") {
                ensure!(
                    Self::read(&root.join(name.as_ref()))?.receipt.status != WriteStatus::Uncertain,
                    "an earlier update of this item is uncertain; reconcile it before any further update"
                );
            }
        }
        Ok(())
    }
    /// Takes the item's exclusive update lock without waiting, then re-checks
    /// that no earlier attempt is uncertain. Hold it until the receipt is saved.
    /// # Errors
    /// Returns an error when another update of the item is running, an earlier
    /// attempt is uncertain, or the lock file cannot be opened safely.
    pub fn lock_update(root: &Path, server: &str, item_id: &str) -> Result<UpdateLock> {
        Self::private_root(root)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file =
            options.open(root.join(format!("{}.lock", Self::update_prefix(server, item_id))))?;
        fs4::FileExt::try_lock(&file).map_err(|_error| {
            anyhow::anyhow!("another update of this item is in progress; nothing was written")
        })?;
        Self::ensure_no_uncertain_update(root, server, item_id)?;
        Ok(UpdateLock { _file: file })
    }
    fn private_root(root: &Path) -> Result<()> {
        fs::create_dir_all(root)?;
        let metadata = fs::symlink_metadata(root)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "unsafe journal directory"
        );
        #[cfg(unix)]
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }
    fn slot(&self, root: &Path) -> PathBuf {
        match &self.update {
            Some(update) => root.join(format!(
                "{}{}.json",
                Self::update_prefix(&self.server, &update.item_id),
                self.receipt.attempt_id
            )),
            None => Self::path(root, &self.server, &self.destination),
        }
    }
    #[must_use]
    pub fn path(root: &Path, server: &str, destination: &Destination) -> PathBuf {
        let server = server.trim_end_matches('/');
        let digest = Sha256::digest(format!(
            "{server}\0{}\0{}\0{}",
            destination.account_id, destination.folder_id, destination.reference
        ));
        root.join(format!("create-{}.json", hex(&digest)))
    }
    /// # Errors
    /// Returns an error when validation, authorization, cryptography or backend access fails.
    pub fn begin(&self, root: &Path) -> Result<PathBuf> {
        ensure!(
            self.receipt.status == WriteStatus::Uncertain,
            "invalid initial write state"
        );
        Self::private_root(root)?;
        let path = self.slot(root);
        // The complete private file is durable before a no-clobber name is published.
        let temporary = self.write_temporary(root)?;
        temporary.persist_noclobber(&path).map_err(|_error| anyhow::anyhow!(
            "reference already has a write attempt; inspect and reconcile it before any further action"))?;
        File::open(root)?.sync_all()?;
        // Persist the new write-attempts directory entry itself before the caller can POST.
        File::open(
            root.parent()
                .ok_or_else(|| anyhow::anyhow!("invalid journal directory"))?,
        )?
        .sync_all()?;
        Ok(path)
    }
    fn write_temporary(&self, root: &Path) -> Result<tempfile::NamedTempFile> {
        let mut temporary = tempfile::Builder::new()
            .prefix(if self.update.is_some() {
                ".update-"
            } else {
                ".create-"
            })
            .suffix(".tmp")
            .tempfile_in(root)?;
        temporary.write_all(&serde_json::to_vec(self)?)?;
        temporary.as_file().sync_all()?;
        Ok(temporary)
    }
    /// # Errors
    /// Returns an error when validation, authorization, cryptography or backend access fails.
    pub fn save(&self, path: &Path) -> Result<()> {
        let root = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("invalid journal path"))?;
        self.write_temporary(root)?.persist(path)?;
        File::open(root)?.sync_all()?;
        Ok(())
    }
    /// # Errors
    /// Returns an error when validation, authorization, cryptography or backend access fails.
    pub fn read(path: &Path) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options.open(path)?;
        ensure!(file.metadata()?.is_file(), "invalid journal file");
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 65536, "invalid journal size");
        serde_json::from_slice(&bytes).map_err(|_error| anyhow::anyhow!("invalid write journal"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn durable_uncertain_receipt_blocks_restart_repetition_and_never_contains_values() {
        let root = tempfile::tempdir().unwrap();
        let journal = WriteJournal {
            server: "https://vault.example".into(),
            destination: Destination {
                account_id: "11111111-1111-1111-1111-111111111111".into(),
                folder: "homelab/production".into(),
                folder_id: "22222222-2222-2222-2222-222222222222".into(),
                reference: "homelab/production/github/token".into(),
            },
            fields: vec!["password".into()],
            receipt: WriteReceipt {
                attempt_id: "attempt".into(),
                item_id: None,
                status: WriteStatus::Uncertain,
            },
            update: None,
        };
        let path = WriteJournal::path(root.path(), &journal.server, &journal.destination);
        // An interrupted temporary write never publishes a partial journal.
        let stale = path.with_extension("attempt.tmp");
        std::fs::write(&stale, b"{torn").unwrap();
        let complete = journal.write_temporary(root.path()).unwrap();
        assert!(!path.exists());
        assert_eq!(
            WriteJournal::read(complete.path()).unwrap().receipt.status,
            WriteStatus::Uncertain
        );
        drop(complete);
        let directory = root.path().join("new-write-attempts");
        let competing = std::sync::Arc::new(std::sync::Barrier::new(2));
        // Spawn both contenders before joining: a lazy spawn/join sequence deadlocks the barrier.
        #[allow(clippy::needless_collect)]
        let contenders = (0..2)
            .map(|index| {
                let mut attempt = journal.clone();
                attempt.receipt.attempt_id = format!("competing-{index}");
                let directory = directory.clone();
                let barrier = competing.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    attempt.begin(&directory)
                })
            })
            .collect::<Vec<_>>();
        let results = contenders
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let published = WriteJournal::read(
            results
                .iter()
                .find_map(|result| result.as_ref().ok())
                .unwrap(),
        )
        .unwrap();
        assert!(published.receipt.attempt_id.starts_with("competing-"));
        assert!(journal.begin(&directory).is_err());
        let path = journal.begin(root.path()).unwrap();
        let mut equivalent = journal;
        equivalent.server.push('/');
        assert_eq!(
            path,
            WriteJournal::path(root.path(), &equivalent.server, &equivalent.destination)
        );
        assert!(equivalent.begin(root.path()).is_err());
        assert_eq!(
            WriteJournal::read(&path).unwrap().receipt.attempt_id,
            "attempt"
        );
        let recovered = WriteJournal::read(&path).unwrap();
        assert_eq!(recovered.receipt.status, WriteStatus::Uncertain);
        assert!(recovered.begin(root.path()).is_err());
        let mut created = recovered;
        created.receipt.item_id = Some("33333333-3333-3333-3333-333333333333".into());
        created.receipt.status = WriteStatus::CreatedUnverified;
        created.save(&path).unwrap();
        created.save(&path).unwrap(); // Recovery must survive an abandoned old fixed-name temporary file.
        assert_eq!(std::fs::read(&stale).unwrap(), b"{torn");
        assert_eq!(
            WriteJournal::read(&path).unwrap().receipt.status,
            WriteStatus::CreatedUnverified
        );
        assert!(
            !std::fs::read_to_string(path)
                .unwrap()
                .contains("secret-value-sentinel")
        );
    }
    #[test]
    fn update_attempts_get_private_slots_and_an_uncertain_one_blocks_the_item() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("write-attempts");
        let item = "33333333-3333-3333-3333-333333333333";
        let attempt = |id: &str| WriteJournal {
            server: "https://vault.example".into(),
            destination: Destination {
                account_id: "11111111-1111-1111-1111-111111111111".into(),
                folder: "homelab/production".into(),
                folder_id: "22222222-2222-2222-2222-222222222222".into(),
                reference: "homelab/production/github/token".into(),
            },
            fields: vec!["password".into()],
            receipt: WriteReceipt {
                attempt_id: id.into(),
                item_id: Some(item.into()),
                status: WriteStatus::Uncertain,
            },
            update: Some(UpdateRecord {
                item_id: item.into(),
                expected_revision: "2026-11-21T10:00:00Z".into(),
            }),
        };
        WriteJournal::ensure_no_uncertain_update(&directory, "https://vault.example", item)
            .unwrap();
        let mut first = attempt("first");
        let path = first.begin(&directory).unwrap();
        assert!(
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("update-")
        );
        assert_ne!(
            path,
            WriteJournal::path(&directory, &first.server, &first.destination)
        );
        for server in [
            "https://vault.example",
            "https://vault.example/",
            "HTTPS://Vault.EXAMPLE",
        ] {
            assert!(WriteJournal::ensure_no_uncertain_update(&directory, server, item).is_err());
        }
        WriteJournal::ensure_no_uncertain_update(
            &directory,
            "https://vault.example",
            "44444444-4444-4444-4444-444444444444",
        )
        .unwrap();
        first.receipt.status = WriteStatus::Verified;
        first.save(&path).unwrap();
        WriteJournal::ensure_no_uncertain_update(&directory, "https://vault.example", item)
            .unwrap();
        // A second attempt never clobbers the first, and the record round-trips.
        let second = attempt("second").begin(&directory).unwrap();
        assert_ne!(second, path);
        assert_eq!(WriteJournal::read(&path).unwrap().update, first.update);
        assert!(
            WriteJournal::ensure_no_uncertain_update(&directory, "https://vault.example", item)
                .is_err()
        );
        // The lock is exclusive per item (also across server spellings) and
        // re-checks the uncertain block after it is taken.
        let mut second_record = WriteJournal::read(&second).unwrap();
        second_record.receipt.status = WriteStatus::Failed;
        second_record.save(&second).unwrap();
        let held = WriteJournal::lock_update(&directory, "https://vault.example", item).unwrap();
        assert!(
            WriteJournal::lock_update(&directory, "https://VAULT.example/", item).is_err(),
            "a second holder"
        );
        WriteJournal::lock_update(
            &directory,
            "https://vault.example",
            "44444444-4444-4444-4444-444444444444",
        )
        .unwrap();
        drop(held);
        let third = attempt("third").begin(&directory).unwrap();
        assert!(WriteJournal::lock_update(&directory, "https://vault.example", item).is_err());
        std::fs::remove_file(third).unwrap();
        WriteJournal::lock_update(&directory, "https://vault.example", item).unwrap();
        // Create journals serialize exactly as before the update record existed.
        let mut create = attempt("create");
        create.update = None;
        assert!(!serde_json::to_string(&create).unwrap().contains("update"));
    }
}
