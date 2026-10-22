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
}
impl WriteJournal {
    #[must_use]
    pub fn path(root: &Path, server: &str, destination: &Destination) -> PathBuf {
        let server = server.trim_end_matches('/');
        let digest = Sha256::digest(format!(
            "{server}\0{}\0{}\0{}",
            destination.account_id, destination.folder_id, destination.reference
        ));
        root.join(format!(
            "create-{}.json",
            digest.iter().fold(String::new(), |mut output, byte| {
                use std::fmt::Write;
                write!(output, "{byte:02x}").expect("writing to String cannot fail");
                output
            })
        ))
    }
    /// # Errors
    /// Returns an error when validation, authorization, cryptography or backend access fails.
    pub fn begin(&self, root: &Path) -> Result<PathBuf> {
        ensure!(
            self.receipt.status == WriteStatus::Uncertain,
            "invalid initial write state"
        );
        fs::create_dir_all(root)?;
        let metadata = fs::symlink_metadata(root)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "unsafe journal directory"
        );
        #[cfg(unix)]
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        let path = Self::path(root, &self.server, &self.destination);
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
            .prefix(".create-")
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
}
