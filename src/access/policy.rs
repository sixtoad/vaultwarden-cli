//! Provider-owned constrained protected-operation policy.
//!
//! A draft selects a provider-owned image ID only. Paths and hashes are held
//! in the private registry, resolved by the provider, and snapshotted here.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::net::IpAddr;
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use super::{valid_operation_id, valid_sha256};

const MAX_DESCRIPTION_LEN: usize = 256;
const MAX_TARGETS: usize = 64;
const MAX_ARGUMENTS: usize = 32;
const MAX_CHOICES: usize = 64;
const MAX_CREDENTIALS: usize = 16;
const MAX_FIELD_MAPPINGS: usize = 8;
const MAX_TARGET_LEN: usize = 256;
const MAX_VALUE_LEN: usize = 256;
const MAX_PRELIMINARY_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationPolicyDraft {
    pub id: String,
    pub description: String,
    pub image_id: String,
    pub targets: Vec<String>,
    pub arguments: Vec<ArgumentSpec>,
    pub credentials: Vec<LoginCredentialDraft>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshOperation>,
}

/// Provider declaration that the pinned artifact was reviewed to contain no
/// interpreter, helper, plugin or runtime code dependencies. ELF inspection
/// cannot establish that behavioral promise on its own.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionProfile {
    ReviewedSelfContainedElf64V1,
}

/// Provider-private registry state; this story intentionally has no public
/// provisioning or inspection API.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovedImage {
    id: String,
    execution_root: String,
    path: String,
    sha256: String,
    profile: ExecutionProfile,
}

impl ApprovedImage {
    pub(crate) fn new(
        id: String,
        execution_root: String,
        path: String,
        sha256: String,
        profile: ExecutionProfile,
    ) -> Result<Self, PolicyValidationError> {
        let image = Self {
            id,
            execution_root,
            path,
            sha256,
            profile,
        };
        if !valid_operation_id(&image.id)
            || !valid_image_path(&image.execution_root)
            || !valid_image_path(&image.path)
            || !Path::new(&image.path)
                .strip_prefix(&image.execution_root)
                .is_ok_and(|relative| !relative.as_os_str().is_empty())
            || !valid_sha256(&image.sha256)
            || !executable_identity_matches(Path::new(&image.path), &image.sha256)
        {
            return Err(PolicyValidationError);
        }
        Ok(image)
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn validate_integrity(&self) -> Result<(), PolicyValidationError> {
        Self::new(
            self.id.clone(),
            self.execution_root.clone(),
            self.path.clone(),
            self.sha256.clone(),
            self.profile,
        )
        .map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArgumentSpec {
    Target,
    Choice { choices: Vec<String> },
    Integer { minimum: i64, maximum: i64 },
}

#[derive(Clone, Debug, Deserialize, Ord, PartialOrd, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LoginField {
    Username,
    Password,
    Custom { name: String },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoginFieldMapping {
    pub field: LoginField,
    pub environment: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialUse {
    Login,
    Ssh,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoginCredentialDraft {
    pub item_id: String,
    pub label: String,
    pub use_type: CredentialUse,
    pub field_mappings: Vec<LoginFieldMapping>,
}

/// Closed provider policy: no command, key path, options, or caller selectors.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshCredential {
    pub item_id: String,
    pub label: String,
    pub use_type: CredentialUse,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshDestination {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub resource_path: String,
    pub host_fingerprint: String,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshOperation {
    pub credential: SshCredential,
    pub working_directory: String,
    pub destination: SshDestination,
}
/// Secret-free authority shown at review and retained in audit history.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshReview {
    pub working_directory: String,
    pub destination: SshDestination,
}
impl SshOperation {
    fn review(&self) -> SshReview {
        SshReview {
            working_directory: self.working_directory.clone(),
            destination: self.destination.clone(),
        }
    }
}
fn normalize_host(value: &str) -> Option<String> {
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    let host = value.strip_suffix('.').unwrap_or(value);
    if host.is_empty()
        || host.len() > 253
        || host.split('.').all(|part| {
            part.bytes().all(|b| b.is_ascii_digit())
                || part
                    .strip_prefix("0x")
                    .or_else(|| part.strip_prefix("0X"))
                    .is_some_and(|hex| {
                        !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
                    })
        })
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return None;
    }
    Some(host.to_ascii_lowercase())
}
fn normalize_fingerprint(value: &str) -> Option<String> {
    let encoded = value.strip_prefix("SHA256:")?;
    let bytes = STANDARD_NO_PAD
        .decode(encoded)
        .or_else(|_| STANDARD.decode(encoded))
        .ok()?;
    (bytes.len() == 32).then(|| format!("SHA256:{}", STANDARD_NO_PAD.encode(bytes)))
}
fn valid_ssh_path(value: &str) -> bool {
    (value == "/" || valid_image_path(value))
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
}
fn valid_ssh_review(working_directory: &str, destination: &SshDestination) -> bool {
    valid_ssh_path(working_directory)
        && valid_ssh_path(&destination.resource_path)
        && normalize_host(&destination.host).is_some()
        && destination.port != 0
        && !destination.user.is_empty()
        && destination.user.len() <= 64
        && destination.user.as_bytes()[0].is_ascii_alphanumeric()
        && destination
            .user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        && normalize_fingerprint(&destination.host_fingerprint).is_some()
}
impl SshReview {
    pub(crate) fn target(&self) -> String {
        let d = &self.destination;
        let host = if d.host.contains(':') {
            format!("[{}]", d.host)
        } else {
            d.host.clone()
        };
        format!("{}@{}:{}{}", d.user, host, d.port, d.resource_path)
    }
    pub(crate) fn valid(&self) -> bool {
        valid_ssh_review(&self.working_directory, &self.destination)
            && normalize_host(&self.destination.host).as_ref() == Some(&self.destination.host)
            && normalize_fingerprint(&self.destination.host_fingerprint).as_ref()
                == Some(&self.destination.host_fingerprint)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(try_from = "StoredOperationPolicy")]
pub(crate) struct OperationPolicy {
    id: String,
    description: String,
    image: ResolvedImage,
    targets: Vec<String>,
    arguments: Vec<ArgumentSpec>,
    credentials: Vec<LoginCredentialDraft>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ssh: Option<SshOperation>,
    revision: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ResolvedImage {
    image_id: String,
    execution_root: String,
    path: String,
    sha256: String,
    profile: ExecutionProfile,
}

#[derive(Debug)]
pub(crate) struct PolicyValidationError;

impl fmt::Display for PolicyValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid operation policy")
    }
}
impl std::error::Error for PolicyValidationError {}

impl OperationPolicy {
    pub(crate) fn from_draft(
        mut draft: OperationPolicyDraft,
        approved: &ApprovedImage,
    ) -> Result<Self, PolicyValidationError> {
        validate_draft(&draft)?;
        if draft.image_id != approved.id {
            return Err(PolicyValidationError);
        }
        approved.validate_integrity()?;
        canonicalize_draft(&mut draft);
        let image = ResolvedImage {
            image_id: approved.id.clone(),
            execution_root: approved.execution_root.clone(),
            profile: approved.profile,
            path: approved.path.clone(),
            sha256: approved.sha256.clone(),
        };
        let revision = revision_for(&draft, &image);
        Ok(Self {
            id: draft.id,
            description: draft.description,
            image,
            targets: draft.targets,
            arguments: draft.arguments,
            credentials: draft.credentials,
            ssh: draft.ssh,
            revision,
        })
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }
    pub(crate) fn revision(&self) -> &str {
        &self.revision
    }
    pub(crate) fn image_id(&self) -> &str {
        &self.image.image_id
    }
    pub(crate) fn image_matches(&self, image: &ApprovedImage) -> bool {
        self.image.image_id == image.id
            && self.image.execution_root == image.execution_root
            && self.image.profile == image.profile
            && self.image.path == image.path
            && self.image.sha256 == image.sha256
    }
    pub(crate) fn execution_image(&self) -> super::ports::ExecutionImage<'_> {
        super::ports::ExecutionImage {
            root: Path::new(&self.image.execution_root),
            path: Path::new(&self.image.path),
            sha256: &self.image.sha256,
            profile: self.image.profile,
        }
    }
    pub(crate) fn ssh(&self) -> Option<&SshOperation> {
        self.ssh.as_ref()
    }
    pub(crate) fn login_bindings(&self) -> impl Iterator<Item = LoginBindingRef<'_>> {
        self.credentials.iter().map(|credential| LoginBindingRef {
            item_id: &credential.item_id,
            required_fields: credential
                .field_mappings
                .iter()
                .map(|mapping| mapping.field.clone())
                .collect(),
            mappings: &credential.field_mappings,
        })
    }
    pub(crate) fn validates_args(&self, values: &[String]) -> bool {
        if self.ssh.is_some() {
            return values.is_empty();
        }
        values.len() == self.arguments.len()
            && self
                .arguments
                .iter()
                .zip(values)
                .all(|(spec, value)| match spec {
                    ArgumentSpec::Target => self.targets.binary_search(value).is_ok(),
                    ArgumentSpec::Choice { choices } => choices.binary_search(value).is_ok(),
                    ArgumentSpec::Integer { minimum, maximum } => value
                        .parse::<i64>()
                        .ok()
                        .is_some_and(|number| number >= *minimum && number <= *maximum),
                })
    }
    pub(crate) fn normalize_args(
        &self,
        values: &[String],
    ) -> Result<Vec<String>, PolicyValidationError> {
        if values.iter().any(|v| v.len() > MAX_VALUE_LEN) || !self.validates_args(values) {
            return Err(PolicyValidationError);
        }
        self.arguments
            .iter()
            .zip(values)
            .map(|(spec, value)| match spec {
                ArgumentSpec::Integer { .. } => value
                    .parse::<i64>()
                    .map(|n| n.to_string())
                    .map_err(|_error| PolicyValidationError),
                _ => Ok(value.clone()),
            })
            .collect()
    }
    pub(crate) fn direct_review(
        &self,
        id: String,
        arguments: Vec<String>,
        expires_at_unix_seconds: u64,
    ) -> super::direct_request::DirectReview {
        use super::direct_request::*;
        let target = self
            .arguments
            .iter()
            .zip(&arguments)
            .find_map(|(spec, value)| matches!(spec, ArgumentSpec::Target).then(|| value.clone()))
            .unwrap_or_else(|| "No target argument".into());
        DirectReview {
            id,
            requester: "local human terminal".into(),
            operation: self.id.clone(),
            effect: self.description.clone(),
            target: self
                .ssh
                .as_ref()
                .map(|ssh| ssh.review().target())
                .unwrap_or(target),
            ssh: self.ssh.as_ref().map(SshOperation::review),
            arguments_digest: arguments_digest(&arguments),
            arguments,
            credentials: self
                .credentials
                .iter()
                .map(|c| ReviewCredential {
                    label: c.label.clone(),
                    use_type: c.use_type,
                })
                .chain(self.ssh.iter().map(|ssh| ReviewCredential {
                    label: ssh.credential.label.clone(),
                    use_type: ssh.credential.use_type,
                }))
                .collect(),
            executable_digest: self.image.sha256.clone(),
            policy_digest: self.revision.clone(),
            expires_at_unix_seconds,
            one_time: super::direct_request::ONE_TIME.into(),
            status: DirectStatus::Pending,
        }
    }
    pub(crate) fn validate_integrity(&self) -> Result<(), PolicyValidationError> {
        let image = ApprovedImage::new(
            self.image.image_id.clone(),
            self.image.execution_root.clone(),
            self.image.path.clone(),
            self.image.sha256.clone(),
            self.image.profile,
        )?;
        let rebuilt = Self::from_draft(
            OperationPolicyDraft {
                id: self.id.clone(),
                description: self.description.clone(),
                image_id: self.image.image_id.clone(),
                targets: self.targets.clone(),
                arguments: self.arguments.clone(),
                credentials: self.credentials.clone(),
                ssh: self.ssh.clone(),
            },
            &image,
        )?;
        if rebuilt.revision == self.revision {
            Ok(())
        } else {
            Err(PolicyValidationError)
        }
    }
}

pub(crate) struct LoginBindingRef<'a> {
    pub(crate) item_id: &'a str,
    pub(crate) required_fields: Vec<LoginField>,
    #[allow(dead_code)] // Consumed by supervised dispatch in Story 1.7.
    pub(crate) mappings: &'a [LoginFieldMapping],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredOperationPolicy {
    id: String,
    description: String,
    image: ResolvedImage,
    targets: Vec<String>,
    arguments: Vec<ArgumentSpec>,
    credentials: Vec<LoginCredentialDraft>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ssh: Option<SshOperation>,
    revision: String,
}

impl TryFrom<StoredOperationPolicy> for OperationPolicy {
    type Error = PolicyValidationError;
    fn try_from(stored: StoredOperationPolicy) -> Result<Self, Self::Error> {
        let image = ApprovedImage::new(
            stored.image.image_id.clone(),
            stored.image.execution_root.clone(),
            stored.image.path.clone(),
            stored.image.sha256.clone(),
            stored.image.profile,
        )?;
        let policy = Self::from_draft(
            OperationPolicyDraft {
                id: stored.id,
                description: stored.description,
                image_id: image.id.clone(),
                targets: stored.targets,
                arguments: stored.arguments,
                credentials: stored.credentials,
                ssh: stored.ssh,
            },
            &image,
        )?;
        if policy.revision == stored.revision {
            Ok(policy)
        } else {
            Err(PolicyValidationError)
        }
    }
}

fn validate_draft(draft: &OperationPolicyDraft) -> Result<(), PolicyValidationError> {
    if let Some(ssh) = &draft.ssh {
        return if valid_operation_id(&draft.id)
            && valid_display_text(&draft.description, MAX_DESCRIPTION_LEN)
            && valid_operation_id(&draft.image_id)
            && draft.targets.is_empty()
            && draft.arguments.is_empty()
            && draft.credentials.is_empty()
            && valid_item_id(&ssh.credential.item_id)
            && valid_display_text(&ssh.credential.label, MAX_DESCRIPTION_LEN)
            && ssh.credential.use_type == CredentialUse::Ssh
            && valid_ssh_review(&ssh.working_directory, &ssh.destination)
        {
            Ok(())
        } else {
            Err(PolicyValidationError)
        };
    }
    if !valid_operation_id(&draft.id)
        || !valid_display_text(&draft.description, MAX_DESCRIPTION_LEN)
        || !valid_operation_id(&draft.image_id)
        || draft.targets.is_empty()
        || draft.targets.len() > MAX_TARGETS
        || draft
            .targets
            .iter()
            .any(|target| !valid_value(target, MAX_TARGET_LEN))
        || has_duplicates(&draft.targets)
        || draft.arguments.len() > MAX_ARGUMENTS
        || !valid_arguments(&draft.arguments)
        || draft.credentials.is_empty()
        || draft.credentials.len() > MAX_CREDENTIALS
        || !valid_credentials(&draft.credentials)
    {
        Err(PolicyValidationError)
    } else {
        Ok(())
    }
}

fn valid_image_path(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        && value.len() <= MAX_VALUE_LEN
        && !value.ends_with('/')
        && value
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

// These provisioning/persistence checks are preliminary only. The execution
// adapter must independently verify descriptor traversal, ownership, modes,
// sealed bytes and the supported ELF profile before yielding a capability.
#[cfg(test)]
thread_local! {
    pub(crate) static TEST_IMAGE_HASH_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
fn executable_identity_matches(path: &Path, expected: &str) -> bool {
    let Some(metadata) = nonsymlink_regular(path) else {
        return false;
    };
    if !metadata.file_type().is_file() || metadata.mode() & 0o111 == 0 {
        return false;
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let Ok(file) = options.open(path) else {
        return false;
    };
    let Ok(opened) = file.metadata() else {
        return false;
    };
    if !opened.file_type().is_file()
        || opened.mode() & 0o111 == 0
        || opened.len() > MAX_PRELIMINARY_IMAGE_BYTES
    {
        return false;
    }
    let mut file = file.take(MAX_PRELIMINARY_IMAGE_BYTES + 1);
    let mut header = [0_u8; 16];
    if file.read_exact(&mut header).is_err()
        || header[..4] != *ELF_MAGIC
        || !matches!(header[4], 1 | 2)
        || !matches!(header[5], 1 | 2)
        || header[6] != 1
    {
        return false;
    }
    let mut digest = Sha256::new();
    digest.update(header);
    #[cfg(test)]
    TEST_IMAGE_HASH_BYTES.with(|count| count.set(count.get() + header.len() as u64));
    let mut total = header.len() as u64;
    let mut buffer = [0_u8; 8192];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                total += read as u64;
                if total > MAX_PRELIMINARY_IMAGE_BYTES {
                    return false;
                }
                digest.update(&buffer[..read]);
                #[cfg(test)]
                TEST_IMAGE_HASH_BYTES.with(|count| count.set(count.get() + read as u64));
            }
            Err(_) => return false,
        }
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        == expected
}

fn nonsymlink_regular(path: &Path) -> Option<fs::Metadata> {
    let components: Vec<_> = path.components().collect();
    let mut current = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(part) => current.push(part),
            _ => return None,
        }
        if matches!(component, Component::RootDir) {
            continue;
        }
        let metadata = fs::symlink_metadata(&current).ok()?;
        if metadata.file_type().is_symlink() {
            return None;
        }
        if index + 1 == components.len() {
            return Some(metadata);
        }
        if !metadata.is_dir() {
            return None;
        }
    }
    None
}

fn valid_arguments(arguments: &[ArgumentSpec]) -> bool {
    arguments
        .iter()
        .filter(|argument| matches!(argument, ArgumentSpec::Target))
        .count()
        == 1
        && arguments.iter().all(|argument| match argument {
            ArgumentSpec::Target => true,
            ArgumentSpec::Choice { choices } => {
                !choices.is_empty()
                    && choices.len() <= MAX_CHOICES
                    && choices
                        .iter()
                        .all(|choice| valid_value(choice, MAX_VALUE_LEN))
                    && !has_duplicates(choices)
            }
            ArgumentSpec::Integer { minimum, maximum } => minimum <= maximum,
        })
}

fn valid_credentials(credentials: &[LoginCredentialDraft]) -> bool {
    let ids: Vec<&str> = credentials
        .iter()
        .map(|credential| credential.item_id.as_str())
        .collect();
    !has_duplicates(&ids)
        && unique_credential_environments(credentials)
        && credentials.iter().all(|credential| {
            credential.use_type == CredentialUse::Login
                && valid_item_id(&credential.item_id)
                && valid_display_text(&credential.label, MAX_DESCRIPTION_LEN)
                && !credential.field_mappings.is_empty()
                && credential.field_mappings.len() <= MAX_FIELD_MAPPINGS
                && credential.field_mappings.iter().all(|mapping| {
                    valid_login_field(&mapping.field) && valid_environment(&mapping.environment)
                })
                && unique_fields(&credential.field_mappings)
                && unique_environments(&credential.field_mappings)
        })
}
fn valid_item_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}
fn valid_login_field(value: &LoginField) -> bool {
    match value {
        LoginField::Username | LoginField::Password => true,
        LoginField::Custom { name } => {
            valid_display_text(name, MAX_VALUE_LEN) && name != "vw-access"
        }
    }
}
fn valid_environment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            (index == 0 && (byte == b'_' || byte.is_ascii_uppercase()))
                || (index > 0
                    && (byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit()))
        })
        && !value.starts_with("LD_")
        && !value.starts_with("DYLD_")
        && !value.starts_with("VAULTWARDEN_")
        && !value.starts_with("BITWARDEN_")
        && !matches!(
            value,
            "PATH"
                | "LANG"
                | "LC_ALL"
                | "IFS"
                | "ENV"
                | "BASH_ENV"
                | "SHELLOPTS"
                | "GLIBC_TUNABLES"
                | "GCONV_PATH"
                | "LOCPATH"
                | "LIBPATH"
                | "SHLIB_PATH"
                | "RUNPATH"
        )
}
fn valid_display_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.contains('\0')
        && !value.chars().any(char::is_control)
}
fn valid_value(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes().all(|byte| byte.is_ascii_graphic())
}
fn has_duplicates<T: Ord>(values: &[T]) -> bool {
    let mut sorted: Vec<&T> = values.iter().collect();
    sorted.sort();
    sorted.windows(2).any(|pair| pair[0] == pair[1])
}
fn unique_fields(values: &[LoginFieldMapping]) -> bool {
    !has_duplicates(
        &values
            .iter()
            .map(|value| value.field.clone())
            .collect::<Vec<_>>(),
    )
}
fn unique_environments(values: &[LoginFieldMapping]) -> bool {
    !has_duplicates(
        &values
            .iter()
            .map(|value| value.environment.as_str())
            .collect::<Vec<_>>(),
    )
}
fn unique_credential_environments(values: &[LoginCredentialDraft]) -> bool {
    !has_duplicates(
        &values
            .iter()
            .flat_map(|credential| credential.field_mappings.iter())
            .map(|mapping| mapping.environment.as_str())
            .collect::<Vec<_>>(),
    )
}
fn canonicalize_draft(draft: &mut OperationPolicyDraft) {
    if let Some(ssh) = &mut draft.ssh {
        ssh.destination.host = normalize_host(&ssh.destination.host).expect("validated SSH host");
        ssh.destination.host_fingerprint = normalize_fingerprint(&ssh.destination.host_fingerprint)
            .expect("validated SSH fingerprint");
    }
    draft.targets.sort_unstable();
    for argument in &mut draft.arguments {
        if let ArgumentSpec::Choice { choices } = argument {
            choices.sort_unstable();
        }
    }
    draft
        .credentials
        .sort_by(|left, right| left.item_id.cmp(&right.item_id));
    for credential in &mut draft.credentials {
        credential.field_mappings.sort_by(|left, right| {
            left.field
                .cmp(&right.field)
                .then_with(|| left.environment.cmp(&right.environment))
        });
    }
}

fn revision_for(draft: &OperationPolicyDraft, image: &ResolvedImage) -> String {
    if let Some(ssh) = &draft.ssh {
        #[derive(Serialize)]
        struct SshProjection<'a> {
            version: u8,
            id: &'a str,
            image: &'a ResolvedImage,
            item_id: &'a str,
            use_type: CredentialUse,
            working_directory: &'a str,
            destination: &'a SshDestination,
        }
        return hex_digest(
            &serde_json::to_vec(&SshProjection {
                version: 3,
                id: &draft.id,
                image,
                item_id: &ssh.credential.item_id,
                use_type: ssh.credential.use_type,
                working_directory: &ssh.working_directory,
                destination: &ssh.destination,
            })
            .expect("canonical SSH projection serializes"),
        );
    }
    #[derive(Serialize)]
    struct Projection<'a> {
        version: u8,
        id: &'a str,
        image: &'a ResolvedImage,
        targets: &'a [String],
        arguments: &'a [ArgumentSpec],
        credentials: Vec<Credential<'a>>,
    }
    #[derive(Serialize)]
    struct Credential<'a> {
        item_id: &'a str,
        use_type: CredentialUse,
        field_mappings: &'a [LoginFieldMapping],
    }
    let credentials = draft
        .credentials
        .iter()
        .map(|credential| Credential {
            item_id: &credential.item_id,
            use_type: credential.use_type,
            field_mappings: &credential.field_mappings,
        })
        .collect();
    hex_digest(
        &serde_json::to_vec(&Projection {
            version: 2,
            id: &draft.id,
            image,
            targets: &draft.targets,
            arguments: &draft.arguments,
            credentials,
        })
        .expect("canonical projection serializes"),
    )
}
fn hex_digest(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
pub(crate) fn test_approved_image(root: &Path, id: &str) -> ApprovedImage {
    const IMAGE: &[u8] = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00\x01\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x40\x00\x00\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x78\x00\x00\x00\x00\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\xb8\x3c\x00\x00\x00\xbf\x00\x00\x00\x00\x0f\x05";
    let path = root.join("approved-image");
    if path.exists() {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(target_arch = "aarch64")]
    let native_image = {
        let mut bytes = IMAGE.to_vec();
        bytes[18..20].copy_from_slice(&183u16.to_le_bytes());
        bytes[120..132].copy_from_slice(&[
            0x00, 0x00, 0x80, 0xd2, 0xa8, 0x0b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
        ]);
        bytes
    };
    #[cfg(target_arch = "aarch64")]
    let image = native_image.as_slice();
    #[cfg(not(target_arch = "aarch64"))]
    let image = IMAGE;
    fs::write(&path, image).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
    ApprovedImage::new(
        id.into(),
        root.to_str().unwrap().into(),
        path.into_os_string().into_string().unwrap(),
        hex_digest(image),
        ExecutionProfile::ReviewedSelfContainedElf64V1,
    )
    .unwrap()
}

#[cfg(test)]
pub(crate) fn test_ssh_draft() -> OperationPolicyDraft {
    OperationPolicyDraft {
        id: "ssh-backup".into(),
        description: "Back up the fixed resource".into(),
        image_id: "deploy-image".into(),
        targets: vec![],
        arguments: vec![],
        credentials: vec![],
        ssh: Some(SshOperation {
            credential: SshCredential {
                item_id: "11111111-1111-1111-1111-111111111111".into(),
                label: "Backup SSH".into(),
                use_type: CredentialUse::Ssh,
            },
            working_directory: "/var/empty".into(),
            destination: SshDestination {
                host: "backup.example.test".into(),
                port: 2222,
                user: "backup".into(),
                resource_path: "/srv/archive".into(),
                host_fingerprint: format!("SHA256:{}", "A".repeat(43)),
            },
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_revision_projection_matches_explicit_v3_contract() {
        // Independent golden projection uses stable symbolic executable paths,
        // so omitting a constant field (SSH use or execution profile) is visible.
        let image = ResolvedImage {
            image_id: "deploy-image".into(),
            execution_root: "/opt/vw-access".into(),
            path: "/opt/vw-access/deploy".into(),
            sha256: "a".repeat(64),
            profile: ExecutionProfile::ReviewedSelfContainedElf64V1,
        };
        assert_eq!(
            revision_for(&test_ssh_draft(), &image),
            "a97fb6ff3bca64fb5339c76464e8b8b7da88e6022f7cac90598310d647e5e065"
        );
    }
    #[test]
    fn ssh_normalization_revision_review_and_persistence() {
        let root = root();
        let image = test_approved_image(root.path(), "deploy-image");
        let draft = test_ssh_draft();
        let baseline = OperationPolicy::from_draft(draft.clone(), &image).unwrap();
        let mut equivalent = draft.clone();
        let ssh = equivalent.ssh.as_mut().unwrap();
        ssh.destination.host = "BACKUP.Example.Test.".into();
        ssh.destination.host_fingerprint.push('=');
        assert_eq!(
            OperationPolicy::from_draft(equivalent, &image).unwrap(),
            baseline
        );
        assert_eq!(
            normalize_host("2001:0DB8:0000:0000:0000:0000:0000:0001"),
            Some("2001:db8::1".into())
        );
        assert_eq!(normalize_host("192.0.2.10"), Some("192.0.2.10".into()));
        let mut ipv6_draft = draft.clone();
        ipv6_draft.ssh.as_mut().unwrap().destination.host = "2001:db8::1".into();
        let ipv6 = OperationPolicy::from_draft(ipv6_draft.clone(), &image).unwrap();
        ipv6_draft.ssh.as_mut().unwrap().destination.host =
            "2001:0DB8:0000:0000:0000:0000:0000:0001".into();
        let expanded = OperationPolicy::from_draft(ipv6_draft, &image).unwrap();
        assert_eq!(expanded.revision(), ipv6.revision());
        assert_eq!(expanded, ipv6);
        let restored: OperationPolicy =
            serde_json::from_slice(&serde_json::to_vec(&expanded).unwrap()).unwrap();
        assert_eq!(restored, ipv6);
        let ipv6_review = restored.direct_review("request".into(), vec![], 100);
        assert_eq!(ipv6_review.target, "backup@[2001:db8::1]:2222/srv/archive");
        assert_eq!(
            ipv6_review.ssh.unwrap().destination,
            SshDestination {
                host: "2001:db8::1".into(),
                port: 2222,
                user: "backup".into(),
                resource_path: "/srv/archive".into(),
                host_fingerprint: format!("SHA256:{}", "A".repeat(43)),
            }
        );
        assert!(baseline.validate_integrity().is_ok());
        let bytes = serde_json::to_vec(&baseline).unwrap();
        assert_eq!(
            serde_json::from_slice::<OperationPolicy>(&bytes).unwrap(),
            baseline
        );
        assert!(baseline.login_bindings().next().is_none());
        assert!(baseline.normalize_args(&[]).unwrap().is_empty());
        for value in ["", "--host", "production", "ssh-key-sentinel"] {
            assert!(baseline.normalize_args(&[value.into()]).is_err());
        }
        let review = baseline.direct_review("request".into(), vec![], 100);
        assert_eq!(review.target, "backup@backup.example.test:2222/srv/archive");
        assert_eq!(review.one_time, super::super::direct_request::ONE_TIME);
        assert_eq!(
            review.ssh,
            Some(SshReview {
                working_directory: "/var/empty".into(),
                destination: SshDestination {
                    host: "backup.example.test".into(),
                    port: 2222,
                    user: "backup".into(),
                    resource_path: "/srv/archive".into(),
                    host_fingerprint: format!("SHA256:{}", "A".repeat(43)),
                },
            })
        );
        assert_eq!(
            review.credentials,
            vec![super::super::direct_request::ReviewCredential {
                label: "Backup SSH".into(),
                use_type: CredentialUse::Ssh
            }]
        );
        let encoded = serde_json::to_string(&review).unwrap();
        assert!(!encoded.contains("11111111"));
        for (pointer, value) in [
            ("/id", serde_json::json!("other")),
            (
                "/ssh/credential/item_id",
                serde_json::json!("22222222-2222-2222-2222-222222222222"),
            ),
            ("/ssh/working_directory", serde_json::json!("/srv")),
            (
                "/ssh/destination/host",
                serde_json::json!("other.example.test"),
            ),
            ("/ssh/destination/port", serde_json::json!(22)),
            ("/ssh/destination/user", serde_json::json!("other")),
            (
                "/ssh/destination/resource_path",
                serde_json::json!("/other"),
            ),
            (
                "/ssh/destination/host_fingerprint",
                serde_json::json!(format!("SHA256:{}", STANDARD_NO_PAD.encode([1; 32]))),
            ),
        ] {
            let mut changed = serde_json::to_value(&draft).unwrap();
            *changed.pointer_mut(pointer).unwrap() = value;
            let changed: OperationPolicyDraft = serde_json::from_value(changed).unwrap();
            let policy = OperationPolicy::from_draft(changed, &image).unwrap();
            assert_ne!(policy.revision(), baseline.revision(), "{pointer}");
            let mut tampered = serde_json::to_value(&baseline).unwrap();
            *tampered.pointer_mut(pointer).unwrap() = serde_json::to_value(&policy)
                .unwrap()
                .pointer(pointer)
                .unwrap()
                .clone();
            assert!(
                serde_json::from_value::<OperationPolicy>(tampered).is_err(),
                "{pointer}"
            );
        }
        for field in ["image_id", "execution_root", "path", "sha256"] {
            let mut changed = baseline.image.clone();
            match field {
                "image_id" => changed.image_id = "other".into(),
                "execution_root" => changed.execution_root = "/other".into(),
                "path" => changed.path = "/other/image".into(),
                _ => changed.sha256 = "b".repeat(64),
            }
            assert_ne!(
                revision_for(&draft, &changed),
                baseline.revision(),
                "{field}"
            );
        }
        let mut labels = draft;
        labels.description = "New description".into();
        labels.ssh.as_mut().unwrap().credential.label = "New label".into();
        assert_eq!(
            OperationPolicy::from_draft(labels, &image)
                .unwrap()
                .revision(),
            baseline.revision()
        );
    }
    #[test]
    fn ssh_rejects_each_invalid_authority_and_selector_independently() {
        let baseline = serde_json::to_value(test_ssh_draft()).unwrap();
        for (pointer, value) in [
            ("/ssh/credential/item_id", serde_json::json!("mutable-name")),
            ("/ssh/credential/use_type", serde_json::json!("login")),
            ("/ssh/credential/label", serde_json::json!("")),
            ("/ssh/working_directory", serde_json::json!("relative")),
            ("/ssh/destination/port", serde_json::json!(0)),
            ("/ssh/destination/user", serde_json::json!("-oProxyCommand")),
            ("/ssh/destination/user", serde_json::json!("root@other")),
            (
                "/ssh/destination/host_fingerprint",
                serde_json::json!("SHA256:AA"),
            ),
            (
                "/ssh/destination/host_fingerprint",
                serde_json::json!("MD5:aa:bb"),
            ),
            // Change only the algorithm prefix; keep valid base64 for 32 bytes.
            (
                "/ssh/destination/host_fingerprint",
                serde_json::json!(format!("MD5:{}", "A".repeat(43))),
            ),
            // Change only one base64 character; preserve the encoded length.
            (
                "/ssh/destination/host_fingerprint",
                serde_json::json!(format!("SHA256:?{}", "A".repeat(42))),
            ),
            // Valid SHA256/base64 envelope, one byte below/above the digest size.
            (
                "/ssh/destination/host_fingerprint",
                serde_json::json!(format!("SHA256:{}", STANDARD_NO_PAD.encode([0; 31]))),
            ),
            (
                "/ssh/destination/host_fingerprint",
                serde_json::json!(format!("SHA256:{}", STANDARD_NO_PAD.encode([0; 33]))),
            ),
            ("/targets", serde_json::json!(["generic"])),
            ("/arguments", serde_json::json!([{"type":"target"}])),
            (
                "/arguments",
                serde_json::json!([{"type":"integer","minimum":0,"maximum":9}]),
            ),
            (
                "/arguments",
                serde_json::json!([{"type":"choice","choices":["fixed"]}]),
            ),
            (
                "/credentials",
                serde_json::to_value(draft().credentials).unwrap(),
            ),
        ] {
            let mut bad = baseline.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            let bad: OperationPolicyDraft = serde_json::from_value(bad).unwrap();
            assert!(validate_draft(&bad).is_err(), "{pointer}");
        }
        for host in [
            "",
            "-host",
            "host:22",
            "ssh://host",
            "user@host",
            "[::1]",
            "::1%eth0",
            "127.1",
            "0177.0.0.1",
            "2130706433",
            "0x7f000001",
            "0x7f.0.0.1",
            "host..",
            "host/other",
            "host\n",
            "höst",
            "a_b",
        ] {
            let mut bad = test_ssh_draft();
            bad.ssh.as_mut().unwrap().destination.host = host.into();
            assert!(validate_draft(&bad).is_err(), "host {host:?}");
        }
        for path in [
            "", "relative", "/a/../b", "/a//b", "/a/./b", "/a/", "/a b", "/a;b", "/a%20b", "/a\nb",
            "~/b", "/a\\b",
        ] {
            for directory in [false, true] {
                let mut bad = test_ssh_draft();
                let ssh = bad.ssh.as_mut().unwrap();
                if directory {
                    ssh.working_directory = path.into()
                } else {
                    ssh.destination.resource_path = path.into()
                }
                assert!(validate_draft(&bad).is_err(), "{path:?}");
            }
        }
        for (parent, member) in [
            ("", "remote"),
            ("", "host"),
            ("", "key_path"),
            ("", "options"),
            ("", "working_directory"),
            ("/ssh", "remote"),
            ("/ssh", "host"),
            ("/ssh/destination", "command"),
            ("/ssh/destination", "key_path"),
            ("/ssh/destination", "options"),
            ("/ssh/destination", "working_directory"),
            ("", "command"),
            ("/ssh", "command"),
            ("/ssh", "key_path"),
            ("/ssh", "options"),
            ("/ssh", "trust_override"),
            ("/ssh/credential", "field_mappings"),
            ("/ssh/credential", "name"),
            ("/ssh/destination", "known_hosts"),
            ("/ssh/destination", "strict_host_key_checking"),
        ] {
            let mut bad = baseline.clone();
            bad.pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(member.into(), serde_json::json!("sentinel"));
            assert!(
                serde_json::from_value::<OperationPolicyDraft>(bad).is_err(),
                "{parent}/{member}"
            );
        }
        for pointer in [
            "/ssh/credential/item_id",
            "/ssh/credential/use_type",
            "/ssh/destination/host",
            "/ssh/destination/port",
            "/ssh/destination/user",
            "/ssh/destination/resource_path",
            "/ssh/destination/host_fingerprint",
            "/ssh/working_directory",
        ] {
            let (parent, member) = pointer.rsplit_once('/').unwrap();
            let mut bad = baseline.clone();
            bad.pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(member);
            assert!(
                serde_json::from_value::<OperationPolicyDraft>(bad).is_err(),
                "missing {pointer}"
            );
        }
        let serialized = serde_json::to_string(&test_ssh_draft()).unwrap();
        let duplicate = serialized.replace("\"port\":2222", "\"port\":2222,\"port\":22");
        assert!(serde_json::from_str::<OperationPolicyDraft>(&duplicate).is_err());
        let mut login = draft();
        login.credentials[0].use_type = CredentialUse::Ssh;
        assert!(validate_draft(&login).is_err());
    }
    const ITEM: &str = "11111111-1111-1111-1111-111111111111";
    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        root
    }
    fn draft() -> OperationPolicyDraft {
        OperationPolicyDraft {
            ssh: None,
            id: "deploy-homelab".into(),
            description: "Deploy".into(),
            image_id: "deploy-image".into(),
            targets: vec!["production".into(), "staging".into()],
            arguments: vec![
                ArgumentSpec::Target,
                ArgumentSpec::Choice {
                    choices: vec!["apply".into(), "plan".into()],
                },
            ],
            credentials: vec![LoginCredentialDraft {
                item_id: ITEM.into(),
                label: "login".into(),
                use_type: CredentialUse::Login,
                field_mappings: vec![LoginFieldMapping {
                    field: LoginField::Password,
                    environment: "DEPLOY_PASSWORD".into(),
                }],
            }],
        }
    }

    fn assert_invalid_draft(draft: OperationPolicyDraft) {
        assert!(validate_draft(&draft).is_err());
    }

    fn credential(item_id: String, environment: String) -> LoginCredentialDraft {
        LoginCredentialDraft {
            item_id,
            label: "login".into(),
            use_type: CredentialUse::Login,
            field_mappings: vec![LoginFieldMapping {
                field: LoginField::Password,
                environment,
            }],
        }
    }
    #[test]
    fn revision_is_stable_for_unordered_input_and_changes_for_authority() {
        let root = root();
        let image = test_approved_image(root.path(), "deploy-image");
        let first = OperationPolicy::from_draft(draft(), &image).unwrap();
        assert_eq!(first.revision().len(), 64);
        let mut canonical = draft();
        canonicalize_draft(&mut canonical);
        assert_eq!(
            revision_for(
                &canonical,
                &ResolvedImage {
                    image_id: "deploy-image".into(),
                    execution_root: "/opt/vw-access".into(),
                    profile: ExecutionProfile::ReviewedSelfContainedElf64V1,
                    path: "/opt/vw-access/deploy".into(),
                    sha256: "a".repeat(64),
                },
            ),
            "517d83ff82fac249a5f19c3306e77ae09af57468e73915273ae4f5f49642c99d"
        );
        let mut reordered = draft();
        reordered.targets.reverse();
        if let ArgumentSpec::Choice { choices } = &mut reordered.arguments[1] {
            choices.reverse();
        }
        assert_eq!(
            first.revision(),
            OperationPolicy::from_draft(reordered, &image)
                .unwrap()
                .revision()
        );
        let other = test_approved_image(root.path(), "other-image");
        let mut changed = draft();
        changed.image_id = "other-image".into();
        assert_ne!(
            first.revision(),
            OperationPolicy::from_draft(changed, &other)
                .unwrap()
                .revision()
        );
    }
    #[test]
    fn root_and_profile_are_mandatory_and_part_of_the_execution_binding() {
        let root = root();
        let nested = root.path().join("images");
        fs::create_dir(&nested).unwrap();
        let image = test_approved_image(&nested, "deploy-image");
        let policy = OperationPolicy::from_draft(draft(), &image).unwrap();
        let mut other_root = image.clone();
        other_root.execution_root = root.path().to_str().unwrap().into();
        assert!(other_root.validate_integrity().is_ok());
        assert!(!policy.image_matches(&other_root));
        assert_ne!(
            policy.revision(),
            OperationPolicy::from_draft(draft(), &other_root)
                .unwrap()
                .revision()
        );
        let execution = policy.execution_image();
        assert_eq!(execution.root, nested);
        assert_eq!(execution.path, Path::new(&image.path));
        assert_eq!(execution.sha256, image.sha256);
        assert_eq!(
            execution.profile,
            ExecutionProfile::ReviewedSelfContainedElf64V1
        );

        for field in ["execution_root", "profile"] {
            let mut stored_image = serde_json::to_value(&image).unwrap();
            stored_image.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<ApprovedImage>(stored_image).is_err());
            let mut stored_policy = serde_json::to_value(&policy).unwrap();
            stored_policy["image"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(serde_json::from_value::<OperationPolicy>(stored_policy).is_err());
        }
        let mut stored = serde_json::to_value(&image).unwrap();
        stored["profile"] = serde_json::json!("unreviewed_elf64");
        assert!(serde_json::from_value::<ApprovedImage>(stored).is_err());
        let mut stored = serde_json::to_value(&policy).unwrap();
        stored["image"]["profile"] = serde_json::json!("reviewed_self_contained_elf64_v2");
        assert!(serde_json::from_value::<OperationPolicy>(stored).is_err());
        let mut stored = serde_json::to_value(&policy).unwrap();
        stored["image"]["execution_root"] = serde_json::json!(root.path());
        assert!(serde_json::from_value::<OperationPolicy>(stored).is_err());
    }

    #[test]
    fn execution_root_must_be_canonical_and_contain_the_image() {
        let root = root();
        let image = test_approved_image(root.path(), "deploy-image");
        for invalid in [
            "relative".to_owned(),
            format!("{}/..", image.execution_root),
            image.path.clone(),
            format!("{}-other", image.execution_root),
        ] {
            assert!(
                ApprovedImage::new(
                    image.id.clone(),
                    invalid,
                    image.path.clone(),
                    image.sha256.clone(),
                    image.profile
                )
                .is_err()
            );
        }
        let (parent, leaf) = image.execution_root.rsplit_once('/').unwrap();
        for noncanonical in [
            format!("{}/.", image.execution_root),
            format!("{}/", image.execution_root),
            format!("{parent}//{leaf}"),
            format!("{}//", image.execution_root),
        ] {
            // Path containment normalizes these spellings, so it cannot mask
            // omission of the constructor's independent canonical-root guard.
            let relative = Path::new(&image.path).strip_prefix(&noncanonical).unwrap();
            assert!(!relative.as_os_str().is_empty());
            assert!(
                ApprovedImage::new(
                    image.id.clone(),
                    noncanonical.clone(),
                    image.path.clone(),
                    image.sha256.clone(),
                    image.profile,
                )
                .is_err(),
                "noncanonical root {noncanonical}"
            );
        }
    }

    #[test]
    fn preliminary_checks_reject_oversized_source_without_reading_it() {
        let root = root();
        let image = test_approved_image(root.path(), "deploy-image");
        fs::set_permissions(&image.path, fs::Permissions::from_mode(0o700)).unwrap();
        OpenOptions::new()
            .write(true)
            .open(&image.path)
            .unwrap()
            .set_len(MAX_PRELIMINARY_IMAGE_BYTES + 1)
            .unwrap();
        fs::set_permissions(&image.path, fs::Permissions::from_mode(0o500)).unwrap();
        assert!(!executable_identity_matches(
            Path::new(&image.path),
            &image.sha256
        ));
    }

    #[test]
    fn rejects_arbitrary_or_expanding_configuration() {
        let root = root();
        let image = test_approved_image(root.path(), "deploy-image");
        let mut bad = draft();
        bad.image_id = "/bin/sh".into();
        assert!(OperationPolicy::from_draft(bad, &image).is_err());
        let mut bad = draft();
        bad.credentials[0].field_mappings[0].environment = "PATH".into();
        assert!(OperationPolicy::from_draft(bad, &image).is_err());
        let mut bad = draft();
        bad.targets.push("staging".into());
        assert!(OperationPolicy::from_draft(bad, &image).is_err());
    }
    #[test]
    fn rejects_unknown_login_field_members_and_loader_controlled_destinations() {
        let mut encoded = serde_json::to_value(draft()).unwrap();
        encoded["credentials"][0]["field_mappings"][0]["field"] = serde_json::json!({
            "custom": {"name": "token", "unknown_selector": "x"}
        });
        assert!(serde_json::from_value::<OperationPolicyDraft>(encoded).is_err());

        for environment in [
            "LD_DEBUG_OUTPUT",
            "LD_PROFILE_OUTPUT",
            "LD_BIND_NOT",
            "DYLD_INSERT_LIBRARIES",
            "GLIBC_TUNABLES",
            "GCONV_PATH",
            "LOCPATH",
            "LIBPATH",
            "SHLIB_PATH",
            "RUNPATH",
        ] {
            let mut invalid = draft();
            invalid.credentials[0].field_mappings[0].environment = environment.into();
            assert_invalid_draft(invalid);
        }
    }
    #[test]
    fn stored_image_is_reverified() {
        let root = root();
        let image = test_approved_image(root.path(), "deploy-image");
        let policy = OperationPolicy::from_draft(draft(), &image).unwrap();
        fs::set_permissions(&image.path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(root.path().join("approved-image"), b"changed").unwrap();
        assert!(policy.validate_integrity().is_err());
    }

    #[test]
    fn approved_images_bind_id_path_and_digest_and_reverify_the_file() {
        let root = root();
        let image = test_approved_image(root.path(), "deploy-image");
        let policy = OperationPolicy::from_draft(draft(), &image).unwrap();
        assert!(image.validate_integrity().is_ok());
        assert!(policy.image_matches(&image));

        let different_id = ApprovedImage {
            id: "other-image".into(),
            path: image.path.clone(),
            sha256: image.sha256.clone(),
            ..image.clone()
        };
        assert!(!policy.image_matches(&different_id));

        let second_path = root.path().join("second-approved-image");
        fs::copy(&image.path, &second_path).unwrap();
        fs::set_permissions(&second_path, fs::Permissions::from_mode(0o500)).unwrap();
        let different_path = ApprovedImage {
            id: image.id.clone(),
            path: second_path.into_os_string().into_string().unwrap(),
            sha256: image.sha256.clone(),
            ..image.clone()
        };
        assert!(!policy.image_matches(&different_path));

        let different_digest = ApprovedImage {
            id: image.id.clone(),
            path: image.path.clone(),
            sha256: "0".repeat(64),
            ..image.clone()
        };
        assert!(!policy.image_matches(&different_digest));
        assert!(different_digest.validate_integrity().is_err());
    }

    #[test]
    fn image_path_and_identity_validation_rejects_all_untrusted_shapes() {
        assert!(valid_image_path("/opt/vw-access/image"));
        for path in [
            "relative/image",
            "/opt//image",
            "/opt/./image",
            "/opt/../image",
            "/opt/image/",
            &format!("/{}", "a".repeat(MAX_VALUE_LEN)),
        ] {
            assert!(!valid_image_path(path), "path {path:?} must be rejected");
        }

        let root = root();
        let image = test_approved_image(root.path(), "deploy-image");
        assert!(executable_identity_matches(
            Path::new(&image.path),
            &image.sha256
        ));
        assert!(!executable_identity_matches(
            Path::new(&image.path),
            &"0".repeat(64)
        ));

        let non_executable = root.path().join("not-executable");
        fs::copy(&image.path, &non_executable).unwrap();
        fs::set_permissions(&non_executable, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!executable_identity_matches(&non_executable, &image.sha256));
        assert!(!executable_identity_matches(root.path(), &image.sha256));

        let symlink = root.path().join("image-link");
        std::os::unix::fs::symlink(&image.path, &symlink).unwrap();
        assert!(!executable_identity_matches(&symlink, &image.sha256));

        for (name, invalid_header) in [
            (
                "bad-magic",
                b"BAD!\x02\x01\x01\0\0\0\0\0\0\0\0\0".as_slice(),
            ),
            (
                "bad-class",
                b"\x7fELF\x03\x01\x01\0\0\0\0\0\0\0\0\0".as_slice(),
            ),
            (
                "bad-endian",
                b"\x7fELF\x02\x03\x01\0\0\0\0\0\0\0\0\0".as_slice(),
            ),
            (
                "bad-version",
                b"\x7fELF\x02\x01\x02\0\0\0\0\0\0\0\0\0".as_slice(),
            ),
            ("short", b"\x7fELF".as_slice()),
        ] {
            let path = root.path().join(name);
            fs::write(&path, invalid_header).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(
                !executable_identity_matches(&path, &hex_digest(invalid_header)),
                "{name} must not be accepted as an executable image"
            );
        }
    }

    #[test]
    fn policy_exposes_exact_login_bindings_and_strictly_validates_arguments() {
        let root = root();
        let image = test_approved_image(root.path(), "deploy-image");
        let mut request = draft();
        request.arguments.push(ArgumentSpec::Integer {
            minimum: 7,
            maximum: 9,
        });
        request.credentials[0]
            .field_mappings
            .push(LoginFieldMapping {
                field: LoginField::Username,
                environment: "DEPLOY_USERNAME".into(),
            });
        let policy = OperationPolicy::from_draft(request, &image).unwrap();

        let bindings: Vec<_> = policy.login_bindings().collect();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].item_id, ITEM);
        assert_eq!(
            bindings[0].required_fields,
            vec![LoginField::Username, LoginField::Password]
        );

        for values in [
            vec!["production".into(), "apply".into(), "7".into()],
            vec!["staging".into(), "plan".into(), "9".into()],
        ] {
            assert!(policy.validates_args(&values));
        }
        for values in [
            vec!["production".into(), "apply".into()],
            vec!["unknown".into(), "apply".into(), "7".into()],
            vec!["production".into(), "destroy".into(), "7".into()],
            vec!["production".into(), "apply".into(), "6".into()],
            vec!["production".into(), "apply".into(), "10".into()],
            vec!["production".into(), "apply".into(), "not-a-number".into()],
        ] {
            assert!(!policy.validates_args(&values));
        }
    }

    #[test]
    fn draft_accepts_exact_authority_component_limits() {
        let mut targets_at_limit = draft();
        targets_at_limit.targets = (0..MAX_TARGETS)
            .map(|index| format!("target-{index}"))
            .collect();
        assert!(validate_draft(&targets_at_limit).is_ok());

        let mut arguments_at_limit = draft();
        arguments_at_limit.arguments = std::iter::once(ArgumentSpec::Target)
            .chain((0..MAX_ARGUMENTS - 1).map(|_| ArgumentSpec::Integer {
                minimum: 0,
                maximum: 1,
            }))
            .collect();
        assert!(validate_draft(&arguments_at_limit).is_ok());

        let mut credentials_at_limit = draft();
        credentials_at_limit.credentials = (0..MAX_CREDENTIALS)
            .map(|index| {
                credential(
                    format!("11111111-1111-1111-1111-{index:012x}"),
                    format!("SECRET_{index}"),
                )
            })
            .collect();
        assert!(validate_draft(&credentials_at_limit).is_ok());
    }

    #[test]
    fn top_level_draft_validation_rejects_each_authority_expansion() {
        let mut invalid = draft();
        invalid.id = "Invalid".into();
        assert_invalid_draft(invalid);
        let mut invalid = draft();
        invalid.description.clear();
        assert_invalid_draft(invalid);
        let mut invalid = draft();
        invalid.image_id = "Invalid".into();
        assert_invalid_draft(invalid);
        let mut invalid = draft();
        invalid.targets.clear();
        assert_invalid_draft(invalid);
        let mut invalid = draft();
        invalid.targets = vec!["with space".into()];
        assert_invalid_draft(invalid);
        let mut invalid = draft();
        invalid.targets.push("staging".into());
        assert_invalid_draft(invalid);
        let mut invalid = draft();
        invalid.targets = (0..MAX_TARGETS + 1)
            .map(|index| format!("target-{index}"))
            .collect();
        assert_invalid_draft(invalid);

        let mut invalid = draft();
        invalid.arguments = vec![ArgumentSpec::Choice {
            choices: vec!["safe".into()],
        }];
        assert_invalid_draft(invalid);
        let mut invalid = draft();
        invalid.arguments = std::iter::once(ArgumentSpec::Target)
            .chain((0..MAX_ARGUMENTS).map(|index| ArgumentSpec::Choice {
                choices: vec![format!("choice-{index}")],
            }))
            .collect();
        assert_invalid_draft(invalid);

        let mut invalid = draft();
        invalid.credentials.clear();
        assert_invalid_draft(invalid);
        let mut invalid = draft();
        invalid.credentials = (0..MAX_CREDENTIALS + 1)
            .map(|index| {
                credential(
                    format!("11111111-1111-1111-1111-{index:012x}"),
                    format!("SECRET_{index}"),
                )
            })
            .collect();
        assert_invalid_draft(invalid);
        let mut invalid = draft();
        invalid.credentials[0].field_mappings.clear();
        assert_invalid_draft(invalid);
    }

    #[test]
    fn argument_and_credential_components_enforce_closed_safe_grammar() {
        assert!(valid_arguments(&[ArgumentSpec::Target]));
        for arguments in [
            vec![],
            vec![ArgumentSpec::Target, ArgumentSpec::Target],
            vec![
                ArgumentSpec::Target,
                ArgumentSpec::Choice { choices: vec![] },
            ],
            vec![
                ArgumentSpec::Target,
                ArgumentSpec::Choice {
                    choices: vec!["same".into(), "same".into()],
                },
            ],
            vec![
                ArgumentSpec::Target,
                ArgumentSpec::Choice {
                    choices: vec!["has space".into()],
                },
            ],
            vec![
                ArgumentSpec::Target,
                ArgumentSpec::Integer {
                    minimum: 2,
                    maximum: 1,
                },
            ],
        ] {
            assert!(!valid_arguments(&arguments));
        }
        assert!(!valid_arguments(&[
            ArgumentSpec::Target,
            ArgumentSpec::Choice {
                choices: (0..MAX_CHOICES + 1)
                    .map(|index| format!("choice-{index}"))
                    .collect(),
            },
        ]));

        for item_id in [
            "11111111-1111-1111-1111-11111111111",
            "111111111111-1111-1111-1111-111111111111",
            "11111111_1111-1111-1111-111111111111",
            "11111111-1111-1111-1111-11111111111g",
            "11111111-1111-1111-1111-11111111111A",
        ] {
            assert!(!valid_item_id(item_id));
        }
        assert!(valid_login_field(&LoginField::Username));
        assert!(valid_login_field(&LoginField::Password));
        assert!(valid_login_field(&LoginField::Custom {
            name: "token".into()
        }));
        for field in [
            LoginField::Custom {
                name: String::new(),
            },
            LoginField::Custom {
                name: "vw-access".into(),
            },
        ] {
            assert!(!valid_login_field(&field));
        }

        assert!(valid_environment("SAFE_VALUE_2"));
        for environment in [
            "",
            "lowercase",
            "2STARTS_WITH_DIGIT",
            "HAS-DASH",
            "PATH",
            "IFS",
            "ENV",
            "BASH_ENV",
            "SHELLOPTS",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "LANG",
            "LC_ALL",
            "VAULTWARDEN_TOKEN",
            "BITWARDEN_SESSION",
        ] {
            assert!(!valid_environment(environment));
        }
        assert!(!valid_environment(&"A".repeat(65)));

        for value in ["", "contains\nnewline", "contains\0nul"] {
            assert!(!valid_display_text(value, MAX_DESCRIPTION_LEN));
        }
        assert!(!valid_display_text(
            &"a".repeat(MAX_DESCRIPTION_LEN + 1),
            MAX_DESCRIPTION_LEN
        ));
        for value in ["", "has space", "has\nnewline", "has\0nul"] {
            assert!(!valid_value(value, MAX_VALUE_LEN));
        }
        assert!(!valid_value(&"a".repeat(MAX_VALUE_LEN + 1), MAX_VALUE_LEN));

        let mappings = vec![
            LoginFieldMapping {
                field: LoginField::Username,
                environment: "USERNAME".into(),
            },
            LoginFieldMapping {
                field: LoginField::Username,
                environment: "OTHER_USERNAME".into(),
            },
        ];
        assert!(!unique_fields(&mappings));
        let mappings = vec![
            LoginFieldMapping {
                field: LoginField::Username,
                environment: "USERNAME".into(),
            },
            LoginFieldMapping {
                field: LoginField::Password,
                environment: "USERNAME".into(),
            },
        ];
        assert!(!unique_environments(&mappings));
        assert!(!unique_credential_environments(&[
            credential(ITEM.into(), "SHARED_SECRET".into()),
            credential(
                "22222222-2222-2222-2222-222222222222".into(),
                "SHARED_SECRET".into(),
            ),
        ]));
        assert!(!valid_credentials(&[
            credential(ITEM.into(), "SECRET".into()),
            credential(ITEM.into(), "OTHER_SECRET".into()),
        ]));
    }
    #[test]
    fn policy_error_is_redacted() {
        assert_eq!(
            PolicyValidationError.to_string(),
            "invalid operation policy"
        );
    }
    #[test]
    fn preliminary_image_limit_uses_independent_literal_boundaries() {
        let root = root();
        let image = test_approved_image(root.path(), "deploy-image");
        fs::set_permissions(&image.path, fs::Permissions::from_mode(0o700)).unwrap();
        let writer = OpenOptions::new().write(true).open(&image.path).unwrap();
        writer.set_len(67_108_864).unwrap();
        fs::set_permissions(&image.path, fs::Permissions::from_mode(0o500)).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(fs::read(&image.path).unwrap());
        let expected: String = hasher
            .clone()
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert!(executable_identity_matches(
            Path::new(&image.path),
            &expected
        ));
        writer.set_len(67_108_865).unwrap();
        hasher.update([0u8]);
        let expected: String = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert!(!executable_identity_matches(
            Path::new(&image.path),
            &expected
        ));
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn preliminary_open_flags_are_required_by_the_syscall_contract() {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "access::policy::tests::preliminary_open_flags_child",
                "--ignored",
                "--nocapture",
            ])
            .env("VW_PRELIMINARY_OPEN_FLAGS_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{} {}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolated preliminary open-flag contract; parent harness only"]
    fn preliminary_open_flags_child() {
        assert_eq!(
            std::env::var("VW_PRELIMINARY_OPEN_FLAGS_CHILD").unwrap(),
            "1"
        );
        let root = root();
        let image = test_approved_image(root.path(), "deploy-image");
        assert!(executable_identity_matches(
            Path::new(&image.path),
            &image.sha256
        ));
        let required = (libc::O_NOFOLLOW | libc::O_NONBLOCK) as u32;
        let instruction = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
        let mut filter = [
            instruction(0x20, 0, 0, 0),
            instruction(0x15, 0, 4, libc::SYS_openat as u32),
            instruction(0x20, 0, 0, 32),
            instruction(0x54, 0, 0, required),
            instruction(0x15, 1, 0, required),
            instruction(0x06, 0, 0, 0x00050000 | libc::EPERM as u32),
            instruction(0x06, 0, 0, 0x7fff0000),
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            0
        );
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &program) }, 0);
        // This checks actual syscall flags on a valid regular image. It does not
        // claim a real FIFO replacement race or rely on a hung-test timeout.
        assert!(executable_identity_matches(
            Path::new(&image.path),
            &image.sha256
        ));
        std::fs::remove_file(&image.path).unwrap();
        std::fs::remove_dir(root.path()).unwrap();
    }
}
