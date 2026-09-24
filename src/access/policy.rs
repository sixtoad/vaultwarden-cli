//! Provider-owned constrained protected-operation policy.
//!
//! A draft selects a provider-owned image ID only. Paths and hashes are held
//! in the private registry, resolved by the provider, and snapshotted here.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Read;
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
}

/// Provider-private registry state; this story intentionally has no public
/// provisioning or inspection API.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovedImage {
    id: String,
    path: String,
    sha256: String,
}

impl ApprovedImage {
    pub(crate) fn new(
        id: String,
        path: String,
        sha256: String,
    ) -> Result<Self, PolicyValidationError> {
        let image = Self { id, path, sha256 };
        if !valid_operation_id(&image.id)
            || !valid_image_path(&image.path)
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
        Self::new(self.id.clone(), self.path.clone(), self.sha256.clone()).map(|_| ())
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
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoginCredentialDraft {
    pub item_id: String,
    pub label: String,
    pub use_type: CredentialUse,
    pub field_mappings: Vec<LoginFieldMapping>,
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
    revision: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ResolvedImage {
    image_id: String,
    path: String,
    sha256: String,
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
            && self.image.path == image.path
            && self.image.sha256 == image.sha256
    }
    pub(crate) fn login_bindings(&self) -> impl Iterator<Item = LoginBindingRef<'_>> {
        self.credentials.iter().map(|credential| LoginBindingRef {
            item_id: &credential.item_id,
            required_fields: credential
                .field_mappings
                .iter()
                .map(|mapping| mapping.field.clone())
                .collect(),
        })
    }
    pub(crate) fn validates_args(&self, values: &[String]) -> bool {
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
            target,
            arguments_digest: arguments_digest(&arguments),
            arguments,
            credentials: self
                .credentials
                .iter()
                .map(|c| ReviewCredential {
                    label: c.label.clone(),
                    use_type: c.use_type,
                })
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
            self.image.path.clone(),
            self.image.sha256.clone(),
        )?;
        let rebuilt = Self::from_draft(
            OperationPolicyDraft {
                id: self.id.clone(),
                description: self.description.clone(),
                image_id: self.image.image_id.clone(),
                targets: self.targets.clone(),
                arguments: self.arguments.clone(),
                credentials: self.credentials.clone(),
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
    revision: String,
}

impl TryFrom<StoredOperationPolicy> for OperationPolicy {
    type Error = PolicyValidationError;
    fn try_from(stored: StoredOperationPolicy) -> Result<Self, Self::Error> {
        let image = ApprovedImage::new(
            stored.image.image_id.clone(),
            stored.image.path.clone(),
            stored.image.sha256.clone(),
        )?;
        let policy = Self::from_draft(
            OperationPolicyDraft {
                id: stored.id,
                description: stored.description,
                image_id: image.id.clone(),
                targets: stored.targets,
                arguments: stored.arguments,
                credentials: stored.credentials,
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

fn executable_identity_matches(path: &Path, expected: &str) -> bool {
    let Some(metadata) = nonsymlink_regular(path) else {
        return false;
    };
    if !metadata.file_type().is_file() || metadata.mode() & 0o111 == 0 {
        return false;
    }
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let Ok(mut file) = options.open(path) else {
        return false;
    };
    let Ok(opened) = file.metadata() else {
        return false;
    };
    if !opened.file_type().is_file() || opened.mode() & 0o111 == 0 {
        return false;
    }
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
    let mut buffer = [0_u8; 8192];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => digest.update(&buffer[..read]),
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
            valid_item_id(&credential.item_id)
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
        && !matches!(
            value,
            "PATH"
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
        && !value.contains(' ')
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
            version: 1,
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
    fs::write(&path, IMAGE).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    ApprovedImage::new(
        id.into(),
        path.into_os_string().into_string().unwrap(),
        hex_digest(IMAGE),
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    const ITEM: &str = "11111111-1111-1111-1111-111111111111";
    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        root
    }
    fn draft() -> OperationPolicyDraft {
        OperationPolicyDraft {
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
                    path: "/opt/vw-access/deploy".into(),
                    sha256: "a".repeat(64),
                },
            ),
            "d5c9504382ca17dc992db82b3c587b2513edfad17a37cd0d63f7bb73a0a4d768"
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
        };
        assert!(!policy.image_matches(&different_id));

        let second_path = root.path().join("second-approved-image");
        fs::copy(&image.path, &second_path).unwrap();
        fs::set_permissions(&second_path, fs::Permissions::from_mode(0o700)).unwrap();
        let different_path = ApprovedImage {
            id: image.id.clone(),
            path: second_path.into_os_string().into_string().unwrap(),
            sha256: image.sha256.clone(),
        };
        assert!(!policy.image_matches(&different_path));

        let different_digest = ApprovedImage {
            id: image.id.clone(),
            path: image.path.clone(),
            sha256: "0".repeat(64),
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
}
