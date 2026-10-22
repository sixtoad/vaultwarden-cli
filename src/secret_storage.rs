//! Create-only encrypted personal-vault storage. Plaintext has no serialization or Debug path.
use crate::{
    crypto::CryptoKeys,
    models::{Cipher, CipherData, SyncResponse},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const MAX_IMPORT_BYTES: usize = 64 * 1024;

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct SecretImport {
    pub password: Option<String>,
    pub notes: Option<String>,
    #[serde(default)]
    pub fields: Vec<NamedSecret>,
}
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct NamedSecret {
    pub name: String,
    pub value: String,
}
impl SecretImport {
    /// # Errors
    /// Returns an error when validation, authorization, cryptography or backend access fails.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_IMPORT_BYTES,
            "secret input exceeds limit"
        );
        let input: Self = serde_json::from_slice(bytes)
            .map_err(|_error| anyhow::anyhow!("invalid secret input"))?;
        input.validate()?;
        Ok(input)
    }
    /// # Errors
    /// Returns an error when validation, authorization, cryptography or backend access fails.
    pub fn validate(&self) -> Result<()> {
        let mut names = HashSet::new();
        ensure!(
            self.password.is_some() || !self.fields.is_empty(),
            "secret input is empty"
        );
        ensure!(
            self.fields.len() <= 32
                && self.fields.iter().all(|f| valid_field_name(&f.name)
                    && f.name != "vw-access"
                    && names.insert(&f.name)),
            "invalid or duplicate secret field"
        );
        ensure!(
            self.password.as_ref().map_or(0, String::len)
                + self.notes.as_ref().map_or(0, String::len)
                + self
                    .fields
                    .iter()
                    .map(|f| f.name.len() + f.value.len())
                    .sum::<usize>()
                <= MAX_IMPORT_BYTES,
            "secret input exceeds limit"
        );
        Ok(())
    }
    #[must_use]
    pub fn selectors(&self) -> Vec<String> {
        let mut fields = Vec::new();
        if self.password.is_some() {
            fields.push("password".into());
        }
        if self.notes.is_some() {
            fields.push("notes".into());
        }
        fields.extend(self.fields.iter().map(|f| format!("custom:{}", f.name)));
        fields.sort();
        fields
    }
}

#[must_use]
pub fn valid_field_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
#[must_use]
pub fn canonical_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.split('/').all(|s| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && s.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
        })
}
#[must_use]
pub fn valid_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}

/// Account identity includes the configured server separately at the caller boundary.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub account_id: String,
    pub folder: String,
    pub folder_id: String,
    pub reference: String,
}
impl Destination {
    /// # Errors
    /// Returns an error when validation, authorization, cryptography or backend access fails.
    pub fn item_name(&self) -> Result<&str> {
        ensure!(
            valid_id(&self.account_id)
                && valid_id(&self.folder_id)
                && canonical_path(&self.folder)
                && canonical_path(&self.reference),
            "invalid storage destination"
        );
        let name = self
            .reference
            .strip_prefix(&self.folder)
            .and_then(|s| s.strip_prefix('/'))
            .ok_or_else(|| anyhow::anyhow!("reference is outside folder"))?;
        ensure!(!name.is_empty(), "invalid storage destination");
        Ok(name)
    }
    /// # Errors
    /// Returns an error when validation, authorization, cryptography or backend access fails.
    pub fn check_sync(&self, sync: &SyncResponse, keys: &CryptoKeys, creating: bool) -> Result<()> {
        let name = self.item_name()?;
        ensure!(
            sync.profile.id == self.account_id,
            "account binding mismatch"
        );
        let folders = sync
            .folders
            .iter()
            .map(|folder| {
                Ok((
                    folder.id.as_str(),
                    keys.decrypt_authenticated_to_string(&folder.name)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let matches = folders
            .iter()
            .filter(|(_, label)| label == &self.folder)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1 && matches[0].0 == self.folder_id,
            "folder binding is ambiguous or changed"
        );
        if creating {
            for cipher in &sync.ciphers {
                if cipher.organization_id.is_none()
                    && cipher.folder_id.as_deref() == Some(self.folder_id.as_str())
                {
                    let item_keys = keys.item_keys(cipher.item_key.as_deref())?;
                    let label = item_keys.decrypt_authenticated_to_string(
                        cipher
                            .get_name()
                            .ok_or_else(|| anyhow::anyhow!("item name unavailable"))?,
                    )?;
                    ensure!(
                        label != name,
                        "reference already exists; updates are unsupported"
                    );
                }
            }
        }
        Ok(())
    }
    /// # Errors
    /// Returns an error when validation, authorization, cryptography or backend access fails.
    pub fn check_item(&self, cipher: &Cipher, id: &str, parent: &CryptoKeys) -> Result<CryptoKeys> {
        ensure!(
            cipher.id == id
                && cipher.deleted_date.is_none()
                && cipher.organization_id.is_none()
                && cipher.folder_id.as_deref() == Some(self.folder_id.as_str()),
            "item binding mismatch"
        );
        let keys = parent.item_keys(cipher.item_key.as_deref())?;
        ensure!(
            keys.decrypt_authenticated_to_string(
                cipher
                    .get_name()
                    .ok_or_else(|| anyhow::anyhow!("item name unavailable"))?
            )? == self.item_name()?,
            "reference binding changed"
        );
        Ok(keys)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedCreate {
    pub r#type: u8,
    pub organization_id: Option<String>,
    pub folder_id: String,
    pub name: String,
    pub key: String,
    pub notes: Option<String>,
    pub login: EncryptedLogin,
    pub fields: Vec<EncryptedField>,
    pub favorite: bool,
    pub reprompt: u8,
}
#[derive(Serialize)]
pub struct EncryptedLogin {
    pub password: Option<String>,
}
#[derive(Serialize)]
pub struct EncryptedField {
    pub name: String,
    pub value: String,
    pub r#type: u8,
}

/// # Errors
/// Returns an error when validation, authorization, cryptography or backend access fails.
pub fn encrypt_create(
    parent: &CryptoKeys,
    destination: &Destination,
    input: &SecretImport,
    marker: Option<&str>,
) -> Result<EncryptedCreate> {
    input.validate()?;
    let (keys, key) = parent.new_wrapped_item_key()?;
    let encrypt = |value: &str| keys.encrypt(value.as_bytes());
    let mut fields = input
        .fields
        .iter()
        .map(|f| {
            Ok(EncryptedField {
                name: encrypt(&f.name)?,
                value: encrypt(&f.value)?,
                r#type: 1,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if let Some(marker) = marker {
        fields.push(EncryptedField {
            name: encrypt("vw-access")?,
            value: encrypt(marker)?,
            r#type: 0,
        });
    }
    Ok(EncryptedCreate {
        r#type: 1,
        organization_id: None,
        folder_id: destination.folder_id.clone(),
        name: encrypt(destination.item_name()?)?,
        key,
        notes: input.notes.as_deref().map(encrypt).transpose()?,
        login: EncryptedLogin {
            password: input.password.as_deref().map(encrypt).transpose()?,
        },
        fields,
        favorite: false,
        reprompt: 0,
    })
}

/// # Errors
/// Returns an error when validation, authorization, cryptography or backend access fails.
pub fn selected_value(
    cipher: &Cipher,
    keys: &CryptoKeys,
    selector: &str,
) -> Result<Zeroizing<String>> {
    ensure!(cipher.deleted_date.is_none(), "item is deleted");
    let mut names = HashSet::new();
    let mut custom = None;
    for field in cipher.get_fields().into_iter().flatten() {
        let name = Zeroizing::new(
            keys.decrypt_authenticated_to_string(
                field
                    .name
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("field name missing"))?,
            )?,
        );
        ensure!(names.insert(name.to_string()), "duplicate custom field");
        if selector.strip_prefix("custom:") == Some(name.as_str()) {
            custom = field.value.as_deref();
        }
    }
    let encrypted = match selector {
        "password" => cipher.get_password(),
        "notes" => cipher.get_notes(),
        value if value.starts_with("custom:") => custom,
        _ => anyhow::bail!("invalid field selector"),
    }
    .ok_or_else(|| anyhow::anyhow!("selected field missing"))?;
    CryptoKeys::require_authenticated(encrypted)?;
    Ok(Zeroizing::new(
        keys.decrypt_authenticated_to_string(encrypted)?,
    ))
}

/// # Errors
/// Returns an error when validation, authorization, cryptography or backend access fails.
pub fn verify_created(
    parent: &CryptoKeys,
    destination: &Destination,
    id: &str,
    cipher: &Cipher,
    input: &SecretImport,
    marker: Option<&str>,
) -> Result<()> {
    ensure!(
        matches!(cipher.cipher_data, Some(CipherData::Login(_))) && cipher.item_key.is_some(),
        "created item shape mismatch"
    );
    let keys = destination.check_item(cipher, id, parent)?;
    ensure!(
        cipher.get_password().is_some() == input.password.is_some()
            && cipher.get_notes().is_some() == input.notes.is_some()
            && cipher.get_fields().map_or(0, Vec::len)
                == input.fields.len() + usize::from(marker.is_some()),
        "created item schema mismatch"
    );
    for field in cipher.get_fields().into_iter().flatten() {
        let name = keys.decrypt_authenticated_to_string(
            field
                .name
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("field name missing"))?,
        )?;
        ensure!(
            (name == "vw-access" && marker.is_some()) || field.r#type.is_hidden(),
            "created secret field is not hidden"
        );
    }
    if let Some(value) = &input.password {
        ensure!(
            *selected_value(cipher, &keys, "password")? == *value,
            "verification mismatch"
        );
    }
    if let Some(value) = &input.notes {
        ensure!(
            *selected_value(cipher, &keys, "notes")? == *value,
            "verification mismatch"
        );
    }
    for field in &input.fields {
        ensure!(
            *selected_value(cipher, &keys, &format!("custom:{}", field.name))? == field.value,
            "verification mismatch"
        );
    }
    if let Some(marker) = marker {
        ensure!(
            *selected_value(cipher, &keys, "custom:vw-access")? == marker,
            "verification mismatch"
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WriteStatus {
    Failed,
    Uncertain,
    CreatedUnverified,
    Verified,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WriteReceipt {
    pub attempt_id: String,
    pub item_id: Option<String>,
    pub status: WriteStatus,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn imports_reject_unknown_duplicate_and_oversized_input_without_echo() {
        for bytes in [
            br#"{"password":"sentinel","unknown":1}"#.as_slice(),
            br#"{"password":"sentinel","password":"other"}"#,
            br#"{"fields":[{"name":"key","value":"sentinel"},{"name":"key","value":"second"}]}"#,
        ] {
            let error = SecretImport::parse(bytes).err().unwrap();
            assert!(!error.to_string().contains("sentinel"));
        }
        assert!(SecretImport::parse(&vec![b' '; MAX_IMPORT_BYTES + 1]).is_err());
    }
    #[test]
    fn encryption_roundtrip_preserves_values_and_requires_wrapped_key() {
        let parent = CryptoKeys::from_key_bytes([1; 32], [2; 32]);
        let destination = Destination {
            account_id: "11111111-1111-1111-1111-111111111111".into(),
            folder_id: "22222222-2222-2222-2222-222222222222".into(),
            folder: "homelab/production".into(),
            reference: "homelab/production/github/deploy-token".into(),
        };
        let input = SecretImport::parse(
            br#"{"password":"  sentinel\n\u0000","fields":[{"name":"api-key","value":"exact\n"}]}"#,
        )
        .unwrap();
        let first = encrypt_create(&parent, &destination, &input, Some("deploy")).unwrap();
        let second = encrypt_create(&parent, &destination, &input, Some("deploy")).unwrap();
        assert_ne!(first.key, second.key);
        assert_ne!(first.login.password, second.login.password);
        let mut wire = serde_json::to_value(first).unwrap();
        assert!(!wire.to_string().contains("sentinel"));
        wire["id"] = serde_json::json!("33333333-3333-3333-3333-333333333333");
        let cipher: Cipher = serde_json::from_value(wire.clone()).unwrap();
        verify_created(
            &parent,
            &destination,
            cipher.id.as_str(),
            &cipher,
            &input,
            Some("deploy"),
        )
        .unwrap();
        wire["key"] = serde_json::json!("2.invalid|key|mac");
        let cipher: Cipher = serde_json::from_value(wire).unwrap();
        assert!(parent.item_keys(cipher.item_key.as_deref()).is_err());
    }
    #[test]
    fn namespace_is_canonical_not_normalized() {
        for bad in [
            "Homelab/test",
            "homelab//test",
            "/test",
            "test/",
            "a/../b",
            "a/_b",
            "a/b ",
            "a/-b",
        ] {
            assert!(!canonical_path(bad));
        }
        assert!(canonical_path("homelab/production/github/deploy-token"));
    }
}

#[cfg(test)]
mod binding_tests {
    use super::*;
    #[test]
    fn account_folder_reference_identity_deletion_and_duplicate_fields_fail_closed() {
        let keys = CryptoKeys::from_key_bytes([1; 32], [2; 32]);
        let d = Destination {
            account_id: "11111111-1111-1111-1111-111111111111".into(),
            folder: "homelab/production".into(),
            folder_id: "22222222-2222-2222-2222-222222222222".into(),
            reference: "homelab/production/github/token".into(),
        };
        let input = SecretImport::parse(
            br#"{"password":"sentinel","fields":[{"name":"api-key","value":"exact"}]}"#,
        )
        .unwrap();
        let mut wire =
            serde_json::to_value(encrypt_create(&keys, &d, &input, None).unwrap()).unwrap();
        wire["id"] = serde_json::json!("33333333-3333-3333-3333-333333333333");
        let mut sync = serde_json::json!({"profile":{"id":d.account_id,"email":"test@example.invalid"},"folders":[{"id":d.folder_id,"name":keys.encrypt(d.folder.as_bytes()).unwrap()}],"ciphers":[]});
        d.check_sync(&serde_json::from_value(sync.clone()).unwrap(), &keys, true)
            .unwrap();
        let duplicate = sync["folders"][0].clone();
        sync["folders"].as_array_mut().unwrap().push(duplicate);
        assert!(
            d.check_sync(&serde_json::from_value(sync.clone()).unwrap(), &keys, true)
                .is_err()
        );
        sync["folders"].as_array_mut().unwrap().pop();
        // A fresh post-create sync must reject a folder rename even when the item GET is unchanged.
        let mut renamed = sync.clone();
        renamed["folders"][0]["name"] =
            serde_json::json!(keys.encrypt(b"homelab/renamed").unwrap());
        assert!(
            d.check_sync(&serde_json::from_value(renamed).unwrap(), &keys, false)
                .is_err()
        );
        sync["profile"]["id"] = serde_json::json!("44444444-4444-4444-4444-444444444444");
        assert!(
            d.check_sync(&serde_json::from_value(sync).unwrap(), &keys, true)
                .is_err()
        );
        for (key, value) in [
            ("id", serde_json::json!("other")),
            ("folderId", serde_json::json!("other")),
            ("deletedDate", serde_json::json!("now")),
            ("organizationId", serde_json::json!("other")),
            ("key", serde_json::json!("2.invalid|key|mac")),
            ("name", serde_json::json!(keys.encrypt(b"renamed").unwrap())),
        ] {
            let mut changed = wire.clone();
            changed[key] = value;
            let cipher: Cipher = serde_json::from_value(changed).unwrap();
            assert!(
                d.check_item(&cipher, "33333333-3333-3333-3333-333333333333", &keys)
                    .is_err(),
                "{key}"
            );
        }
        let field = wire["fields"][0].clone();
        wire["fields"].as_array_mut().unwrap().push(field);
        let cipher: Cipher = serde_json::from_value(wire).unwrap();
        let item_keys = keys.item_keys(cipher.item_key.as_deref()).unwrap();
        assert!(selected_value(&cipher, &item_keys, "custom:api-key").is_err());
        assert!(selected_value(&cipher, &item_keys, "password").is_err());
    }
}
