//! Field-selective replacement of an existing personal Login item (issue 48).
//! Preserved components are sent and verified as verbatim ciphertext; plaintext
//! has no serialization or Debug path. See `docs/implementation/issue-48-spec.md`.
use crate::{
    crypto::CryptoKeys,
    models::{Cipher, CipherData},
    secret_storage::{Destination, SecretImport, selected_value},
};
use anyhow::{Result, ensure};
use serde_json::{Map, Value};

/// Members copied verbatim from the fresh read into the update body.
const PRESERVED: [&str; 11] = [
    "type",
    "folderId",
    "organizationId",
    "key",
    "name",
    "notes",
    "favorite",
    "reprompt",
    "login",
    "fields",
    "passwordHistory",
];
/// Members whose stored value must be unchanged after the update.
const IDENTITY: [&str; 8] = [
    "type",
    "folderId",
    "organizationId",
    "key",
    "name",
    "favorite",
    "reprompt",
    "passwordHistory",
];

/// One authenticated read of an item: the raw JSON plus its parsed form.
pub struct ItemSnapshot {
    raw: Map<String, Value>,
    cipher: Cipher,
    revision: String,
}
impl ItemSnapshot {
    /// # Errors
    /// Returns an error for another ID, a missing revision or a response shape
    /// other than Vaultwarden 1.36's camelCase item.
    pub fn parse(raw: Value, id: &str) -> Result<Self> {
        let Value::Object(raw) = raw else {
            anyhow::bail!("unsupported item response shape");
        };
        ensure!(
            raw.keys()
                .all(|key| !key.starts_with(|c: char| c.is_ascii_uppercase())),
            "unsupported item response shape"
        );
        ensure!(
            raw.get("id").and_then(Value::as_str) == Some(id),
            "item binding mismatch"
        );
        let revision = raw
            .get("revisionDate")
            .and_then(Value::as_str)
            .filter(|r| !r.is_empty() && r.len() <= 64 && !r.chars().any(char::is_control))
            .ok_or_else(|| anyhow::anyhow!("item revision unavailable"))?
            .to_owned();
        let cipher = serde_json::from_value(Value::Object(raw.clone()))
            .map_err(|_error| anyhow::anyhow!("unsupported item response shape"))?;
        Ok(Self {
            raw,
            cipher,
            revision,
        })
    }
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }
    /// # Errors
    /// Returns an error when the item no longer matches the binding or is not a personal login.
    pub fn check_binding(&self, parent: &CryptoKeys, destination: &Destination) -> Result<()> {
        self.bound_keys(parent, destination).map(|_keys| ())
    }
    fn login(&self) -> Option<&Map<String, Value>> {
        self.raw.get("login").and_then(Value::as_object)
    }
    fn fields(&self) -> &[Value] {
        self.raw
            .get("fields")
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice)
    }
    /// Checks the binding and item kind; returns the item's effective keys.
    fn bound_keys(&self, parent: &CryptoKeys, destination: &Destination) -> Result<CryptoKeys> {
        let id = self.cipher.id.as_str();
        let keys = destination.check_item(&self.cipher, id, parent)?;
        ensure!(
            matches!(self.cipher.cipher_data, Some(CipherData::Login(_))),
            "only personal login items can be updated"
        );
        Ok(keys)
    }
}

/// Decrypted custom field names in order; duplicates fail closed.
fn field_names(snapshot: &ItemSnapshot, keys: &CryptoKeys) -> Result<Vec<String>> {
    let mut names: Vec<String> = Vec::new();
    for field in snapshot.fields() {
        let name = keys.decrypt_authenticated_to_string(
            field
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("field name missing"))?,
        )?;
        ensure!(!names.contains(&name), "duplicate custom field");
        names.push(name);
    }
    Ok(names)
}

/// Builds the PUT body: selected values re-encrypted with the item's key and
/// fresh IVs, everything else verbatim, bound to the snapshot's revision.
/// # Errors
/// Returns an error for a binding mismatch, a missing or unsupported field, or
/// an unsupported item; nothing is sent.
pub fn plan_update(
    parent: &CryptoKeys,
    destination: &Destination,
    snapshot: &ItemSnapshot,
    input: &SecretImport,
) -> Result<Value> {
    input.validate_update()?;
    let keys = snapshot.bound_keys(parent, destination)?;
    let mut body = Map::new();
    for member in PRESERVED {
        if let Some(value) = snapshot.raw.get(member) {
            body.insert(member.to_owned(), value.clone());
        }
    }
    let encrypt = |value: &str| keys.encrypt(value.as_bytes()).map(Value::String);
    if let Some(password) = &input.password {
        let slot = body
            .get_mut("login")
            .and_then(Value::as_object_mut)
            .and_then(|login| login.get_mut("password"))
            .filter(|current| current.is_string())
            .ok_or_else(|| anyhow::anyhow!("selected field missing"))?;
        *slot = encrypt(password)?;
    }
    if let Some(notes) = &input.notes {
        let slot = body
            .get_mut("notes")
            .filter(|current| current.is_string())
            .ok_or_else(|| anyhow::anyhow!("selected field missing"))?;
        *slot = encrypt(notes)?;
    }
    let names = field_names(snapshot, &keys)?;
    for wanted in &input.fields {
        let index = names
            .iter()
            .position(|name| *name == wanted.name)
            .ok_or_else(|| anyhow::anyhow!("selected field missing"))?;
        let field = body
            .get_mut("fields")
            .and_then(Value::as_array_mut)
            .and_then(|fields| fields.get_mut(index))
            .and_then(Value::as_object_mut)
            .ok_or_else(|| anyhow::anyhow!("selected field missing"))?;
        ensure!(
            matches!(field.get("type").and_then(Value::as_u64), Some(0 | 1)),
            "only text or hidden custom fields can be updated"
        );
        ensure!(
            field.get("value").is_some_and(Value::is_string),
            "selected field missing"
        );
        field.insert("value".into(), encrypt(&wanted.value)?);
    }
    body.insert(
        "lastKnownRevisionDate".into(),
        Value::String(snapshot.revision.clone()),
    );
    Ok(Value::Object(body))
}

/// Exact comparison after a fresh read: new plaintext for selected fields,
/// identical ciphertext for every preserved component, same bindings.
/// # Errors
/// Returns an error on any difference; callers then report `updated_unverified`.
pub fn verify_updated(
    parent: &CryptoKeys,
    destination: &Destination,
    before: &ItemSnapshot,
    after: &ItemSnapshot,
    input: &SecretImport,
) -> Result<()> {
    let keys = after.bound_keys(parent, destination)?;
    ensure!(before.cipher.id == after.cipher.id, "item binding mismatch");
    for member in IDENTITY {
        ensure!(
            before.raw.get(member) == after.raw.get(member),
            "preserved component changed"
        );
    }
    let same = |a: Option<&Value>, b: Option<&Value>| a == b;
    let (old_login, new_login) = (before.login(), after.login());
    for member in ["username", "totp"] {
        ensure!(
            same(
                old_login.and_then(|l| l.get(member)),
                new_login.and_then(|l| l.get(member))
            ),
            "preserved component changed"
        );
    }
    let uris = |login: Option<&Map<String, Value>>| {
        login
            .and_then(|l| l.get("uris"))
            .and_then(Value::as_array)
            .map(|uris| {
                uris.iter()
                    .map(|u| u.get("uri").cloned())
                    .collect::<Vec<_>>()
            })
    };
    ensure!(
        uris(old_login) == uris(new_login),
        "preserved component changed"
    );
    let exact = |selector: &str, expected: &str| -> Result<()> {
        ensure!(
            *selected_value(&after.cipher, &keys, selector)? == *expected,
            "verification mismatch"
        );
        Ok(())
    };
    match &input.password {
        Some(value) => exact("password", value)?,
        None => ensure!(
            same(
                old_login.and_then(|l| l.get("password")),
                new_login.and_then(|l| l.get("password"))
            ),
            "preserved component changed"
        ),
    }
    match &input.notes {
        Some(value) => exact("notes", value)?,
        None => ensure!(
            same(before.raw.get("notes"), after.raw.get("notes")),
            "preserved component changed"
        ),
    }
    let names = field_names(after, &keys)?;
    ensure!(
        names == field_names(before, &keys)?,
        "preserved component changed"
    );
    for ((name, old), new) in names.iter().zip(before.fields()).zip(after.fields()) {
        ensure!(
            old.get("name") == new.get("name") && old.get("type") == new.get("type"),
            "preserved component changed"
        );
        match input.fields.iter().find(|f| f.name == *name) {
            Some(wanted) => exact(&format!("custom:{name}"), &wanted.value)?,
            None => ensure!(
                old.get("value") == new.get("value"),
                "preserved component changed"
            ),
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "secret_update_tests.rs"]
mod tests;
