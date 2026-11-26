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
use zeroize::Zeroizing;

#[path = "secret_update_dates.rs"]
mod dates;
pub use dates::same_instant;

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
/// Members whose stored value must equal the sent body after the update.
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
/// Official Bitwarden clients keep the newest five password-history entries.
pub const PASSWORD_HISTORY_LIMIT: usize = 5;

/// What one update sends, and which replaced values it keeps in password history.
#[derive(Default)]
pub struct UpdatePlan {
    /// The PUT body; holds ciphertext only.
    pub body: Value,
    /// Selectors whose replaced value is added to the item's password history.
    pub history: Vec<String>,
}

/// A planned update bound to the fresh read it was built from: what the
/// protected provider journals, sends once and then verifies (issue 48 phase 2).
pub struct PreparedUpdate {
    before: ItemSnapshot,
    plan: UpdatePlan,
}
impl PreparedUpdate {
    #[must_use]
    pub const fn new(before: ItemSnapshot, plan: UpdatePlan) -> Self {
        Self { before, plan }
    }
    #[must_use]
    pub const fn before(&self) -> &ItemSnapshot {
        &self.before
    }
    /// The PUT body (ciphertext only).
    #[must_use]
    pub const fn body(&self) -> &Value {
        &self.plan.body
    }
    /// A minimal plan for application tests whose fake backend never sends it.
    /// # Panics
    /// Never for the fixed synthetic item.
    #[cfg(test)]
    #[must_use]
    pub fn synthetic(id: &str, revision: &str) -> Self {
        let raw = serde_json::json!({"id": id, "revisionDate": revision, "type": 1, "login": {}});
        Self::new(
            ItemSnapshot::parse(raw, id).expect("synthetic item parses"),
            UpdatePlan::default(),
        )
    }
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` (UTC), the form Bitwarden clients send for
/// `lastUsedDate` and `passwordRevisionDate`.
#[must_use]
pub fn history_timestamp(since_epoch: std::time::Duration) -> String {
    let secs = since_epoch.as_secs();
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX / 2);
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        since_epoch.subsec_millis()
    )
}

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
    /// `--prompt` replaces the password: refuse before prompting when there is none.
    /// # Errors
    /// Returns an error when the item has no stored password.
    pub fn require_password(&self) -> Result<()> {
        ensure!(
            self.login()
                .and_then(|login| login.get("password"))
                .is_some_and(Value::is_string),
            "selected field missing"
        );
        Ok(())
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

/// A password-history entry as official clients write it, under the item's key.
fn history_entry(keys: &CryptoKeys, plaintext: &str, now: &str) -> Result<Value> {
    let mut entry = Map::new();
    entry.insert(
        "password".into(),
        Value::String(keys.encrypt(plaintext.as_bytes())?),
    );
    entry.insert("lastUsedDate".into(), Value::String(now.to_owned()));
    Ok(Value::Object(entry))
}

/// Builds the PUT body: selected values re-encrypted with the item's key and
/// fresh IVs, everything else verbatim, bound to the snapshot's revision. Like
/// official Bitwarden clients, a changed non-empty password and every changed
/// non-empty hidden field value are added (newest first, at most five entries)
/// to password history, and a changed password sets `passwordRevisionDate`.
/// # Errors
/// Returns an error for a binding mismatch, a missing or unsupported field, or
/// an unsupported item; nothing is sent.
pub fn plan_update(
    parent: &CryptoKeys,
    destination: &Destination,
    snapshot: &ItemSnapshot,
    input: &SecretImport,
    now: &str,
) -> Result<UpdatePlan> {
    input.validate_update()?;
    let keys = snapshot.bound_keys(parent, destination)?;
    let mut body = Map::new();
    for member in PRESERVED {
        if let Some(value) = snapshot.raw.get(member) {
            body.insert(member.to_owned(), value.clone());
        }
    }
    let encrypt = |value: &str| keys.encrypt(value.as_bytes()).map(Value::String);
    // Newest first, in the order official clients insert them.
    let mut added = Vec::new();
    let mut history = Vec::new();
    if let Some(password) = &input.password {
        let login = body
            .get_mut("login")
            .and_then(Value::as_object_mut)
            .filter(|login| login.get("password").is_some_and(Value::is_string))
            .ok_or_else(|| anyhow::anyhow!("selected field missing"))?;
        let old = selected_value(&snapshot.cipher, &keys, "password")?;
        login.insert("password".into(), encrypt(password)?);
        if !old.is_empty() && *old != *password {
            added.insert(0, history_entry(&keys, &old, now)?);
            login.insert("passwordRevisionDate".into(), Value::String(now.to_owned()));
            history.push("password".to_owned());
        }
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
        ensure!(names.contains(&wanted.name), "selected field missing");
    }
    // Item order, as official clients walk existing hidden fields.
    for (index, name) in names.iter().enumerate() {
        let Some(wanted) = input.fields.iter().find(|f| f.name == *name) else {
            continue;
        };
        let field = body
            .get_mut("fields")
            .and_then(Value::as_array_mut)
            .and_then(|fields| fields.get_mut(index))
            .and_then(Value::as_object_mut)
            .ok_or_else(|| anyhow::anyhow!("selected field missing"))?;
        let kind = field.get("type").and_then(Value::as_u64);
        ensure!(
            matches!(kind, Some(0 | 1)),
            "only text or hidden custom fields can be updated"
        );
        ensure!(
            field.get("value").is_some_and(Value::is_string),
            "selected field missing"
        );
        field.insert("value".into(), encrypt(&wanted.value)?);
        if kind == Some(1) {
            let old = selected_value(&snapshot.cipher, &keys, &format!("custom:{name}"))?;
            if !old.is_empty() && *old != *wanted.value {
                let entry = Zeroizing::new(format!("{name}: {}", old.as_str()));
                added.insert(0, history_entry(&keys, &entry, now)?);
                history.push(format!("custom:{name}"));
            }
        }
    }
    if !added.is_empty() {
        match body.get("passwordHistory") {
            None | Some(Value::Null) => {}
            Some(Value::Array(existing)) => added.extend(existing.iter().cloned()),
            Some(_) => anyhow::bail!("unsupported item response shape"),
        }
        added.truncate(PASSWORD_HISTORY_LIMIT);
        body.insert("passwordHistory".into(), Value::Array(added));
    }
    body.insert(
        "lastKnownRevisionDate".into(),
        Value::String(snapshot.revision.clone()),
    );
    Ok(UpdatePlan {
        body: Value::Object(body),
        history,
    })
}

/// A JSON object without the named members, for whole-object comparison.
fn without(value: Option<&Value>, skip: &[&str]) -> Option<Map<String, Value>> {
    value.and_then(Value::as_object).map(|object| {
        object
            .iter()
            .filter(|(key, _)| !skip.contains(&key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    })
}

/// Attachments must be unchanged; a download `url` carries a per-response token.
fn attachments(snapshot: &ItemSnapshot) -> Option<Vec<Option<Map<String, Value>>>> {
    snapshot
        .raw
        .get("attachments")
        .and_then(Value::as_array)
        .map(|list| list.iter().map(|a| without(Some(a), &["url"])).collect())
}

/// Exact comparison after a fresh read against the body that was sent: new
/// plaintext for selected fields, identical ciphertext and members for
/// everything else (the whole login object, every field object, password
/// history, attachments), same bindings. Date members (`lastUsedDate`,
/// `passwordRevisionDate`, a passkey's `creationDate`) compare as instants,
/// since Vaultwarden 1.36 re-serializes them with six fractional digits.
/// # Errors
/// Returns an error on any difference; callers then report `updated_unverified`.
pub fn verify_updated(
    parent: &CryptoKeys,
    destination: &Destination,
    before: &ItemSnapshot,
    sent: &Value,
    after: &ItemSnapshot,
    input: &SecretImport,
) -> Result<()> {
    let keys = after.bound_keys(parent, destination)?;
    ensure!(before.cipher.id == after.cipher.id, "item binding mismatch");
    let sent = sent
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("preserved component changed"))?;
    for member in IDENTITY {
        let same = match (sent.get(member), after.raw.get(member)) {
            (Some(sent), Some(stored)) => dates::same_json(sent, stored),
            (sent, stored) => sent == stored,
        };
        ensure!(same, "preserved component changed");
    }
    ensure!(
        attachments(before) == attachments(after),
        "preserved component changed"
    );
    let skip: &[&str] = if input.password.is_some() {
        &["password"]
    } else {
        &[]
    };
    let login = |item: Option<&Value>| without(item, skip).map(Value::Object);
    ensure!(
        match (login(sent.get("login")), login(after.raw.get("login"))) {
            (Some(sent), Some(stored)) => dates::same_json(&sent, &stored),
            (sent, stored) => sent == stored,
        },
        "preserved component changed"
    );
    let exact = |selector: &str, expected: &str| -> Result<()> {
        ensure!(
            *selected_value(&after.cipher, &keys, selector)? == *expected,
            "verification mismatch"
        );
        Ok(())
    };
    if let Some(value) = &input.password {
        exact("password", value)?;
    }
    match &input.notes {
        Some(value) => exact("notes", value)?,
        None => ensure!(
            sent.get("notes") == after.raw.get("notes"),
            "preserved component changed"
        ),
    }
    let names = field_names(after, &keys)?;
    let sent_fields = sent
        .get("fields")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    ensure!(
        names == field_names(before, &keys)? && sent_fields.len() == after.fields().len(),
        "preserved component changed"
    );
    for ((name, old), new) in names.iter().zip(sent_fields).zip(after.fields()) {
        match input.fields.iter().find(|f| f.name == *name) {
            Some(wanted) => {
                ensure!(
                    without(Some(old), &["value"]) == without(Some(new), &["value"]),
                    "preserved component changed"
                );
                exact(&format!("custom:{name}"), &wanted.value)?;
            }
            None => ensure!(old == new, "preserved component changed"),
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "secret_update_tests.rs"]
mod tests;
