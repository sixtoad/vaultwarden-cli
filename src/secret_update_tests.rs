use super::*;
use crate::secret_storage::encrypt_create;
use serde_json::json;

const ID: &str = "33333333-3333-3333-3333-333333333333";
const NOW: &str = "2026-11-22T09:30:00.123Z";

fn plan(before: &ItemSnapshot, input: &SecretImport) -> UpdatePlan {
    plan_update(&parent(), &destination(), before, input, NOW).unwrap()
}
fn verify(
    before: &ItemSnapshot,
    plan: &UpdatePlan,
    after: &ItemSnapshot,
    input: &SecretImport,
) -> Result<()> {
    verify_updated(&parent(), &destination(), before, &plan.body, after, input)
}

fn parent() -> CryptoKeys {
    CryptoKeys::from_key_bytes([1; 32], [2; 32])
}
fn destination() -> Destination {
    Destination {
        account_id: "11111111-1111-1111-1111-111111111111".into(),
        folder: "homelab/production".into(),
        folder_id: "22222222-2222-2222-2222-222222222222".into(),
        reference: "homelab/production/github/token".into(),
    }
}
/// A stored item as Vaultwarden 1.36 returns it, with unselected components.
fn stored(parent: &CryptoKeys) -> Value {
    let input = SecretImport::parse(
        br#"{"password":"old-private","notes":"old-notes","fields":[{"name":"api-key","value":"old-key"},{"name":"other","value":"keep-private"}]}"#,
    )
    .unwrap();
    let mut item =
        serde_json::to_value(encrypt_create(parent, &destination(), &input, None).unwrap())
            .unwrap();
    item["id"] = json!(ID);
    item["revisionDate"] = json!("2026-11-21T10:00:00.000000Z");
    item["login"]["username"] = json!(parent.encrypt(b"deploy").unwrap());
    item["login"]["totp"] = Value::Null;
    item["login"]["uris"] = json!([{
        "uri": parent.encrypt(b"https://example.invalid").unwrap(),
        "uriChecksum": parent.encrypt(b"checksum").unwrap(),
        "match": null
    }]);
    item["login"]["fido2Credentials"] =
        json!([{"credentialId": parent.encrypt(b"passkey").unwrap(), "rpId": "example.invalid"}]);
    item["login"]["passwordRevisionDate"] = json!("2026-01-01T00:00:00.000Z");
    item["fields"][1]["linkedId"] = Value::Null;
    item["attachments"] = json!([{"id": "a1", "fileName": parent.encrypt(b"f").unwrap(), "url": "https://vault/a1?token=one"}]);
    let item_keys = parent.item_keys(item["key"].as_str()).unwrap();
    item["passwordHistory"] = json!([{"password": item_keys.encrypt(b"older").unwrap(), "lastUsedDate": "2026-01-01T00:00:00Z"}]);
    item
}
/// What a faithful server stores and returns for a PUT body (attachments are
/// not part of the body; the server keeps them).
fn applied(body: &Value, before: &ItemSnapshot) -> Value {
    let mut item = body.clone();
    let object = item.as_object_mut().unwrap();
    object.remove("lastKnownRevisionDate");
    if let Some(attachments) = before.raw.get("attachments") {
        object.insert("attachments".into(), attachments.clone());
    }
    object.insert("id".into(), json!(ID));
    object.insert("revisionDate".into(), json!("2026-11-21T10:05:00.000000Z"));
    item
}
fn snapshot(value: Value) -> ItemSnapshot {
    ItemSnapshot::parse(value, ID).unwrap()
}

#[test]
fn update_replaces_only_selected_values_and_preserves_ciphertext_verbatim() {
    let parent = parent();
    let before = snapshot(stored(&parent));
    let input = SecretImport::parse_update(
        br#"{"password":"  new-private\n\u0000","fields":[{"name":"api-key","value":"new-key\n"}]}"#,
    )
    .unwrap();
    let update = plan(&before, &input);
    let body = &update.body;
    let wire = body.to_string();
    assert!(!wire.contains("new-private") && !wire.contains("new-key"));
    assert!(!wire.contains("old-private") && !wire.contains("old-key"));
    assert_eq!(body["lastKnownRevisionDate"], json!(before.revision()));
    for member in ["key", "name", "notes", "folderId"] {
        assert_eq!(body[member], before.raw[member], "{member}");
    }
    // Official-client history: hidden field entry, then password, then older entries.
    assert_eq!(update.history, ["password", "custom:api-key"]);
    let keys = parent.item_keys(before.cipher.item_key.as_deref()).unwrap();
    let history = body["passwordHistory"].as_array().unwrap();
    let entries: Vec<String> = history
        .iter()
        .map(|e| {
            keys.decrypt_authenticated_to_string(e["password"].as_str().unwrap())
                .unwrap()
        })
        .collect();
    assert_eq!(entries, ["api-key: old-key", "old-private", "older"]);
    assert_eq!(history[0]["lastUsedDate"], json!(NOW));
    assert_eq!(history[1]["lastUsedDate"], json!(NOW));
    assert_eq!(history[2], before.raw["passwordHistory"][0]);
    assert_eq!(body["login"]["passwordRevisionDate"], json!(NOW));
    assert_eq!(
        body["login"]["fido2Credentials"],
        before.raw["login"]["fido2Credentials"]
    );
    assert_eq!(body["login"]["username"], before.raw["login"]["username"]);
    assert_ne!(body["login"]["password"], before.raw["login"]["password"]);
    assert_ne!(body["fields"][0]["value"], before.raw["fields"][0]["value"]);
    assert_eq!(body["fields"][1], before.raw["fields"][1]);
    let after = snapshot(applied(body, &before));
    verify(&before, &update, &after, &input).unwrap();
    assert_eq!(
        *selected_value(&after.cipher, &keys, "password").unwrap(),
        "  new-private\n\u{0}"
    );
    // Notes alone is a valid update selection, unlike creation.
    let notes = SecretImport::parse_update(br#"{"notes":"rotated"}"#).unwrap();
    assert!(notes.validate().is_err());
    let notes_only = plan(&before, &notes);
    assert!(
        notes_only.history.is_empty(),
        "notes never go to password history"
    );
    assert_eq!(
        notes_only.body["passwordHistory"],
        before.raw["passwordHistory"]
    );
    verify(
        &before,
        &notes_only,
        &snapshot(applied(&notes_only.body, &before)),
        &notes,
    )
    .unwrap();
    assert!(SecretImport::parse_update(b"{}").is_err());
}

#[test]
fn history_matches_official_clients_only_for_changed_values_and_keeps_five() {
    let parent = parent();
    let mut item = stored(&parent);
    // An unchanged value and a text field add nothing and keep the revision date.
    item["fields"][1]["type"] = json!(0);
    let before = snapshot(item.clone());
    let same = SecretImport::parse_update(
        br#"{"password":"old-private","fields":[{"name":"other","value":"changed"}]}"#,
    )
    .unwrap();
    let unchanged = plan(&before, &same);
    assert!(unchanged.history.is_empty());
    assert_eq!(
        unchanged.body["passwordHistory"],
        before.raw["passwordHistory"]
    );
    assert_eq!(
        unchanged.body["login"]["passwordRevisionDate"],
        before.raw["login"]["passwordRevisionDate"]
    );
    verify(
        &before,
        &unchanged,
        &snapshot(applied(&unchanged.body, &before)),
        &same,
    )
    .unwrap();
    // Five existing entries: two new ones push the two oldest out.
    let keys = parent.item_keys(before.cipher.item_key.as_deref()).unwrap();
    item["passwordHistory"] = Value::Array(
        (0..5)
            .map(|n| json!({"password": keys.encrypt(format!("h{n}").as_bytes()).unwrap(), "lastUsedDate": "2026-01-01T00:00:00.000Z"}))
            .collect(),
    );
    let before = snapshot(item);
    let input = SecretImport::parse_update(
        br#"{"password":"new","fields":[{"name":"api-key","value":"new"}]}"#,
    )
    .unwrap();
    let full = plan(&before, &input);
    let history = full.body["passwordHistory"].as_array().unwrap();
    assert_eq!(history.len(), PASSWORD_HISTORY_LIMIT);
    assert_eq!(
        &history[2..],
        &before.raw["passwordHistory"].as_array().unwrap()[..3]
    );
    // An empty old password is not history, as in official clients.
    let mut empty = stored(&parent);
    let empty_keys = parent.item_keys(empty["key"].as_str()).unwrap();
    empty["login"]["password"] = json!(empty_keys.encrypt(b"").unwrap());
    let empty = snapshot(empty);
    let password = SecretImport::parse_update(br#"{"password":"new"}"#).unwrap();
    let first = plan(&empty, &password);
    assert!(first.history.is_empty());
    assert_eq!(
        first.body["login"]["passwordRevisionDate"],
        empty.raw["login"]["passwordRevisionDate"]
    );
}

#[test]
fn history_timestamps_use_the_client_iso_form() {
    use std::time::Duration;
    for (since, expected) in [
        (Duration::ZERO, "1970-01-01T00:00:00.000Z"),
        (
            Duration::from_millis(1_700_000_000_123),
            "2023-11-14T22:13:20.123Z",
        ),
        (
            Duration::from_secs(1_709_164_800),
            "2024-02-29T00:00:00.000Z",
        ),
        (
            Duration::from_secs(1_735_689_599),
            "2024-12-31T23:59:59.000Z",
        ),
    ] {
        assert_eq!(history_timestamp(since), expected);
    }
}

#[test]
fn missing_unsupported_and_rebound_items_are_refused_before_any_write() {
    let parent = parent();
    let item = stored(&parent);
    let input = |json: &[u8]| SecretImport::parse_update(json).unwrap();
    let refused = |item: Value, json: &[u8]| {
        plan_update(&parent, &destination(), &snapshot(item), &input(json), NOW).is_err()
    };
    assert!(refused(
        item.clone(),
        br#"{"fields":[{"name":"absent","value":"x"}]}"#
    ));
    let mut no_notes = item.clone();
    no_notes["notes"] = Value::Null;
    assert!(refused(no_notes, br#"{"notes":"x"}"#));
    let mut no_password = item.clone();
    no_password["login"]["password"] = Value::Null;
    assert!(refused(no_password, br#"{"password":"x"}"#));
    let mut boolean = item.clone();
    boolean["fields"][0]["type"] = json!(2);
    assert!(refused(
        boolean,
        br#"{"fields":[{"name":"api-key","value":"x"}]}"#
    ));
    let mut organization = item.clone();
    organization["organizationId"] = json!("44444444-4444-4444-4444-444444444444");
    assert!(refused(organization, br#"{"password":"x"}"#));
    let mut moved = item.clone();
    moved["folderId"] = json!("55555555-5555-5555-5555-555555555555");
    assert!(refused(moved, br#"{"password":"x"}"#));
    let mut duplicate = item.clone();
    let copy = duplicate["fields"][0].clone();
    duplicate["fields"].as_array_mut().unwrap().push(copy);
    assert!(refused(
        duplicate,
        br#"{"fields":[{"name":"other","value":"x"}]}"#
    ));
    let mut pascal = item.clone();
    // A PascalCase member serde would ignore: only the shape guard refuses it.
    pascal["Edit"] = json!(true);
    assert!(ItemSnapshot::parse(pascal, ID).is_err());
    let mut no_revision = item.clone();
    no_revision["revisionDate"] = Value::Null;
    assert!(ItemSnapshot::parse(no_revision, ID).is_err());
    assert!(ItemSnapshot::parse(item, "44444444-4444-4444-4444-444444444444").is_err());
    assert!(
        SecretImport::parse_update(br#"{"fields":[{"name":"vw-access","value":"x"}]}"#).is_err()
    );
}

#[test]
fn verification_fails_closed_on_any_changed_or_wrong_component() {
    let parent = parent();
    let before = snapshot(stored(&parent));
    let input = SecretImport::parse_update(br#"{"fields":[{"name":"api-key","value":"new-key"}]}"#)
        .unwrap();
    let plan = plan(&before, &input);
    let good = applied(&plan.body, &before);
    let tampered = |path: &[&str], value: Value| {
        let mut item = good.clone();
        let mut slot = &mut item;
        for step in path {
            slot = match step.parse::<usize>() {
                Ok(index) => &mut slot[index],
                Err(_) => &mut slot[*step],
            };
        }
        *slot = value;
        verify(&before, &plan, &snapshot(item), &input).is_err()
    };
    // Authentic ciphertext under the item's own key, so only value comparison can catch it.
    let item_keys = parent.item_keys(before.cipher.item_key.as_deref()).unwrap();
    let other = item_keys.encrypt(b"other").unwrap();
    assert!(tampered(
        &["fields", "0", "value"],
        json!(item_keys.encrypt(b"wrong").unwrap())
    ));
    assert!(tampered(&["fields", "1", "value"], json!(other)));
    assert!(tampered(&["fields", "1", "type"], json!(0)));
    assert!(tampered(&["login", "password"], json!(other)));
    assert!(tampered(&["login", "username"], json!(other)));
    assert!(tampered(&["login", "uris", "0", "uri"], json!(other)));
    assert!(tampered(&["notes"], json!(other)));
    assert!(tampered(&["passwordHistory"], Value::Null));
    assert!(tampered(
        &["passwordHistory", "0", "lastUsedDate"],
        json!("2026-11-22T00:00:00.000Z")
    ));
    assert!(tampered(&["login", "passwordRevisionDate"], json!(NOW)));
    assert!(tampered(&["login", "fido2Credentials"], json!([])));
    assert!(tampered(&["login", "uris", "0", "match"], json!(3)));
    assert!(tampered(
        &["login", "uris", "0", "uriChecksum"],
        json!(other)
    ));
    assert!(tampered(&["login", "autofillOnPageLoad"], json!(true)));
    assert!(tampered(&["fields", "0", "linkedId"], json!(1)));
    assert!(tampered(&["fields", "1", "linkedId"], json!(1)));
    assert!(tampered(&["attachments", "0", "fileName"], json!(other)));
    assert!(tampered(&["favorite"], json!(true)));
    assert!(tampered(&["deletedDate"], json!("2026-11-21T10:06:00Z")));
    let mut dropped = good.clone();
    dropped["fields"].as_array_mut().unwrap().pop();
    assert!(verify(&before, &plan, &snapshot(dropped), &input).is_err());
    let mut passkey = good.clone();
    passkey["login"]
        .as_object_mut()
        .unwrap()
        .remove("fido2Credentials");
    assert!(
        verify(&before, &plan, &snapshot(passkey), &input).is_err(),
        "a dropped passkey"
    );
    // A download URL carries a per-response token and may differ.
    let mut fresh_url = good.clone();
    fresh_url["attachments"][0]["url"] = json!("https://vault/a1?token=two");
    verify(&before, &plan, &snapshot(fresh_url), &input).unwrap();
    verify(&before, &plan, &snapshot(good), &input).unwrap();
}
