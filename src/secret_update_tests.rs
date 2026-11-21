use super::*;
use crate::secret_storage::encrypt_create;
use serde_json::json;

const ID: &str = "33333333-3333-3333-3333-333333333333";

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
    item["login"]["uris"] =
        json!([{"uri": parent.encrypt(b"https://example.invalid").unwrap(), "match": null}]);
    item["passwordHistory"] = json!([{"password": parent.encrypt(b"older").unwrap(), "lastUsedDate": "2026-01-01T00:00:00Z"}]);
    item
}
/// What a faithful server stores and returns for a PUT body.
fn applied(body: &Value) -> Value {
    let mut item = body.clone();
    let object = item.as_object_mut().unwrap();
    object.remove("lastKnownRevisionDate");
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
    let body = plan_update(&parent, &destination(), &before, &input).unwrap();
    let wire = body.to_string();
    assert!(!wire.contains("new-private") && !wire.contains("new-key"));
    assert_eq!(body["lastKnownRevisionDate"], json!(before.revision()));
    for member in ["key", "name", "notes", "folderId", "passwordHistory"] {
        assert_eq!(body[member], before.raw[member], "{member}");
    }
    assert_eq!(body["login"]["username"], before.raw["login"]["username"]);
    assert_ne!(body["login"]["password"], before.raw["login"]["password"]);
    assert_ne!(body["fields"][0]["value"], before.raw["fields"][0]["value"]);
    assert_eq!(body["fields"][1], before.raw["fields"][1]);
    let after = snapshot(applied(&body));
    verify_updated(&parent, &destination(), &before, &after, &input).unwrap();
    let keys = parent.item_keys(after.cipher.item_key.as_deref()).unwrap();
    assert_eq!(
        *selected_value(&after.cipher, &keys, "password").unwrap(),
        "  new-private\n\u{0}"
    );
    // Notes alone is a valid update selection, unlike creation.
    let notes = SecretImport::parse_update(br#"{"notes":"rotated"}"#).unwrap();
    assert!(notes.validate().is_err());
    let body = plan_update(&parent, &destination(), &before, &notes).unwrap();
    verify_updated(
        &parent,
        &destination(),
        &before,
        &snapshot(applied(&body)),
        &notes,
    )
    .unwrap();
    assert!(SecretImport::parse_update(b"{}").is_err());
}

#[test]
fn missing_unsupported_and_rebound_items_are_refused_before_any_write() {
    let parent = parent();
    let item = stored(&parent);
    let input = |json: &[u8]| SecretImport::parse_update(json).unwrap();
    let refused = |item: Value, json: &[u8]| {
        plan_update(&parent, &destination(), &snapshot(item), &input(json)).is_err()
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
    pascal["Name"] = pascal["name"].clone();
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
    let body = plan_update(&parent, &destination(), &before, &input).unwrap();
    let good = applied(&body);
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
        verify_updated(&parent, &destination(), &before, &snapshot(item), &input).is_err()
    };
    let other = parent.encrypt(b"other").unwrap();
    assert!(tampered(
        &["fields", "0", "value"],
        json!(parent.encrypt(b"wrong").unwrap())
    ));
    assert!(tampered(&["fields", "1", "value"], json!(other)));
    assert!(tampered(&["fields", "1", "type"], json!(0)));
    assert!(tampered(&["login", "password"], json!(other)));
    assert!(tampered(&["login", "username"], json!(other)));
    assert!(tampered(&["login", "uris", "0", "uri"], json!(other)));
    assert!(tampered(&["notes"], json!(other)));
    assert!(tampered(&["passwordHistory"], Value::Null));
    assert!(tampered(&["favorite"], json!(true)));
    assert!(tampered(&["deletedDate"], json!("2026-11-21T10:06:00Z")));
    let mut dropped = good.clone();
    dropped["fields"].as_array_mut().unwrap().pop();
    assert!(verify_updated(&parent, &destination(), &before, &snapshot(dropped), &input).is_err());
    verify_updated(&parent, &destination(), &before, &snapshot(good), &input).unwrap();
}
