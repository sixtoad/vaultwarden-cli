//! HTTP contract of the protected update against a stateful mock Vaultwarden.
use super::*;
use crate::{
    access::{
        policy::{UpdateEffect, UpdateReview},
        ports::{SecretBackend, SensitiveString},
    },
    config::Config,
    crypto::CryptoKeys,
    secret_storage::{Destination, SecretImport, encrypt_create},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const ITEM: &str = "33333333-3333-3333-3333-333333333333";
const REVISION: &str = "2026-11-21T10:00:00.000000Z";

fn destination() -> Destination {
    Destination {
        account_id: "11111111-1111-1111-1111-111111111111".into(),
        folder: "homelab/production".into(),
        folder_id: "22222222-2222-2222-2222-222222222222".into(),
        reference: "homelab/production/github/token".into(),
    }
}
fn effect(fields: &[&str]) -> UpdateEffect {
    UpdateEffect {
        server: "https://vault.example".into(),
        item_id: ITEM.into(),
        destination: destination(),
        fields: fields.iter().map(|f| (*f).to_owned()).collect(),
    }
}

struct Vault {
    rt: tokio::runtime::Runtime,
    server: MockServer,
    backend: VaultwardenBackend,
    keys: CryptoKeys,
    sync: Arc<Mutex<Value>>,
    item: Arc<Mutex<Value>>,
    puts: Arc<Mutex<Vec<Value>>>,
    put_status: Arc<Mutex<(u16, Option<Value>)>>,
}
impl Vault {
    fn new() -> Self {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(MockServer::start());
        let config = Config {
            server: Some(server.uri()),
            ..Config::default()
        };
        let mut backend = VaultwardenBackend::new(config, true).unwrap();
        // The production HTTPS identity; only the test transport is loopback HTTP.
        backend.config.server = Some("https://vault.example/".into());
        backend.compatible = true;
        let keys = CryptoKeys::from_key_bytes([42; 32], [43; 32]);
        backend.session = Some((
            SensitiveString::new("session-sentinel".into()),
            keys.clone(),
        ));
        let sync = json!({"profile":{"id":destination().account_id,"email":"synthetic@example.invalid"},
            "folders":[{"id":destination().folder_id,"name":keys.encrypt(destination().folder.as_bytes()).unwrap()}],"ciphers":[]});
        let input = SecretImport::parse(
            br#"{"password":"old-private","notes":"old-notes","fields":[{"name":"api-key","value":"old-key"}]}"#,
        )
        .unwrap();
        let mut item =
            serde_json::to_value(encrypt_create(&keys, &destination(), &input, None).unwrap())
                .unwrap();
        item["id"] = json!(ITEM);
        item["revisionDate"] = json!(REVISION);
        let vault = Self {
            rt,
            server,
            backend,
            keys,
            sync: Arc::new(Mutex::new(sync)),
            item: Arc::new(Mutex::new(item)),
            puts: Arc::new(Mutex::new(Vec::new())),
            put_status: Arc::new(Mutex::new((200, None))),
        };
        vault.mount();
        vault
    }
    fn mount(&self) {
        let (sync, item, puts, status) = (
            self.sync.clone(),
            self.item.clone(),
            self.puts.clone(),
            self.put_status.clone(),
        );
        let get = self.item.clone();
        self.rt.block_on(async {
            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(move |_: &wiremock::Request| {
                    ResponseTemplate::new(200).set_body_json(sync.lock().unwrap().clone())
                })
                .mount(&self.server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/api/ciphers/{ITEM}")))
                .respond_with(move |_: &wiremock::Request| {
                    ResponseTemplate::new(200).set_body_json(get.lock().unwrap().clone())
                })
                .mount(&self.server)
                .await;
            Mock::given(method("PUT"))
                .and(path(format!("/api/ciphers/{ITEM}")))
                .respond_with(move |request: &wiremock::Request| {
                    let body: Value = serde_json::from_slice(&request.body).unwrap();
                    puts.lock().unwrap().push(body.clone());
                    let (code, reply) = status.lock().unwrap().clone();
                    if code != 200 {
                        return ResponseTemplate::new(code).set_body_string("server-detail");
                    }
                    let mut stored = body;
                    let object = stored.as_object_mut().unwrap();
                    object.remove("lastKnownRevisionDate");
                    object.insert("id".into(), json!(ITEM));
                    object.insert("revisionDate".into(), json!("2026-11-21T10:05:00.000000Z"));
                    *item.lock().unwrap() = stored.clone();
                    ResponseTemplate::new(200).set_body_json(reply.unwrap_or(stored))
                })
                .mount(&self.server)
                .await;
        });
    }
    fn review(&mut self, fields: &[&str]) -> UpdateReview {
        let effect = effect(fields);
        let revision = self.backend.update_review(&effect).unwrap();
        effect.review(revision)
    }
    fn item_keys(&self) -> CryptoKeys {
        let item = self.item.lock().unwrap().clone();
        self.keys.item_keys(item["key"].as_str()).unwrap()
    }
}

fn input(json: &[u8]) -> SecretImport {
    SecretImport::parse_update(json).unwrap()
}

#[test]
fn provider_update_puts_once_bound_to_the_reviewed_revision_and_verifies() {
    let mut vault = Vault::new();
    let review = vault.review(&["password", "custom:api-key"]);
    assert_eq!(review.expected_revision, REVISION);
    let value =
        input(br#"{"password":"new-private","fields":[{"name":"api-key","value":"new-key"}]}"#);
    let prepared = vault.backend.update_prepare(&review, &value).unwrap();
    assert!(vault.puts.lock().unwrap().is_empty(), "prepare never sends");
    vault
        .backend
        .update_secret(&review, &prepared, &|| true)
        .unwrap();
    let puts = vault.puts.lock().unwrap().clone();
    assert_eq!(puts.len(), 1);
    assert_eq!(puts[0]["lastKnownRevisionDate"], REVISION);
    let wire = puts[0].to_string();
    for plaintext in ["new-private", "new-key", "old-private", "old-key"] {
        assert!(!wire.contains(plaintext), "{plaintext}");
    }
    // The old password and the old hidden field value, as official clients do (D6).
    assert_eq!(puts[0]["passwordHistory"].as_array().unwrap().len(), 2);
    vault
        .backend
        .verify_update(&review, &prepared, &value)
        .unwrap();
    // A valid authenticated replacement must fail exact comparison.
    let keys = vault.item_keys();
    vault.item.lock().unwrap()["login"]["password"] = json!(keys.encrypt(b"someone-else").unwrap());
    assert!(
        vault
            .backend
            .verify_update(&review, &prepared, &value)
            .is_err()
    );
}

#[test]
fn provider_update_refuses_stale_revision_wrong_schema_and_broken_binding_before_any_put() {
    let mut vault = Vault::new();
    let review = vault.review(&["password"]);
    let value = input(br#"{"password":"new-private"}"#);
    // The producer must emit exactly the reviewed schema.
    for other in [
        br#"{"password":"new","notes":"n"}"#.as_slice(),
        br#"{"notes":"n"}"#.as_slice(),
    ] {
        assert_eq!(
            vault.backend.update_prepare(&review, &input(other)).err(),
            Some(SessionError::InvalidRequest)
        );
    }
    vault.item.lock().unwrap()["revisionDate"] = json!("2026-11-21T10:00:01.000000Z");
    assert_eq!(
        vault.backend.update_prepare(&review, &value).err(),
        Some(SessionError::InvalidRequest),
        "a write since review consumes the approval"
    );
    vault.item.lock().unwrap()["revisionDate"] = json!(REVISION);
    let original_sync = vault.sync.lock().unwrap().clone();
    let original_item = vault.item.lock().unwrap().clone();
    let keys = vault.keys.clone();
    let item_keys = vault.item_keys();
    for change in ["account", "folder", "name", "deleted", "organization"] {
        *vault.sync.lock().unwrap() = original_sync.clone();
        *vault.item.lock().unwrap() = original_item.clone();
        match change {
            "account" => {
                vault.sync.lock().unwrap()["profile"]["id"] =
                    json!("44444444-4444-4444-4444-444444444444");
            }
            "folder" => {
                vault.sync.lock().unwrap()["folders"][0]["name"] =
                    json!(keys.encrypt(b"homelab/renamed").unwrap());
            }
            "name" => {
                vault.item.lock().unwrap()["name"] =
                    json!(item_keys.encrypt(b"github/renamed").unwrap());
            }
            "deleted" => {
                vault.item.lock().unwrap()["deletedDate"] = json!("2026-11-21T10:00:00Z");
            }
            _ => {
                vault.item.lock().unwrap()["organizationId"] =
                    json!("55555555-5555-5555-5555-555555555555");
            }
        }
        assert!(
            vault.backend.update_review(&review.effect()).is_err(),
            "{change}"
        );
        assert!(
            vault.backend.update_prepare(&review, &value).is_err(),
            "{change}"
        );
    }
    *vault.sync.lock().unwrap() = original_sync;
    *vault.item.lock().unwrap() = original_item;
    let prepared = vault.backend.update_prepare(&review, &value).unwrap();
    assert_eq!(
        vault.backend.update_secret(&review, &prepared, &|| false),
        Err(WriteStatus::Failed),
        "no PUT once the approval is no longer live"
    );
    let mut other_server = review.clone();
    other_server.server = "https://other.example".into();
    assert_eq!(
        vault
            .backend
            .update_secret(&other_server, &prepared, &|| true),
        Err(WriteStatus::Failed)
    );
    let mut other_revision = review.clone();
    other_revision.expected_revision = "2026-11-21T09:00:00.000000Z".into();
    assert_eq!(
        vault
            .backend
            .update_secret(&other_revision, &prepared, &|| true),
        Err(WriteStatus::Failed),
        "the body is bound to the reviewed revision"
    );
    assert!(vault.puts.lock().unwrap().is_empty());
}

#[test]
fn provider_update_maps_put_outcomes_like_create_and_never_echoes_server_bodies() {
    for (code, reply, expected) in [
        (400, None, Err(WriteStatus::Failed)),
        (404, None, Err(WriteStatus::Failed)),
        (422, None, Err(WriteStatus::Failed)),
        (500, None, Err(WriteStatus::Uncertain)),
        (409, None, Err(WriteStatus::Uncertain)),
        (
            200,
            Some(json!({"id": "44444444-4444-4444-4444-444444444444"})),
            Err(WriteStatus::Uncertain),
        ),
        (
            200,
            Some(json!(["not", "an", "item"])),
            Err(WriteStatus::Uncertain),
        ),
        (200, None, Ok(())),
    ] {
        let mut vault = Vault::new();
        *vault.put_status.lock().unwrap() = (code, reply.clone());
        let review = vault.review(&["notes"]);
        let value = input(br#"{"notes":"new notes"}"#);
        let prepared = vault.backend.update_prepare(&review, &value).unwrap();
        assert_eq!(
            vault.backend.update_secret(&review, &prepared, &|| true),
            expected,
            "{code} {reply:?}"
        );
        assert_eq!(vault.puts.lock().unwrap().len(), 1, "{code}");
    }
}

#[test]
fn provider_update_reconcile_compares_revisions_and_never_writes() {
    let mut vault = Vault::new();
    let review = vault.review(&["password"]);
    assert_eq!(
        vault.backend.reconcile_update(&review),
        Ok(WriteStatus::Failed),
        "unchanged revision: nothing was written"
    );
    // Unchanged revision but a broken binding is not proof of anything.
    let item_keys = vault.item_keys();
    let original = vault.item.lock().unwrap().clone();
    vault.item.lock().unwrap()["name"] = json!(item_keys.encrypt(b"github/renamed").unwrap());
    assert!(vault.backend.reconcile_update(&review).is_err());
    // Any later write (a rename or a trash included) bumps the revision.
    vault.item.lock().unwrap()["revisionDate"] = json!("2026-11-21T10:05:00.000000Z");
    assert_eq!(
        vault.backend.reconcile_update(&review),
        Ok(WriteStatus::UpdatedUnverified)
    );
    *vault.item.lock().unwrap() = original;
    vault.sync.lock().unwrap()["profile"]["id"] = json!("44444444-4444-4444-4444-444444444444");
    assert!(
        vault.backend.reconcile_update(&review).is_err(),
        "account binding"
    );
    assert!(vault.puts.lock().unwrap().is_empty());
}
