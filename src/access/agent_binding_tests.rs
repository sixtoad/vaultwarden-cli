use super::agent_binding::*;
use super::provider_store::{ProviderState, ProviderStore};
use super::{decode_public_key, encode_public_key};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use std::os::unix::fs::PermissionsExt;

fn pairing(seed: u8) -> AgentPairing {
    AgentPairing {
        label: "build agent".into(),
        public_key: encode_public_key(&SigningKey::from_bytes(&[seed; 32]).verifying_key()),
        uid: 41001,
        gid: 41002,
    }
}

#[test]
fn bindings_have_random_ids_derived_fingerprints_and_closed_safe_views() {
    let first = AgentBinding::new(pairing(1), 1000).unwrap();
    let second = AgentBinding::new(pairing(1), 1000).unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!(first.fingerprint, second.fingerprint);
    assert_eq!(first.status, AgentBindingStatus::Enabled);
    let view = serde_json::to_value(first.view()).unwrap();
    assert_eq!(view.as_object().unwrap().len(), 6);
    assert!(view.get("public_key").is_none());
    let audit = first.audit(1000, 12, AgentAuditAction::Paired);
    let encoded = serde_json::to_string(&audit).unwrap();
    assert!(!encoded.contains(&first.public_key));
    let mut injected = serde_json::to_value(audit).unwrap();
    injected["public_key"] = first.public_key.into();
    assert!(serde_json::from_value::<AgentAuditEvent>(injected).is_err());
}

#[test]
fn pairing_rejects_each_invalid_label_and_os_identity_independently() {
    for label in ["", " ", "a\nb", "agent\tname", "é", &"a".repeat(129)] {
        let mut input = pairing(1);
        input.label = label.into();
        assert!(AgentBinding::new(input, 1000).is_err(), "{label:?}");
    }
    for uid in [0, u32::MAX, 1000] {
        let mut input = pairing(1);
        input.uid = uid;
        assert!(AgentBinding::new(input, 1000).is_err());
    }
    for gid in [0, u32::MAX] {
        let mut input = pairing(1);
        input.gid = gid;
        assert!(AgentBinding::new(input, 1000).is_err());
    }
}

#[test]
fn key_codec_rejects_encoding_length_invalid_points_weak_and_noncanonical_points() {
    let valid = pairing(1).public_key;
    for key in [
        "!".into(),
        format!("{valid}="),
        URL_SAFE_NO_PAD.encode([1; 31]),
    ] {
        assert!(decode_public_key(&key).is_err());
    }
    // y = 2 has no curve point; y = 1 is the identity (weak).
    for y in [1, 2] {
        let mut bytes = [0; 32];
        bytes[0] = y;
        assert!(decode_public_key(&URL_SAFE_NO_PAD.encode(bytes)).is_err());
    }
    // p + 3 is a noncanonical representation of the nonweak point y = 3.
    let mut bytes = [0xff; 32];
    bytes[0] = 0xf0;
    bytes[31] = 0x7f;
    let noncanonical = ed25519_dalek::VerifyingKey::from_bytes(&bytes).unwrap();
    assert!(!noncanonical.is_weak());
    assert_ne!(noncanonical.to_edwards().compress().to_bytes(), bytes);
    assert!(decode_public_key(&URL_SAFE_NO_PAD.encode(bytes)).is_err());
}

#[test]
fn os_match_requires_enabled_exact_uid_and_required_membership() {
    let mut binding = AgentBinding::new(pairing(1), 1000).unwrap();
    assert!(binding.matches_os(41001, &[5, 41002]));
    assert!(!binding.matches_os(41003, &[41002]));
    assert!(!binding.matches_os(41001, &[5]));
    binding.status = AgentBindingStatus::Revoked;
    assert!(!binding.matches_os(41001, &[41002]));
}

#[test]
fn registry_enforces_unique_ids_keys_enabled_labels_and_immutable_audit() {
    let first = AgentBinding::new(pairing(1), 1000).unwrap();
    let mut second = AgentBinding::new(pairing(2), 1000).unwrap();
    let audit = |bindings: &[AgentBinding]| {
        bindings
            .iter()
            .map(|b| b.audit(1000, 1, AgentAuditAction::Paired))
            .collect::<Vec<_>>()
    };
    let bindings = vec![first.clone(), second.clone()];
    assert!(validate_registry(&bindings, &audit(&bindings), 1000).is_err());
    second.label = "other".into();
    let good = vec![first.clone(), second.clone()];
    assert!(validate_registry(&good, &audit(&good), 1000).is_ok());
    for change in 0..3 {
        let mut bad = good.clone();
        match change {
            0 => bad[1].id = first.id.clone(),
            1 => {
                bad[1].public_key = first.public_key.clone();
                bad[1].fingerprint = first.fingerprint.clone();
            }
            _ => bad[1].fingerprint = "0".repeat(64),
        }
        assert!(validate_registry(&bad, &audit(&bad), 1000).is_err());
    }
    let mut events = audit(&good);
    events[0].actor_uid = 1001;
    assert!(validate_registry(&good, &events, 1000).is_err());
    assert!(validate_registry(&good, &[], 1000).is_err());
}

#[test]
fn revoked_label_needs_fresh_key_and_id_and_retains_both_audit_events() {
    let mut old = AgentBinding::new(pairing(1), 1000).unwrap();
    let mut events = vec![old.audit(1000, 1, AgentAuditAction::Paired)];
    old.status = AgentBindingStatus::Revoked;
    events.push(old.audit(1000, 2, AgentAuditAction::Revoked));
    let replacement = AgentBinding::new(pairing(2), 1000).unwrap();
    events.push(replacement.audit(1000, 3, AgentAuditAction::Paired));
    assert!(validate_registry(&[old.clone(), replacement], &events, 1000).is_ok());
    let reused = AgentBinding::new(pairing(1), 1000).unwrap();
    events[2] = reused.audit(1000, 3, AgentAuditAction::Paired);
    assert!(validate_registry(&[old.clone(), reused], &events, 1000).is_err());
    events.truncate(2);
    events.push(old.audit(1000, 4, AgentAuditAction::Revoked));
    assert!(validate_registry(&[old], &events, 1000).is_err());
}

#[test]
fn store_round_trips_revoked_tombstones_and_audit_on_repeated_restart() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = temp.path().join("provider");
    let mut store = ProviderStore::open(&root).unwrap();
    let mut state = store.read_state().unwrap();
    let owner = unsafe { libc::geteuid() };
    let mut binding = AgentBinding::new(pairing(1), owner).unwrap();
    state
        .agent_audit
        .push(binding.audit(owner, 1, AgentAuditAction::Paired));
    binding.status = AgentBindingStatus::Revoked;
    state
        .agent_audit
        .push(binding.audit(owner, 2, AgentAuditAction::Revoked));
    state.pairings.push(binding);
    store.write_state(&state).unwrap();
    drop(store);
    for _ in 0..2 {
        let reopened = ProviderStore::open(&root).unwrap();
        assert_eq!(reopened.read_state().unwrap(), state);
    }
}

#[test]
fn schema_migration_is_narrow_closed_and_repeatable() {
    let legacy =
        r#"{"schema_version":1,"lifecycle_epoch":9,"pairings":[],"operations":[],"requests":[]}"#;
    let migrated: ProviderState = serde_json::from_str(legacy).unwrap();
    assert_eq!(migrated.schema_version, 2);
    assert!(migrated.agent_audit.is_empty());
    assert_eq!(
        serde_json::from_str::<ProviderState>(&serde_json::to_string(&migrated).unwrap()).unwrap(),
        migrated
    );
    for bad in [
        legacy.replace("\"pairings\":[]", "\"pairings\":[\"old-agent\"]"),
        legacy.replace("\"schema_version\":1", "\"schema_version\":2"),
        legacy.replace("\"schema_version\":1", "\"schema_version\":3"),
        legacy.replace("\"requests\":[]", "\"requests\":[],\"unknown\":true"),
        legacy.replace("\"requests\":[]", "\"requests\":[],\"agent_audit\":[]"),
        legacy.replace(
            "\"lifecycle_epoch\":9",
            "\"lifecycle_epoch\":9,\"lifecycle_epoch\":10",
        ),
    ] {
        assert!(serde_json::from_str::<ProviderState>(&bad).is_err());
    }
}

#[test]
fn duplicate_binding_id_is_rejected_independently_of_key_label_and_audit_checks() {
    let first = AgentBinding::new(pairing(11), 1000).unwrap();
    let mut second_input = pairing(12);
    second_input.label = "second label".into();
    let mut second = AgentBinding::new(second_input, 1000).unwrap();
    second.id = first.id.clone();
    // A map implementation without ID uniqueness overwrites the first binding.
    // Supply exactly the surviving entry's valid audit so a duplicate audit or
    // metadata mismatch cannot mask the missing ID uniqueness check.
    let audit = vec![second.audit(1000, 12, AgentAuditAction::Paired)];
    assert_ne!(first.public_key, second.public_key);
    assert_ne!(first.label, second.label);
    first.validate(1000).unwrap();
    second.validate(1000).unwrap();
    assert!(validate_registry(&[first, second], &audit, 1000).is_err());
}

#[test]
fn durable_binding_registry_corruption_rejects_warmed_reads_and_restart_independently() {
    use super::provider::{Provider, ProviderDiagnostic};
    for corruption in [
        "key",
        "fingerprint",
        "audit_actor",
        "provider_uid",
        "missing_audit",
    ] {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = temp.path().join("provider");
        let path = root.join("provider-state.json");
        let mut store = ProviderStore::open(&root).unwrap();
        let owner = unsafe { libc::geteuid() };
        let mut input = pairing(13);
        if input.uid == owner {
            input.uid += 1;
        }
        let binding = AgentBinding::new(input, owner).unwrap();
        let mut state = store.read_state().unwrap();
        state
            .agent_audit
            .push(binding.audit(owner, 13, AgentAuditAction::Paired));
        state.pairings.push(binding);
        store.write_state(&state).unwrap();
        assert_eq!(store.read_state().unwrap(), state);
        assert!(state.requests.is_empty());
        let mut corrupt = serde_json::to_value(state).unwrap();
        match corruption {
            "key" => corrupt["pairings"][0]["public_key"] = "invalid-public-key-sentinel".into(),
            "fingerprint" => {
                corrupt["pairings"][0]["fingerprint"] = "0".repeat(64).into();
                // Preserve the audit snapshot so only the derived fingerprint
                // validation, rather than audit mismatch, rejects the data.
                corrupt["agent_audit"][0]["fingerprint"] = "0".repeat(64).into();
            }
            "audit_actor" => corrupt["agent_audit"][0]["actor_uid"] = serde_json::json!(owner + 1),
            "provider_uid" => {
                corrupt["pairings"][0]["uid"] = serde_json::json!(owner);
                corrupt["agent_audit"][0]["uid"] = serde_json::json!(owner);
            }
            "missing_audit" => corrupt["agent_audit"] = serde_json::json!([]),
            _ => panic!("unexpected corrupt-registry fixture"),
        }
        let bytes = serde_json::to_vec(&corrupt).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            store.read_state().unwrap_err().diagnostic(),
            ProviderDiagnostic::InvalidState,
            "{corruption}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        drop(store);
        assert_eq!(
            Provider::start(&root).unwrap_err().diagnostic(),
            ProviderDiagnostic::InvalidState,
            "{corruption}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn stored_binding_ids_require_canonical_32_byte_values() {
    let binding = AgentBinding::new(pairing(14), 1000).unwrap();
    binding.validate(1000).unwrap();
    for id in [
        String::new(),
        "!".into(),
        URL_SAFE_NO_PAD.encode([7; 31]),
        URL_SAFE_NO_PAD.encode([7; 33]),
        format!("{}=", binding.id),
    ] {
        let mut invalid = binding.clone();
        invalid.id = id;
        assert!(invalid.validate(1000).is_err());
    }
}
