use super::*;
use crate::desktop::transport::tests::{identity, pin, server_ca};

fn saved() -> Saved {
    Saved {
        endpoint: Endpoint::parse("https://127.0.0.1:8443").unwrap(),
        ca: server_ca(),
        pin: pin(),
        identity: identity(),
        recovery: Recovery::default(),
    }
}

#[test]
fn a_saved_configuration_round_trips_privately() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("provider"));
    assert!(!store.exists());
    assert_eq!(store.load().err(), Some(StoreError::Unreadable));
    store.save(&saved()).unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(loaded.endpoint.url(), "https://127.0.0.1:8443/v1/companion");
    assert_eq!(loaded.ca, server_ca());
    assert_eq!(loaded.identity.fingerprint(), identity().fingerprint());
    assert_eq!(&*loaded.identity.key, &*identity().key);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.path().join("provider")), 0o700);
        assert_eq!(mode(&store.file()), 0o600);
    }
    // No temporary file is left behind.
    assert_eq!(
        std::fs::read_dir(dir.path().join("provider"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn damaged_or_foreign_files_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().to_path_buf());
    store.save(&saved()).unwrap();
    let good: serde_json::Value =
        serde_json::from_slice(&std::fs::read(store.file()).unwrap()).unwrap();
    let check = |edit: &dyn Fn(&mut serde_json::Value), expected: StoreError| {
        let mut value = good.clone();
        edit(&mut value);
        std::fs::write(store.file(), value.to_string()).unwrap();
        assert_eq!(store.load().err(), Some(expected), "{value}");
    };
    check(&|v| v["version"] = 2.into(), StoreError::Invalid);
    check(&|v| v["extra"] = true.into(), StoreError::Invalid);
    check(&|v| v["pin"] = "A".repeat(64).into(), StoreError::Invalid);
    check(
        &|v| v["endpoint"] = "http://127.0.0.1".into(),
        StoreError::Invalid,
    );
    check(&|v| v["ca"] = "".into(), StoreError::Invalid);
    check(
        &|v| v["recovery"] = serde_json::json!({"pending_id":"short"}),
        StoreError::Invalid,
    );
    check(
        &|v| v["identity"] = "00".into(),
        StoreError::IdentityUnavailable,
    );
    std::fs::write(store.file(), vec![b' '; MAX_FILE as usize + 1]).unwrap();
    assert_eq!(store.load().err(), Some(StoreError::Invalid));
}

#[test]
fn the_default_directory_needs_an_absolute_base() {
    // Read-only check of the current environment's answer.
    if let Some(dir) = Store::default_directory() {
        assert!(dir.is_absolute());
        assert!(dir.ends_with(Path::new("dev.vaultwarden.companionSlice").join("provider")));
    }
}
