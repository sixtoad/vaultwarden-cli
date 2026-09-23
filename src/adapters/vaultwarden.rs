//! Provider-only metadata, session and selective login adapter. No CipherOutput.
use super::session::{ProviderKeyring, derive_keys, load_setup};
use crate::{
    access::{policy::LoginField, ports::*},
    config::Config,
    crypto::CryptoKeys,
    models::{Cipher, CipherData, TokenResponse},
};
use reqwest::{
    Url,
    blocking::{Client, Response},
    redirect::Policy,
};
use std::{io::Read, path::Path, time::Duration};
use zeroize::Zeroizing;

// Keep provider-specific wire fields inside this adapter; the CLI model remains
// unchanged. Serde rejects duplicate aliases and malformed non-string keys.
#[derive(serde::Deserialize)]
struct ProviderCipher {
    #[serde(default, rename = "key", alias = "Key")]
    item_key: Option<String>,
    #[serde(flatten)]
    cipher: Cipher,
}

pub struct VaultwardenBackend {
    config: Config,
    client: Client,
    base: Url,
    keyring: ProviderKeyring,
    session: Option<(SensitiveString, CryptoKeys)>,
    compatible: bool,
}
impl VaultwardenBackend {
    pub fn from_setup(path: &Path) -> Result<Self, SessionError> {
        ProviderKeyring.clear()?;
        Self::new(load_setup(path)?, false)
    }
    fn new(config: Config, allow_test_http: bool) -> Result<Self, SessionError> {
        crate::install_rustls_crypto_provider();
        let base = Url::parse(
            config
                .server
                .as_deref()
                .ok_or(SessionError::BackendUnavailable)?,
        )
        .map_err(|_| SessionError::BackendUnavailable)?;
        let loopback = matches!(base.host_str(), Some("127.0.0.1") | Some("[::1]"));
        if !(base.scheme() == "https" || allow_test_http && base.scheme() == "http" && loopback)
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path() != "/"
        {
            return Err(SessionError::BackendUnavailable);
        }
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(3))
            .no_proxy()
            .build()
            .map_err(|_| SessionError::BackendUnavailable)?;
        Ok(Self {
            config,
            client,
            base,
            keyring: ProviderKeyring,
            session: None,
            compatible: false,
        })
    }
    fn url(&self, path: &str) -> Result<Url, SessionError> {
        self.base
            .join(path)
            .map_err(|_| SessionError::BackendUnavailable)
    }
    fn body(response: Response) -> Result<Zeroizing<Vec<u8>>, SessionError> {
        if !response.status().is_success() {
            return Err(SessionError::BackendUnavailable);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        response
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(|_| SessionError::BackendUnavailable)?;
        if bytes.len() > 1_048_576 {
            return Err(SessionError::BackendUnavailable);
        }
        Ok(bytes)
    }
    fn metadata(&self, path: &str) -> Result<serde_json::Value, SessionError> {
        let response = self
            .client
            .get(self.url(path)?)
            .send()
            .map_err(|_| SessionError::Incompatible)?;
        serde_json::from_slice(&Self::body(response).map_err(|_| SessionError::Incompatible)?)
            .map_err(|_| SessionError::Incompatible)
    }
    fn selected(
        &mut self,
        binding: &CredentialBinding<'_>,
    ) -> Result<Vec<SensitiveString>, SessionError> {
        if self.session.is_none() {
            return Err(SessionError::Locked);
        }
        // Core probes then rechecks its deadline before calling this method.
        // Performing network metadata I/O here would reopen that expiry gap.
        if !self.compatible {
            return Err(SessionError::Incompatible);
        }
        if binding.immutable_item_id.len() != 36
            || !binding.immutable_item_id.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
            || binding.fields.is_empty()
        {
            return Err(SessionError::InvalidRequest);
        }
        let (token, keys) = self.session.as_ref().ok_or(SessionError::Locked)?;
        let response = self
            .client
            .get(self.url(&format!("api/ciphers/{}", binding.immutable_item_id))?)
            .bearer_auth(token.expose())
            .send()
            .map_err(|_| SessionError::BackendUnavailable)?;
        let ProviderCipher { cipher, item_key } = serde_json::from_slice(&Self::body(response)?)
            .map_err(|_| SessionError::BackendUnavailable)?;
        if cipher.id.as_str() != binding.immutable_item_id
            || cipher.deleted_date.is_some()
            || !matches!(cipher.cipher_data, Some(CipherData::Login(_)))
        {
            return Err(SessionError::BackendUnavailable);
        }
        let organization_keys = if let Some(id) = &cipher.organization_id {
            let private = self
                .config
                .encrypted_private_key
                .as_deref()
                .ok_or(SessionError::BackendUnavailable)?;
            if !private.starts_with("2.") || private.split('|').count() != 3 {
                return Err(SessionError::BackendUnavailable);
            }
            let private = keys
                .decrypt_private_key(private)
                .map_err(|_| SessionError::BackendUnavailable)?;
            let encrypted = self
                .config
                .org_keys
                .get(id)
                .ok_or(SessionError::BackendUnavailable)?;
            Some(
                CryptoKeys::decrypt_org_key(encrypted, &private)
                    .map_err(|_| SessionError::BackendUnavailable)?,
            )
        } else {
            None
        };
        let parent_keys = organization_keys.as_ref().unwrap_or(keys);
        let item_keys = item_key
            .as_deref()
            .map(|encrypted| {
                if !encrypted.starts_with("2.") || encrypted.split('|').count() != 3 {
                    return Err(SessionError::BackendUnavailable);
                }
                let bytes = Zeroizing::new(
                    parent_keys
                        .decrypt(encrypted)
                        .map_err(|_| SessionError::BackendUnavailable)?,
                );
                CryptoKeys::from_symmetric_key(&bytes).map_err(|_| SessionError::BackendUnavailable)
            })
            .transpose()?;
        let keys = item_keys.as_ref().unwrap_or(parent_keys);
        let decrypt = |value: &str| -> Result<SensitiveString, SessionError> {
            if !value.starts_with("2.") || value.split('|').count() != 3 {
                return Err(SessionError::BackendUnavailable);
            }
            keys.decrypt_to_string(value)
                .map(SensitiveString::new)
                .map_err(|_| SessionError::BackendUnavailable)
        };
        let mut marker_matches = 0;
        let mut custom = Vec::new();
        for field in cipher.get_fields().into_iter().flatten() {
            let name = decrypt(
                field
                    .name
                    .as_deref()
                    .ok_or(SessionError::BackendUnavailable)?,
            )?;
            if name.expose() == "vw-access" {
                let value = decrypt(
                    field
                        .value
                        .as_deref()
                        .ok_or(SessionError::BackendUnavailable)?,
                )?;
                if format!("vw-access={}", value.expose()) == binding.marker {
                    marker_matches += 1;
                } else {
                    return Err(SessionError::BackendUnavailable);
                }
            }
            custom.push((name, field.value.as_deref()));
        }
        if marker_matches != 1 {
            return Err(SessionError::BackendUnavailable);
        }
        binding
            .fields
            .iter()
            .map(|field| {
                let encrypted = match field {
                    LoginField::Username => cipher.get_username(),
                    LoginField::Password => cipher.get_password(),
                    LoginField::Custom { name } => {
                        let matches: Vec<_> =
                            custom.iter().filter(|(n, _)| n.expose() == name).collect();
                        if matches.len() != 1 {
                            return Err(SessionError::BackendUnavailable);
                        }
                        matches[0].1
                    }
                }
                .ok_or(SessionError::BackendUnavailable)?;
                decrypt(encrypted)
            })
            .collect()
    }
}
impl ProviderSession for VaultwardenBackend {
    fn probe_compatibility(&mut self) -> Result<(), SessionError> {
        self.compatible = false;
        let version = self.metadata("api/version")?;
        let config = self.metadata("api/config")?;
        if version != "1.36.0"
            || config["version"] != "2025.12.0"
            || config["object"] != "config"
            || config["server"]["name"] != "Vaultwarden"
        {
            return Err(SessionError::Incompatible);
        }
        self.compatible = true;
        Ok(())
    }
    fn unlock(&mut self, password: SensitiveString) -> Result<Duration, SessionError> {
        if !self.compatible {
            return Err(SessionError::Incompatible);
        }
        let keys = derive_keys(&self.config, &password)?;
        let bootstrap = self.keyring.bootstrap()?;
        let params = [
            ("grant_type", "client_credentials"),
            ("scope", "api"),
            (
                "client_id",
                self.config
                    .client_id
                    .as_deref()
                    .ok_or(SessionError::AuthenticationFailed)?,
            ),
            ("client_secret", bootstrap.expose()),
            ("deviceType", "14"),
            ("deviceIdentifier", "vaultwarden-accessd"),
            ("deviceName", "Vaultwarden Access"),
        ];
        let response = self
            .client
            .post(self.url("identity/connect/token")?)
            .form(&params)
            .send()
            .map_err(|_| SessionError::AuthenticationFailed)?;
        let mut token: TokenResponse = serde_json::from_slice(
            &Self::body(response).map_err(|_| SessionError::AuthenticationFailed)?,
        )
        .map_err(|_| SessionError::AuthenticationFailed)?;
        use zeroize::Zeroize;
        if let Some(refresh) = &mut token.refresh_token {
            refresh.zeroize();
        }
        let access = SensitiveString::new(std::mem::take(&mut token.access_token));
        if token
            .kdf
            .is_some_and(|kdf| kdf != crate::models::KdfType::Pbkdf2)
            || token.kdf_iterations.is_some_and(|iterations| {
                Some(iterations) != self.config.kdf_iterations.map(|kdf| kdf.get())
            })
            || token
                .key
                .as_ref()
                .is_some_and(|key| Some(key) != self.config.encrypted_key.as_ref())
            || token.expires_in <= 0
            || access.expose().is_empty()
            || !token.token_type.eq_ignore_ascii_case("bearer")
        {
            return Err(SessionError::AuthenticationFailed);
        }
        self.keyring.save(access.expose(), &keys)?;
        self.session = Some((access, keys));
        Ok(Duration::from_secs(token.expires_in as u64))
    }
    fn clear(&mut self) -> Result<(), SessionError> {
        self.session = None;
        self.compatible = false;
        self.keyring.clear()
    }
}
impl SecretBackend for VaultwardenBackend {
    fn eligible(&mut self, binding: &CredentialBinding<'_>) -> Result<bool, SessionError> {
        self.selected(binding).map(|_| true)
    }
    fn resolve(
        &mut self,
        binding: &CredentialBinding<'_>,
    ) -> Result<Vec<SensitiveString>, SessionError> {
        self.selected(binding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        KdfIterations, MasterKey,
        crypto_keys::tests::test_helpers::encrypt_bytes_for_test as encrypt,
    };
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };
    const ITEM: &str = "11111111-1111-1111-1111-111111111111";
    fn binding() -> CredentialBinding<'static> {
        CredentialBinding {
            immutable_item_id: ITEM,
            fields: &[LoginField::Password],
            marker: "vw-access=deploy",
        }
    }
    fn setup(server: String) -> Config {
        let iterations = KdfIterations::new(1).unwrap();
        let stretched = MasterKey::derive("password-sentinel", "human@example.test", iterations)
            .stretch()
            .unwrap();
        Config {
            server: Some(server),
            client_id: Some("human-client".into()),
            email: Some("human@example.test".into()),
            kdf_iterations: Some(iterations),
            encrypted_key: Some(encrypt(&[42; 64], stretched.enc_key(), stretched.mac_key())),
            ..Config::default()
        }
    }
    fn metadata(
        rt: &tokio::runtime::Runtime,
        server: &MockServer,
        version: serde_json::Value,
        config: serde_json::Value,
    ) {
        rt.block_on(async {
            Mock::given(path("/api/version"))
                .respond_with(ResponseTemplate::new(200).set_body_json(version))
                .mount(server)
                .await;
            Mock::given(path("/api/config"))
                .respond_with(ResponseTemplate::new(200).set_body_json(config))
                .mount(server)
                .await;
        });
    }
    fn supported() -> serde_json::Value {
        serde_json::json!({"version":"2025.12.0","object":"config","server":{"name":"Vaultwarden"}})
    }
    #[test]
    fn compatibility_is_exact_and_never_fetches_items() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(MockServer::start());
        for (version, config) in [
            (serde_json::json!("1.36.0"), supported()),
            (serde_json::json!("1.36.1"), supported()),
            (serde_json::json!("password-sentinel"), supported()),
            (
                serde_json::json!("1.36.0"),
                serde_json::json!({"version":"2025.12.1","object":"config","server":{"name":"Vaultwarden"}}),
            ),
            (
                serde_json::json!("1.36.0"),
                serde_json::json!({"version":"2025.12.0","object":"other","server":{"name":"Vaultwarden"}}),
            ),
            (
                serde_json::json!("1.36.0"),
                serde_json::json!({"version":"2025.12.0","object":"config","server":{"name":"Other"}}),
            ),
            (serde_json::Value::Null, serde_json::Value::Null),
        ] {
            rt.block_on(server.reset());
            metadata(&rt, &server, version.clone(), config.clone());
            let mut backend = VaultwardenBackend::new(setup(server.uri()), true).unwrap();
            assert_eq!(
                backend.probe_compatibility().is_ok(),
                version == "1.36.0" && config == supported()
            );
            assert_eq!(
                backend.resolve(&binding()).unwrap_err(),
                SessionError::Locked
            );
            let requests = rt.block_on(server.received_requests()).unwrap();
            // Resolution must not hide additional metadata network I/O after core's
            // post-probe expiry check and before fetching the requested item.
            assert_eq!(
                requests
                    .iter()
                    .filter(|r| r.url.path() == "/api/version")
                    .count(),
                1
            );
            assert_eq!(
                requests
                    .iter()
                    .filter(|r| r.url.path() == "/api/config")
                    .count(),
                1
            );
            for request in requests {
                assert!(matches!(request.url.path(), "/api/version" | "/api/config"));
                assert!(!format!("{request:?}").contains("password-sentinel"));
            }
        }
    }
    #[test]
    fn real_password_keyring_session_and_selective_resolution_stay_redacted() {
        let _guard = crate::KEYRING_TEST_LOCK.lock().unwrap();
        let previous = keyring_core::unset_default_store();
        keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap());
        keyring_core::Entry::new(
            super::super::session::KEYRING_SERVICE,
            super::super::session::BOOTSTRAP_ACCOUNT,
        )
        .unwrap()
        .set_password("bootstrap-sentinel")
        .unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(MockServer::start());
        metadata(&rt, &server, serde_json::json!("1.36.0"), supported());
        let encrypted = |value: &str| encrypt(value.as_bytes(), &[42; 32], &[42; 32]);
        rt.block_on(async {
            Mock::given(path("/identity/connect/token")).and(method("POST")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"access_token":"session-sentinel","token_type":"Bearer","expires_in":60,"refresh_token":"refresh-sentinel"}))).mount(&server).await;
            Mock::given(path(format!("/api/ciphers/{ITEM}"))).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"Id":ITEM,"Type":1,"Name":encrypted("unused-name"),"Login":{"Username":encrypted("username-sentinel"),"Password":encrypted("secret-sentinel")},"Fields":[{"Name":encrypted("vw-access"),"Value":encrypted("deploy"),"Type":0},{"Name":encrypted("custom"),"Value":encrypted("custom-sentinel"),"Type":1}]}))).mount(&server).await;
        });
        let mut backend = VaultwardenBackend::new(setup(server.uri()), true).unwrap();
        assert_eq!(
            backend.unlock(SensitiveString::new("password-sentinel".into())),
            Err(SessionError::Incompatible)
        );
        backend.probe_compatibility().unwrap();
        assert_eq!(
            backend.unlock(SensitiveString::new("wrong-password".into())),
            Err(SessionError::AuthenticationFailed)
        );
        assert_eq!(
            backend
                .unlock(SensitiveString::new("password-sentinel".into()))
                .unwrap(),
            Duration::from_secs(60)
        );
        let fields = [
            LoginField::Username,
            LoginField::Password,
            LoginField::Custom {
                name: "custom".into(),
            },
        ];
        let binding = CredentialBinding {
            fields: &fields,
            ..binding()
        };
        let values = backend.resolve(&binding).unwrap();
        assert_eq!(
            values
                .iter()
                .map(SensitiveString::expose)
                .collect::<Vec<_>>(),
            ["username-sentinel", "secret-sentinel", "custom-sentinel"]
        );
        assert_eq!(
            format!("{values:?}"),
            "[[REDACTED], [REDACTED], [REDACTED]]"
        );
        assert!(backend.eligible(&binding).unwrap());
        assert!(
            backend
                .resolve(&CredentialBinding {
                    marker: "vw-access=wrong",
                    ..binding
                })
                .is_err()
        );
        assert!(
            backend
                .resolve(&CredentialBinding {
                    immutable_item_id: "../../sync",
                    ..binding
                })
                .is_err()
        );
        for request in rt.block_on(server.received_requests()).unwrap() {
            let externally_sent = format!("{request:?}");
            assert!(!externally_sent.contains("password-sentinel"));
            assert!(!externally_sent.contains("secret-sentinel"));
            assert!(!request.url.as_str().contains("session-sentinel"));
            assert_ne!(request.url.path(), "/api/sync");
        }
        rt.block_on(server.reset());
        metadata(&rt, &server, serde_json::json!("9.9.9"), supported());
        assert_eq!(
            backend.probe_compatibility(),
            Err(SessionError::Incompatible)
        );
        assert_eq!(
            backend.resolve(&binding).unwrap_err(),
            SessionError::Incompatible
        );
        assert_eq!(
            rt.block_on(server.received_requests())
                .unwrap()
                .iter()
                .filter(|r| r.url.path().contains("ciphers"))
                .count(),
            0
        );
        backend.clear().unwrap();
        assert!(backend.session.is_none());
        assert!(!backend.compatible);
        assert!(matches!(
            keyring_core::Entry::new(
                super::super::session::KEYRING_SERVICE,
                super::super::session::SESSION_ACCOUNT
            )
            .unwrap()
            .get_password(),
            Err(keyring_core::Error::NoEntry)
        ));
        if let Some(previous) = previous {
            keyring_core::set_default_store(previous);
        } else {
            keyring_core::unset_default_store();
        }
    }
    #[test]
    fn resolution_rejects_wrong_deleted_unmarked_or_ambiguous_items() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(MockServer::start());
        let encrypted = |value: &str| encrypt(value.as_bytes(), &[42; 32], &[42; 32]);
        let valid = serde_json::json!({"Id":ITEM,"Type":1,"Login":{"Username":encrypted("user"),"Password":encrypted("secret-sentinel")},"Fields":[{"Name":encrypted("vw-access"),"Value":encrypted("deploy"),"Type":0},{"Name":encrypted("custom"),"Value":encrypted("custom-sentinel"),"Type":1}]});
        for variant in [
            "valid",
            "wrong-id",
            "deleted",
            "wrong-type",
            "no-marker",
            "duplicate-marker",
            "wrong-marker",
            "missing-password",
            "duplicate-custom",
            "unauthenticated-password",
        ] {
            rt.block_on(server.reset());
            metadata(&rt, &server, serde_json::json!("1.36.0"), supported());
            let mut item = valid.clone();
            match variant {
                "wrong-id" => {
                    item["Id"] = serde_json::json!("22222222-2222-2222-2222-222222222222")
                }
                "deleted" => item["DeletedDate"] = serde_json::json!("2026-09-23T00:00:00Z"),
                "wrong-type" => {
                    item["Type"] = serde_json::json!(2);
                    item["SecureNote"] = serde_json::json!({"Type":0});
                }
                "no-marker" => item["Fields"] = serde_json::json!([]),
                "duplicate-marker" => {
                    let marker = item["Fields"][0].clone();
                    item["Fields"].as_array_mut().unwrap().push(marker);
                }
                "wrong-marker" => {
                    item["Fields"][0]["Value"] = serde_json::json!(encrypted("other"))
                }
                "missing-password" => {
                    item["Login"].as_object_mut().unwrap().remove("Password");
                }
                "duplicate-custom" => {
                    let custom = item["Fields"][1].clone();
                    item["Fields"].as_array_mut().unwrap().push(custom);
                }
                "unauthenticated-password" => {
                    item["Login"]["Password"] =
                        serde_json::json!(encrypted("secret-sentinel").rsplit_once('|').unwrap().0)
                }
                _ => {}
            }
            rt.block_on(
                Mock::given(path(format!("/api/ciphers/{ITEM}")))
                    .respond_with(ResponseTemplate::new(200).set_body_json(item))
                    .mount(&server),
            );
            let mut backend = VaultwardenBackend::new(setup(server.uri()), true).unwrap();
            backend.probe_compatibility().unwrap();
            backend.session = Some((
                SensitiveString::new("session-sentinel".into()),
                CryptoKeys::from_key_bytes([42; 32], [42; 32]),
            ));
            let fields = [
                LoginField::Password,
                LoginField::Custom {
                    name: "custom".into(),
                },
            ];
            let result = backend.resolve(&CredentialBinding {
                fields: &fields,
                ..binding()
            });
            assert_eq!(result.is_ok(), variant == "valid", "item variant {variant}");
            assert_eq!(
                backend
                    .eligible(&CredentialBinding {
                        fields: &fields,
                        ..binding()
                    })
                    .is_ok(),
                variant == "valid",
                "eligibility variant {variant}"
            );
        }
        for id in [
            "11111111x1111-1111-1111-111111111111",
            "11111111-1111-1111-1111-11111111111z",
        ] {
            let mut backend = VaultwardenBackend::new(setup(server.uri()), true).unwrap();
            backend.probe_compatibility().unwrap();
            backend.session = Some((
                SensitiveString::new("session-sentinel".into()),
                CryptoKeys::from_key_bytes([42; 32], [42; 32]),
            ));
            assert_eq!(
                backend
                    .resolve(&CredentialBinding {
                        immutable_item_id: id,
                        ..binding()
                    })
                    .unwrap_err(),
                SessionError::InvalidRequest
            );
        }
        let mut backend = VaultwardenBackend::new(setup(server.uri()), true).unwrap();
        backend.probe_compatibility().unwrap();
        backend.session = Some((
            SensitiveString::new("session-sentinel".into()),
            CryptoKeys::from_key_bytes([42; 32], [42; 32]),
        ));
        assert_eq!(
            backend
                .resolve(&CredentialBinding {
                    fields: &[],
                    ..binding()
                })
                .unwrap_err(),
            SessionError::InvalidRequest
        );
    }
    #[test]
    fn token_validation_rejects_expired_or_mismatched_authority_before_persistence() {
        use super::super::session::{BOOTSTRAP_ACCOUNT, KEYRING_SERVICE, SESSION_ACCOUNT};
        let _guard = crate::KEYRING_TEST_LOCK.lock().unwrap();
        let previous = keyring_core::unset_default_store();
        keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap());
        keyring_core::Entry::new(KEYRING_SERVICE, BOOTSTRAP_ACCOUNT)
            .unwrap()
            .set_password("bootstrap-sentinel")
            .unwrap();
        let session = keyring_core::Entry::new(KEYRING_SERVICE, SESSION_ACCOUNT).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(MockServer::start());
        let valid = serde_json::json!({"access_token":"session-sentinel","token_type":"Bearer","expires_in":60});
        for (field, value) in [
            ("expires_in", serde_json::json!(0)),
            ("expires_in", serde_json::json!(-1)),
            ("access_token", serde_json::json!("")),
            ("token_type", serde_json::json!("Other")),
            ("Kdf", serde_json::json!(1)),
            ("KdfIterations", serde_json::json!(2)),
            ("Key", serde_json::json!("2.mismatched-key")),
        ] {
            rt.block_on(server.reset());
            metadata(&rt, &server, serde_json::json!("1.36.0"), supported());
            let mut token = valid.clone();
            token[field] = value;
            rt.block_on(
                Mock::given(path("/identity/connect/token"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(token))
                    .mount(&server),
            );
            let mut backend = VaultwardenBackend::new(setup(server.uri()), true).unwrap();
            backend.probe_compatibility().unwrap();
            assert_eq!(
                backend.unlock(SensitiveString::new("password-sentinel".into())),
                Err(SessionError::AuthenticationFailed),
                "token field {field}"
            );
            assert!(backend.session.is_none());
            assert!(matches!(
                session.get_password(),
                Err(keyring_core::Error::NoEntry)
            ));
        }
        rt.block_on(server.reset());
        metadata(&rt, &server, serde_json::json!("1.36.0"), supported());
        let config = setup(server.uri());
        let mut matching = valid;
        matching["Kdf"] = serde_json::json!(0);
        matching["KdfIterations"] = serde_json::json!(1);
        matching["Key"] = serde_json::json!(config.encrypted_key);
        rt.block_on(
            Mock::given(path("/identity/connect/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(matching))
                .mount(&server),
        );
        let mut backend = VaultwardenBackend::new(config, true).unwrap();
        backend.probe_compatibility().unwrap();
        assert_eq!(
            backend.unlock(SensitiveString::new("password-sentinel".into())),
            Ok(Duration::from_secs(60))
        );
        backend.clear().unwrap();
        if let Some(previous) = previous {
            keyring_core::set_default_store(previous);
        } else {
            keyring_core::unset_default_store();
        }
    }
    #[test]
    fn provider_lock_and_restart_clear_the_actual_adapter_keyring_session() {
        use super::super::session::{
            BOOTSTRAP_ACCOUNT, KEYRING_SERVICE, MonotonicClock, SESSION_ACCOUNT,
        };
        use crate::access::{
            application::{ProviderApplication, SessionStatus},
            ports::ApprovalAuthenticator,
            provider::Provider,
        };
        let _guard = crate::KEYRING_TEST_LOCK.lock().unwrap();
        let previous = keyring_core::unset_default_store();
        keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap());
        let bootstrap = keyring_core::Entry::new(KEYRING_SERVICE, BOOTSTRAP_ACCOUNT).unwrap();
        bootstrap.set_password("bootstrap-sentinel").unwrap();
        let session = keyring_core::Entry::new(KEYRING_SERVICE, SESSION_ACCOUNT).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(MockServer::start());
        metadata(&rt, &server, serde_json::json!("1.36.0"), supported());
        rt.block_on(Mock::given(path("/identity/connect/token")).and(method("POST")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"access_token":"session-sentinel","token_type":"Bearer","expires_in":60}))).mount(&server));
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = dir.path().join("provider");
        let make_app = || {
            ProviderApplication::new(
                Provider::start(&root).unwrap(),
                Box::new(VaultwardenBackend::new(setup(server.uri()), true).unwrap()),
                Box::<MonotonicClock>::default(),
            )
            .unwrap()
        };
        let app = make_app();
        app.authenticate(SensitiveString::new("password-sentinel".into()))
            .unwrap();
        assert_eq!(app.status(), Ok(SessionStatus::Unlocked));
        assert!(session.get_password().unwrap().contains("session-sentinel"));
        app.lock().unwrap();
        assert_eq!(app.status(), Ok(SessionStatus::Locked));
        assert!(matches!(
            session.get_password(),
            Err(keyring_core::Error::NoEntry)
        ));
        assert_eq!(bootstrap.get_password().unwrap(), "bootstrap-sentinel");
        drop(app);
        session.set_password("stale-session-sentinel").unwrap();
        let restarted = make_app();
        assert_eq!(restarted.status(), Ok(SessionStatus::Locked));
        assert!(matches!(
            session.get_password(),
            Err(keyring_core::Error::NoEntry)
        ));
        let persisted = std::fs::read_to_string(root.join("provider-state.json")).unwrap();
        for sentinel in [
            "password-sentinel",
            "session-sentinel",
            "bootstrap-sentinel",
        ] {
            assert!(!persisted.contains(sentinel));
        }
        if let Some(previous) = previous {
            keyring_core::set_default_store(previous);
        } else {
            keyring_core::unset_default_store();
        }
    }
    #[test]
    fn url_validation_never_echoes_input_or_accepts_credential_urls() {
        for url in [
            "http://example.test/",
            "http://127.0.0.1:123/",
            "https://user@example.test/",
            "https://:password-sentinel@example.test/",
            "https://user:password-sentinel@example.test/",
            "https://example.test/?token=session-sentinel",
            "https://example.test/#secret-sentinel",
            "https://example.test/path",
            "file:///tmp/vault",
        ] {
            assert!(matches!(
                VaultwardenBackend::new(setup(url.into()), false),
                Err(SessionError::BackendUnavailable)
            ));
        }
        assert!(VaultwardenBackend::new(setup("https://example.test/".into()), false).is_ok());
        assert!(VaultwardenBackend::new(setup("http://example.test/".into()), true).is_err());
    }
    #[test]
    fn response_limit_accepts_exact_boundary_and_rejects_oversized_valid_json() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(MockServer::start());
        for length in [1_048_576, 1_048_577] {
            rt.block_on(server.reset());
            let mut body = serde_json::to_vec("1.36.0").unwrap();
            body.resize(length, b' ');
            rt.block_on(async {
                Mock::given(path("/api/version"))
                    .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
                    .mount(&server)
                    .await;
                Mock::given(path("/api/config"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(supported()))
                    .mount(&server)
                    .await;
            });
            let mut backend = VaultwardenBackend::new(setup(server.uri()), true).unwrap();
            assert_eq!(backend.probe_compatibility().is_ok(), length == 1_048_576);
            assert!(
                rt.block_on(server.received_requests())
                    .unwrap()
                    .iter()
                    .all(|r| !r.url.path().contains("ciphers"))
            );
        }
    }
    #[test]
    fn redirect_and_oversized_metadata_fail_closed() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(MockServer::start());
        for response in [
            ResponseTemplate::new(302).insert_header("Location", "/api/ciphers/password-sentinel"),
            ResponseTemplate::new(200).set_body_string("x".repeat(1_048_577)),
            ResponseTemplate::new(500).set_body_string("secret-sentinel"),
        ] {
            rt.block_on(server.reset());
            rt.block_on(
                Mock::given(path("/api/version"))
                    .respond_with(response)
                    .mount(&server),
            );
            let mut backend = VaultwardenBackend::new(setup(server.uri()), true).unwrap();
            assert_eq!(
                backend.probe_compatibility(),
                Err(SessionError::Incompatible)
            );
            assert_eq!(rt.block_on(server.received_requests()).unwrap().len(), 1);
        }
    }
    #[test]
    fn personal_and_organization_item_keys_authenticate_before_selected_fields() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use rsa::{Oaep, RsaPrivateKey, RsaPublicKey, pkcs8::EncodePrivateKey};
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(MockServer::start());
        let mut rng = rand::rng();
        let private = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let org = "22222222-2222-2222-2222-222222222222";
        for organization in [false, true] {
            let mut config = setup(server.uri());
            if organization {
                config.encrypted_private_key = Some(encrypt(
                    private.to_pkcs8_der().unwrap().as_bytes(),
                    &[42; 32],
                    &[42; 32],
                ));
                let encrypted_org = RsaPublicKey::from(&private)
                    .encrypt(&mut rng, Oaep::<sha1::Sha1>::new(), &[43; 64])
                    .unwrap();
                config.org_keys.insert(
                    crate::models::OrgId::new(org).unwrap(),
                    format!("4.{}", STANDARD.encode(encrypted_org)),
                );
            }
            let parent = if organization { 43 } else { 42 };
            let make_cipher = |field_key| {
                let encrypted =
                    |value: &str| encrypt(value.as_bytes(), &[field_key; 32], &[field_key; 32]);
                let mut cipher = serde_json::json!({"id":ITEM,"type":1,
                    "login":{"username":encrypted("item-user-sentinel"),"password":encrypted("item-password-sentinel")},
                    "fields":[{"name":encrypted("vw-access"),"value":encrypted("deploy"),"type":0},
                              {"name":encrypted("custom"),"value":encrypted("item-custom-sentinel"),"type":1}]});
                if organization {
                    cipher["organizationId"] = serde_json::json!(org);
                }
                cipher
            };
            let key = encrypt(&[44; 64], &[parent; 32], &[parent; 32]);
            let mut cases = Vec::new();
            for alias in ["key", "Key"] {
                let mut cipher = make_cipher(44);
                cipher[alias] = serde_json::json!(key);
                cases.push((cipher, true));
            }
            cases.push((make_cipher(parent), true));
            let mut null = make_cipher(parent);
            null["key"] = serde_json::Value::Null;
            cases.push((null, true));
            // These fields must be valid under the unwrapped item key: a
            // weakened format guard must not be hidden by a later field MAC
            // failure. The isolated legacy-override run covers missing MACs.
            for malformed in [
                key.rsplit_once('|').unwrap().0.to_owned(),
                format!("{key}|unexpected"),
            ] {
                let mut cipher = make_cipher(44);
                cipher["key"] = serde_json::json!(malformed);
                cases.push((cipher, false));
            }
            // Fields use valid parent encryption in negative cases: ignoring the
            // present item key would wrongly succeed rather than fail closed.
            for invalid in [
                serde_json::json!(""),
                serde_json::json!(42),
                serde_json::json!({}),
                serde_json::json!(key.rsplit_once('|').unwrap().0),
                serde_json::json!(format!(
                    "{}|{}",
                    key.rsplit_once('|').unwrap().0,
                    STANDARD.encode([0; 32])
                )),
                serde_json::json!(format!("0.{}", &key[2..])),
                serde_json::json!("2.not-base64|invalid|invalid"),
                serde_json::json!(encrypt(&[44; 63], &[parent; 32], &[parent; 32])),
                serde_json::json!(encrypt(&[44; 65], &[parent; 32], &[parent; 32])),
                serde_json::json!(encrypt(&[44; 64], &[45; 32], &[45; 32])),
            ] {
                let mut cipher = make_cipher(parent);
                cipher["key"] = invalid;
                cases.push((cipher, false));
            }
            let mut duplicate = make_cipher(parent);
            duplicate["key"] = serde_json::json!(key);
            duplicate["Key"] = serde_json::json!(key);
            cases.push((duplicate, false));
            let mut backend = VaultwardenBackend::new(config, true).unwrap();
            for (cipher, valid) in cases {
                rt.block_on(server.reset());
                metadata(&rt, &server, serde_json::json!("1.36.0"), supported());
                rt.block_on(
                    Mock::given(path(format!("/api/ciphers/{ITEM}")))
                        .respond_with(ResponseTemplate::new(200).set_body_json(cipher))
                        .mount(&server),
                );
                backend.probe_compatibility().unwrap();
                backend.session = Some((
                    SensitiveString::new("session-sentinel".into()),
                    CryptoKeys::from_key_bytes([42; 32], [42; 32]),
                ));
                let selected = CredentialBinding {
                    immutable_item_id: ITEM,
                    fields: &[
                        LoginField::Username,
                        LoginField::Password,
                        LoginField::Custom {
                            name: "custom".into(),
                        },
                    ],
                    marker: "vw-access=deploy",
                };
                let result = backend.resolve(&selected);
                if valid {
                    let values = result.unwrap();
                    assert_eq!(
                        values.iter().map(|v| v.expose()).collect::<Vec<_>>(),
                        [
                            "item-user-sentinel",
                            "item-password-sentinel",
                            "item-custom-sentinel"
                        ]
                    );
                    assert!(!format!("{values:?}").contains("sentinel"));
                } else {
                    assert_eq!(result.unwrap_err(), SessionError::BackendUnavailable);
                }
            }
        }
    }

    #[test]
    fn organization_binding_uses_only_provisioned_org_keys() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use rsa::{Oaep, RsaPrivateKey, RsaPublicKey, pkcs8::EncodePrivateKey};
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = rt.block_on(MockServer::start());
        metadata(&rt, &server, serde_json::json!("1.36.0"), supported());
        let mut rng = rand::rng();
        let private = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let encrypted_org = RsaPublicKey::from(&private)
            .encrypt(&mut rng, Oaep::<sha1::Sha1>::new(), &[43; 64])
            .unwrap();
        let mut config = setup(server.uri());
        config.encrypted_private_key = Some(encrypt(
            private.to_pkcs8_der().unwrap().as_bytes(),
            &[42; 32],
            &[42; 32],
        ));
        let org = "22222222-2222-2222-2222-222222222222";
        config.org_keys.insert(
            crate::models::OrgId::new(org).unwrap(),
            format!("4.{}", STANDARD.encode(encrypted_org)),
        );
        let encrypted = |value: &str| encrypt(value.as_bytes(), &[43; 32], &[43; 32]);
        rt.block_on(Mock::given(path(format!("/api/ciphers/{ITEM}"))).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"Id":ITEM,"Type":1,"OrganizationId":org,"Login":{"Password":encrypted("org-secret-sentinel")},"Fields":[{"Name":encrypted("vw-access"),"Value":encrypted("deploy"),"Type":0}]}))).mount(&server));
        let mut backend = VaultwardenBackend::new(config, true).unwrap();
        backend.probe_compatibility().unwrap();
        backend.session = Some((
            SensitiveString::new("session-sentinel".into()),
            CryptoKeys::from_key_bytes([42; 32], [42; 32]),
        ));
        let values = backend.resolve(&binding()).unwrap();
        assert_eq!(values[0].expose(), "org-secret-sentinel");
        let authenticated_private = backend.config.encrypted_private_key.clone().unwrap();
        backend.config.encrypted_private_key =
            Some(authenticated_private.rsplit_once('|').unwrap().0.to_owned());
        assert_eq!(
            backend.resolve(&binding()).unwrap_err(),
            SessionError::BackendUnavailable
        );
        backend.config.encrypted_private_key = Some(authenticated_private);
        backend.config.org_keys.clear();
        assert_eq!(
            backend.resolve(&binding()).unwrap_err(),
            SessionError::BackendUnavailable
        );
        backend.config.encrypted_private_key = None;
        assert_eq!(
            backend.resolve(&binding()).unwrap_err(),
            SessionError::BackendUnavailable
        );
    }
}
