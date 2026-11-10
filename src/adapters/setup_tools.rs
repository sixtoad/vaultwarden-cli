//! Operator setup helpers behind `vw-access setup …` (docs/macos-setup.md).
//!
//! They only write new local files: nothing here talks to the provider, the
//! vault, a keyring or a service manager. Every private output is created
//! exclusively (`O_EXCL|O_NOFOLLOW`), `0600`, and synced; existing files are
//! never replaced. Secrets are read from a terminal or stdin, never argv.
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SetupError {
    #[error("{0} already exists; refusing to replace it")]
    Exists(PathBuf),
    #[error("cannot write {0}")]
    Write(PathBuf),
    #[error("{0}")]
    Invalid(String),
    #[error("openssl failed while {0}")]
    Openssl(String),
}

/// Create `path` exclusively with mode 0600, write `bytes` and sync file and directory.
pub fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), SetupError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                SetupError::Exists(path.into())
            } else {
                SetupError::Write(path.into())
            }
        })?;
    let written = file
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .and_then(|()| file.write_all(bytes))
        .and_then(|()| file.sync_all());
    if written.is_err() {
        drop(file);
        let _ignored = std::fs::remove_file(path);
        return Err(SetupError::Write(path.into()));
    }
    sync_parent(path);
    Ok(())
}

fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty())
        && let Ok(directory) = File::open(parent)
    {
        let _ignored = directory.sync_all();
    }
}

/// Generate an agent Ed25519 key: the raw 32-byte seed goes to `out` (0600, new
/// file only); the canonical unpadded base64url public key is returned for
/// `vw-access agent pair --public-key`.
pub fn agent_key(out: &Path) -> Result<String, SetupError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut())
        .map_err(|_error| SetupError::Invalid("random source unavailable".into()))?;
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    write_new_private(out, seed.as_ref())?;
    Ok(URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()))
}

/// Fields `backend.json` may carry; everything else (tokens, keys) is dropped.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BackendFields {
    pub server: Option<String>,
    pub email: Option<String>,
    pub client_id: Option<String>,
    pub encrypted_key: Option<String>,
    /// The account's KDF as stated by the operator (`pbkdf2`); the CLI login does not record it.
    pub kdf: Option<String>,
    pub kdf_iterations: Option<u32>,
}

pub const KDF_REQUIRED: &str = "--kdf pbkdf2 is required: a vaultwarden-cli login does not record the account's KDF \
     (web vault: Settings > Security > Keys); state it with --kdf pbkdf2 --kdf-iterations N";
pub const KDF_ARGON2: &str =
    "Argon2id accounts are not supported: the provider derives the master key with PBKDF2 only";

/// Build the provider `backend.json` from an existing `vaultwarden-cli login`
/// `config.json` (optional) overridden by explicit fields. The result contains
/// no token, password, derived key or client secret.
pub fn backend_json(
    cli_config: Option<&Path>,
    overrides: &BackendFields,
) -> Result<Vec<u8>, SetupError> {
    let source: serde_json::Value = match cli_config {
        Some(path) => {
            let bytes = std::fs::read(path)
                .map_err(|_error| SetupError::Invalid(format!("cannot read {}", path.display())))?;
            serde_json::from_slice(&bytes)
                .map_err(|_error| SetupError::Invalid(format!("{} is not JSON", path.display())))?
        }
        None => serde_json::Value::Null,
    };
    let text = |key: &str, explicit: &Option<String>| -> Option<String> {
        explicit.clone().or_else(|| {
            source
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
    };
    let server = text("server", &overrides.server)
        .ok_or_else(|| SetupError::Invalid("server is required".into()))?;
    let server = https_origin(&server)?;
    let email = text("email", &overrides.email)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| SetupError::Invalid("email is required".into()))?;
    let client_id = text("client_id", &overrides.client_id)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            SetupError::Invalid("client_id is required (the API key client_id)".into())
        })?;
    let encrypted_key = text("encrypted_key", &overrides.encrypted_key)
        .ok_or_else(|| SetupError::Invalid("encrypted_key is required".into()))?;
    if !encrypted_key.starts_with("2.") || encrypted_key.split('|').count() != 3 {
        return Err(SetupError::Invalid(
            "encrypted_key must be an authenticated type-2 key (2.iv|data|mac)".into(),
        ));
    }
    // A vaultwarden-cli login stores kdf_iterations but not the KDF type, and an
    // Argon2id account's iteration count is a small number that would pass as a
    // (weak, wrong) PBKDF2 count: the operator states both explicitly.
    match overrides.kdf.as_deref() {
        Some("pbkdf2") => {}
        Some("argon2id") => return Err(SetupError::Invalid(KDF_ARGON2.into())),
        _ => return Err(SetupError::Invalid(KDF_REQUIRED.into())),
    }
    // The login may record the KDF type (0 = PBKDF2, 1 = Argon2id); absent or
    // null means it did not, and the operator's statement above stands.
    match source.get("kdf") {
        None | Some(serde_json::Value::Null) => {}
        Some(kdf) if kdf.as_u64() == Some(0) => {}
        Some(kdf) if kdf.as_u64() == Some(1) => {
            return Err(SetupError::Invalid(KDF_ARGON2.into()));
        }
        Some(kdf) => {
            return Err(SetupError::Invalid(format!(
                "the vaultwarden-cli login records an unknown kdf {kdf} (expected 0 = PBKDF2)"
            )));
        }
    }
    let kdf_iterations = overrides
        .kdf_iterations
        .filter(|v| (1..=2_000_000).contains(v))
        .ok_or_else(|| {
            SetupError::Invalid("--kdf-iterations (PBKDF2, 1-2000000) is required".into())
        })?;
    if let Some(recorded) = source.get("kdf_iterations").filter(|v| !v.is_null())
        && recorded.as_u64() != Some(u64::from(kdf_iterations))
    {
        return Err(SetupError::Invalid(
            "--kdf-iterations differs from the kdf_iterations of the vaultwarden-cli login".into(),
        ));
    }
    let mut setup = serde_json::json!({
        "server": server,
        "email": email,
        "client_id": client_id,
        "encrypted_key": encrypted_key,
        "kdf_iterations": kdf_iterations,
    });
    // Organization bindings also need these, copied verbatim when present.
    if let Some(private) = source
        .get("encrypted_private_key")
        .filter(|v| v.is_string())
    {
        setup["encrypted_private_key"] = private.clone();
    }
    if let Some(org_keys) = source
        .get("org_keys")
        .filter(|v| v.as_object().is_some_and(|o| !o.is_empty()))
    {
        setup["org_keys"] = org_keys.clone();
    }
    let mut bytes = serde_json::to_vec_pretty(&setup)
        .map_err(|_error| SetupError::Invalid("cannot encode backend.json".into()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn https_origin(server: &str) -> Result<String, SetupError> {
    let invalid = || {
        SetupError::Invalid(
            "server must be an https origin without userinfo, path, query or fragment".into(),
        )
    };
    let url = reqwest::Url::parse(server).map_err(|_error| invalid())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(url.as_str().to_owned())
}

/// Inputs for the companion TLS bundle.
#[derive(Debug, Clone)]
pub struct TlsRequest {
    /// New directory to create (0700); must not exist.
    pub out_dir: PathBuf,
    /// Absolute path of the `openssl` (or LibreSSL) executable.
    pub openssl: PathBuf,
    /// IP SANs of the provider certificate (the companion connects to one).
    pub server_ips: Vec<std::net::IpAddr>,
    /// Optional DNS SANs of the provider certificate.
    pub server_dns: Vec<String>,
    /// Leaf validity in days (CAs get ten years).
    pub days: u32,
    /// Friendly name inside the PKCS#12 and the client certificate CN.
    pub client_name: String,
}

/// What the operator transfers to the companion and enrolls on the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSummary {
    pub server_leaf_sha256: String,
    pub client_leaf_sha256: String,
}

pub const TLS_FILES: &[(&str, &str)] = &[
    (
        "server-ca.key",
        "server CA private key: keep offline, never on the provider",
    ),
    ("server-ca.pem", "server CA certificate"),
    (
        "server-ca.der",
        "server CA (DER): import into the companion as its trusted CA",
    ),
    (
        "provider-cert.pem",
        "provider server certificate: state/provider-cert.pem",
    ),
    (
        "provider-key.pem",
        "provider server private key: state/provider-key.pem",
    ),
    (
        "server-leaf.sha256",
        "provider leaf SHA-256 pin for the companion",
    ),
    (
        "companion-ca.key",
        "companion client CA private key: keep offline",
    ),
    (
        "companion-ca.pem",
        "companion client CA: state/companion-ca.pem",
    ),
    (
        "companion-client.pem",
        "companion client certificate: enroll with --companion-enroll-cert",
    ),
    (
        "companion-client.key",
        "companion client private key (inside the PKCS#12)",
    ),
    (
        "companion-client.p12",
        "password-protected PKCS#12 to import into the companion",
    ),
];

const CA_CONFIG: &str = "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=@CN@\n[ext]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n";

/// Create the two private CAs, the provider server identity, the companion
/// client identity and its PKCS#12, using the given `openssl` binary.
/// `p12_password` is passed to openssl on its stdin, never in argv or env.
pub fn tls_bundle(request: &TlsRequest, p12_password: &str) -> Result<TlsSummary, SetupError> {
    validate_tls_request(request, p12_password)?;
    let mut created = Vec::new();
    let result = create_private_parents(&request.out_dir, &mut created)
        .and_then(|()| {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&request.out_dir)
                .map_err(|error| {
                    if error.kind() == std::io::ErrorKind::AlreadyExists {
                        SetupError::Exists(request.out_dir.clone())
                    } else {
                        SetupError::Write(request.out_dir.clone())
                    }
                })
        })
        .and_then(|()| {
            let result = tls_bundle_in(request, p12_password);
            if result.is_err() {
                // Never leave a partial set of keys behind.
                let _ignored = std::fs::remove_dir_all(&request.out_dir);
            }
            result
        });
    if result.is_err() {
        // Remove only the ancestors this run created, deepest first, and only
        // while empty: an existing or meanwhile populated directory stays.
        for directory in created.iter().rev() {
            if std::fs::remove_dir(directory).is_err() {
                break;
            }
        }
    }
    result
}

/// Create the missing ancestors of `path` (for example `~/vw-setup`) one level
/// at a time, each `0700`, without following a link at the new name, and check
/// that each new directory is a private directory of the running user. Existing
/// ancestors are used as they are. Each directory created is pushed to
/// `created` (shallowest first), so a failed run can remove them again.
fn create_private_parents(path: &Path, created: &mut Vec<PathBuf>) -> Result<(), SetupError> {
    use std::os::unix::fs::MetadataExt;
    let mut missing = Vec::new();
    let mut parent = path.parent();
    while let Some(directory) = parent.filter(|p| !p.as_os_str().is_empty()) {
        match std::fs::symlink_metadata(directory) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(directory.to_path_buf());
                parent = directory.parent();
            }
            Err(_) => return Err(SetupError::Write(directory.into())),
        }
    }
    let euid = unsafe { libc::geteuid() };
    for directory in missing.into_iter().rev() {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|_error| SetupError::Write(directory.clone()))?;
        created.push(directory.clone());
        let metadata = std::fs::symlink_metadata(&directory)
            .map_err(|_error| SetupError::Write(directory.clone()))?;
        if !metadata.is_dir() || metadata.uid() != euid || metadata.mode() & 0o077 != 0 {
            return Err(SetupError::Invalid(format!(
                "{} is not a private directory of the running user",
                directory.display()
            )));
        }
    }
    Ok(())
}

fn validate_tls_request(request: &TlsRequest, p12_password: &str) -> Result<(), SetupError> {
    if !request.openssl.is_absolute() {
        return Err(SetupError::Invalid(
            "--openssl must be an absolute path".into(),
        ));
    }
    if request.server_ips.is_empty() && request.server_dns.is_empty() {
        return Err(SetupError::Invalid(
            "at least one server IP or DNS name is required".into(),
        ));
    }
    if !(1..=825).contains(&request.days) {
        return Err(SetupError::Invalid(
            "leaf validity must be 1-825 days (Apple TLS policy)".into(),
        ));
    }
    let printable = |v: &str| {
        !v.is_empty()
            && v.len() <= 64
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b" .-_".contains(&b))
    };
    if !printable(&request.client_name) {
        return Err(SetupError::Invalid(
            "client name must be 1-64 characters of [A-Za-z0-9 ._-]".into(),
        ));
    }
    for name in &request.server_dns {
        if !printable(name) || name.contains(' ') {
            return Err(SetupError::Invalid(format!("invalid DNS name {name:?}")));
        }
    }
    if p12_password.chars().count() < 8 || p12_password.contains(['\n', '\r']) {
        return Err(SetupError::Invalid(
            "the PKCS#12 password must be one line of at least 8 characters".into(),
        ));
    }
    Ok(())
}

fn tls_bundle_in(request: &TlsRequest, p12_password: &str) -> Result<TlsSummary, SetupError> {
    let dir = &request.out_dir;
    let openssl = |step: &str, args: &[&str], stdin: Option<&str>| -> Result<(), SetupError> {
        let mut child = Command::new(&request.openssl)
            .args(args)
            .current_dir(dir)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_error| SetupError::Openssl(format!("{step} (cannot start)")))?;
        if let Some(input) = stdin {
            let mut pipe = child
                .stdin
                .take()
                .ok_or_else(|| SetupError::Openssl(step.into()))?;
            let line = Zeroizing::new(format!("{input}\n"));
            pipe.write_all(line.as_bytes())
                .map_err(|_error| SetupError::Openssl(step.into()))?;
        }
        let output = child
            .wait_with_output()
            .map_err(|_error| SetupError::Openssl(step.into()))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(SetupError::Openssl(format!(
                "{step}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    };
    // Scratch configuration files are public and removed at the end.
    let scratch = |name: &str, text: String| -> Result<(), SetupError> {
        write_new_private(&dir.join(name), text.as_bytes())
    };
    let days = request.days.to_string();
    for (ca, cn) in [
        ("server-ca", "vaultwarden-accessd provider server CA"),
        ("companion-ca", "vaultwarden-accessd companion client CA"),
    ] {
        scratch(&format!("{ca}.cnf"), CA_CONFIG.replace("@CN@", cn))?;
        openssl(
            &format!("creating {ca}"),
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:3072",
                "-nodes",
                "-sha256",
                "-days",
                "3650",
                "-config",
                &format!("{ca}.cnf"),
                "-keyout",
                &format!("{ca}.key"),
                "-out",
                &format!("{ca}.pem"),
            ],
            None,
        )?;
    }
    let mut san: Vec<String> = request
        .server_ips
        .iter()
        .map(|ip| format!("IP:{ip}"))
        .collect();
    san.extend(request.server_dns.iter().map(|dns| format!("DNS:{dns}")));
    for (leaf, ca, cn, usage) in [
        (
            "provider",
            "server-ca",
            "vaultwarden-accessd provider".to_owned(),
            "serverAuth",
        ),
        (
            "companion-client",
            "companion-ca",
            request.client_name.clone(),
            "clientAuth",
        ),
    ] {
        let key = if leaf == "provider" {
            "provider-key.pem".to_owned()
        } else {
            format!("{leaf}.key")
        };
        let cert = if leaf == "provider" {
            "provider-cert.pem".to_owned()
        } else {
            format!("{leaf}.pem")
        };
        let mut extensions = format!(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"
        );
        if leaf == "provider" {
            extensions.push_str(&format!("subjectAltName={}\n", san.join(",")));
        }
        scratch(&format!("{leaf}.ext"), extensions)?;
        openssl(
            &format!("creating the {leaf} key"),
            &[
                "req",
                "-new",
                "-newkey",
                "rsa:3072",
                "-nodes",
                "-sha256",
                "-subj",
                &format!("/CN={cn}"),
                "-keyout",
                &key,
                "-out",
                &format!("{leaf}.csr"),
            ],
            None,
        )?;
        openssl(
            &format!("signing the {leaf} certificate"),
            &[
                "x509",
                "-req",
                "-sha256",
                "-in",
                &format!("{leaf}.csr"),
                "-CA",
                &format!("{ca}.pem"),
                "-CAkey",
                &format!("{ca}.key"),
                "-set_serial",
                &random_serial()?,
                "-days",
                &days,
                "-extfile",
                &format!("{leaf}.ext"),
                "-out",
                &cert,
            ],
            None,
        )?;
    }
    openssl(
        "converting the server CA to DER",
        &[
            "x509",
            "-in",
            "server-ca.pem",
            "-outform",
            "DER",
            "-out",
            "server-ca.der",
        ],
        None,
    )?;
    // 3DES/SHA-1 PKCS#12: the format macOS Keychain import accepts on every
    // supported release (the same parameters as the packaged-app TLS fixtures).
    openssl(
        "exporting the PKCS#12",
        &[
            "pkcs12",
            "-export",
            "-inkey",
            "companion-client.key",
            "-in",
            "companion-client.pem",
            "-certfile",
            "companion-ca.pem",
            "-name",
            &request.client_name,
            "-passout",
            "stdin",
            "-keypbe",
            "PBE-SHA1-3DES",
            "-certpbe",
            "PBE-SHA1-3DES",
            "-macalg",
            "sha1",
            "-out",
            "companion-client.p12",
        ],
        Some(p12_password),
    )?;
    for scratch in [
        "server-ca.cnf",
        "companion-ca.cnf",
        "provider.ext",
        "companion-client.ext",
        "provider.csr",
        "companion-client.csr",
    ] {
        let _ignored = std::fs::remove_file(dir.join(scratch));
    }
    let server_leaf_sha256 = pem_leaf_sha256(&dir.join("provider-cert.pem"))?;
    let client_leaf_sha256 = pem_leaf_sha256(&dir.join("companion-client.pem"))?;
    write_new_private(
        &dir.join("server-leaf.sha256"),
        format!("{server_leaf_sha256}\n").as_bytes(),
    )?;
    // openssl honours the umask for some outputs; every file here is private.
    for (name, _) in TLS_FILES {
        let path = dir.join(name);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_error| SetupError::Write(path.clone()))?;
    }
    Ok(TlsSummary {
        server_leaf_sha256,
        client_leaf_sha256,
    })
}

fn random_serial() -> Result<String, SetupError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_error| SetupError::Invalid("random source unavailable".into()))?;
    bytes[0] &= 0x7f; // positive, non-zero high byte keeps it a 128-bit serial
    bytes[0] |= 0x01;
    Ok(format!(
        "0x{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

/// Lowercase hex SHA-256 of the first certificate's DER: the companion's exact leaf pin.
pub fn pem_leaf_sha256(path: &Path) -> Result<String, SetupError> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)
        .map_err(|_error| SetupError::Invalid(format!("cannot read {}", path.display())))?;
    let certificate = CertificateDer::pem_slice_iter(&bytes)
        .next()
        .and_then(Result::ok)
        .ok_or_else(|| SetupError::Invalid(format!("{} has no certificate", path.display())))?;
    Ok(Sha256::digest(certificate.as_ref())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    #[test]
    fn agent_key_writes_private_seed_once_and_returns_matching_public_key() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let dir = private_dir();
        let path = dir.path().join("agent.key");
        let public = agent_key(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        let seed: [u8; 32] = std::fs::read(&path).unwrap().try_into().unwrap();
        let expected = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&public).unwrap(),
            expected.to_bytes()
        );
        // The key file is exactly what `vw-access submit --key-file` loads.
        assert_eq!(
            crate::adapters::unix_socket::load_signing_key(&path)
                .unwrap()
                .verifying_key(),
            expected
        );
        assert_eq!(agent_key(&path), Err(SetupError::Exists(path.clone())));
        assert_eq!(std::fs::read(&path).unwrap(), seed);
        let link = dir.path().join("link.key");
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), &link).unwrap();
        assert!(agent_key(&link).is_err());
        assert!(!dir.path().join("elsewhere").exists());
    }

    fn cli_config() -> serde_json::Value {
        serde_json::json!({
            "server": "https://vault.example.test",
            "client_id": "user.0000",
            "email": "human@example.test",
            "access_token": "token-sentinel",
            "refresh_token": "refresh-sentinel",
            "token_expiry": 1,
            "encrypted_key": "2.aXY=|ZGF0YQ==|bWFj",
            "encrypted_private_key": "2.cA==|cA==|cA==",
            "kdf_iterations": 600000,
            "org_keys": {}
        })
    }

    #[test]
    fn backend_json_from_cli_session_drops_authority_and_validates_with_provider_reader() {
        let dir = private_dir();
        let source = dir.path().join("config.json");
        std::fs::write(&source, serde_json::to_vec(&cli_config()).unwrap()).unwrap();
        // config.json carries no KDF type: an explicit PBKDF2 statement is required.
        assert_eq!(
            backend_json(Some(&source), &BackendFields::default()),
            Err(SetupError::Invalid(KDF_REQUIRED.into()))
        );
        let pbkdf2 = BackendFields {
            kdf: Some("pbkdf2".into()),
            kdf_iterations: Some(600_000),
            ..BackendFields::default()
        };
        for fields in [
            BackendFields {
                kdf: Some("argon2id".into()),
                kdf_iterations: Some(3),
                ..BackendFields::default()
            },
            BackendFields {
                kdf: Some("argon2id".into()),
                ..pbkdf2.clone()
            },
        ] {
            assert_eq!(
                backend_json(Some(&source), &fields),
                Err(SetupError::Invalid(KDF_ARGON2.into()))
            );
        }
        // The iteration count is stated too, and must agree with the login's.
        assert!(
            backend_json(
                Some(&source),
                &BackendFields {
                    kdf_iterations: None,
                    ..pbkdf2.clone()
                }
            )
            .is_err()
        );
        assert!(
            backend_json(
                Some(&source),
                &BackendFields {
                    kdf_iterations: Some(100_000),
                    ..pbkdf2.clone()
                }
            )
            .is_err()
        );
        let bytes = backend_json(Some(&source), &pbkdf2).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        for forbidden in [
            "token-sentinel",
            "refresh-sentinel",
            "token_expiry",
            "org_keys",
        ] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
        let out = dir.path().join("backend.json");
        write_new_private(&out, &bytes).unwrap();
        assert_eq!(mode(&out), 0o600);
        crate::adapters::session::validate_setup(&out).unwrap();
        assert_eq!(
            write_new_private(&out, b"{}"),
            Err(SetupError::Exists(out.clone()))
        );
        // Explicit flags override and can stand alone.
        let explicit = BackendFields {
            server: Some("https://other.example.test/".into()),
            email: Some("other@example.test".into()),
            client_id: Some("user.1111".into()),
            encrypted_key: Some("2.aXY=|ZGF0YQ==|bWFj".into()),
            kdf: Some("pbkdf2".into()),
            kdf_iterations: Some(1),
        };
        let value: serde_json::Value =
            serde_json::from_slice(&backend_json(None, &explicit).unwrap()).unwrap();
        assert_eq!(value["server"], "https://other.example.test/");
        assert_eq!(value["kdf_iterations"], 1);
        for server in [
            "http://vault.example.test",
            "https://user@vault.example.test",
            "https://vault.example.test/prefix",
            "https://vault.example.test/?q=1",
            "not a url",
        ] {
            let fields = BackendFields {
                server: Some(server.into()),
                ..explicit.clone()
            };
            assert!(backend_json(None, &fields).is_err(), "{server}");
        }
        for (field, bad) in [
            ("kdf", serde_json::json!(1)),
            ("kdf_iterations", serde_json::json!(2_000_001)),
        ] {
            let mut config = cli_config();
            config[field] = bad;
            std::fs::write(&source, serde_json::to_vec(&config).unwrap()).unwrap();
            assert!(backend_json(Some(&source), &pbkdf2).is_err(), "{field}");
        }
        // A login that records no KDF type (absent or null) defers to --kdf;
        // a recorded Argon2id or an unknown value is named as such.
        for (kdf, expected) in [
            (serde_json::Value::Null, None),
            (serde_json::json!(0), None),
            (serde_json::json!(1), Some(KDF_ARGON2.to_owned())),
            (
                serde_json::json!(7),
                Some(
                    "the vaultwarden-cli login records an unknown kdf 7 (expected 0 = PBKDF2)"
                        .to_owned(),
                ),
            ),
            (
                serde_json::json!("pbkdf2"),
                Some(
                    "the vaultwarden-cli login records an unknown kdf \"pbkdf2\" (expected 0 = PBKDF2)"
                        .to_owned(),
                ),
            ),
        ] {
            let mut config = cli_config();
            config["kdf"] = kdf.clone();
            std::fs::write(&source, serde_json::to_vec(&config).unwrap()).unwrap();
            let result = backend_json(Some(&source), &pbkdf2);
            match expected {
                None => assert!(result.is_ok(), "{kdf}: {result:?}"),
                Some(message) => assert_eq!(result, Err(SetupError::Invalid(message)), "{kdf}"),
            }
        }
        let fields = BackendFields {
            encrypted_key: Some("0.legacy".into()),
            ..explicit
        };
        assert!(backend_json(None, &fields).is_err());
        assert!(backend_json(None, &BackendFields::default()).is_err());
    }

    fn openssl() -> Option<PathBuf> {
        [
            "/usr/bin/openssl",
            "/opt/homebrew/bin/openssl",
            "/usr/local/bin/openssl",
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
    }

    #[test]
    fn tls_bundle_failure_removes_only_the_parents_it_created() {
        let dir = private_dir();
        let existing = dir.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        let request = TlsRequest {
            out_dir: existing.join("vw-setup").join("nested").join("tls"),
            openssl: PathBuf::from("/nonexistent/openssl"),
            server_ips: vec!["127.0.0.1".parse().unwrap()],
            server_dns: vec![],
            days: 30,
            client_name: "Mac operator".into(),
        };
        assert!(matches!(
            tls_bundle(&request, "synthetic-password"),
            Err(SetupError::Openssl(_))
        ));
        // The pre-existing ancestor stays; nothing this run created survives.
        assert!(existing.is_dir());
        assert_eq!(std::fs::read_dir(&existing).unwrap().count(), 0);
        // With vw-setup already present (and holding a file), only the levels
        // this run created below it are removed.
        let populated = existing.join("vw-setup");
        std::fs::create_dir(&populated).unwrap();
        std::fs::write(populated.join("keep"), b"x").unwrap();
        assert!(tls_bundle(&request, "synthetic-password").is_err());
        assert!(populated.join("keep").exists());
        assert!(!populated.join("nested").exists());
    }

    #[test]
    fn tls_bundle_produces_private_files_a_working_provider_identity_and_the_pin() {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{
            CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject,
        };
        let Some(openssl) = openssl() else {
            eprintln!("skipping: no openssl executable");
            return;
        };
        crate::install_rustls_crypto_provider();
        let dir = private_dir();
        let request = TlsRequest {
            // Missing parents (e.g. ~/vw-setup) are created private, not refused.
            out_dir: dir.path().join("vw-setup").join("nested").join("tls"),
            openssl,
            server_ips: vec!["127.0.0.1".parse().unwrap()],
            server_dns: vec![],
            days: 30,
            client_name: "Mac operator".into(),
        };
        assert!(matches!(
            tls_bundle(&request, "short"),
            Err(SetupError::Invalid(_))
        ));
        assert!(!dir.path().join("vw-setup").exists());
        let summary = tls_bundle(&request, "synthetic-password").unwrap();
        let out = &request.out_dir;
        assert_eq!(mode(out), 0o700);
        assert_eq!(mode(&dir.path().join("vw-setup")), 0o700);
        assert_eq!(mode(&dir.path().join("vw-setup/nested")), 0o700);
        let mut names: Vec<_> = std::fs::read_dir(out)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        let mut expected: Vec<_> = TLS_FILES.iter().map(|(n, _)| (*n).to_owned()).collect();
        expected.sort();
        assert_eq!(names, expected);
        for name in &names {
            assert_eq!(mode(&out.join(name)), 0o600, "{name}");
        }
        let read = |name: &str| std::fs::read(out.join(name)).unwrap();
        let server_ca = CertificateDer::from(read("server-ca.der"));
        assert_eq!(
            CertificateDer::from_pem_slice(&read("server-ca.pem")).unwrap(),
            server_ca
        );
        let leaf = CertificateDer::from_pem_slice(&read("provider-cert.pem")).unwrap();
        assert_eq!(
            String::from_utf8(read("server-leaf.sha256")).unwrap(),
            format!("{}\n", summary.server_leaf_sha256)
        );
        assert_eq!(summary.server_leaf_sha256.len(), 64);
        // The provider loads this identity exactly as Companion::bind does.
        let key = PrivateKeyDer::from_pem_slice(&read("provider-key.pem")).unwrap();
        let mut client_roots = rustls::RootCertStore::empty();
        client_roots
            .add(CertificateDer::from_pem_slice(&read("companion-ca.pem")).unwrap())
            .unwrap();
        let client_verifier = rustls::server::WebPkiClientVerifier::builder(client_roots.into())
            .build()
            .unwrap();
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier.clone())
            .with_single_cert(vec![leaf.clone()], key)
            .unwrap();
        // The companion trusts the server CA for IP 127.0.0.1 only.
        let mut server_roots = rustls::RootCertStore::empty();
        server_roots.add(server_ca).unwrap();
        let server_verifier = rustls::client::WebPkiServerVerifier::builder(server_roots.into())
            .build()
            .unwrap();
        let now = UnixTime::now();
        server_verifier
            .verify_server_cert(
                &leaf,
                &[],
                &ServerName::try_from("127.0.0.1").unwrap(),
                &[],
                now,
            )
            .unwrap();
        assert!(
            server_verifier
                .verify_server_cert(
                    &leaf,
                    &[],
                    &ServerName::try_from("127.0.0.2").unwrap(),
                    &[],
                    now
                )
                .is_err()
        );
        // The client certificate is accepted by the provider's client CA.
        let client = CertificateDer::from_pem_slice(&read("companion-client.pem")).unwrap();
        client_verifier
            .verify_client_cert(&client, &[], now)
            .unwrap();
        assert!(client_verifier.verify_client_cert(&leaf, &[], now).is_err());
        assert_eq!(
            summary.client_leaf_sha256,
            pem_leaf_sha256(&out.join("companion-client.pem")).unwrap()
        );
        // The PKCS#12 opens with the password given on stdin, not without it.
        let check = |password: &str| {
            Command::new(&request.openssl)
                .args([
                    "pkcs12",
                    "-in",
                    "companion-client.p12",
                    "-nokeys",
                    "-passin",
                    "stdin",
                ])
                .current_dir(out)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .and_then(|mut child| {
                    child
                        .stdin
                        .take()
                        .unwrap()
                        .write_all(format!("{password}\n").as_bytes())?;
                    child.wait()
                })
                .unwrap()
                .success()
        };
        assert!(check("synthetic-password"));
        assert!(!check("wrong-password"));
        // Never replaces an existing bundle.
        assert_eq!(
            tls_bundle(&request, "synthetic-password"),
            Err(SetupError::Exists(out.clone()))
        );
    }
}
