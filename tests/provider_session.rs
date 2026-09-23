//! Transport-level boundary tests; no public production secret-resolution hook.
use std::{
    os::unix::fs::PermissionsExt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use vaultwarden_cli::{
    access::{application::ProviderApplication, ports::*, provider::Provider},
    adapters::{loopback_ui::LoopbackUi, session::MonotonicClock},
};
struct Backend(Arc<AtomicUsize>);
impl ProviderSession for Backend {
    fn probe_compatibility(&mut self) -> Result<(), SessionError> {
        Ok(())
    }
    fn unlock(&mut self, _: SensitiveString) -> Result<Duration, SessionError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Duration::from_secs(900))
    }
    fn clear(&mut self) -> Result<(), SessionError> {
        Ok(())
    }
}
impl SecretBackend for Backend {
    fn eligible(&mut self, _: &CredentialBinding<'_>) -> Result<bool, SessionError> {
        panic!("transport cannot resolve")
    }
    fn resolve(&mut self, _: &CredentialBinding<'_>) -> Result<Vec<SensitiveString>, SessionError> {
        panic!("transport cannot resolve")
    }
}
#[test]
fn actual_loopback_exchange_unlock_lock_and_replay_are_redacted() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let app = Arc::new(
        ProviderApplication::new(
            Provider::start(dir.path().join("provider")).unwrap(),
            Box::new(Backend(calls.clone())),
            Box::<MonotonicClock>::default(),
        )
        .unwrap(),
    );
    let artifact = dir.path().join("launch.html");
    let (certificate, key) = identity(dir.path());
    let ui = LoopbackUi::bind(&artifact, &certificate, &key).unwrap();
    let text = std::fs::read_to_string(&artifact).unwrap();
    let url = text
        .split("href=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let (base, capability) = url.split_once("/#").unwrap();
    let base = base.to_owned();
    let capability = capability.to_owned();
    let stop = Arc::new(AtomicBool::new(false));
    let worker = {
        let app = app.clone();
        let stop = stop.clone();
        std::thread::spawn(move || ui.serve(app, stop))
    };
    vaultwarden_cli::install_rustls_crypto_provider();
    let client = trusted_client();
    let launch = || {
        client
            .post(format!("{base}/launch"))
            .header("Origin", &base)
            .header("Content-Type", "text/plain")
            .body(capability.clone())
            .send()
            .unwrap()
    };
    let response = launch();
    assert!(response.status().is_success());
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let csrf = response.text().unwrap();
    assert_eq!(launch().status().as_u16(), 403);
    let page = client
        .get(format!("{base}/"))
        .header("Cookie", &cookie)
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(!page.contains(&csrf));
    assert!(page.contains("sessionStorage.getItem('vw_proof')"));
    let send = |path: &str, body: &str, origin: &str| {
        client
            .post(format!("{base}{path}"))
            .header("Origin", origin)
            .header("Cookie", &cookie)
            .header("X-CSRF-Token", &csrf)
            .header("Content-Type", "application/json")
            .body(body.to_owned())
            .send()
            .unwrap()
    };
    for (body, origin) in [
        ("password-sentinel", base.as_str()),
        (r#"{"password":"password-sentinel"}"#, "http://evil.test"),
    ] {
        let response = send("/unlock", body, origin);
        assert_eq!(response.status().as_u16(), 403);
        assert!(!response.text().unwrap().contains("sentinel"));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let response = send("/unlock", r#"{"password":"password-sentinel"}"#, &base);
    assert_eq!(response.text().unwrap(), "Provider unlocked");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // Actual trusted HTTPS transport accepts every 4096-byte password, including
    // the worst-case six-byte JSON escaping, and rejects the decoded 4097th byte.
    for password in [
        "\u{0001}".repeat(4096),
        "\\".repeat(4096),
        "\"".repeat(4096),
        "é".repeat(2048),
    ] {
        let body = serde_json::json!({"password": password}).to_string();
        assert_eq!(send("/unlock", &body, &base).status().as_u16(), 200);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    // Stay within the encoded-body limit to exercise the decoded-password
    // rejection. An oversized encoded body can be closed before it is drained.
    let body = serde_json::json!({"password": "p".repeat(4097)}).to_string();
    assert_eq!(send("/unlock", &body, &base).status().as_u16(), 403);
    for body in [
        r#"{"password":"password-sentinel","unknown":true}"#,
        r#"{"password":"password-sentinel","password":"second-sentinel"}"#,
        r#"{"password":"password-sentinel",malformed}"#,
        r#"{"password":"password-sentinel"} trailing"#,
    ] {
        let response = send("/unlock", body, &base);
        assert_eq!(response.status().as_u16(), 403);
        assert!(!response.text().unwrap().contains("sentinel"));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    let response = send("/lock", "{}", &base);
    assert_eq!(response.text().unwrap(), "Provider locked");
    let persisted =
        std::fs::read_to_string(dir.path().join("provider/provider-state.json")).unwrap();
    for forbidden in ["password-sentinel", &capability, &cookie, &csrf] {
        assert!(!persisted.contains(forbidden));
    }
    stop.store(true, Ordering::Release);
    join_ui(worker).unwrap();
    app.lock().unwrap();
}
#[test]
fn daemon_missing_keyring_fails_closed_even_without_backend_config() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = dir.path().join("provider");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vaultwarden-accessd"))
        .arg("--state-root")
        .arg(&root)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/nonexistent-story13-bus",
        )
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "vaultwarden-accessd: provider unavailable\n"
    );
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("provider-state.json")).unwrap()).unwrap();
    assert!(state["operations"].as_array().unwrap().is_empty());
    let help = std::process::Command::new(env!("CARGO_BIN_EXE_vaultwarden-accessd"))
        .arg("--help")
        .output()
        .unwrap();
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(!text.contains("--password"));
    assert!(!text.contains("--token"));
    assert!(text.contains("--ui-tls-cert"));
    assert!(text.contains("--ui-tls-key"));
    assert!(!root.join("open-vaultwarden-access.html").exists());
}

fn identity(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let certificate = dir.join("server.pem");
    let key = dir.join("server-key.pem");
    std::fs::write(
        &certificate,
        include_bytes!("fixtures/provider-tls/server.pem"),
    )
    .unwrap();
    std::fs::write(&key, include_bytes!("fixtures/provider-tls/server-key.pem")).unwrap();
    for file in [&certificate, &key] {
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (certificate, key)
}
fn trusted_client() -> reqwest::blocking::Client {
    vaultwarden_cli::install_rustls_crypto_provider();
    reqwest::blocking::Client::builder()
        .no_proxy()
        .tls_certs_only([reqwest::Certificate::from_pem(include_bytes!(
            "fixtures/provider-tls/ca.pem"
        ))
        .unwrap()])
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

#[test]
fn plaintext_cannot_submit_and_slow_clients_do_not_starve_lock() {
    use std::io::{Read, Write};
    let (dir, app, calls, ui, base, capability) = transport_fixture();
    let stop = Arc::new(AtomicBool::new(false));
    let worker = {
        let app = app.clone();
        let stop = stop.clone();
        std::thread::spawn(move || ui.serve(app, stop))
    };
    let client = trusted_client();
    let launch = client
        .post(format!("{base}/launch"))
        .header("Origin", &base)
        .header("Content-Type", "text/plain")
        .body(capability)
        .send()
        .unwrap();
    let cookie = launch.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert!(
        launch.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Secure")
    );
    let proof = launch.text().unwrap();
    let address = base.strip_prefix("https://").unwrap();
    let mut raw = std::net::TcpStream::connect(address).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let body = r#"{"password":"plaintext-password-sentinel"}"#;
    raw.write_all(format!("POST /unlock HTTP/1.1\r\nHost: {address}\r\nOrigin: {base}\r\nCookie: {cookie}\r\nX-CSRF-Token: {proof}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",body.len()).as_bytes()).unwrap();
    let mut response = Vec::new();
    let _ = raw.read_to_end(&mut response);
    assert!(!String::from_utf8_lossy(&response).contains("Provider unlocked"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    app.authenticate(SensitiveString::new("human-test-password".into()))
        .unwrap();
    // Keep a freshly admitted partial TLS handshake open while Lock completes.
    let _slow = std::net::TcpStream::connect(address).unwrap();
    std::thread::sleep(Duration::from_millis(75));
    let started = std::time::Instant::now();
    let response = client
        .post(format!("{base}/lock"))
        .header("Origin", &base)
        .header("Cookie", format!("unrelated=value; {cookie}"))
        .header("X-CSRF-Token", proof)
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .unwrap();
    assert_eq!(response.text().unwrap(), "Provider locked");
    assert!(started.elapsed() < Duration::from_secs(1));
    stop.store(true, Ordering::Release);
    join_ui(worker).unwrap();
    drop(dir);
}

#[test]
fn completed_connections_do_not_exhaust_parser_capacity() {
    use vaultwarden_cli::access::application::SessionStatus;
    let (_dir, app, calls, ui, base, _) = transport_fixture();
    app.authenticate(SensitiveString::new("human-test-password".into()))
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let worker = {
        let app = app.clone();
        let stop = stop.clone();
        std::thread::spawn(move || ui.serve(app, stop))
    };
    let client = trusted_client();
    for _ in 0..24 {
        let response = client.get(format!("{base}/")).send().unwrap();
        assert!(response.status().is_success());
        assert!(response.text().unwrap().contains("Master password"));
    }
    assert_eq!(app.status(), Ok(SessionStatus::Unlocked));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    stop.store(true, Ordering::Release);
    join_ui(worker).unwrap();
}

#[test]
fn parser_capacity_exhaustion_revokes_authority_and_joins_all_workers() {
    use vaultwarden_cli::access::application::SessionStatus;
    let (_dir, app, calls, ui, base, _) = transport_fixture();
    app.authenticate(SensitiveString::new("human-test-password".into()))
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let worker = {
        let app = app.clone();
        let stop = stop.clone();
        std::thread::spawn(move || ui.serve(app, stop))
    };
    let streams: Vec<_> = (0..9)
        .map(|_| std::net::TcpStream::connect(base.strip_prefix("https://").unwrap()).unwrap())
        .collect();
    assert_eq!(join_ui(worker), Err(SessionError::BackendUnavailable));
    assert!(stop.load(Ordering::Acquire));
    assert_eq!(app.status(), Ok(SessionStatus::Locked));
    assert_eq!(
        app.authenticate(SensitiveString::new("human-test-password".into())),
        Err(SessionError::Locked)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(streams);
}

#[test]
fn stale_origin_replacement_with_untrusted_identity_receives_no_password() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    use std::io::Read;
    let (_dir, app, _calls, ui, base, _) = transport_fixture();
    let stop = Arc::new(AtomicBool::new(true));
    ui.serve(app, stop).unwrap();
    // Reoccupy the exact original endpoint after provider exit. The old browser
    // client still trusts ONLY the provisioned CA, never this replacement.
    let listener = std::net::TcpListener::bind(base.strip_prefix("https://").unwrap()).unwrap();
    let certificates =
        CertificateDer::pem_slice_iter(include_bytes!("fixtures/provider-tls/replacement.pem"))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    let key =
        PrivateKeyDer::from_pem_slice(include_bytes!("fixtures/provider-tls/replacement-key.pem"))
            .unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap();
    let replacement = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut stream = rustls::StreamOwned::new(
            rustls::ServerConnection::new(Arc::new(config)).unwrap(),
            socket,
        );
        let mut plaintext = Vec::new();
        let result = stream.read_to_end(&mut plaintext);
        assert!(result.is_err());
        assert!(plaintext.is_empty());
    });
    let result = trusted_client()
        .post(format!("{base}/unlock"))
        .body(r#"{"password":"must-not-reach-replacement"}"#)
        .send();
    assert!(result.is_err());
    replacement.join().unwrap();
}

fn transport_fixture() -> (
    tempfile::TempDir,
    Arc<ProviderApplication>,
    Arc<AtomicUsize>,
    LoopbackUi,
    String,
    String,
) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let app = Arc::new(
        ProviderApplication::new(
            Provider::start(dir.path().join("provider")).unwrap(),
            Box::new(Backend(calls.clone())),
            Box::<MonotonicClock>::default(),
        )
        .unwrap(),
    );
    let (cert, key) = identity(dir.path());
    let artifact = dir.path().join("launch.html");
    let ui = LoopbackUi::bind(&artifact, &cert, &key).unwrap();
    let text = std::fs::read_to_string(artifact).unwrap();
    let url = text
        .split("href=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let (base, capability) = url.split_once("/#").unwrap();
    (dir, app, calls, ui, base.into(), capability.into())
}

// Keep a deliberately broken serving loop from hanging the test process. The
// normal transport has a two-second I/O deadline; allow scheduler headroom.
fn join_ui(worker: std::thread::JoinHandle<Result<(), SessionError>>) -> Result<(), SessionError> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = worker.join().expect("UI worker panicked");
        let _ = sender.send(result);
    });
    receiver
        .recv_timeout(Duration::from_secs(8))
        .expect("UI failed to stop within its cleanup deadline")
}
