//! Real Unix + trusted HTTPS boundaries with a synthetic backend; no real account.
use std::{
    os::unix::fs::PermissionsExt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use vaultwarden_cli::{
    access::{
        application::ProviderApplication, direct_request::*, policy::*, ports::*,
        provider::Provider,
    },
    adapters::{
        human_socket::{HumanCommand, HumanResponse, HumanSocket, exchange},
        loopback_ui::LoopbackUi,
    },
};
struct Clock(Arc<AtomicU64>);
impl SessionClock for Clock {
    fn now(&self) -> Duration {
        Duration::from_secs(self.0.load(Ordering::SeqCst))
    }
    fn unix_seconds(&self) -> Result<u64, SessionError> {
        Ok(1700000000)
    }
}
struct Backend;
impl ProviderSession for Backend {
    fn probe_compatibility(&mut self) -> Result<(), SessionError> {
        Ok(())
    }
    fn unlock(&mut self, _: SensitiveString) -> Result<Duration, SessionError> {
        Ok(Duration::from_secs(900))
    }
    fn clear(&mut self) -> Result<(), SessionError> {
        Ok(())
    }
}
impl SecretBackend for Backend {
    fn eligible(&mut self, _: &CredentialBinding<'_>) -> Result<bool, SessionError> {
        Ok(true)
    }
    fn resolve(&mut self, _: &CredentialBinding<'_>) -> Result<Vec<SensitiveString>, SessionError> {
        panic!("no secret resolution")
    }
}
struct ApprovalCheck;
impl ApprovalAuthenticator for ApprovalCheck {
    fn authenticate(&self, _: SensitiveString) -> Result<(), SessionError> {
        Ok(())
    }
}
struct Launcher(AtomicUsize);
impl DirectReviewLauncher for Launcher {
    fn launch(&self, _: &str) -> Result<(), DirectRequestError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
#[test]
fn human_submission_https_review_expiry_and_independent_negative_cases() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = dir.path().join("provider");
    let clock = Arc::new(AtomicU64::new(0));
    let app = Arc::new(
        ProviderApplication::new(
            Provider::start(&root).unwrap(),
            Box::new(Backend),
            Box::new(Clock(clock.clone())),
        )
        .unwrap(),
    );
    app.authenticate(SensitiveString::new("synthetic-password".into()))
        .unwrap();
    let image = dir.path().join("image");
    let bytes = std::fs::read("/usr/bin/true").unwrap();
    std::fs::write(&image, &bytes).unwrap();
    std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o700)).unwrap();
    use sha2::Digest;
    let digest: String = sha2::Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let state_path = root.join("provider-state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    state["approved_images"] =
        serde_json::json!([{"id":"test-image","path":image,"sha256":digest}]);
    std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let revision = app
        .activate_operation(OperationPolicyDraft {
            id: "deploy".into(),
            description: "Deploy <script>sentinel</script>".into(),
            image_id: "test-image".into(),
            targets: vec!["staging".into()],
            arguments: vec![
                ArgumentSpec::Target,
                ArgumentSpec::Integer {
                    minimum: 0,
                    maximum: 9,
                },
            ],
            credentials: vec![LoginCredentialDraft {
                item_id: "11111111-1111-1111-1111-111111111111".into(),
                label: "Deploy login".into(),
                use_type: CredentialUse::Login,
                field_mappings: vec![LoginFieldMapping {
                    field: LoginField::Password,
                    environment: "DEPLOY_PASSWORD".into(),
                }],
            }],
        })
        .unwrap();
    let cert = root.join("server.pem");
    let key = root.join("server-key.pem");
    std::fs::write(&cert, include_bytes!("fixtures/provider-tls/server.pem")).unwrap();
    std::fs::write(&key, include_bytes!("fixtures/provider-tls/server-key.pem")).unwrap();
    for p in [&cert, &key] {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let artifact = root.join("launch.html");
    let ui = LoopbackUi::bind(&artifact, &cert, &key)
        .unwrap()
        .with_approval_authenticator(Arc::new(ApprovalCheck));
    let html = std::fs::read_to_string(&artifact).unwrap();
    let url = html
        .split("href=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let (base, cap) = url.split_once("/#").unwrap();
    let (base, cap) = (base.to_owned(), cap.to_owned());
    let socket = HumanSocket::bind(&root).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let launcher = Arc::new(Launcher(AtomicUsize::new(0)));
    let human = {
        let (app, stop, launcher) = (app.clone(), stop.clone(), launcher.clone());
        std::thread::spawn(move || socket.serve(app, launcher, stop))
    };
    let browser = {
        let (app, stop) = (app.clone(), stop.clone());
        std::thread::spawn(move || ui.serve(app, stop))
    };
    let input = || DirectSubmission {
        operation: "deploy".into(),
        revision: Some(revision.clone()),
        values: vec!["staging".into(), "+003".into()],
    };
    for case in ["target", "integer", "stale"] {
        let mut submission = input();
        let expected = match case {
            "target" => {
                submission.values[0] = "production".into();
                DirectRequestError::InvalidRequest
            }
            "integer" => {
                submission.values[1] = "10".into();
                DirectRequestError::InvalidRequest
            }
            _ => {
                submission.revision = Some("b".repeat(64));
                DirectRequestError::StaleRevision
            }
        };
        assert!(
            matches!(exchange(&root,HumanCommand::Request{submission}).unwrap(),HumanResponse::Rejected{reason} if reason==expected)
        );
        assert_eq!(launcher.0.load(Ordering::SeqCst), 0);
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        assert!(state["requests"].as_array().unwrap().is_empty());
    }
    let rejected_cli = std::process::Command::new(env!("CARGO_BIN_EXE_vw-access"))
        .args([
            "--state-root",
            root.to_str().unwrap(),
            "request",
            "deploy",
            "--",
            "forbidden-target-sentinel",
            "3",
        ])
        .output()
        .unwrap();
    assert!(!rejected_cli.status.success());
    assert!(rejected_cli.stdout.is_empty());
    assert_eq!(
        String::from_utf8(rejected_cli.stderr).unwrap(),
        "vw-access: invalid request\n"
    );
    assert_eq!(launcher.0.load(Ordering::SeqCst), 0);
    let HumanResponse::Submitted { receipt } = exchange(
        &root,
        HumanCommand::Request {
            submission: input(),
        },
    )
    .unwrap() else {
        panic!("expected accepted receipt")
    };
    assert_eq!(receipt.status, DirectStatus::Pending);
    assert_eq!(launcher.0.load(Ordering::SeqCst), 1);
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .tls_certs_only([reqwest::Certificate::from_pem(include_bytes!(
            "fixtures/provider-tls/ca.pem"
        ))
        .unwrap()])
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let launch = client
        .post(format!("{base}/launch"))
        .header("Origin", &base)
        .header("Content-Type", "text/plain")
        .body(cap.clone())
        .send()
        .unwrap();
    let cookie = launch.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let proof = launch.text().unwrap();
    let review_body = serde_json::json!({"request_id":receipt.id}).to_string();
    for case in ["cookie", "csrf", "origin", "host", "unknown_field"] {
        let request = client
            .post(format!("{base}/review"))
            .header(
                "Origin",
                if case == "origin" {
                    "https://evil.invalid"
                } else {
                    &base
                },
            )
            .header(
                "Host",
                if case == "host" {
                    "evil.invalid"
                } else {
                    base.strip_prefix("https://").unwrap()
                },
            )
            .header(
                "Cookie",
                if case == "cookie" {
                    "vw_session=wrong"
                } else {
                    &cookie
                },
            )
            .header("Content-Type", "application/json");
        let request = if case == "csrf" {
            request
        } else {
            request.header("X-CSRF-Token", &proof)
        };
        let body = if case == "unknown_field" {
            serde_json::json!({"request_id":receipt.id,"identity":"sentinel"}).to_string()
        } else {
            review_body.clone()
        };
        let response = request.body(body).send().unwrap();
        assert_eq!(response.status().as_u16(), 403, "{case}");
        assert!(!response.text().unwrap().contains("sentinel"));
    }
    let review = || {
        client
            .post(format!("{base}/review"))
            .header("Origin", &base)
            .header("Cookie", &cookie)
            .header("X-CSRF-Token", &proof)
            .header("Content-Type", "application/json")
            .body(review_body.clone())
            .send()
            .unwrap()
    };
    let r: DirectReview = review().json().unwrap();
    assert_eq!(r.arguments, vec!["staging", "3"]);
    assert_eq!(r.policy_digest, revision);
    assert_eq!(r.status, DirectStatus::Pending);
    let raw = serde_json::to_string(&r).unwrap();
    assert!(!raw.contains("DEPLOY_PASSWORD"));
    assert!(!raw.contains("11111111-1111-1111-1111-111111111111"));
    let page = client
        .get(format!("{base}/"))
        .header("Cookie", &cookie)
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(!page.contains(&receipt.id));
    assert!(!page.contains(&proof));
    assert!(!page.contains("Deploy <script>sentinel"));
    // --no-wait must return while the request remains pending.
    let mut immediate = std::process::Command::new(env!("CARGO_BIN_EXE_vw-access"))
        .args([
            "--state-root",
            root.to_str().unwrap(),
            "request",
            "deploy",
            "--no-wait",
            "--",
            "staging",
            "3",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let limit = std::time::Instant::now() + Duration::from_secs(3);
    let mut returned = false;
    while std::time::Instant::now() < limit {
        if immediate.try_wait().unwrap().is_some() {
            returned = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !returned {
        let _ignored = immediate.kill();
    }
    let immediate = immediate.wait_with_output().unwrap();
    assert!(returned, "--no-wait must not poll a pending request");
    assert!(immediate.status.success());
    assert!(immediate.stderr.is_empty());
    let HumanResponse::Submitted {
        receipt: denied_receipt,
    } = serde_json::from_slice::<HumanResponse>(&immediate.stdout).unwrap()
    else {
        panic!("receipt")
    };
    for (path, id) in [("/approve", &receipt.id), ("/deny", &denied_receipt.id)] {
        let body = if path == "/approve" {
            serde_json::json!({"request_id":id,"password":"approval-secret-sentinel"})
        } else {
            serde_json::json!({"request_id":id})
        };
        let send = || {
            client
                .post(format!("{base}{path}"))
                .header("Origin", &base)
                .header("Cookie", &cookie)
                .header("X-CSRF-Token", &proof)
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .send()
                .unwrap()
        };
        assert_eq!(send().status().as_u16(), 200);
        assert_eq!(send().status().as_u16(), 403);
        let observed = exchange(&root, HumanCommand::Status { id: id.clone() }).unwrap();
        assert!(
            matches!(observed, HumanResponse::Status { state } if state == if path == "/approve" {DirectStatus::Approved} else {DirectStatus::Denied})
        );
        assert!(
            !std::fs::read_to_string(&state_path)
                .unwrap()
                .contains("approval-secret-sentinel")
        );
    }
    // The real CLI emits its durable receipt, then waits without resubmission.
    use std::io::BufRead;
    let mut waiting = std::process::Command::new(env!("CARGO_BIN_EXE_vw-access"))
        .args([
            "--state-root",
            root.to_str().unwrap(),
            "request",
            "deploy",
            "--",
            "staging",
            "3",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = waiting.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            if send.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let first = receive.recv_timeout(Duration::from_secs(5));
    if first.is_err() {
        let _ignored = waiting.kill();
    }
    let first: HumanResponse = serde_json::from_str(&first.unwrap()).unwrap();
    assert!(matches!(first, HumanResponse::Submitted { .. }));
    assert!(waiting.try_wait().unwrap().is_none());
    assert_eq!(launcher.0.load(Ordering::SeqCst), 3);
    clock.store(300, Ordering::SeqCst);
    app.status().unwrap();
    assert!(matches!(
        exchange(
            &root,
            HumanCommand::Status {
                id: receipt.id.clone()
            }
        )
        .unwrap(),
        HumanResponse::Status {
            state: DirectStatus::Expired
        }
    ));
    let terminal = receive.recv_timeout(Duration::from_secs(5));
    if terminal.is_err() {
        let _ignored = waiting.kill();
    }
    assert!(matches!(
        serde_json::from_str::<HumanResponse>(&terminal.unwrap()).unwrap(),
        HumanResponse::Status {
            state: DirectStatus::Expired
        }
    ));
    assert!(waiting.wait().unwrap().success());
    reader.join().unwrap();
    assert_eq!(launcher.0.load(Ordering::SeqCst), 3);
    app.lock().unwrap();
    let r: DirectReview = review().json().unwrap();
    assert_eq!(r.status, DirectStatus::Expired);
    assert_eq!(
        client
            .post(format!("{base}/launch"))
            .header("Origin", &base)
            .header("Content-Type", "text/plain")
            .body(cap)
            .send()
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    stop.store(true, Ordering::Release);
    human.join().unwrap().unwrap();
    browser.join().unwrap().unwrap();
    assert!(!root.join("human.sock").exists());
}
