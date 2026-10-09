//! Real Unix + trusted HTTPS boundaries with a synthetic backend; no real account.
#![cfg(target_os = "linux")]
#[path = "support/ssh_policy.rs"]
mod ssh_policy;

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
    fn ssh_eligible(&mut self, _: &str) -> Result<bool, SessionError> {
        Ok(true)
    }
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

fn provisioning_cli(root: &std::path::Path, args: &[&str]) -> HumanResponse {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vw-access"))
        .arg("--state-root")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

fn rejected_provisioning_cli(root: &std::path::Path, args: &[&str], diagnostic: &'static str) {
    assert_cmd::Command::new(env!("CARGO_BIN_EXE_vw-access"))
        .timeout(Duration::from_secs(5))
        .arg("--state-root")
        .arg(root)
        .args(args)
        .assert()
        .failure()
        .stdout("")
        .stderr(diagnostic);
}

#[test]
fn cli_provisioning_restart_retains_revision_and_agent_approval() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    use vaultwarden_cli::access::{agent_binding::AgentPairing, protocol::SignedSubmission};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("provider");
    let image_path = dir.path().join("image");
    let mut bytes = vec![0u8; 120];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    #[cfg(target_arch = "x86_64")]
    let (machine, code) = (
        62u16,
        include_bytes!("fixtures/protected-exit-x86_64.bin").as_slice(),
    );
    #[cfg(target_arch = "aarch64")]
    let (machine, code) = (
        183u16,
        include_bytes!("fixtures/protected-exit-aarch64.bin").as_slice(),
    );
    bytes[18..20].copy_from_slice(&machine.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x400078u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
    bytes[72..80].copy_from_slice(&120u64.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400078u64.to_le_bytes());
    bytes[88..96].copy_from_slice(&0x400078u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&(code.len() as u64).to_le_bytes());
    bytes[104..112].copy_from_slice(&(code.len() as u64).to_le_bytes());
    bytes[112..120].copy_from_slice(&4096u64.to_le_bytes());
    bytes.extend_from_slice(code);
    std::fs::write(&image_path, &bytes).unwrap();
    std::fs::set_permissions(&image_path, std::fs::Permissions::from_mode(0o500)).unwrap();
    let digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let clock = Arc::new(AtomicU64::new(0));
    let make_app = || {
        Arc::new(
            ProviderApplication::new(
                Provider::start(&root).unwrap(),
                Box::new(Backend),
                Box::new(Clock(clock.clone())),
            )
            .unwrap(),
        )
    };
    let app = make_app();
    app.authenticate(SensitiveString::new("synthetic".into()))
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let launcher = Arc::new(Launcher(AtomicUsize::new(0)));
    let socket = HumanSocket::bind(&root).unwrap();
    let server = {
        let app = app.clone();
        let stop = stop.clone();
        let launcher = launcher.clone();
        std::thread::spawn(move || socket.serve(app, launcher, stop))
    };
    let image_args = [
        "image",
        "register",
        "--id",
        "test-image",
        "--execution-root",
        dir.path().to_str().unwrap(),
        "--path",
        image_path.to_str().unwrap(),
        "--sha256",
        &digest,
        "--profile",
        "reviewed_self_contained_elf64_v1",
    ];
    provisioning_cli(&root, &image_args);
    rejected_provisioning_cli(
        &root,
        &image_args,
        "vw-access: record already exists; use show to reconcile\n",
    );
    let mut policy = ssh_policy::draft("test-image");
    policy.description = "sentinel-secret-description".into();
    let path = dir.path().join("policy.json");
    std::fs::write(&path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let HumanResponse::OperationCreated { operation } = provisioning_cli(
        &root,
        &["operation", "create", "--file", path.to_str().unwrap()],
    ) else {
        panic!("missing creation")
    };
    rejected_provisioning_cli(
        &root,
        &["operation", "create", "--file", path.to_str().unwrap()],
        "vw-access: record already exists; use show to reconcile\n",
    );
    // Commit a second operation but discard the original socket response. A
    // separate inspection proves commit before the response-bearing stream drops.
    let mut lost_policy = policy.clone();
    lost_policy.id = "lost-response".into();
    let lost_path = dir.path().join("sentinel-secret-lost-policy.json");
    std::fs::write(&lost_path, serde_json::to_vec(&lost_policy).unwrap()).unwrap();
    use std::io::Write;
    let mut lost_stream = std::os::unix::net::UnixStream::connect(root.join("human.sock")).unwrap();
    lost_stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    lost_stream
        .write_all(
            &serde_json::to_vec(&vaultwarden_cli::adapters::human_socket::HumanMessage {
                version: 1,
                command: HumanCommand::OperationCreate {
                    policy: Box::new(lost_policy),
                },
            })
            .unwrap(),
        )
        .unwrap();
    lost_stream.shutdown(std::net::Shutdown::Write).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let lost_record = loop {
        match exchange(
            &root,
            HumanCommand::OperationShow {
                id: "lost-response".into(),
            },
        )
        .unwrap()
        {
            HumanResponse::Operation { operation } => break operation,
            HumanResponse::ProvisioningRejected {
                reason: vaultwarden_cli::access::provisioning::ProvisioningError::NotFound,
            } => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "lost-response write did not commit"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            other => panic!("unexpected reconciliation response: {other:?}"),
        }
    };
    drop(lost_stream);
    let key = ed25519_dalek::SigningKey::from_bytes(&[73; 32]);
    let uid = unsafe { libc::geteuid() }.wrapping_add(1);
    let HumanResponse::AgentPaired { agent: binding } = exchange(
        &root,
        HumanCommand::AgentPair {
            pairing: AgentPairing {
                label: "synthetic".into(),
                public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
                uid,
                gid: 42001,
            },
        },
    )
    .unwrap() else {
        panic!("pairing failed")
    };
    stop.store(true, Ordering::Release);
    server.join().unwrap().unwrap();
    drop(app);
    let app = make_app();
    let stop = Arc::new(AtomicBool::new(false));
    let socket = HumanSocket::bind(&root).unwrap();
    let server = {
        let app = app.clone();
        let stop = stop.clone();
        let launcher = launcher.clone();
        std::thread::spawn(move || socket.serve(app, launcher, stop))
    };
    let HumanResponse::Operation {
        operation: observed,
    } = provisioning_cli(&root, &["operation", "show", "ssh-backup"])
    else {
        panic!("missing operation")
    };
    assert_eq!(observed.revision, operation.revision);
    assert!(
        matches!(provisioning_cli(&root, &["image", "list"]), HumanResponse::Images { images } if images.len() == 1)
    );
    assert!(
        matches!(provisioning_cli(&root, &["operation", "list"]), HumanResponse::Operations { operations } if operations.len() == 2 && operations.contains(&operation) && operations.iter().any(|entry| entry.id == "lost-response" && entry.revision == lost_record.revision))
    );
    assert!(
        matches!(provisioning_cli(&root, &["image", "show", "test-image"]), HumanResponse::Image { image } if image.sha256 == digest)
    );
    assert!(
        matches!(provisioning_cli(&root, &["operation", "show", "lost-response"]), HumanResponse::Operation { operation } if operation == lost_record)
    );
    rejected_provisioning_cli(&root, &image_args, "vw-access: provider locked\n");
    rejected_provisioning_cli(
        &root,
        &["operation", "create", "--file", path.to_str().unwrap()],
        "vw-access: provider locked\n",
    );
    app.authenticate(SensitiveString::new("synthetic".into()))
        .unwrap();
    rejected_provisioning_cli(
        &root,
        &["operation", "create", "--file", lost_path.to_str().unwrap()],
        "vw-access: record already exists; use show to reconcile\n",
    );
    let signed = SignedSubmission::sign(
        binding.id,
        [42; 32],
        "ssh-backup".into(),
        operation.revision,
        vec![],
        &key,
    )
    .unwrap();
    let receipt = app
        .submit_signed(uid, &[42001], signed, launcher.as_ref())
        .unwrap();
    assert!(matches!(
        exchange(&root, HumanCommand::Status { id: receipt }).unwrap(),
        HumanResponse::Status {
            state: DirectStatus::Pending
        }
    ));
    assert_eq!(launcher.0.load(Ordering::SeqCst), 1);
    stop.store(true, Ordering::Release);
    server.join().unwrap().unwrap();
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
    let bytes: &[u8] = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00\x01\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x40\x00\x00\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x78\x00\x00\x00\x00\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\xb8\x3c\x00\x00\x00\xbf\x00\x00\x00\x00\x0f\x05";
    #[cfg(target_arch = "aarch64")]
    let native_bytes = {
        let mut native = bytes.to_vec();
        native[18..20].copy_from_slice(&183u16.to_le_bytes());
        // mov x0, #0; mov x8, #93; svc #0 (native Linux exit(0)).
        native[120..132].copy_from_slice(&[
            0x00, 0x00, 0x80, 0xd2, 0xa8, 0x0b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
        ]);
        native
    };
    #[cfg(target_arch = "aarch64")]
    let bytes = native_bytes.as_slice();
    std::fs::write(&image, bytes).unwrap();
    std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o500)).unwrap();
    use sha2::Digest;
    let digest: String = sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let state_path = root.join("provider-state.json");
    let policy = OperationPolicyDraft {
        ssh: None,
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
    };
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
    let registered = provisioning_cli(
        &root,
        &[
            "image",
            "register",
            "--id",
            "test-image",
            "--execution-root",
            dir.path().to_str().unwrap(),
            "--path",
            image.to_str().unwrap(),
            "--sha256",
            &digest,
            "--profile",
            "reviewed_self_contained_elf64_v1",
        ],
    );
    assert!(matches!(registered, HumanResponse::ImageRegistered { .. }));
    let policy_file = dir.path().join("policy.json");
    std::fs::write(&policy_file, serde_json::to_vec(&policy).unwrap()).unwrap();
    let HumanResponse::OperationCreated { operation } = provisioning_cli(
        &root,
        &[
            "operation",
            "create",
            "--file",
            policy_file.to_str().unwrap(),
        ],
    ) else {
        panic!("creation rejected")
    };
    let revision = operation.revision;
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
    let HumanResponse::OperationCreated { operation } = exchange(
        &root,
        HumanCommand::OperationCreate {
            policy: Box::new(ssh_policy::draft("test-image")),
        },
    )
    .unwrap() else {
        panic!("SSH creation failed")
    };
    let ssh_revision = operation.revision;
    for values in [
        vec!["--host=other".into()],
        vec!["--key=/tmp/private-key-sentinel".into()],
    ] {
        let response = exchange(
            &root,
            HumanCommand::Request {
                submission: DirectSubmission {
                    operation: "ssh-backup".into(),
                    revision: Some(ssh_revision.clone()),
                    values,
                },
            },
        )
        .unwrap();
        assert!(matches!(
            response,
            HumanResponse::Rejected {
                reason: DirectRequestError::InvalidRequest
            }
        ));
        assert_eq!(launcher.0.load(Ordering::SeqCst), 3);
    }
    let response = exchange(
        &root,
        HumanCommand::Request {
            submission: DirectSubmission {
                operation: "ssh-backup".into(),
                revision: Some(ssh_revision),
                values: vec![],
            },
        },
    )
    .unwrap();
    let HumanResponse::Submitted {
        receipt: ssh_receipt,
    } = response
    else {
        panic!("SSH fixed policy should admit")
    };
    let stored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    let ssh_review: DirectReview = serde_json::from_value(
        stored["requests"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == ssh_receipt.id)
            .unwrap()["direct"]["review"]
            .clone(),
    )
    .unwrap();
    assert_eq!(
        ssh_review.target,
        "backup@backup.example.test:2222/srv/archive"
    );
    assert_eq!(ssh_review.credentials[0].use_type, CredentialUse::Ssh);
    assert_eq!(
        ssh_review.one_time,
        "Approval authorizes one protected execution. Lock or cancellation stops its descendants."
    );
    let visible = serde_json::to_string(&ssh_review).unwrap();
    for forbidden in [
        "private-key-sentinel",
        "SSH_AUTH_SOCK",
        "known_hosts",
        "IdentityFile",
        "item_id",
        "11111111",
        "field_mappings",
    ] {
        assert!(!visible.contains(forbidden));
    }
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
