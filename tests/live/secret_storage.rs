//! Disposable Vaultwarden 1.36.0 roundtrip using production encryption/API paths.
use crate::live_env::LiveTestEnv;
use vaultwarden_cli::{api::ApiClient, secret_storage::*};

#[tokio::test]
async fn create_and_select_each_secret_representation_verbatim() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    let tokens: serde_json::Value =
        serde_json::from_slice(&std::fs::read(env.config_dir.join("tokens.json")).unwrap())
            .unwrap();
    let token = tokens["access_token"].as_str().unwrap();
    let api = ApiClient::new_with_flags(&env.server_url, true).unwrap();
    let sync = api.sync(token).await.unwrap();
    let folder_label = "homelab/production";
    let response: serde_json::Value = reqwest::Client::new()
        .post(format!("{}/api/folders", env.server_url))
        .bearer_auth(token)
        .json(&serde_json::json!({"name": env.user_keys.encrypt(folder_label.as_bytes()).unwrap()}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let folder_id = response["id"]
        .as_str()
        .or_else(|| response["Id"].as_str())
        .unwrap();
    for (index,json) in [
        r#"{"password":"  storage-sentinel\n🔐\u0000"}"#,
        r#"{"fields":[{"name":"api-key","value":"first\nsecond\n"}]}"#,
        r#"{"password":"token","notes":"notes\r\n","fields":[{"name":"related","value":"  exact  "}]}"#,
    ].iter().enumerate() {
        let input = SecretImport::parse(json.as_bytes()).unwrap();
        let destination = Destination { account_id:sync.profile.id.to_string(), folder:folder_label.into(), folder_id:folder_id.into(), reference:format!("{folder_label}/github/secret-{index}") };
        destination.check_sync(&api.sync(token).await.unwrap(),&env.user_keys,true).unwrap();
        let encrypted = encrypt_create(&env.user_keys,&destination,&input,None).unwrap();
        let wire = serde_json::to_string(&encrypted).unwrap();
        assert!(!wire.contains("storage-sentinel"));
        let created = api.create_cipher(token,&encrypted).await.unwrap();
        let fetched = api.cipher_by_id(token,created.id.as_str()).await.unwrap();
        verify_created(&env.user_keys,&destination,created.id.as_str(),&fetched,&input,None).unwrap();
        for selector in input.selectors() {
            let keys = env.user_keys.item_keys(fetched.item_key.as_deref()).unwrap();
            let expected = selected_value(&fetched,&keys,&selector).unwrap();
            let output = env.binary().args(["read-field","--id",created.id.as_str(),"--field",&selector]).output().unwrap();
            assert!(output.status.success(), "selected CLI read failed");
            assert_eq!(output.stdout,expected.as_bytes());
        }
        assert!(destination.check_sync(&api.sync(token).await.unwrap(),&env.user_keys,true).is_err());
    }
}

/// A controlling terminal is required for the one-attempt human decision;
/// stdin remains a separate bounded secret channel throughout this test.
#[cfg(target_os = "linux")]
fn terminal_import(
    env: &LiveTestEnv,
    account: &str,
    reference: &str,
    approve: bool,
) -> (std::process::Output, String) {
    use std::{
        fs::File,
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::process::CommandExt,
        },
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let mut master = -1;
    let mut slave = -1;
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    let mut master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    assert_eq!(
        unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
        0
    );
    let isolated = env.binary();
    let mut command = Command::new(isolated.get_program());
    command.env_clear();
    for (name, value) in isolated.get_envs() {
        if let Some(value) = value {
            command.env(name, value);
        }
    }
    command
        .args([
            "create",
            "--account",
            account,
            "--folder",
            "homelab/production",
            "--reference",
            reference,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // The controlling terminal remains separate even when stderr is redirected.
    let terminal_fd = slave.as_raw_fd();
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 || libc::ioctl(terminal_fd, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(br#"{"password":"terminal-private-sentinel\n","fields":[{"name":"token","value":" related "}]}"#).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut transcript = Vec::new();
    let mut answered = false;
    loop {
        let mut buffer = [0u8; 4096];
        match master.read(&mut buffer) {
            Ok(n) => transcript.extend_from_slice(&buffer[..n]),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.raw_os_error() == Some(libc::EIO) => {}
            Err(error) => panic!("terminal read failed: {error}"),
        }
        let text = String::from_utf8_lossy(&transcript);
        if !answered && text.contains("Authorize this single attempt") && text.ends_with(": ") {
            let challenge = text
                .split("typing '")
                .nth(1)
                .unwrap()
                .split('\'')
                .next()
                .unwrap();
            let answer = if approve { challenge } else { "deny" };
            master.write_all(format!("{answer}\n").as_bytes()).unwrap();
            answered = true;
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("terminal import timed out");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(answered, "terminal decision was never presented");
    (
        child.wait_with_output().unwrap(),
        String::from_utf8(transcript).unwrap(),
    )
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn trusted_cli_uses_fresh_terminal_authorization_and_durable_receipt() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    let tokens: serde_json::Value =
        serde_json::from_slice(&std::fs::read(env.config_dir.join("tokens.json")).unwrap())
            .unwrap();
    let token = tokens["access_token"].as_str().unwrap();
    let api = ApiClient::new_with_flags(&env.server_url, true).unwrap();
    let account = api.sync(token).await.unwrap().profile.id.to_string();
    let response = reqwest::Client::new()
        .post(format!("{}/api/folders", env.server_url))
        .bearer_auth(token)
        .json(&serde_json::json!({"name": env.user_keys.encrypt(b"homelab/production").unwrap()}))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let before = api.sync(token).await.unwrap().ciphers.len();
    let (denied, review) =
        terminal_import(&env, &account, "homelab/production/github/denied", false);
    assert!(!denied.status.success());
    assert!(!review.contains("terminal-private-sentinel"));
    assert_eq!(api.sync(token).await.unwrap().ciphers.len(), before);
    let (created, review) =
        terminal_import(&env, &account, "homelab/production/github/approved", true);
    assert!(created.status.success(), "authorized import failed");
    assert!(review.contains("CREATE personal vault item") && review.contains("custom:token"));
    assert!(!review.contains("terminal-private-sentinel"));
    assert!(!String::from_utf8_lossy(&created.stderr).contains("CREATE personal vault item"));
    let receipt: WriteReceipt = serde_json::from_slice(&created.stdout).unwrap();
    assert_eq!(receipt.status, WriteStatus::Verified);
    let id = receipt.item_id.unwrap();
    let output = env
        .binary()
        .args(["read-field", "--id", &id, "--field", "password"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"terminal-private-sentinel\n");
    let journals = std::fs::read_dir(env.config_dir.join("write-attempts"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(journals.len(), 1);
    let journal = std::fs::read(journals[0].path()).unwrap();
    assert!(!String::from_utf8_lossy(&journal).contains("terminal-private-sentinel"));
    let recovery = env
        .binary()
        .args([
            "reconcile",
            "--journal",
            journals[0].path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(recovery.status.success());
    assert_eq!(
        serde_json::from_slice::<WriteReceipt>(&recovery.stdout)
            .unwrap()
            .status,
        WriteStatus::Verified
    );
    let journal_path = journals[0].path();
    let mut uncertain: vaultwarden_cli::write_journal::WriteJournal =
        serde_json::from_slice(&journal).unwrap();
    uncertain.receipt.status = WriteStatus::Uncertain;
    uncertain.receipt.item_id = None;
    uncertain.save(&journal_path).unwrap();
    let recovery = env
        .binary()
        .args([
            "reconcile",
            "--journal",
            journal_path.to_str().unwrap(),
            "--id",
            &id,
        ])
        .output()
        .unwrap();
    assert!(recovery.status.success());
    let recovered: WriteReceipt = serde_json::from_slice(&recovery.stdout).unwrap();
    assert_eq!(recovered.status, WriteStatus::CreatedUnverified);
    assert_eq!(recovered.item_id.as_deref(), Some(id.as_str()));
    assert_eq!(
        vaultwarden_cli::write_journal::WriteJournal::read(&journal_path)
            .unwrap()
            .receipt,
        recovered
    );
    let retarget = env
        .binary()
        .args([
            "reconcile",
            "--journal",
            journal_path.to_str().unwrap(),
            "--id",
            "44444444-4444-4444-4444-444444444444",
        ])
        .output()
        .unwrap();
    assert!(!retarget.status.success());
    assert_eq!(
        vaultwarden_cli::write_journal::WriteJournal::read(&journal_path)
            .unwrap()
            .receipt,
        recovered
    );
    assert_eq!(api.sync(token).await.unwrap().ciphers.len(), before + 1);
}
