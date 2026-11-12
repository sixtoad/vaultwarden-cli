//! Native subprocess smoke tests restricted to paths that cannot open Keychain or
//! installed identity state: help, parser rejection and invalid local seed input.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::process::Command;
fn isolated(binary: &str, root: &std::path::Path) -> Command {
    let mut command = Command::new(binary);
    command
        .env_clear()
        .env("HOME", root)
        .env("TMPDIR", root)
        .current_dir(root);
    command
}
#[test]
fn native_protected_binary_help_and_invalid_startup_do_not_create_state() {
    let root = tempfile::tempdir().unwrap();
    for binary in [
        env!("CARGO_BIN_EXE_vaultwarden-accessd"),
        env!("CARGO_BIN_EXE_vw-access"),
    ] {
        let output = isolated(binary, root.path())
            .arg("--help")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("--state-root"));
    }
    let output = isolated(env!("CARGO_BIN_EXE_vaultwarden-accessd"), root.path())
        .args([
            "--state-root",
            "uncreated-state",
            "--request-lifetime-seconds",
            "0",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!root.path().join("uncreated-state").exists());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
#[test]
fn native_agent_cli_rejects_bad_relative_seed_without_echo_or_provider_connection() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let seed = root.path().join("seed");
    std::fs::write(&seed, b"synthetic-short-seed").unwrap();
    std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = isolated(env!("CARGO_BIN_EXE_vw-access"), root.path())
        .args([
            "submit",
            "synthetic-op",
            "--socket",
            "missing.sock",
            "--key-file",
            "seed",
            "--binding-id",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--revision",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!all.contains("synthetic-short-seed"));
    assert!(!all.contains("synthetic-op"));
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}

fn private_root() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}
fn run_with_stdin(mut command: Command, input: &[u8]) -> std::process::Output {
    use std::io::Write;
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn native_bootstrap_secret_goes_to_the_private_state_file_store_from_stdin_only() {
    use std::os::unix::fs::MetadataExt;
    let root = private_root();
    let state = root.path().join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let mut command = isolated(env!("CARGO_BIN_EXE_vaultwarden-accessd"), root.path());
    command
        .arg("--state-root")
        .arg(&state)
        .arg("--store-bootstrap-secret");
    let output = run_with_stdin(command, b"client-secret-sentinel\n");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for stream in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(stream).contains("client-secret-sentinel"));
    }
    let record = state.join("secrets/vaultwarden-accessd.bootstrap-client-secret");
    assert_eq!(
        std::fs::read_to_string(&record).unwrap(),
        "client-secret-sentinel"
    );
    let metadata = std::fs::symlink_metadata(&record).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(
        std::fs::symlink_metadata(state.join("secrets"))
            .unwrap()
            .mode()
            & 0o7777,
        0o700
    );
    // Empty or multi-line input is refused; the stored secret is unchanged.
    for input in [&b""[..], b"\n", b"one\ntwo\n"] {
        let mut command = isolated(env!("CARGO_BIN_EXE_vaultwarden-accessd"), root.path());
        command
            .arg("--state-root")
            .arg(&state)
            .arg("--store-bootstrap-secret");
        assert!(!run_with_stdin(command, input).status.success());
    }
    assert_eq!(
        std::fs::read_to_string(&record).unwrap(),
        "client-secret-sentinel"
    );
    // An unsafe state root is refused before anything is written.
    let unsafe_state = root.path().join("unsafe");
    std::fs::create_dir(&unsafe_state).unwrap();
    std::fs::set_permissions(
        &unsafe_state,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let mut command = isolated(env!("CARGO_BIN_EXE_vaultwarden-accessd"), root.path());
    command
        .arg("--state-root")
        .arg(&unsafe_state)
        .arg("--store-bootstrap-secret");
    let output = run_with_stdin(command, b"secret-sentinel\n");
    assert!(!output.status.success());
    assert_eq!(std::fs::read_dir(&unsafe_state).unwrap().count(), 0);
    // The failure names its class (never the secret), not a bare "unavailable".
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot store the bootstrap secret")
            && stderr.contains("state directory must be mode 0700"),
        "{stderr}"
    );
    assert!(!stderr.contains("secret-sentinel"));
}

#[test]
fn native_vw_access_without_installed_endpoint_names_the_identity_record() {
    let identities = std::path::Path::new("/Library/VaultwardenAccess/native-identities.json");
    if identities.exists() {
        // An installed provider makes the default resolvable; nothing to check here.
        return;
    }
    let root = private_root();
    let output = isolated(env!("CARGO_BIN_EXE_vw-access"), root.path())
        .args(["history", "--limit", "1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "vw-access: no installed endpoint found at \
         /Library/VaultwardenAccess/native-identities.json; pass --state-root\n"
    );
}

#[test]
fn native_setup_commands_write_private_outputs_without_provider_state() {
    use std::os::unix::fs::MetadataExt;
    let root = private_root();
    let vw = env!("CARGO_BIN_EXE_vw-access");
    let key = root.path().join("agent.key");
    let output = isolated(vw, root.path())
        .args(["setup", "agent-key", "--out"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(output.status.success());
    let public = String::from_utf8(output.stdout).unwrap();
    assert_eq!(public.trim().len(), 43);
    assert_eq!(std::fs::metadata(&key).unwrap().mode() & 0o7777, 0o600);
    assert_eq!(std::fs::metadata(&key).unwrap().len(), 32);
    let again = isolated(vw, root.path())
        .args(["setup", "agent-key", "--out"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(!again.status.success());
    let backend = root.path().join("backend.json");
    let output = isolated(vw, root.path())
        .args([
            "setup",
            "backend-json",
            "--server",
            "https://vault.example.test",
            "--email",
            "human@example.test",
            "--client-id",
            "user.0000",
            "--encrypted-key",
            "2.aXY=|ZGF0YQ==|bWFj",
            "--kdf-iterations",
            "600000",
            "--out",
        ])
        .arg(&backend)
        .output()
        .unwrap();
    // The KDF cannot be read from a CLI login: it must be stated explicitly.
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--kdf pbkdf2 is required"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!backend.exists());
    let argon = isolated(vw, root.path())
        .args([
            "setup",
            "backend-json",
            "--server",
            "https://vault.example.test",
            "--email",
            "human@example.test",
            "--client-id",
            "user.0000",
            "--encrypted-key",
            "2.aXY=|ZGF0YQ==|bWFj",
            "--kdf",
            "argon2id",
            "--kdf-iterations",
            "3",
            "--out",
        ])
        .arg(&backend)
        .output()
        .unwrap();
    assert!(!argon.status.success());
    assert!(
        String::from_utf8_lossy(&argon.stderr).contains("Argon2id accounts are not supported"),
        "{}",
        String::from_utf8_lossy(&argon.stderr)
    );
    assert!(!backend.exists());
    let output = isolated(vw, root.path())
        .args([
            "setup",
            "backend-json",
            "--server",
            "https://vault.example.test",
            "--email",
            "human@example.test",
            "--client-id",
            "user.0000",
            "--encrypted-key",
            "2.aXY=|ZGF0YQ==|bWFj",
            "--kdf",
            "pbkdf2",
            "--kdf-iterations",
            "600000",
            "--out",
        ])
        .arg(&backend)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::metadata(&backend).unwrap().mode() & 0o7777, 0o600);
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&backend).unwrap()).unwrap();
    assert_eq!(value["server"], "https://vault.example.test/");
    // A relative --out resolves against the current directory.
    let output = isolated(vw, root.path())
        .args([
            "setup",
            "backend-json",
            "--server",
            "https://vault.example.test",
            "--email",
            "human@example.test",
            "--client-id",
            "user.0000",
            "--encrypted-key",
            "2.aXY=|ZGF0YQ==|bWFj",
            "--kdf",
            "pbkdf2",
            "--kdf-iterations",
            "600000",
            "--out",
            "relative.json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let relative = root.path().join("relative.json");
    assert_eq!(std::fs::metadata(&relative).unwrap().mode() & 0o7777, 0o600);
    let rejected = root.path().join("rejected.json");
    let output = isolated(vw, root.path())
        .args([
            "setup",
            "backend-json",
            "--server",
            "http://vault.example.test",
            "--out",
        ])
        .arg(&rejected)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!rejected.exists());
}
