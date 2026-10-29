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
