//! Real process checks: parser errors cannot reflect terminal-provided values.
#![cfg(target_os = "linux")]

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn agent_commands_send_exact_identity_fields_and_print_only_safe_views() {
    use std::{
        fs,
        io::{Read, Write},
        net::Shutdown,
        os::unix::{fs::PermissionsExt, net::UnixListener},
    };
    let key = "-public-verification-bytes-sentinel";
    let id = "-binding-id-sentinel";
    let label = "-builder";
    let view = serde_json::json!({"id":id,"label":label,"fingerprint":"a".repeat(64),"uid":42001,"gid":42003,"status":"enabled"});
    let mut revoked = view.clone();
    revoked["status"] = "revoked".into();
    for (arguments, expected, response) in [
        (
            vec![
                "agent",
                "pair",
                label,
                "--public-key",
                key,
                "--uid",
                "42001",
                "--gid",
                "42003",
            ],
            serde_json::json!({"kind":"agent_pair","pairing":{"label":label,"public_key":key,"uid":42001,"gid":42003}}),
            serde_json::json!({"result":"agent_paired","agent":view}),
        ),
        (
            vec!["agent", "list"],
            serde_json::json!({"kind":"agent_list"}),
            serde_json::json!({"result":"agents","agents":[view]}),
        ),
        (
            vec!["agent", "revoke", id],
            serde_json::json!({"kind":"agent_revoke","id":id}),
            serde_json::json!({"result":"agent_revoked","agent":revoked}),
        ),
        (
            vec!["status", id],
            serde_json::json!({"kind":"status","id":id}),
            serde_json::json!({"result":"status","state":{"status":"pending"}}),
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("human.sock");
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let encoded = serde_json::to_vec(&response).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                serde_json::json!({"version":1,"command":expected})
            );
            stream.write_all(&encoded).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });
        let result = Command::new(assert_cmd::cargo::cargo_bin!("vw-access"))
            .arg("--state-root")
            .arg(directory.path())
            .args(arguments)
            .assert()
            .success()
            .stderr("");
        let output = String::from_utf8(result.get_output().stdout.clone()).unwrap();
        server.join().unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&output).unwrap(),
            response
        );
        assert!(!output.contains(key));
        assert!(!output.contains("public_key"));
    }
}

#[test]
fn agent_parser_failures_are_redacted_and_help_describes_identity_not_authority() {
    for arguments in [
        vec![
            "agent",
            "pair",
            "private-sentinel",
            "--public-key",
            "private-sentinel",
            "--uid",
            "4294967296",
            "--gid",
            "42003",
        ],
        vec![
            "agent",
            "pair",
            "private-sentinel",
            "--public-key",
            "private-sentinel",
            "--uid",
            "42001",
        ],
        vec![
            "agent",
            "pair",
            "private-sentinel",
            "--public-key",
            "private-sentinel",
            "--uid",
            "42001",
            "--gid",
            "-1",
        ],
        vec!["agent", "list", "--uid", "private-sentinel"],
        vec![
            "agent",
            "revoke",
            "private-sentinel",
            "--label",
            "private-sentinel",
        ],
    ] {
        Command::new(assert_cmd::cargo::cargo_bin!("vw-access"))
            .args(["--state-root", "/private"])
            .args(arguments)
            .assert()
            .code(2)
            .stdout("")
            .stderr("vw-access: invalid command; use --help\n");
    }
    Command::new(assert_cmd::cargo::cargo_bin!("vw-access"))
        .args(["agent", "pair", "private-sentinel", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--public-key"))
        .stdout(predicate::str::contains("--uid"))
        .stdout(predicate::str::contains("--gid"))
        .stdout(predicate::str::contains("private-sentinel").not());
    Command::new(assert_cmd::cargo::cargo_bin!("vw-access"))
        .args(["agent", "revoke", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("<ID>"));
}
#[test]
fn parser_failure_and_help_do_not_echo_rejected_values() {
    for args in [
        vec![
            "--state-root",
            "/private",
            "request",
            "deploy",
            "--invalid-private-sentinel",
        ],
        vec!["--state-root", "/private", "private-sentinel"],
        vec![
            "--state-root",
            "/private",
            "status",
            "id",
            "private-sentinel",
        ],
    ] {
        Command::new(assert_cmd::cargo::cargo_bin!("vw-access"))
            .args(args)
            .assert()
            .code(2)
            .stdout("")
            .stderr("vw-access: invalid command; use --help\n");
    }
    Command::new(assert_cmd::cargo::cargo_bin!("vw-access"))
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Submit a one-time human request"));
}
#[test]
fn unavailable_transport_is_redacted() {
    Command::new(assert_cmd::cargo::cargo_bin!("vw-access"))
        .args([
            "--state-root",
            "/absent-private-sentinel",
            "request",
            "private-sentinel",
            "--",
            "private-sentinel",
        ])
        .assert()
        .failure()
        .stdout("")
        .stderr("vw-access: human transport unavailable\n");
}

#[test]
fn subcommand_help_shows_its_static_options_without_argument_values() {
    for args in [
        vec!["request", "--help"],
        vec!["request", "private-sentinel", "--help"],
    ] {
        Command::new(assert_cmd::cargo::cargo_bin!("vw-access"))
            .args(args)
            .assert()
            .success()
            .stdout(predicate::str::contains(" request [OPTIONS] <OPERATION>"))
            .stdout(predicate::str::contains("--revision"))
            .stdout(predicate::str::contains("--no-wait"))
            .stdout(predicate::str::contains("[-- <VALUES>...]"))
            .stdout(predicate::str::contains("private-sentinel").not());
    }
    Command::new(assert_cmd::cargo::cargo_bin!("vw-access"))
        .args(["status", "private-sentinel", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains(" status <ID>"))
        .stdout(predicate::str::contains("--revision").not())
        .stdout(predicate::str::contains("private-sentinel").not());
}

#[test]
fn history_cli_uses_human_socket_and_escapes_controls_without_losing_attribution() {
    use std::{
        fs,
        io::{Read, Write},
        net::Shutdown,
        os::unix::{fs::PermissionsExt, net::UnixListener},
    };
    use vaultwarden_cli::adapters::human_socket::{HumanCommand, HumanMessage};
    for limit in [None, Some(1), Some(200)] {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("human.sock");
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let label = "Agent <img src=x>\n\x1b]2;title\x07\x7f\u{0085}\u{009b}\u{061c}\u{200e}\u{200f}\u{202e}\u{2066}\u{2069}";
        let event = serde_json::json!({
            "version":1, "request_id":"A".repeat(43), "operation":"deploy",
            "requester":{"kind":"agent","label":label,"fingerprint":"b".repeat(64)},
            "policy_revision":"c".repeat(64), "credentials":[{"label":"Deployment <login>","use_type":"login"}],
            "created_at_unix_seconds":1,"expires_at_unix_seconds":301,"at_unix_seconds":1,"ordinal":0,
            "outcome":"submitted","status":{"status":"pending"}
        });
        let response = serde_json::json!({"result":"history", "events":[event]});
        let encoded = serde_json::to_vec(&response).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut input = Vec::new();
            stream.read_to_end(&mut input).unwrap();
            let request: HumanMessage = serde_json::from_slice(&input).unwrap();
            assert_eq!(request.version, 1);
            assert!(
                matches!(request.command, HumanCommand::History { limit: actual } if actual == limit)
            );
            stream.write_all(&encoded).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("vw-access"));
        command
            .arg("--state-root")
            .arg(directory.path())
            .arg("history");
        if let Some(limit) = limit {
            command.arg("--limit").arg(limit.to_string());
        }
        let result = command.assert().success().stderr("");
        let output = String::from_utf8(result.get_output().stdout.clone()).unwrap();
        server.join().unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&output).unwrap(),
            response
        );
        assert!(
            output.contains("Deployment <login>"),
            "successful capture must contain known history data"
        );
        assert!(
            output.contains(r"\u007f") && output.contains(r"\u0085") && output.contains(r"\u202e")
        );
        assert!(!output.trim_end_matches('\n').chars().any(char::is_control));
        for forbidden in [
            "vault-value-sentinel",
            "master-password-sentinel",
            "PRIVATE KEY",
            "child-stdout-sentinel",
            "child-stderr-sentinel",
            "browser-session-sentinel",
            "backend-session-sentinel",
            "launch-capability-sentinel",
            "approval-binding-sentinel",
            "DEPLOY_PASSWORD",
            "11111111-1111-1111-1111-111111111111",
        ] {
            assert!(!output.contains(forbidden));
        }
    }
}

#[test]
fn history_parser_errors_and_help_are_static() {
    for limit in [
        "4294967296",
        "-1",
        "private-sentinel",
        "\x1b]2;private-sentinel\x07\u{0085}\u{202e}",
    ] {
        Command::new(assert_cmd::cargo::cargo_bin!("vw-access"))
            .args(["--state-root", "/private", "history", "--limit", limit])
            .assert()
            .code(2)
            .stdout("")
            .stderr("vw-access: invalid command; use --help\n");
    }
    Command::new(assert_cmd::cargo::cargo_bin!("vw-access"))
        .args(["history", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--limit"))
        .stdout(predicate::str::contains("default 50; range 1–200"));
}

#[test]
fn signed_submit_without_stdin_or_tty_sends_only_signed_envelope() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::{
        fs,
        io::{Read, Write},
        net::Shutdown,
        os::unix::{fs::PermissionsExt, net::UnixListener, process::CommandExt},
        process::Stdio,
    };
    use vaultwarden_cli::access::protocol::SignedSubmission;
    for rejected in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750)).unwrap();
        let seed = directory.path().join("seed");
        fs::write(&seed, [17u8; 32]).unwrap();
        fs::set_permissions(&seed, fs::Permissions::from_mode(0o600)).unwrap();
        let path = directory.path().join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        let id = URL_SAFE_NO_PAD.encode([19u8; 32]);
        let binding = URL_SAFE_NO_PAD.encode([18u8; 32]);
        let server_listener = listener.try_clone().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = server_listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes.pop(), Some(b'\n'));
            let input = SignedSubmission::parse(&bytes).unwrap();
            input
                .verify(
                    &URL_SAFE_NO_PAD.encode(
                        ed25519_dalek::SigningKey::from_bytes(&[17; 32])
                            .verifying_key()
                            .to_bytes(),
                    ),
                )
                .unwrap();
            assert_eq!(input.binding_id, binding);
            assert_eq!(input.operation_id, "deploy");
            assert_eq!(input.expected_policy_revision, "a".repeat(64));
            assert_eq!(input.args, ["staging"]);
            let response = if rejected {
                serde_json::json!({"protocol_version":1,"status":"rejected","category":"unauthorized"})
            } else {
                serde_json::json!({"protocol_version":1,"status":"pending","request_id":id})
            };
            writeln!(stream, "{response}").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            response
        });
        let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin!("vw-access"));
        command
            .args(["submit", "deploy", "--socket"])
            .arg(path)
            .arg("--key-file")
            .arg(seed)
            .arg("--binding-id")
            .arg(URL_SAFE_NO_PAD.encode([18u8; 32]))
            .arg("--revision")
            .arg("a".repeat(64))
            .args(["--", "staging"])
            .env_remove("VAULTWARDEN_ACCESS_STATE_ROOT")
            .stdin(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::isatty(0) != 0 {
                    return Err(std::io::Error::other("unexpected tty"));
                }
                Ok(())
            });
        }
        let output = command.output().unwrap();
        let response = server.join().unwrap();
        if rejected {
            assert_eq!(output.status.code(), Some(1));
            assert_eq!(
                output.stdout,
                b"{\"status\":\"rejected\",\"protocol_version\":1,\"category\":\"unauthorized\"}\n"
            );
            assert_eq!(output.stderr, b"vw-access: agent submission rejected\n");
        } else {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.stderr.is_empty());
        }
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "client must not retry"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            response
        );
    }
}

#[test]
fn signed_submit_missing_arguments_and_unsafe_seed_errors_are_redacted() {
    Command::new(assert_cmd::cargo::cargo_bin!("vw-access"))
        .args(["submit", "private-sentinel", "--socket", "private-sentinel"])
        .assert()
        .code(2)
        .stdout("")
        .stderr("vw-access: invalid command; use --help\n");
    Command::new(assert_cmd::cargo::cargo_bin!("vw-access"))
        .args([
            "submit",
            "deploy",
            "--socket",
            "/absent",
            "--key-file",
            "/absent-private-sentinel",
            "--binding-id",
            "private-sentinel",
            "--revision",
            "private-sentinel",
        ])
        .assert()
        .failure()
        .stdout("")
        .stderr("vw-access: agent key unavailable\n");
}
