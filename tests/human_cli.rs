//! Real process checks: parser errors cannot reflect terminal-provided values.
#![cfg(target_os = "linux")]

use assert_cmd::Command;
use predicates::prelude::*;
#[path = "support/bounded_process.rs"]
mod bounded_process;
use bounded_process::BoundedChild;

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
            assert!(output.stderr.is_empty());
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
            "ERERERERERERERERERERERERERERERERERERERERERE",
            "--revision",
            "private-sentinel",
        ])
        .assert()
        .failure()
        .stdout("")
        .stderr(
            "{\"event\":\"client_error\",\"category\":\"local_failure\",\"request_id\":null}\n",
        );
}

/// Synthetic provider with the production client framing and authentication.
struct AgentFixture {
    _directory: tempfile::TempDir,
    listener: std::os::unix::net::UnixListener,
    socket: std::path::PathBuf,
    seed: std::path::PathBuf,
    id: String,
    binding: String,
}
impl AgentFixture {
    fn new() -> Self {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use std::{
            fs,
            os::unix::{fs::PermissionsExt, net::UnixListener},
        };
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750)).unwrap();
        let seed = directory.path().join("seed");
        fs::write(&seed, [17; 32]).unwrap();
        fs::set_permissions(&seed, fs::Permissions::from_mode(0o600)).unwrap();
        let socket = directory.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
        Self {
            _directory: directory,
            listener,
            socket,
            seed,
            id: URL_SAFE_NO_PAD.encode([19; 32]),
            binding: URL_SAFE_NO_PAD.encode([18; 32]),
        }
    }
    fn command(&self, verb: &str) -> std::process::Command {
        use std::{os::unix::process::CommandExt, process::Stdio};
        let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin!("vw-access"));
        command
            .arg(verb)
            .arg(if verb == "submit" { "deploy" } else { &self.id })
            .arg("--socket")
            .arg(&self.socket)
            .arg("--key-file")
            .arg(&self.seed)
            .arg("--binding-id")
            .arg(&self.binding)
            .env_remove("VAULTWARDEN_ACCESS_STATE_ROOT")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if verb == "submit" {
            command.arg("--revision").arg("a".repeat(64));
        }
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                assert_eq!(libc::isatty(0), 0);
                Ok(())
            });
        }
        command
    }
    fn no_retry(&self) {
        self.listener.set_nonblocking(true).unwrap();
        assert_eq!(
            self.listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
fn receive_agent(stream: &mut std::os::unix::net::UnixStream) -> Vec<u8> {
    use std::io::Read;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes.pop(), Some(b'\n'));
    bytes
}
fn send_agent(stream: &mut std::os::unix::net::UnixStream, value: &serde_json::Value) {
    use std::io::Write;
    writeln!(stream, "{value}").unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
}
fn verify_query(bytes: &[u8], id: &str) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use vaultwarden_cli::access::protocol::SignedStatusQuery;
    let query = SignedStatusQuery::parse(bytes).unwrap();
    query
        .verify(
            &URL_SAFE_NO_PAD.encode(
                ed25519_dalek::SigningKey::from_bytes(&[17; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
        )
        .unwrap();
    assert_eq!(query.request_id, id);
    assert_eq!(query.binding_id, URL_SAFE_NO_PAD.encode([18; 32]));
    query.nonce
}

#[test]
fn agent_submit_wait_busy_changed_states_only_and_resume_without_tty() {
    use std::{
        io::{BufRead, BufReader},
        process::Stdio,
    };
    let fixture = AgentFixture::new();
    let listener = bounded_process::Listener::new(fixture.listener.try_clone().unwrap());
    let id = fixture.id.clone();
    let (receipt_seen, receipt_confirmed) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut stream = listener.accept();
        vaultwarden_cli::access::protocol::SignedSubmission::parse(&receive_agent(&mut stream))
            .unwrap();
        send_agent(
            &mut stream,
            &serde_json::json!({"status":"pending","protocol_version":1,"request_id":id}),
        );
        // Parent cannot signal this until receipt has actually been flushed.
        receipt_confirmed
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let mut nonces = std::collections::HashSet::new();
        for state in [
            None,
            Some("running"),
            Some("running"),
            Some("completed"),
            Some("completed"),
        ] {
            let mut stream = listener.accept();
            assert!(nonces.insert(verify_query(&receive_agent(&mut stream), &id)));
            let response = match state {
                None => {
                    serde_json::json!({"status":"rejected","protocol_version":1,"category":"busy"})
                }
                Some("completed") => {
                    serde_json::json!({"status":"status","protocol_version":1,"request_id":id,"state":{"status":"completed","exit_code":7}})
                }
                Some(value) => {
                    serde_json::json!({"status":"status","protocol_version":1,"request_id":id,"state":{"status":value}})
                }
            };
            send_agent(&mut stream, &response);
        }
    });
    let mut command = fixture.command("submit");
    command
        .arg("--wait")
        .arg("--timeout-seconds")
        .arg("5")
        .stdout(Stdio::piped());
    let mut child = BoundedChild::spawn(&mut command);
    let mut stdout = BufReader::new(child.stdout());
    let (stdout, receipt) = bounded_process::io(move || {
        let mut receipt = String::new();
        stdout.read_line(&mut receipt).unwrap();
        (stdout, receipt)
    });
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&receipt).unwrap()["request_id"],
        fixture.id
    );
    receipt_seen.send(()).unwrap();
    let remaining: Vec<_> = bounded_process::io(move || {
        stdout
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(&line.unwrap()).unwrap())
            .collect()
    });
    let output = child.wait_with_output();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(remaining.len(), 2);
    assert_eq!(remaining[0]["state"]["status"], "running");
    assert_eq!(remaining[1]["state"]["exit_code"], 7);
    let resumed = bounded_process::output(&mut fixture.command("wait"));
    assert!(resumed.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&resumed.stdout).unwrap()["state"]["status"],
        "completed"
    );
    bounded_process::join(server);
    fixture.no_retry();
}

#[test]
fn agent_poll_preserves_terminal_exit_information_and_busy_is_one_shot() {
    for (state, code) in [
        (serde_json::json!({"status":"pending"}), 0),
        (serde_json::json!({"status":"approved"}), 0),
        (serde_json::json!({"status":"running"}), 0),
        (serde_json::json!({"status":"denied"}), 1),
        (serde_json::json!({"status":"expired"}), 1),
        (serde_json::json!({"status":"completed","exit_code":255}), 0),
        (
            serde_json::json!({"status":"failed","category":"execution_nonzero"}),
            1,
        ),
        (serde_json::Value::Null, 1),
    ] {
        let fixture = AgentFixture::new();
        let listener = bounded_process::Listener::new(fixture.listener.try_clone().unwrap());
        let id = fixture.id.clone();
        let response = if state.is_null() {
            serde_json::json!({"status":"rejected","protocol_version":1,"category":"busy"})
        } else {
            serde_json::json!({"status":"status","protocol_version":1,"request_id":id,"state":state})
        };
        let sent = response.clone();
        let server = std::thread::spawn(move || {
            let mut stream = listener.accept();
            verify_query(&receive_agent(&mut stream), &id);
            send_agent(&mut stream, &sent);
        });
        let output = bounded_process::output(&mut fixture.command("poll"));
        bounded_process::join(server);
        assert_eq!(output.status.code(), Some(code));
        assert!(output.stderr.is_empty());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            response
        );
        fixture.no_retry();
    }
}

#[test]
fn agent_wait_signal_after_receipt_retains_id_and_never_resubmits() {
    use std::io::{BufRead, BufReader};
    for (signal, code, category) in [
        (libc::SIGINT, 130, "interrupted"),
        (libc::SIGTERM, 143, "terminated"),
    ] {
        let fixture = AgentFixture::new();
        let listener = bounded_process::Listener::new(fixture.listener.try_clone().unwrap());
        let id = fixture.id.clone();
        let (started, ready) = std::sync::mpsc::channel();
        let (release, finish) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let mut stream = listener.accept();
            vaultwarden_cli::access::protocol::SignedSubmission::parse(&receive_agent(&mut stream))
                .unwrap();
            send_agent(
                &mut stream,
                &serde_json::json!({"status":"pending","protocol_version":1,"request_id":id}),
            );
            let mut stream = listener.accept();
            verify_query(&receive_agent(&mut stream), &id);
            started.send(()).unwrap();
            finish
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        });
        let mut child = BoundedChild::spawn(fixture.command("submit").arg("--wait"));
        let mut stdout = BufReader::new(child.stdout());
        let (stdout, receipt) = bounded_process::io(move || {
            let mut receipt = String::new();
            stdout.read_line(&mut receipt).unwrap();
            (stdout, receipt)
        });
        drop(stdout);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&receipt).unwrap()["request_id"],
            fixture.id
        );
        ready
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
        let output = child.wait_with_output();
        release.send(()).unwrap();
        bounded_process::join(server);
        assert_eq!(output.status.code(), Some(code));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stderr).unwrap(),
            serde_json::json!({"event":"client_error","category":category,"request_id":fixture.id})
        );
        fixture.no_retry();
    }
}

#[test]
fn agent_wait_timeout_and_disconnect_keep_client_uncertainty_separate() {
    for (verb, acknowledge, timeout) in [
        ("submit", false, false),
        ("submit", true, false),
        ("wait", false, true),
    ] {
        let fixture = AgentFixture::new();
        let listener = bounded_process::Listener::new(fixture.listener.try_clone().unwrap());
        let id = fixture.id.clone();
        let (release, finish) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let mut stream = listener.accept();
            let bytes = receive_agent(&mut stream);
            if verb == "submit" {
                vaultwarden_cli::access::protocol::SignedSubmission::parse(&bytes).unwrap();
                if acknowledge {
                    send_agent(
                        &mut stream,
                        &serde_json::json!({"status":"pending","protocol_version":1,"request_id":id}),
                    );
                    let mut query = listener.accept();
                    verify_query(&receive_agent(&mut query), &id);
                }
            } else {
                verify_query(&bytes, &id);
            }
            if timeout {
                finish
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
            }
        });
        let mut command = fixture.command(verb);
        if verb == "submit" {
            command.arg("--wait");
        }
        command.args(["--timeout-seconds", "1"]);
        let output = bounded_process::output(&mut command);
        if timeout {
            release.send(()).unwrap();
        }
        bounded_process::join(server);
        assert_eq!(output.status.code(), Some(if timeout { 4 } else { 3 }));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stderr).unwrap(),
            serde_json::json!({"event":"client_error","category":if timeout {"wait_timeout"}else{"transport_uncertain"},"request_id":if verb=="wait"||acknowledge {Some(&fixture.id)}else{None}})
        );
        fixture.no_retry();
    }
}

#[test]
fn agent_wait_usage_is_checked_before_submission_and_never_echoes_input() {
    for args in [
        vec!["--timeout-seconds", "1"],
        vec!["--wait", "--timeout-seconds", "0"],
        vec!["--wait", "--timeout-seconds", "18446744073709551615"],
        vec!["--wait", "--timeout-seconds", "private-sentinel"],
    ] {
        let fixture = AgentFixture::new();
        let output = bounded_process::output(fixture.command("submit").args(args));
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"vw-access: invalid command; use --help\n");
        fixture.no_retry();
    }
}

#[test]
fn agent_wait_signal_before_acknowledgment_reports_unknown_id_without_retry() {
    for (signal, code, category) in [
        (libc::SIGINT, 130, "interrupted"),
        (libc::SIGTERM, 143, "terminated"),
    ] {
        let fixture = AgentFixture::new();
        let listener = bounded_process::Listener::new(fixture.listener.try_clone().unwrap());
        let (started, ready) = std::sync::mpsc::channel();
        let (release, finish) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let mut stream = listener.accept();
            vaultwarden_cli::access::protocol::SignedSubmission::parse(&receive_agent(&mut stream))
                .unwrap();
            started.send(()).unwrap();
            finish
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        });
        let child = BoundedChild::spawn(fixture.command("submit").arg("--wait"));
        ready
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
        let output = child.wait_with_output();
        release.send(()).unwrap();
        bounded_process::join(server);
        assert_eq!(output.status.code(), Some(code));
        assert!(output.stdout.is_empty());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stderr).unwrap(),
            serde_json::json!({"event":"client_error","category":category,"request_id":null})
        );
        fixture.no_retry();
    }
}

#[test]
fn malformed_agent_selectors_are_usage_errors_before_key_access() {
    for (verb, corrupt_binding) in [
        ("submit", true),
        ("poll", true),
        ("wait", true),
        ("poll", false),
        ("wait", false),
    ] {
        let fixture = AgentFixture::new();
        let mut command = fixture.command(verb);
        // Corrupt exactly one selector, leaving the other valid. An absent key
        // proves selector validation wins over local filesystem failure.
        let mut arguments: Vec<_> = command.get_args().map(|arg| arg.to_os_string()).collect();
        let selector = if corrupt_binding {
            arguments
                .iter()
                .position(|arg| arg == "--binding-id")
                .unwrap()
                + 1
        } else {
            1
        };
        arguments[selector] = "private-selector-sentinel".into();
        let key = arguments
            .iter()
            .position(|arg| arg == "--key-file")
            .unwrap();
        arguments[key + 1] = "/absent-key".into();
        command = std::process::Command::new(assert_cmd::cargo::cargo_bin!("vw-access"));
        command
            .args(arguments)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let output = bounded_process::output(&mut command);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"vw-access: invalid command; use --help\n");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private-selector-sentinel"));
        fixture.no_retry();
    }
}

fn full_output_pipe() -> (std::fs::File, std::process::Stdio) {
    use std::{
        io::Write,
        os::fd::{AsRawFd, FromRawFd},
    };
    let mut descriptors = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
        0
    );
    let reader = unsafe { std::fs::File::from_raw_fd(descriptors[0]) };
    let mut writer = unsafe { std::fs::File::from_raw_fd(descriptors[1]) };
    loop {
        match writer.write(&[b'x'; 4096]) {
            Ok(count) => assert!(count > 0),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("fill pipe: {error}"),
        }
    }
    assert_eq!(
        unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, 0) },
        0
    );
    (reader, writer.into())
}

fn await_blocked_pipe_write(pid: u32) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        let blocked = std::fs::read_dir(format!("/proc/{pid}/task"))
            .unwrap()
            .any(|entry| {
                entry.is_ok_and(|entry| {
                    std::fs::read_to_string(entry.path().join("wchan"))
                        .is_ok_and(|state| state.trim().ends_with("pipe_write"))
                })
            });
        if blocked {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "could not observe the child blocked in pipe_write: this Linux witness requires readable /proc/<pid>/task/<tid>/wchan symbols (including anon_pipe_write); hidden/zero symbols or an unobserved block are test failures, not skips"
        );
        std::thread::yield_now();
    }
}

#[test]
fn agent_wait_full_stdout_and_stderr_preserve_timeout_and_signal_exits() {
    for (verb, terminal) in [("submit", false), ("wait", false), ("wait", true)] {
        for (signal, code, category) in [
            (None, 4, "wait_timeout"),
            (Some(libc::SIGINT), 130, "interrupted"),
            (Some(libc::SIGTERM), 143, "terminated"),
        ] {
            for blocked_stderr in [false, true] {
                let fixture = AgentFixture::new();
                let listener =
                    bounded_process::Listener::new(fixture.listener.try_clone().unwrap());
                let id = fixture.id.clone();
                let server = std::thread::spawn(move || {
                    let mut stream = listener.accept();
                    let bytes = receive_agent(&mut stream);
                    let response = if verb == "submit" {
                        vaultwarden_cli::access::protocol::SignedSubmission::parse(&bytes).unwrap();
                        serde_json::json!({"status":"pending","protocol_version":1,"request_id":id})
                    } else {
                        verify_query(&bytes, &id);
                        let state = if terminal {
                            serde_json::json!({"status":"completed","exit_code":0})
                        } else {
                            serde_json::json!({"status":"running"})
                        };
                        serde_json::json!({"status":"status","protocol_version":1,"request_id":id,"state":state})
                    };
                    send_agent(&mut stream, &response);
                });
                let (_stdout_reader, stdout) = full_output_pipe();
                let mut command = fixture.command(verb);
                command.stdout(stdout);
                let _stderr_reader = if blocked_stderr {
                    let (reader, stderr) = full_output_pipe();
                    command.stderr(stderr);
                    Some(reader)
                } else {
                    None
                };
                if verb == "submit" {
                    command.arg("--wait");
                }
                command.args([
                    "--timeout-seconds",
                    if signal.is_none() { "1" } else { "30" },
                ]);
                let child = BoundedChild::spawn(&mut command);
                await_blocked_pipe_write(child.id());
                if let Some(signal) = signal {
                    assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
                }
                let started = std::time::Instant::now();
                let output = child.wait_with_output();
                assert!(started.elapsed() < std::time::Duration::from_secs(2));
                assert_eq!(output.status.code(), Some(code));
                if !blocked_stderr {
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&output.stderr).unwrap(),
                        serde_json::json!({"event":"client_error","category":category,"request_id":fixture.id})
                    );
                }
                bounded_process::join(server);
                fixture.no_retry();
            }
        }
    }
}

#[test]
fn agent_wait_closed_stdout_after_receipt_retains_id_without_later_queries() {
    use std::io::{BufRead, BufReader};
    for state in [
        serde_json::json!({"status":"running"}),
        serde_json::json!({"status":"completed","exit_code":0}),
    ] {
        let fixture = AgentFixture::new();
        let listener = bounded_process::Listener::new(fixture.listener.try_clone().unwrap());
        let id = fixture.id.clone();
        let (closed_tx, closed_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let mut stream = listener.accept();
            vaultwarden_cli::access::protocol::SignedSubmission::parse(&receive_agent(&mut stream))
                .unwrap();
            send_agent(
                &mut stream,
                &serde_json::json!({"status":"pending","protocol_version":1,"request_id":id}),
            );
            let mut query = listener.accept();
            verify_query(&receive_agent(&mut query), &id);
            // The parent's receipt reader must be closed before status output.
            closed_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            send_agent(
                &mut query,
                &serde_json::json!({"status":"status","protocol_version":1,"request_id":id,"state":state}),
            );
        });
        let mut child = BoundedChild::spawn(fixture.command("submit").args([
            "--wait",
            "--timeout-seconds",
            "5",
        ]));
        let stdout = child.stdout();
        let receipt = bounded_process::io(move || {
            let mut reader = BufReader::new(stdout);
            let mut receipt = String::new();
            reader.read_line(&mut receipt).unwrap();
            // Drop the sole pipe reader before notifying the provider fixture.
            drop(reader);
            receipt
        });
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&receipt).unwrap()["request_id"],
            fixture.id
        );
        closed_tx.send(()).unwrap();
        let output = child.wait_with_output();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stderr).unwrap(),
            serde_json::json!({"event":"client_error","category":"local_failure","request_id":fixture.id})
        );
        bounded_process::join(server);
        fixture.no_retry();
    }
}
