//! Real process checks: parser errors cannot reflect terminal-provided values.
use assert_cmd::Command;
use predicates::prelude::*;
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
