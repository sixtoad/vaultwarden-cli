//! Trusted `update` end to end: real binary, real pseudo-terminal decision,
//! stateful fake of Vaultwarden 1.36's item routes (issue 48).
#![cfg(unix)]
#[path = "support/fake_vault.rs"]
mod fake_vault;
mod support;

use fake_vault::{ACCOUNT, Answer, FOLDER, FakeVault, ITEM, PutMode, REFERENCE, Run, run_cli};
use serde_json::json;
use support::{TestContext, test_crypto_keys};
use vaultwarden_cli::config::Config;
use vaultwarden_cli::secret_storage::{WriteReceipt, WriteStatus};
use vaultwarden_cli::write_journal::WriteJournal;

const NEW_VALUES: &[u8] =
    br#"{"password":"  new-password-private\n\u0000","fields":[{"name":"api-key","value":"new-key-private\n"}]}"#;
const PRIVATE: [&str; 6] = [
    "new-password-private",
    "new-key-private",
    "old-password-private",
    "old-key-private",
    "kept-private",
    "old-notes-private",
];

struct Harness {
    ctx: TestContext,
    vault: FakeVault,
}
impl Harness {
    async fn start() -> Self {
        let ctx = TestContext::new();
        let keys = test_crypto_keys();
        let vault = FakeVault::start(&keys).await;
        ctx.write_config(&Config {
            server: Some(vault.uri.clone()),
            access_token: Some("access-token".into()),
            token_expiry: Some(i64::MAX),
            ..Default::default()
        })
        .unwrap();
        ctx.write_saved_user_keys(&keys).unwrap();
        Self { ctx, vault }
    }
    fn command(&self, args: &[&str]) -> std::process::Command {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_vaultwarden-cli"));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.ctx.home_dir())
            .env("XDG_CONFIG_HOME", self.ctx.config_root())
            .env("VAULTWARDEN_ALLOW_PLAINTEXT_JSON", "true")
            .env("VAULTWARDEN_ALLOW_INSECURE_KEY_FILE", "true")
            .arg("--allow-insecure-http")
            .args(args);
        command
    }
    async fn update(
        &self,
        extra: &[&str],
        stdin: &[u8],
        password: Option<&str>,
        answer: Answer,
    ) -> Run {
        let mut args = vec![
            "update",
            "--id",
            ITEM,
            "--account",
            ACCOUNT,
            "--folder",
            FOLDER,
            "--reference",
            REFERENCE,
        ];
        args.extend_from_slice(extra);
        let command = self.command(&args);
        let (stdin, password) = (stdin.to_vec(), password.map(str::to_owned));
        tokio::task::spawn_blocking(move || run_cli(command, &stdin, password.as_deref(), answer))
            .await
            .unwrap()
    }
    async fn reconcile(&self, journal: &std::path::Path, id: &str) -> std::process::Output {
        self.plain(&[
            "reconcile",
            "--journal",
            journal.to_str().unwrap(),
            "--id",
            id,
        ])
        .await
    }
    /// The item's effective keys and its decrypted password history, newest first.
    fn history(&self) -> (Vec<String>, serde_json::Value) {
        let item = self.vault.state.lock().unwrap().item.clone();
        let keys = test_crypto_keys().item_keys(item["key"].as_str()).unwrap();
        let entries = item["passwordHistory"]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .map(|e| {
                        keys.decrypt_authenticated_to_string(e["password"].as_str().unwrap())
                            .unwrap()
                    })
                    .collect()
            })
            .unwrap_or_default();
        (entries, item)
    }
    async fn plain(&self, args: &[&str]) -> std::process::Output {
        let mut command = self.command(args);
        tokio::task::spawn_blocking(move || command.output().unwrap())
            .await
            .unwrap()
    }
    fn journals(&self) -> Vec<std::path::PathBuf> {
        let mut paths = std::fs::read_dir(self.ctx.config_dir().join("write-attempts"))
            .map(|entries| entries.map(|e| e.unwrap().path()).collect::<Vec<_>>())
            .unwrap_or_default();
        paths.retain(|p| {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            name.starts_with("update-") && name.ends_with(".json")
        });
        paths.sort_by_key(|p| std::fs::metadata(p).unwrap().modified().unwrap());
        paths
    }
}

fn receipt(run: &Run) -> WriteReceipt {
    serde_json::from_slice(&run.output.stdout).expect("stdout is exactly one receipt")
}
fn assert_no_plaintext(run: &Run, harness: &Harness) {
    let mut observed = vec![
        String::from_utf8_lossy(&run.output.stdout).into_owned(),
        String::from_utf8_lossy(&run.output.stderr).into_owned(),
        run.terminal.clone(),
    ];
    observed.extend(
        harness
            .journals()
            .iter()
            .map(|p| std::fs::read_to_string(p).unwrap()),
    );
    for text in observed {
        for value in PRIVATE {
            assert!(!text.contains(value), "plaintext {value} leaked");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn approved_update_replaces_selected_fields_verifies_and_reads_back_exactly() {
    let harness = Harness::start().await;
    let before = harness.vault.state.lock().unwrap().item.clone();
    let run = harness.update(&[], NEW_VALUES, None, Answer::Approve).await;
    assert!(
        run.output.status.success(),
        "{}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let receipt = receipt(&run);
    assert_eq!(receipt.status, WriteStatus::Verified);
    assert_eq!(receipt.item_id.as_deref(), Some(ITEM));
    for line in [
        "UPDATE personal vault item",
        &format!("Item: {ITEM}"),
        "Expected revision: 2026-11-21T10:01:00.000000Z",
        "Fields replaced: custom:api-key, password",
        "Password history: old values of password, custom:api-key kept in password history (newest 5)",
        &format!("typing 'update {}'", receipt.attempt_id),
    ] {
        assert!(run.terminal.contains(line), "review lacks {line}");
    }
    assert_no_plaintext(&run, &harness);
    let state = harness.vault.state.lock().unwrap().puts.clone();
    assert_eq!(state.len(), 1);
    assert_eq!(
        state[0]["lastKnownRevisionDate"],
        json!("2026-11-21T10:01:00.000000Z")
    );
    let after = harness.vault.state.lock().unwrap().item.clone();
    // Like official Bitwarden clients: the replaced password and hidden field
    // value go to password history (newest first) with one lastUsedDate, and
    // the password revision date is that time.
    let (history, _item) = harness.history();
    assert_eq!(
        history,
        ["api-key: old-key-private", "old-password-private"]
    );
    let date = after["passwordHistory"][0]["lastUsedDate"].clone();
    assert_eq!(after["passwordHistory"][1]["lastUsedDate"], date);
    assert_eq!(after["login"]["passwordRevisionDate"], date);
    let date = date.as_str().unwrap();
    assert!(
        date.len() == 24 && date.starts_with("20") && date.ends_with('Z') && &date[19..20] == ".",
        "{date}"
    );
    assert_eq!(
        after["login"]["fido2Credentials"],
        before["login"]["fido2Credentials"]
    );
    assert_eq!(after["login"]["uris"], before["login"]["uris"]);
    for preserved in ["key", "name", "notes", "folderId"] {
        assert_eq!(after[preserved], before[preserved], "{preserved}");
    }
    assert_eq!(after["login"]["username"], before["login"]["username"]);
    assert_eq!(after["fields"][1], before["fields"][1]);
    for (field, expected) in [
        ("password", b"  new-password-private\n\0".as_slice()),
        ("custom:api-key", b"new-key-private\n"),
        ("custom:other", b"kept-private"),
        ("notes", b"old-notes-private"),
    ] {
        let output = harness
            .plain(&["read-field", "--id", ITEM, "--field", field])
            .await;
        assert!(output.status.success(), "read-field {field}");
        assert_eq!(output.stdout, expected, "{field}");
    }
    let journal = WriteJournal::read(&harness.journals()[0]).unwrap();
    assert_eq!(journal.receipt, receipt);
    assert_eq!(
        journal.update.unwrap().expected_revision,
        "2026-11-21T10:01:00.000000Z"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn prompt_mode_replaces_only_the_password_from_a_hidden_prompt() {
    let harness = Harness::start().await;
    let run = harness
        .update(
            &["--prompt"],
            b"",
            Some("new-password-private"),
            Answer::Approve,
        )
        .await;
    assert_eq!(receipt(&run).status, WriteStatus::Verified);
    assert!(
        run.terminal.contains("Fields replaced: password\r\n")
            || run.terminal.contains("Fields replaced: password\n")
    );
    assert_no_plaintext(&run, &harness);
    let output = harness
        .plain(&["read-field", "--id", ITEM, "--field", "password"])
        .await;
    assert_eq!(output.stdout, b"new-password-private");
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_expected_revision_and_concurrent_edits_never_write() {
    let harness = Harness::start().await;
    let stale = harness
        .update(
            &["--expected-revision", "2026-11-21T10:00:00.000000Z"],
            NEW_VALUES,
            None,
            Answer::Approve,
        )
        .await;
    assert!(!stale.output.status.success());
    assert!(
        !stale.terminal.contains("Authorize"),
        "stale revision reached the decision"
    );
    // Another writer edits the item after the review, before the write.
    let gets = harness.vault.state.lock().unwrap().item_gets;
    harness.vault.state.lock().unwrap().edit_before_get = Some(gets + 2);
    let raced = harness.update(&[], NEW_VALUES, None, Answer::Approve).await;
    assert!(!raced.output.status.success());
    assert!(raced.terminal.contains("Authorize"));
    assert!(String::from_utf8_lossy(&raced.output.stderr).contains("item changed since review"));
    assert_eq!(harness.vault.puts(), 0);
    assert!(harness.journals().is_empty());
    assert_no_plaintext(&raced, &harness);
    // A pinned current revision is accepted.
    let current = harness.vault.state.lock().unwrap().current_revision();
    let pinned = harness
        .update(
            &["--expected-revision", &current],
            NEW_VALUES,
            None,
            Answer::Approve,
        )
        .await;
    assert_eq!(receipt(&pinned).status, WriteStatus::Verified);
}

#[tokio::test(flavor = "multi_thread")]
async fn server_rejection_is_failed_and_never_retried() {
    let harness = Harness::start().await;
    harness.vault.state.lock().unwrap().put_mode = PutMode::Reject;
    let run = harness.update(&[], NEW_VALUES, None, Answer::Approve).await;
    assert!(!run.output.status.success());
    assert_eq!(receipt(&run).status, WriteStatus::Failed);
    assert_eq!(harness.vault.puts(), 1);
    assert_no_plaintext(&run, &harness);
}

#[tokio::test(flavor = "multi_thread")]
async fn denial_and_a_missing_terminal_never_write() {
    let harness = Harness::start().await;
    for (answer, reason) in [
        (Answer::Deny, "update denied"),
        (Answer::NoTerminal, "human write authorization unavailable"),
    ] {
        let run = harness.update(&[], NEW_VALUES, None, answer).await;
        assert!(!run.output.status.success());
        assert!(String::from_utf8_lossy(&run.output.stderr).contains(reason));
        assert_eq!(run.terminal.contains("Authorize"), answer == Answer::Deny);
        assert!(run.output.stdout.is_empty());
        assert_no_plaintext(&run, &harness);
    }
    assert_eq!(harness.vault.puts(), 0);
    assert!(harness.journals().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_input_and_missing_fields_are_refused_before_the_decision() {
    let harness = Harness::start().await;
    let oversized = format!(r#"{{"password":"{}"}}"#, "x".repeat(70_000));
    for input in [
        br#"{"password":"new-password-private","unknown":1}"#.as_slice(),
        br#"{"password":"new-password-private","password":"new-key-private"}"#,
        b"{}",
        b"not json new-password-private",
        oversized.as_bytes(),
        br#"{"fields":[{"name":"absent","value":"new-key-private"}]}"#,
        br#"{"fields":[{"name":"vw-access","value":"new-key-private"}]}"#,
    ] {
        let run = harness.update(&[], input, None, Answer::Approve).await;
        assert!(!run.output.status.success());
        assert!(
            !run.terminal.contains("Authorize"),
            "refused input reached the decision"
        );
        assert_no_plaintext(&run, &harness);
    }
    assert_eq!(harness.vault.puts(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn uncertain_update_blocks_the_item_until_reconciled_and_is_never_replayed() {
    let harness = Harness::start().await;
    let reconcile = |path: std::path::PathBuf| {
        let harness = &harness;
        async move {
            let output = harness.reconcile(&path, ITEM).await;
            // Like `update`, reconcile exits non-zero unless the receipt is verified.
            assert!(!output.status.success());
            serde_json::from_slice::<WriteReceipt>(&output.stdout)
                .unwrap()
                .status
        }
    };
    // The write fails before applying: reconcile proves nothing changed.
    harness.vault.state.lock().unwrap().put_mode = PutMode::LoseWithoutApplying;
    let lost = harness.update(&[], NEW_VALUES, None, Answer::Approve).await;
    assert_eq!(receipt(&lost).status, WriteStatus::Uncertain);
    let blocked = harness.update(&[], NEW_VALUES, None, Answer::Approve).await;
    assert!(!blocked.output.status.success());
    assert!(!blocked.terminal.contains("Authorize"));
    assert_eq!(harness.vault.puts(), 1);
    assert_eq!(
        reconcile(harness.journals()[0].clone()).await,
        WriteStatus::Failed
    );
    // The write applies but its response is lost: reconcile sees a newer revision.
    harness.vault.state.lock().unwrap().put_mode = PutMode::ApplyThenLose;
    let interrupted = harness.update(&[], NEW_VALUES, None, Answer::Approve).await;
    assert_eq!(receipt(&interrupted).status, WriteStatus::Uncertain);
    assert_no_plaintext(&interrupted, &harness);
    assert_eq!(harness.vault.puts(), 2);
    let journal = harness.journals()[1].clone();
    let other = harness
        .reconcile(&journal, "44444444-4444-4444-4444-444444444444")
        .await;
    assert!(!other.status.success(), "a receipt cannot be retargeted");
    let gets = harness.vault.state.lock().unwrap().item_gets;
    for invalid in [
        "../33333333-3333-3333-3333-333333333333",
        "33333333-3333-3333-3333-33333333333A",
    ] {
        let refused = harness.reconcile(&journal, invalid).await;
        assert!(!refused.status.success());
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(stderr.contains("invalid item ID"), "{invalid}: {stderr}");
    }
    assert_eq!(harness.vault.state.lock().unwrap().item_gets, gets);
    assert_eq!(
        reconcile(journal.clone()).await,
        WriteStatus::UpdatedUnverified
    );
    assert_eq!(reconcile(journal).await, WriteStatus::UpdatedUnverified);
    assert_eq!(harness.vault.puts(), 2, "reconcile never writes");
    harness.vault.state.lock().unwrap().put_mode = PutMode::Apply;
    let next = harness.update(&[], NEW_VALUES, None, Answer::Approve).await;
    assert_eq!(receipt(&next).status, WriteStatus::Verified);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_value_that_differs_is_updated_unverified() {
    let harness = Harness::start().await;
    harness.vault.state.lock().unwrap().put_mode = PutMode::ApplyCorrupted;
    let run = harness.update(&[], NEW_VALUES, None, Answer::Approve).await;
    assert!(!run.output.status.success());
    assert_eq!(receipt(&run).status, WriteStatus::UpdatedUnverified);
    assert_eq!(harness.vault.puts(), 1);
    assert_no_plaintext(&run, &harness);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_dropped_after_the_write_applied_is_uncertain() {
    let harness = Harness::start().await;
    harness.vault.state.lock().unwrap().put_mode = PutMode::ApplyThenDrop;
    let run = harness.update(&[], NEW_VALUES, None, Answer::Approve).await;
    assert!(!run.output.status.success());
    assert_eq!(receipt(&run).status, WriteStatus::Uncertain);
    assert_eq!(harness.vault.puts(), 1, "a dropped write is never retried");
    assert_no_plaintext(&run, &harness);
    let output = harness.reconcile(&harness.journals()[0], ITEM).await;
    assert_eq!(
        serde_json::from_slice::<WriteReceipt>(&output.stdout)
            .unwrap()
            .status,
        WriteStatus::UpdatedUnverified
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn end_of_input_or_interrupt_at_the_challenge_never_writes() {
    let harness = Harness::start().await;
    for answer in [Answer::Eof, Answer::Interrupt] {
        let run = harness.update(&[], NEW_VALUES, None, answer).await;
        assert!(!run.output.status.success());
        assert!(run.terminal.contains("Authorize"));
        assert!(run.output.stdout.is_empty());
        assert_no_plaintext(&run, &harness);
    }
    assert_eq!(harness.vault.puts(), 0);
    assert!(harness.journals().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_passkey_or_changed_uri_match_is_updated_unverified() {
    let harness = Harness::start().await;
    for mode in [
        PutMode::ApplyDroppingPasskey,
        PutMode::ApplyChangingUriMatch,
    ] {
        harness.vault.state.lock().unwrap().put_mode = mode;
        let run = harness.update(&[], NEW_VALUES, None, Answer::Approve).await;
        assert!(!run.output.status.success());
        assert_eq!(receipt(&run).status, WriteStatus::UpdatedUnverified);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn prompt_mode_refuses_a_missing_password_before_asking_for_the_secret() {
    let harness = Harness::start().await;
    harness.vault.state.lock().unwrap().item["login"]["password"] = serde_json::Value::Null;
    let run = harness
        .update(
            &["--prompt"],
            b"",
            Some("new-password-private"),
            Answer::Approve,
        )
        .await;
    assert!(!run.output.status.success());
    assert!(String::from_utf8_lossy(&run.output.stderr).contains("selected field missing"));
    assert!(
        !run.terminal.contains("Secret password"),
        "prompted for a missing field"
    );
    assert_eq!(harness.vault.puts(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_resolves_an_uncertain_update_of_an_item_moved_or_trashed_since() {
    let harness = Harness::start().await;
    harness.vault.state.lock().unwrap().put_mode = PutMode::LoseWithoutApplying;
    let lost = harness.update(&[], NEW_VALUES, None, Answer::Approve).await;
    assert_eq!(receipt(&lost).status, WriteStatus::Uncertain);
    {
        // Someone trashes the item after the uncertain attempt.
        let mut state = harness.vault.state.lock().unwrap();
        state.item["deletedDate"] = json!("2026-11-21T11:00:00.000000Z");
        state.bump();
    }
    let output = harness.reconcile(&harness.journals()[0], ITEM).await;
    assert_eq!(
        serde_json::from_slice::<WriteReceipt>(&output.stdout)
            .unwrap()
            .status,
        WriteStatus::UpdatedUnverified
    );
    assert_eq!(
        WriteJournal::read(&harness.journals()[0])
            .unwrap()
            .receipt
            .status,
        WriteStatus::UpdatedUnverified,
        "the item is no longer blocked"
    );
    assert_eq!(harness.vault.puts(), 1);
}

/// Two approved invocations for one item. `offset` is when the second starts;
/// every item GET is delayed by `delay`, so the phases overlap predictably.
async fn concurrent_pair(
    harness: &Harness,
    delay: std::time::Duration,
    offset: std::time::Duration,
) -> (Run, Run) {
    harness.vault.state.lock().unwrap().get_delay = Some(delay);
    let first = harness.update(&[], NEW_VALUES, None, Answer::Approve);
    let second = async {
        tokio::time::sleep(offset).await;
        harness.update(&[], NEW_VALUES, None, Answer::Approve).await
    };
    tokio::join!(first, second)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_concurrent_update_of_the_same_item_is_refused_while_the_first_holds_the_lock() {
    let harness = Harness::start().await;
    let delay = std::time::Duration::from_secs(3);
    // The second decision lands while the first is between its fresh read and its PUT.
    let (first, second) = concurrent_pair(&harness, delay, delay / 2).await;
    assert_eq!(receipt(&first).status, WriteStatus::Verified);
    assert!(!second.output.status.success());
    assert!(
        String::from_utf8_lossy(&second.output.stderr).contains("in progress"),
        "{}",
        String::from_utf8_lossy(&second.output.stderr)
    );
    assert!(second.output.stdout.is_empty());
    assert_eq!(harness.vault.puts(), 1);
    assert_eq!(harness.journals().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_uncertain_attempt_recorded_during_review_blocks_the_second_decision() {
    let harness = Harness::start().await;
    harness.vault.state.lock().unwrap().put_mode = PutMode::LoseWithoutApplying;
    let delay = std::time::Duration::from_secs(2);
    // The second passes its first check, then decides after the first ended uncertain.
    let (first, second) = concurrent_pair(&harness, delay, delay * 3 / 2).await;
    assert_eq!(receipt(&first).status, WriteStatus::Uncertain);
    assert!(!second.output.status.success());
    assert!(String::from_utf8_lossy(&second.output.stderr).contains("uncertain"));
    assert!(second.terminal.contains("Authorize"));
    assert_eq!(harness.vault.puts(), 1);
}
