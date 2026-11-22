//! Trusted terminal update of selected fields of one existing item (issue 48).
use super::{
    CommandOptions, Config, Context, Result, SyncContext, authorize_on_terminal, fresh_attempt_id,
    load_sync_context, read_secret_input, resolve_destination,
};
use crate::{
    crypto::CryptoKeys,
    secret_storage::{Destination, WriteReceipt, WriteStatus, valid_id},
    secret_update::{
        ItemSnapshot, PASSWORD_HISTORY_LIMIT, history_timestamp, plan_update, verify_updated,
    },
    write_journal::{UpdateRecord, WriteJournal},
};

/// A bound, fresh read: the account/folder namespace from a sync, then the item.
async fn bound_snapshot(
    ctx: &SyncContext,
    keys: &CryptoKeys,
    destination: &Destination,
    id: &str,
) -> Result<ItemSnapshot> {
    let sync = ctx.api.sync(&ctx.access_token).await?;
    destination.check_sync(&sync, keys, false)?;
    let raw = ctx.api.cipher_json_by_id(&ctx.access_token, id).await?;
    let snapshot = ItemSnapshot::parse(raw, id)?;
    Ok(snapshot)
}

/// The current time in the form official clients use for password history.
fn now() -> Result<String> {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_error| anyhow::anyhow!("system clock unavailable"))?;
    Ok(history_timestamp(since))
}

/// Replace selected fields after a fresh terminal decision bound to the exact
/// item, binding, fields and revision. Never retried; see the issue-48 spec.
/// # Errors
/// Returns an error when validation, authorization, cryptography or backend
/// access fails, or when the write is not verified.
pub async fn update_secret(
    id: &str,
    account: &str,
    folder: &str,
    reference: &str,
    expected_revision: Option<&str>,
    prompt: bool,
    opts: &CommandOptions,
) -> Result<()> {
    anyhow::ensure!(valid_id(id), "invalid item ID");
    let ctx = load_sync_context(opts.allow_insecure_http).await?;
    let keys = ctx
        .config
        .get_keys_for_cipher(None)
        .context("vault locked")?;
    let destination = resolve_destination(&ctx.sync_response, keys, account, folder, reference)?;
    destination.check_sync(&ctx.sync_response, keys, false)?;
    let server = ctx.config.server.clone().context("server unavailable")?;
    let root = Config::config_dir()?.join("write-attempts");
    WriteJournal::ensure_no_uncertain_update(&root, &server, id)?;
    let reviewed =
        ItemSnapshot::parse(ctx.api.cipher_json_by_id(&ctx.access_token, id).await?, id)?;
    anyhow::ensure!(
        expected_revision.is_none_or(|expected| expected == reviewed.revision()),
        "item revision differs from the expected revision"
    );
    if prompt {
        reviewed.check_binding(keys, &destination)?;
        reviewed.require_password()?;
    }
    let input = read_secret_input(prompt, true)?;
    // Refuse missing or unsupported fields before asking for a decision.
    let preview = plan_update(keys, &destination, &reviewed, &input, &now()?)?;
    let attempt = fresh_attempt_id()?;
    let history = if preview.history.is_empty() {
        "none".to_owned()
    } else {
        format!(
            "old values of {} kept in password history (newest {PASSWORD_HISTORY_LIMIT})",
            preview.history.join(", ")
        )
    };
    let review = format!(
        "UPDATE personal vault item (no create)\nItem: {id}\nAccount: {account} at {server}\nFolder: {folder} ({})\nReference: {reference}\nExpected revision: {}\nFields replaced: {}\nPassword history: {history}",
        destination.folder_id,
        reviewed.revision(),
        input.selectors().join(", ")
    );
    authorize_on_terminal(&review, "update", &attempt, "update denied")?;
    // One update of an item at a time, from the uncertain check to the receipt.
    let _lock = WriteJournal::lock_update(&root, &server, id)?;
    // The approval covers the reviewed revision only: any edit since then refuses.
    let fresh = bound_snapshot(&ctx, keys, &destination, id)
        .await
        .map_err(|_error| anyhow::anyhow!("update preflight failed"))?;
    anyhow::ensure!(
        fresh.revision() == reviewed.revision(),
        "item changed since review; nothing was written"
    );
    let plan = plan_update(keys, &destination, &fresh, &input, &now()?)?;
    let mut journal = WriteJournal {
        server,
        destination,
        fields: input.selectors(),
        receipt: WriteReceipt {
            attempt_id: attempt,
            item_id: Some(id.to_owned()),
            status: WriteStatus::Uncertain,
        },
        update: Some(UpdateRecord {
            item_id: id.to_owned(),
            expected_revision: reviewed.revision().to_owned(),
        }),
    };
    let path = journal.begin(&root)?;
    match ctx
        .api
        .update_cipher(&ctx.access_token, id, &plan.body)
        .await
    {
        Ok(_accepted) => {
            journal.receipt.status = WriteStatus::UpdatedUnverified;
            journal.save(&path)?;
            if let Ok(after) = bound_snapshot(&ctx, keys, &journal.destination, id).await
                && verify_updated(
                    keys,
                    &journal.destination,
                    &fresh,
                    &plan.body,
                    &after,
                    &input,
                )
                .is_ok()
            {
                journal.receipt.status = WriteStatus::Verified;
            }
        }
        Err(status) => journal.receipt.status = status,
    }
    journal.save(&path)?;
    println!("{}", serde_json::to_string(&journal.receipt)?);
    anyhow::ensure!(
        journal.receipt.status == WriteStatus::Verified,
        "update is not verified; inspect durable receipt and reconcile; it is never retried"
    );
    Ok(())
}

/// Read-only resolution of an update receipt: an unchanged revision proves the
/// attempt wrote nothing; a newer one cannot be compared after a restart, also
/// when the item was moved or trashed since. Exits non-zero unless `verified`,
/// like `update` itself.
pub(super) async fn reconcile_update(
    journal_path: &std::path::Path,
    mut journal: WriteJournal,
    id: Option<&str>,
    opts: &CommandOptions,
) -> Result<()> {
    let update = journal.update.clone().context("not an update journal")?;
    if let Some(id) = id {
        anyhow::ensure!(valid_id(id), "invalid item ID");
        anyhow::ensure!(id == update.item_id, "cannot retarget a receipt");
        let ctx = load_sync_context(opts.allow_insecure_http).await?;
        anyhow::ensure!(
            ctx.config.server.as_deref() == Some(journal.server.as_str()),
            "server binding mismatch"
        );
        let keys = ctx
            .config
            .get_keys_for_cipher(None)
            .context("vault locked")?;
        journal
            .destination
            .check_sync(&ctx.sync_response, keys, false)?;
        let raw = ctx.api.cipher_json_by_id(&ctx.access_token, id).await?;
        let current = ItemSnapshot::parse(raw, id)?;
        if journal.receipt.status == WriteStatus::Uncertain {
            journal.receipt.status = if current.revision() == update.expected_revision {
                // Unchanged since the attempt: the binding still holds, nothing was written.
                current.check_binding(keys, &journal.destination)?;
                WriteStatus::Failed
            } else {
                // Any later write (including a move or a trash) bumps the revision.
                WriteStatus::UpdatedUnverified
            };
        }
        journal.save(journal_path)?;
    }
    println!("{}", serde_json::to_string(&journal.receipt)?);
    anyhow::ensure!(
        journal.receipt.status == WriteStatus::Verified,
        "update receipt is not verified; inspect the item before any new update"
    );
    Ok(())
}
