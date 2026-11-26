//! Protected update of one pinned item (issue 48 phase 2), over the same
//! blocking client as the protected create. The body is built and verified by
//! `crate::secret_update`, exactly as the trusted CLI path does it (D7, D14).
use super::VaultwardenBackend;
use crate::{
    access::{
        policy::{UpdateEffect, UpdateReview},
        ports::SessionError,
    },
    secret_storage::{SecretImport, WriteStatus},
    secret_update::{ItemSnapshot, PreparedUpdate, history_timestamp, plan_update, verify_updated},
};

impl VaultwardenBackend {
    fn update_server_matches(&self, effect: &UpdateEffect) -> bool {
        self.config
            .server
            .as_deref()
            .map(|server| server.trim_end_matches('/'))
            == Some(effect.server_key())
    }
    /// The account/folder binding from a fresh sync, then a bounded GET of
    /// the pinned item whose binding (ID, personal, folder, name) must hold.
    fn bound_item(&self, effect: &UpdateEffect) -> Result<ItemSnapshot, SessionError> {
        if !self.compatible || !effect.valid() || !self.update_server_matches(effect) {
            return Err(SessionError::InvalidRequest);
        }
        let (_, keys) = self.session.as_ref().ok_or(SessionError::Locked)?;
        effect
            .destination
            .check_sync(&self.storage_sync()?, keys, false)
            .map_err(|_error| SessionError::BackendUnavailable)?;
        let snapshot = self.read_item(effect)?;
        snapshot
            .check_binding(keys, &effect.destination)
            .map_err(|_error| SessionError::BackendUnavailable)?;
        Ok(snapshot)
    }
    fn read_item(&self, effect: &UpdateEffect) -> Result<ItemSnapshot, SessionError> {
        let raw: serde_json::Value = serde_json::from_slice(&self.ssh_response(&effect.item_id)?)
            .map_err(|_error| SessionError::BackendUnavailable)?;
        ItemSnapshot::parse(raw, &effect.item_id).map_err(|_error| SessionError::BackendUnavailable)
    }

    pub(super) fn review_update(&self, effect: &UpdateEffect) -> Result<String, SessionError> {
        self.bound_item(effect)
            .map(|snapshot| snapshot.revision().to_owned())
    }

    pub(super) fn prepare_update(
        &self,
        review: &UpdateReview,
        input: &SecretImport,
    ) -> Result<PreparedUpdate, SessionError> {
        let effect = review.effect();
        if input.selectors() != effect.sorted_fields() {
            return Err(SessionError::InvalidRequest);
        }
        let fresh = self.bound_item(&effect)?;
        // The approval covers the reviewed revision only (D2): any write
        // since the request was created consumes it with nothing sent.
        if fresh.revision() != review.expected_revision {
            return Err(SessionError::InvalidRequest);
        }
        let since = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_error| SessionError::BackendUnavailable)?;
        let (_, keys) = self.session.as_ref().ok_or(SessionError::Locked)?;
        let plan = plan_update(
            keys,
            &effect.destination,
            &fresh,
            input,
            &history_timestamp(since),
        )
        .map_err(|_error| SessionError::InvalidRequest)?;
        Ok(PreparedUpdate::new(fresh, plan))
    }

    pub(super) fn put_update(
        &self,
        review: &UpdateReview,
        prepared: &PreparedUpdate,
        live: &dyn Fn() -> bool,
    ) -> Result<(), WriteStatus> {
        let effect = review.effect();
        if !self.compatible || !effect.valid() || !self.update_server_matches(&effect) {
            return Err(WriteStatus::Failed);
        }
        let (token, _) = self.session.as_ref().ok_or(WriteStatus::Failed)?;
        // The body is bound to the reviewed revision (`lastKnownRevisionDate`).
        if prepared
            .body()
            .get("lastKnownRevisionDate")
            .and_then(serde_json::Value::as_str)
            != Some(review.expected_revision.as_str())
        {
            return Err(WriteStatus::Failed);
        }
        let url = self
            .url(&format!("api/ciphers/{}", effect.item_id))
            .map_err(|_error| WriteStatus::Failed)?;
        if !live() {
            return Err(WriteStatus::Failed);
        }
        let response = self
            .client
            .put(url)
            .bearer_auth(token.expose())
            .json(prepared.body())
            .send()
            .map_err(|_error| WriteStatus::Uncertain)?;
        let status = response.status();
        if !status.is_success() {
            // D11: Vaultwarden validates (stale revision included) before committing.
            return Err(
                if matches!(status.as_u16(), 400 | 401 | 403 | 404 | 405 | 422) {
                    WriteStatus::Failed
                } else {
                    WriteStatus::Uncertain
                },
            );
        }
        let body = Self::body(response).map_err(|_error| WriteStatus::Uncertain)?;
        let value: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_error| WriteStatus::Uncertain)?;
        if value.get("id").and_then(serde_json::Value::as_str) != Some(effect.item_id.as_str()) {
            return Err(WriteStatus::Uncertain);
        }
        Ok(())
    }

    pub(super) fn check_update(
        &self,
        review: &UpdateReview,
        prepared: &PreparedUpdate,
        input: &SecretImport,
    ) -> Result<(), SessionError> {
        let effect = review.effect();
        let after = self.bound_item(&effect)?;
        let (_, keys) = self.session.as_ref().ok_or(SessionError::Locked)?;
        verify_updated(
            keys,
            &effect.destination,
            prepared.before(),
            prepared.body(),
            &after,
            input,
        )
        .map_err(|_error| SessionError::BackendUnavailable)
    }

    /// D9 without the folder/name binding when the revision moved: a move,
    /// rename or trash also bumps it, and none of them proves the write.
    pub(super) fn reconcile_item(
        &self,
        review: &UpdateReview,
    ) -> Result<WriteStatus, SessionError> {
        let effect = review.effect();
        if !self.compatible || !effect.valid() || !self.update_server_matches(&effect) {
            return Err(SessionError::InvalidRequest);
        }
        let (_, keys) = self.session.as_ref().ok_or(SessionError::Locked)?;
        effect
            .destination
            .check_sync(&self.storage_sync()?, keys, false)
            .map_err(|_error| SessionError::BackendUnavailable)?;
        let current = self.read_item(&effect)?;
        if current.revision() == review.expected_revision {
            current
                .check_binding(keys, &effect.destination)
                .map_err(|_error| SessionError::BackendUnavailable)?;
            Ok(WriteStatus::Failed)
        } else {
            Ok(WriteStatus::UpdatedUnverified)
        }
    }
}

#[cfg(test)]
#[path = "update_tests.rs"]
mod tests;
