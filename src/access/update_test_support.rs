//! A synthetic, per-thread item for the application's protected update path
//! (issue 48 phase 2). The platform test backends delegate their update
//! methods here; the HTTP contract itself is tested in the Vaultwarden adapter.
use super::{
    policy::{UpdateEffect, UpdateReview},
    ports::SessionError,
};
use crate::{
    secret_storage::{SecretImport, WriteStatus},
    secret_update::PreparedUpdate,
};
use std::cell::RefCell;

/// The update policy every application and companion test provisions.
pub(crate) fn effect() -> UpdateEffect {
    UpdateEffect {
        server: "https://vault.example".into(),
        item_id: ITEM.into(),
        destination: crate::secret_storage::Destination {
            account_id: "11111111-1111-1111-1111-111111111111".into(),
            folder: "homelab/production".into(),
            folder_id: "22222222-2222-2222-2222-222222222222".into(),
            reference: "homelab/production/github/token".into(),
        },
        fields: vec!["password".into()],
    }
}
pub(crate) fn update_draft(image: &str) -> super::policy::OperationPolicyDraft {
    super::policy::OperationPolicyDraft {
        id: "rotate-token".into(),
        description: "Rotate the deploy token".into(),
        image_id: image.into(),
        targets: vec![],
        arguments: vec![],
        credentials: vec![],
        ssh: None,
        create: None,
        update: Some(effect()),
        require_password: false,
    }
}
/// A request for the `rotate-token` policy (it takes no arguments).
pub(crate) fn update_submission() -> super::direct_request::DirectSubmission {
    super::direct_request::DirectSubmission {
        operation: "rotate-token".into(),
        revision: None,
        values: vec![],
    }
}
pub(crate) const ITEM: &str = "33333333-3333-3333-3333-333333333333";
pub(crate) const FIRST_REVISION: &str = "2026-11-21T10:00:00.000000Z";

pub(crate) type PrepareHook = Box<dyn FnOnce(&mut FakeItem)>;
/// What the synthetic vault holds and how its next write behaves.
pub(crate) struct FakeItem {
    pub revision: String,
    /// Whether the D1 account/folder/item binding holds.
    pub binding_ok: bool,
    /// Result of the next PUT. `Ok` bumps the revision.
    pub put: Result<(), WriteStatus>,
    pub verify_ok: bool,
    /// Runs inside `update_prepare`, before the revision check.
    pub before_prepare: Option<PrepareHook>,
    pub reviews: usize,
    pub prepares: usize,
    pub puts: usize,
    pub verifies: usize,
    pub reconciles: usize,
    /// Values received by the PUT, for leak checks by the caller.
    pub received: Vec<String>,
}
impl Default for FakeItem {
    fn default() -> Self {
        Self {
            revision: FIRST_REVISION.into(),
            binding_ok: true,
            put: Ok(()),
            verify_ok: true,
            before_prepare: None,
            reviews: 0,
            prepares: 0,
            puts: 0,
            verifies: 0,
            reconciles: 0,
            received: Vec::new(),
        }
    }
}
thread_local! {
    pub(crate) static FAKE_ITEM: RefCell<FakeItem> = RefCell::new(FakeItem::default());
}
/// Reset the synthetic item for a new test on this thread.
pub(crate) fn reset() {
    FAKE_ITEM.with(|item| *item.borrow_mut() = FakeItem::default());
}
pub(crate) fn with<T>(f: impl FnOnce(&mut FakeItem) -> T) -> T {
    FAKE_ITEM.with(|item| f(&mut item.borrow_mut()))
}

pub(crate) fn update_review(effect: &UpdateEffect) -> Result<String, SessionError> {
    with(|item| {
        item.reviews += 1;
        if effect.item_id != ITEM || !effect.valid() || !item.binding_ok {
            return Err(SessionError::BackendUnavailable);
        }
        Ok(item.revision.clone())
    })
}
pub(crate) fn update_prepare(
    review: &UpdateReview,
    input: &SecretImport,
) -> Result<PreparedUpdate, SessionError> {
    let hook = with(|item| {
        item.prepares += 1;
        item.before_prepare.take()
    });
    if let Some(hook) = hook {
        with(hook);
    }
    with(|item| {
        if input.selectors() != review.effect().sorted_fields() {
            return Err(SessionError::InvalidRequest);
        }
        if !item.binding_ok {
            return Err(SessionError::BackendUnavailable);
        }
        if item.revision != review.expected_revision {
            return Err(SessionError::InvalidRequest);
        }
        Ok(PreparedUpdate::synthetic(ITEM, &item.revision))
    })
}
pub(crate) fn update_secret(
    review: &UpdateReview,
    prepared: &PreparedUpdate,
    live: &dyn Fn() -> bool,
) -> Result<(), WriteStatus> {
    if !live() || prepared.before().revision() != review.expected_revision {
        return Err(WriteStatus::Failed);
    }
    with(|item| {
        item.puts += 1;
        if item.put.is_ok() {
            item.revision = format!("2026-11-21T10:{:02}:00.000000Z", item.puts);
        }
        item.put
    })
}
pub(crate) fn verify_update(input: &SecretImport) -> Result<(), SessionError> {
    with(|item| {
        item.verifies += 1;
        item.received.extend(input.password.iter().cloned());
        if item.verify_ok {
            Ok(())
        } else {
            Err(SessionError::BackendUnavailable)
        }
    })
}
pub(crate) fn reconcile_update(review: &UpdateReview) -> Result<WriteStatus, SessionError> {
    with(|item| {
        item.reconciles += 1;
        if !item.binding_ok {
            return Err(SessionError::BackendUnavailable);
        }
        Ok(if item.revision == review.expected_revision {
            WriteStatus::Failed
        } else {
            WriteStatus::UpdatedUnverified
        })
    })
}

/// The five `SecretBackend` update methods, delegating to this module.
macro_rules! delegate_update_backend {
    () => {
        fn update_review(
            &mut self,
            effect: &crate::access::policy::UpdateEffect,
        ) -> Result<String, SessionError> {
            crate::access::update_test_support::update_review(effect)
        }
        fn update_prepare(
            &mut self,
            review: &crate::access::policy::UpdateReview,
            input: &crate::secret_storage::SecretImport,
        ) -> Result<crate::secret_update::PreparedUpdate, SessionError> {
            crate::access::update_test_support::update_prepare(review, input)
        }
        fn update_secret(
            &mut self,
            review: &crate::access::policy::UpdateReview,
            prepared: &crate::secret_update::PreparedUpdate,
            live: &dyn Fn() -> bool,
        ) -> Result<(), crate::secret_storage::WriteStatus> {
            crate::access::update_test_support::update_secret(review, prepared, live)
        }
        fn verify_update(
            &mut self,
            _: &crate::access::policy::UpdateReview,
            _: &crate::secret_update::PreparedUpdate,
            input: &crate::secret_storage::SecretImport,
        ) -> Result<(), SessionError> {
            crate::access::update_test_support::verify_update(input)
        }
        fn reconcile_update(
            &mut self,
            review: &crate::access::policy::UpdateReview,
        ) -> Result<crate::secret_storage::WriteStatus, SessionError> {
            crate::access::update_test_support::reconcile_update(review)
        }
    };
}
pub(crate) use delegate_update_backend;
