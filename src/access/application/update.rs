//! Protected update of one existing item (issue 48 phase 2): the revision
//! bound at request creation, and the one-shot write after a fully reaped
//! producer. Nothing here retries a producer or a PUT.
use super::{ApplicationExecution, Authority, ProviderApplication};
use crate::access::{
    direct_request::{ApprovalBinding, DirectRequestError},
    policy::UpdateReview,
    ports::{
        CleanupEvidence, ExecutionControl, ExecutionOutcome, ProducerOutput, SessionError,
        Supervision,
    },
};
use crate::secret_storage::WriteStatus;

impl ProviderApplication {
    /// The revision an update request binds, read now (D1 checks and a GET).
    /// `None` for every policy that is not an update.
    pub(super) fn update_revision(
        authority: &mut Authority,
        operation: &str,
    ) -> Result<Option<String>, SessionError> {
        let Some(effect) = authority
            .provider
            .operation(operation)
            .map_err(|_error| SessionError::BackendUnavailable)?
            .and_then(|metadata| metadata.policy.update)
        else {
            return Ok(None);
        };
        authority.backend.probe_compatibility()?;
        authority.backend.update_review(&effect).map(Some)
    }

    /// Before the producer runs: the item must still be bound and still have
    /// the reviewed revision, so a stale approval never starts a producer.
    pub(super) fn update_still_reviewed(
        authority: &mut Authority,
        review: &UpdateReview,
    ) -> Result<(), DirectRequestError> {
        if authority.backend.update_review(&review.effect())? == review.expected_revision {
            Ok(())
        } else {
            Err(DirectRequestError::Unavailable)
        }
    }

    /// The write after a successful, fully reaped producer: fresh sync and GET
    /// (the reviewed revision or nothing), journal, exactly one PUT bound to
    /// that revision, then verification. An uncertain result stays durable.
    pub(super) fn write_update(
        &self,
        review: &UpdateReview,
        report: &Supervision,
        producer: Option<&mut Box<dyn ProducerOutput>>,
        control: &ApplicationExecution<'_>,
        binding: &ApprovalBinding,
        revocation_epoch: u64,
    ) -> Result<(), DirectRequestError> {
        if report.outcome != Ok(ExecutionOutcome::ExitedZero)
            || report.cleanup != CleanupEvidence::Reaped
            || !control.live()
        {
            return Err(DirectRequestError::Unavailable);
        }
        let input = producer
            .ok_or(DirectRequestError::Unavailable)?
            .read(report.cleanup)
            .map_err(|_error| DirectRequestError::Unavailable)?;
        if input.selectors() != review.effect().sorted_fields() {
            return Err(DirectRequestError::InvalidRequest);
        }
        let id = binding.request_id.as_str();
        let mut authority = self
            .gate
            .lock()
            .map_err(|_error| DirectRequestError::Unavailable)?;
        self.execution_live_current(&mut authority, id, revocation_epoch)?;
        if !authority.provider.execution_matches(binding)? {
            return Err(DirectRequestError::Unavailable);
        }
        let prepared = authority.backend.update_prepare(review, &input)?;
        self.execution_live_current(&mut authority, id, revocation_epoch)?;
        authority.provider.begin_write(binding)?;
        let item = Some(review.item_id.clone());
        // Serialize the irreversible write with cancellation, as create does.
        let write_gate = self
            .release_gate
            .lock()
            .map_err(|_error| DirectRequestError::Unavailable)?;
        if !control.live_fast() {
            drop(write_gate);
            authority
                .provider
                .record_write(binding, item, WriteStatus::Failed)?;
            return Err(DirectRequestError::Unavailable);
        }
        let result = authority
            .backend
            .update_secret(review, &prepared, &|| control.live_fast());
        drop(write_gate);
        match result {
            Ok(()) => {
                authority.provider.record_write(
                    binding,
                    item.clone(),
                    WriteStatus::UpdatedUnverified,
                )?;
                if !control.live_fast()
                    || authority
                        .backend
                        .verify_update(review, &prepared, &input)
                        .is_err()
                {
                    return Err(DirectRequestError::Unavailable);
                }
                authority
                    .provider
                    .record_write(binding, item, WriteStatus::Verified)?;
                Ok(())
            }
            Err(status) => {
                authority.provider.record_write(binding, item, status)?;
                Err(DirectRequestError::Unavailable)
            }
        }
    }
}
