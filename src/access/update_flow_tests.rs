//! Protected update through the provider application (issue 48 phase 2), on
//! the platform test fixtures with the synthetic item of
//! `update_test_support`. Runs on Linux and on native macOS.
use super::{
    direct_request::{DirectRequestError, DirectStatus},
    policy::UPDATE_EFFECT_LINE,
    ports::{
        ChildEnvironment, CleanupEvidence, ExecutionError, ExecutionImage, ExecutionOutcome,
        ProcessSupervisor, ProducerOutput, ProtectedExecution,
    },
    update_test_support::{self as vault, FIRST_REVISION, ITEM, effect, update_draft},
};
use crate::secret_storage::{SecretImport, WriteStatus};
use std::{cell::Cell, sync::atomic::Ordering};

const SECRET: &str = "rotated-private-sentinel";

#[cfg(target_os = "linux")]
mod platform {
    use crate::access::direct_request_tests::{Fixture, approval, fixture};
    pub(super) struct Env(pub Fixture);
    impl Env {
        pub fn new() -> Self {
            Self(fixture())
        }
        pub fn app(&self) -> &crate::access::application::ProviderApplication {
            &self.0.app
        }
        pub fn root(&self) -> std::path::PathBuf {
            self.0.dir.path().join("provider")
        }
        pub fn clock(&self) -> &std::sync::atomic::AtomicU64 {
            &self.0.monotonic
        }
        pub fn image(&self) -> &'static str {
            "deploy-image"
        }
        pub fn approval(&self, id: &str) -> crate::access::direct_request::AuthenticatedApproval {
            approval(&self.0, id)
        }
    }
}
#[cfg(target_os = "macos")]
mod platform {
    use crate::adapters::native::tests::Fixture;
    pub(super) struct Env(pub Fixture);
    impl Env {
        pub fn new() -> Self {
            Self(Fixture::new())
        }
        pub fn app(&self) -> &crate::access::application::ProviderApplication {
            self.0.app()
        }
        pub fn root(&self) -> std::path::PathBuf {
            self.0.root.path().join("provider")
        }
        pub fn clock(&self) -> &std::sync::atomic::AtomicU64 {
            &self.0.clock
        }
        pub fn image(&self) -> &'static str {
            "native-ssh"
        }
        pub fn approval(&self, id: &str) -> crate::access::direct_request::AuthenticatedApproval {
            let app = self.0.app();
            app.prepare_approval(app.human_owner(), id)
                .unwrap()
                .authenticate(
                    crate::access::ports::SensitiveString::new("synthetic-password".into()),
                    &crate::adapters::native::tests::Auth,
                )
                .unwrap()
        }
    }
}
use platform::Env;

impl Env {
    pub(super) fn approve(&self, id: &str) {
        assert_eq!(
            self.app().commit_approval(self.approval(id)).unwrap(),
            DirectStatus::Approved
        );
    }
    /// A fresh fixture with the update policy provisioned and a clean item.
    pub(super) fn with_update() -> Self {
        vault::reset();
        let env = Self::new();
        env.app()
            .create_operation(env.app().human_owner(), update_draft(env.image()))
            .unwrap();
        env
    }
    pub(super) fn submit(&self) -> Result<String, DirectRequestError> {
        self.app()
            .submit_direct(
                self.app().human_owner(),
                vault::update_submission(),
                &NoLaunch,
            )
            .map(|receipt| receipt.id)
    }
    fn run(&self, id: &str, producer: &Producer) -> Result<DirectStatus, DirectRequestError> {
        self.app()
            .run_execution(self.app().human_owner(), id, producer, &Supervisor)
    }
    fn state(&self) -> String {
        std::fs::read_to_string(self.root().join("provider-state.json")).unwrap()
    }
    fn receipt(&self, id: &str) -> serde_json::Value {
        let state: serde_json::Value = serde_json::from_str(&self.state()).unwrap();
        state["requests"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap()["direct"]["write_receipt"]
            .clone()
    }
}
struct NoLaunch;
impl super::ports::DirectReviewLauncher for NoLaunch {
    fn launch(&self, _: &str) -> Result<(), DirectRequestError> {
        Ok(())
    }
}

thread_local! {
    static PRODUCER_RUNS: Cell<usize> = const { Cell::new(0) };
}
fn runs() -> usize {
    PRODUCER_RUNS.with(Cell::get)
}
/// A producer that emits a fixed fd 3 document after a successful exit.
struct Producer(&'static [u8]);
struct Output(&'static [u8]);
impl ProducerOutput for Output {
    fn read(&mut self, evidence: CleanupEvidence) -> Result<SecretImport, ExecutionError> {
        assert_eq!(evidence, CleanupEvidence::Reaped);
        SecretImport::parse_update(self.0).map_err(|_error| ExecutionError::ExecutionFailed)
    }
}
impl ProtectedExecution for Producer {
    type Prepared = ();
    fn prepare(&self, _: ExecutionImage<'_>, argv: Vec<String>) -> Result<(), ExecutionError> {
        assert_eq!(argv, ["rotate-token"]);
        Ok(())
    }
    fn prepare_producer(&self, (): &mut ()) -> Result<Box<dyn ProducerOutput>, ExecutionError> {
        Ok(Box::new(Output(self.0)))
    }
}
struct Supervisor;
impl ProcessSupervisor<Producer> for Supervisor {
    fn available(&self) -> bool {
        true
    }
    fn supervise(
        &self,
        (): (),
        environment: ChildEnvironment,
    ) -> Result<ExecutionOutcome, ExecutionError> {
        // No vault value or provider authority reaches the producer.
        assert_eq!(environment.entries().len(), 2);
        PRODUCER_RUNS.with(|runs| runs.set(runs.get() + 1));
        Ok(ExecutionOutcome::ExitedZero)
    }
}
const GOOD: Producer = Producer(br#"{"password":"rotated-private-sentinel"}"#);

#[test]
fn update_request_binds_the_revision_read_at_submission_into_the_review() {
    let env = Env::with_update();
    let id = env.submit().unwrap();
    let review = env
        .app()
        .review_direct(env.app().human_owner(), &id)
        .unwrap();
    assert_eq!(review.effect, UPDATE_EFFECT_LINE);
    assert!(review.create.is_none());
    let update = review.update.unwrap();
    assert_eq!(update.expected_revision, FIRST_REVISION);
    assert_eq!(update.item_id, ITEM);
    assert_eq!(update.fields, ["password"]);
    assert_eq!(update.destination, effect().destination);
    assert_eq!(review.target, effect().destination.reference);
    // Provisioning and submission each read the item; neither wrote.
    vault::with(|item| {
        assert_eq!((item.reviews, item.prepares, item.puts), (2, 0, 0));
    });
    // A broken binding refuses the request: nothing to review.
    vault::with(|item| item.binding_ok = false);
    assert!(env.submit().is_err());
}

#[test]
fn approved_update_runs_the_producer_once_puts_once_and_records_verified_without_values() {
    let env = Env::with_update();
    PRODUCER_RUNS.with(|runs| runs.set(0));
    let id = env.submit().unwrap();
    assert!(env.run(&id, &GOOD).is_err(), "no execution before approval");
    assert_eq!(runs(), 0);
    env.approve(&id);
    assert_eq!(
        env.run(&id, &GOOD).unwrap(),
        DirectStatus::Completed { exit_code: 0 }
    );
    assert!(env.run(&id, &GOOD).is_err(), "one-shot");
    assert_eq!(runs(), 1);
    vault::with(|item| {
        assert_eq!((item.puts, item.verifies), (1, 1));
        assert_eq!(item.received, [SECRET]);
    });
    let receipt = env.receipt(&id);
    assert_eq!(receipt["status"], "verified");
    assert_eq!(receipt["item_id"], ITEM);
    assert_eq!(receipt["attempt_id"], id.as_str());
    let state = env.state();
    assert!(!state.contains(SECRET));
    let history = env.app().history(env.app().human_owner(), None).unwrap();
    let last = history.iter().find(|e| e.request_id == id).unwrap();
    assert_eq!(
        last.write_receipt.as_ref().unwrap().status,
        WriteStatus::Verified
    );
    assert_eq!(last.update.as_ref().unwrap().fields, ["password"]);
    assert!(!serde_json::to_string(&history).unwrap().contains(SECRET));
    // Reconciling a definite receipt never rewrites it (the revision moved).
    let receipt = env
        .app()
        .reconcile_write(env.app().human_owner(), &id, ITEM)
        .unwrap();
    assert_eq!(receipt.status, WriteStatus::Verified);
}

#[test]
fn a_write_since_review_consumes_the_approval_before_or_after_the_producer() {
    // Before the producer: refused without running it.
    let env = Env::with_update();
    PRODUCER_RUNS.with(|runs| runs.set(0));
    let id = env.submit().unwrap();
    env.approve(&id);
    vault::with(|item| item.revision = "2026-11-21T11:00:00.000000Z".into());
    assert!(env.run(&id, &GOOD).is_err());
    assert_eq!(runs(), 0);
    assert!(env.receipt(&id).is_null(), "nothing journaled");
    vault::with(|item| item.revision = FIRST_REVISION.into());
    assert!(env.run(&id, &GOOD).is_err(), "the approval is consumed");
    // Between the producer and the PUT: the fresh read refuses.
    let env = Env::with_update();
    let id = env.submit().unwrap();
    env.approve(&id);
    vault::with(|item| {
        item.before_prepare = Some(Box::new(|item: &mut vault::FakeItem| {
            item.revision = "2026-11-21T11:00:00.000000Z".into();
        }));
    });
    assert!(env.run(&id, &GOOD).is_err());
    vault::with(|item| assert_eq!((item.prepares, item.puts), (1, 0)));
    assert!(env.receipt(&id).is_null());
}

#[test]
fn producer_schema_mismatch_denial_expiry_and_lock_never_put() {
    for case in ["schema", "extra", "denied", "expired", "locked"] {
        let env = Env::with_update();
        let id = env.submit().unwrap();
        if case == "denied" {
            env.app().deny_direct(env.app().human_owner(), &id).unwrap();
        } else {
            env.approve(&id);
        }
        if case == "expired" {
            env.clock().fetch_add(100_000, Ordering::SeqCst);
        }
        if case == "locked" {
            env.app().lock().unwrap();
        }
        let producer = match case {
            "schema" => Producer(br#"{"notes":"rotated-private-sentinel"}"#),
            "extra" => Producer(br#"{"password":"a","notes":"b"}"#),
            _ => GOOD,
        };
        assert!(env.run(&id, &producer).is_err(), "{case}");
        vault::with(|item| assert_eq!(item.puts, 0, "{case}"));
    }
}

#[test]
fn uncertain_update_blocks_the_item_until_reconciled_and_is_never_repeated() {
    let env = Env::with_update();
    let first = env.submit().unwrap();
    env.approve(&first);
    vault::with(|item| item.put = Err(WriteStatus::Uncertain));
    assert!(env.run(&first, &GOOD).is_err());
    assert_eq!(env.receipt(&first)["status"], "uncertain");
    assert_eq!(env.receipt(&first)["item_id"], ITEM);
    // Another approved update of the same item is refused before its PUT.
    vault::with(|item| item.put = Ok(()));
    let second = env.submit().unwrap();
    env.approve(&second);
    assert!(env.run(&second, &GOOD).is_err());
    vault::with(|item| assert_eq!(item.puts, 1));
    // Reconcile is read-only, rejects another item, and never PUTs.
    let owner = env.app().human_owner();
    assert!(
        env.app()
            .reconcile_write(owner, &first, "44444444-4444-4444-4444-444444444444")
            .is_err()
    );
    let receipt = env.app().reconcile_write(owner, &first, ITEM).unwrap();
    assert_eq!(receipt.status, WriteStatus::Failed, "revision unchanged");
    assert_eq!(
        env.app().reconcile_write(owner, &first, ITEM).unwrap(),
        receipt,
        "idempotent"
    );
    // Two read-only reconciliations; the first durable resolution stands.
    vault::with(|item| assert_eq!((item.puts, item.reconciles), (1, 2)));
    // Unblocked: a fresh request writes.
    let third = env.submit().unwrap();
    env.approve(&third);
    assert!(env.run(&third, &GOOD).is_ok());
    assert_eq!(env.receipt(&third)["status"], "verified");
}

#[test]
fn reconcile_reports_updated_unverified_when_anything_wrote_since() {
    let env = Env::with_update();
    let id = env.submit().unwrap();
    env.approve(&id);
    vault::with(|item| item.put = Err(WriteStatus::Uncertain));
    assert!(env.run(&id, &GOOD).is_err());
    vault::with(|item| item.revision = "2026-11-21T12:00:00.000000Z".into());
    let receipt = env
        .app()
        .reconcile_write(env.app().human_owner(), &id, ITEM)
        .unwrap();
    assert_eq!(receipt.status, WriteStatus::UpdatedUnverified);
}

#[test]
fn definite_rejection_and_failed_verification_keep_honest_receipts() {
    for (put, verify_ok, status) in [
        (Err(WriteStatus::Failed), true, "failed"),
        (Ok(()), false, "updated_unverified"),
    ] {
        let env = Env::with_update();
        let id = env.submit().unwrap();
        env.approve(&id);
        vault::with(|item| {
            item.put = put;
            item.verify_ok = verify_ok;
        });
        assert!(env.run(&id, &GOOD).is_err(), "{status}");
        assert_eq!(env.receipt(&id)["status"], status);
        vault::with(|item| assert_eq!(item.puts, 1, "{status}"));
    }
}

#[test]
fn an_update_review_cannot_be_approved_once_the_item_changed() {
    let env = Env::with_update();
    let id = env.submit().unwrap();
    vault::with(|item| item.revision = "2026-11-21T12:00:00.000000Z".into());
    // The decision path rereads the item: the stale review is not committed.
    assert!(env.app().commit_approval(env.approval(&id)).is_err());
    assert_ne!(
        env.app()
            .direct_status(env.app().human_owner(), &id)
            .unwrap(),
        DirectStatus::Approved
    );
    vault::with(|item| assert_eq!(item.puts, 0));
}
