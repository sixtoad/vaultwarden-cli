use super::{
    application::ProviderApplication, direct_request::*, policy::*, ports::*, provider::Provider,
};
use std::{
    os::unix::fs::PermissionsExt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
type WallReadAction = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;
pub(crate) struct Clock {
    pub monotonic: Arc<AtomicU64>,
    pub wall: Arc<AtomicU64>,
    pub on_wall_read: WallReadAction,
}
impl SessionClock for Clock {
    fn now(&self) -> Duration {
        Duration::from_secs(self.monotonic.load(Ordering::SeqCst))
    }
    fn unix_seconds(&self) -> Result<u64, SessionError> {
        if let Some(action) = self.on_wall_read.lock().unwrap().take() {
            action();
        }
        Ok(self.wall.load(Ordering::SeqCst))
    }
}
type EligibilityAction = std::cell::RefCell<Option<Box<dyn FnMut() -> Result<bool, SessionError>>>>;
thread_local! {
    static ELIGIBILITY_ACTION: EligibilityAction = std::cell::RefCell::new(None);
    static BACKEND_UNLOCKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
struct Backend;
impl ProviderSession for Backend {
    fn probe_compatibility(&mut self) -> Result<(), SessionError> {
        Ok(())
    }
    fn unlock(&mut self, _: SensitiveString) -> Result<Duration, SessionError> {
        BACKEND_UNLOCKS.with(|count| count.set(count.get() + 1));
        Ok(Duration::from_secs(900))
    }
    fn clear(&mut self) -> Result<(), SessionError> {
        Ok(())
    }
}
impl SecretBackend for Backend {
    fn eligible(&mut self, _: &CredentialBinding<'_>) -> Result<bool, SessionError> {
        ELIGIBILITY_ACTION.with(|action| {
            action
                .borrow_mut()
                .as_mut()
                .map_or(Ok(true), |callback| callback())
        })
    }
    fn resolve(&mut self, _: &CredentialBinding<'_>) -> Result<Vec<SensitiveString>, SessionError> {
        panic!("request must not resolve secrets")
    }
}
pub(crate) struct Fixture {
    pub dir: tempfile::TempDir,
    pub app: Arc<ProviderApplication>,
    pub monotonic: Arc<AtomicU64>,
    pub wall: Arc<AtomicU64>,
    pub on_wall_read: WallReadAction,
}
pub(crate) fn fixture() -> Fixture {
    fixture_with_lifetime(DEFAULT_REQUEST_LIFETIME)
}
fn fixture_with_lifetime(lifetime: Duration) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let provider = Provider::start(dir.path().join("provider")).unwrap();
    let monotonic = Arc::new(AtomicU64::new(10));
    let wall = Arc::new(AtomicU64::new(1700000000));
    let on_wall_read = Arc::new(Mutex::new(None));
    let app = Arc::new(
        ProviderApplication::new_with_request_lifetime(
            provider,
            Box::new(Backend),
            Box::new(Clock {
                monotonic: monotonic.clone(),
                wall: wall.clone(),
                on_wall_read: on_wall_read.clone(),
            }),
            lifetime,
        )
        .unwrap(),
    );
    app.authenticate(SensitiveString::new("synthetic-password".into()))
        .unwrap();
    let path = dir.path().join("provider/provider-state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    state["approved_images"] = serde_json::json!([test_approved_image(dir.path(), "deploy-image")]);
    std::fs::write(path, serde_json::to_vec(&state).unwrap()).unwrap();
    app.activate_operation(operation_draft()).unwrap();
    Fixture {
        dir,
        app,
        monotonic,
        wall,
        on_wall_read,
    }
}
fn operation_draft() -> OperationPolicyDraft {
    OperationPolicyDraft {
        id: "deploy".into(),
        description: "Deploy <img src=x onerror=alert(1)>".into(),
        image_id: "deploy-image".into(),
        targets: vec!["staging".into()],
        arguments: vec![
            ArgumentSpec::Target,
            ArgumentSpec::Choice {
                choices: vec!["safe".into(), "safe|\"quoted\"".into()],
            },
            ArgumentSpec::Integer {
                minimum: -10,
                maximum: 10,
            },
        ],
        credentials: vec![LoginCredentialDraft {
            item_id: "11111111-1111-1111-1111-111111111111".into(),
            label: "Deployment <login>".into(),
            use_type: CredentialUse::Login,
            field_mappings: vec![LoginFieldMapping {
                field: LoginField::Password,
                environment: "DEPLOY_PASSWORD".into(),
            }],
        }],
    }
}
pub(crate) fn input() -> DirectSubmission {
    DirectSubmission {
        operation: "deploy".into(),
        revision: None,
        values: vec!["staging".into(), "safe".into(), "+0003".into()],
    }
}
#[derive(Default)]
pub(crate) struct Launcher {
    pub calls: AtomicUsize,
    pub fail: bool,
}
impl DirectReviewLauncher for Launcher {
    fn launch(&self, _: &str) -> Result<(), DirectRequestError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err(DirectRequestError::ReviewUnavailable)
        } else {
            Ok(())
        }
    }
}
fn records(f: &Fixture) -> serde_json::Value {
    serde_json::from_slice(
        &std::fs::read(f.dir.path().join("provider/provider-state.json")).unwrap(),
    )
    .unwrap()
}
#[test]
fn owned_submission_canonicalizes_and_projects_only_safe_metadata() {
    let f = fixture();
    let launcher = Launcher::default();
    let owner = f.app.human_owner();
    let receipt = f.app.submit_direct(owner, input(), &launcher).unwrap();
    assert!(valid_request_id(&receipt.id));
    assert_eq!(receipt.expires_at_unix_seconds, 1700000300);
    assert_eq!(receipt.status, DirectStatus::Pending);
    assert_eq!(launcher.calls.load(Ordering::SeqCst), 1);
    let review = f.app.review_direct(owner, &receipt.id).unwrap();
    assert_eq!(review.arguments, vec!["staging", "safe", "3"]);
    assert_eq!(review.requester, "local human terminal");
    assert_eq!(review.target, "staging");
    assert_eq!(review.policy_digest, receipt.revision);
    assert_eq!(review.arguments_digest, receipt.arguments_digest);
    let serialized = serde_json::to_string(&review).unwrap();
    for excluded in [
        "11111111-1111-1111-1111-111111111111",
        "DEPLOY_PASSWORD",
        "synthetic-password",
        "field_mappings",
        "item_id",
    ] {
        assert!(!serialized.contains(excluded));
    }
    let record = &records(&f)["requests"][0];
    assert_eq!(record["direct"]["created_at_unix_seconds"], 1700000000);
    assert_eq!(record["direct"]["owner_uid"], unsafe { libc::geteuid() });
    let second = f.app.submit_direct(owner, input(), &launcher).unwrap();
    assert_ne!(receipt.id, second.id);
    assert_eq!(receipt.arguments_digest, second.arguments_digest);
}
#[test]
fn each_admission_rejection_has_no_record_and_no_desktop() {
    for case in [
        "locked",
        "owner",
        "operation",
        "stale",
        "malformed_revision",
        "missing",
        "extra",
        "target",
        "choice",
        "integer",
        "too_long",
    ] {
        let f = fixture();
        let launcher = Launcher::default();
        let mut owner = f.app.human_owner();
        let mut submitted = input();
        let expected = match case {
            "locked" => {
                f.app.lock().unwrap();
                DirectRequestError::Locked
            }
            "owner" => {
                owner = AuthenticatedHuman::from_peer_uid(owner.uid() + 1);
                DirectRequestError::Unauthorized
            }
            "stale" => {
                submitted.revision = Some("a".repeat(64));
                DirectRequestError::StaleRevision
            }
            other => {
                match other {
                    "operation" => submitted.operation = "unknown".into(),
                    "malformed_revision" => submitted.revision = Some("not-a-digest".into()),
                    "missing" => {
                        submitted.values.pop();
                    }
                    "extra" => submitted.values.push("x".into()),
                    "target" => submitted.values[0] = "production".into(),
                    "choice" => submitted.values[1] = "unsafe".into(),
                    "integer" => submitted.values[2] = "11".into(),
                    "too_long" => submitted.values[2] = "0".repeat(257),
                    _ => panic!(),
                };
                DirectRequestError::InvalidRequest
            }
        };
        assert_eq!(
            f.app.submit_direct(owner, submitted, &launcher),
            Err(expected),
            "{case}"
        );
        assert_eq!(launcher.calls.load(Ordering::SeqCst), 0, "{case}");
        assert!(
            records(&f)["requests"].as_array().unwrap().is_empty(),
            "{case}"
        );
    }
}
#[test]
fn deadlines_survive_wall_rollback_and_terminal_states_do_not_revive() {
    for action in ["expiry", "lock", "session_expiry", "shutdown", "restart"] {
        let f = fixture();
        let owner = f.app.human_owner();
        let receipt = f
            .app
            .submit_direct(owner, input(), &Launcher::default())
            .unwrap();
        f.monotonic.store(309, Ordering::SeqCst);
        f.wall.store(1, Ordering::SeqCst);
        assert_eq!(
            f.app.direct_status(owner, &receipt.id),
            Ok(DirectStatus::Pending)
        );
        match action {
            "expiry" => {
                f.monotonic.store(310, Ordering::SeqCst);
                f.app.status().unwrap();
            }
            "lock" => f.app.lock().unwrap(),
            "session_expiry" => {
                f.monotonic.store(910, Ordering::SeqCst);
                f.app.status().unwrap();
            }
            "shutdown" => f.app.shutdown().unwrap(),
            _ => {
                let root = f.dir.path().join("provider");
                drop(f.app);
                let provider = Provider::start(root).unwrap();
                let app = ProviderApplication::new(
                    provider,
                    Box::new(Backend),
                    Box::new(Clock {
                        monotonic: f.monotonic,
                        wall: f.wall,
                        on_wall_read: f.on_wall_read,
                    }),
                )
                .unwrap();
                assert_eq!(
                    app.direct_status(app.human_owner(), &receipt.id),
                    Ok(DirectStatus::Expired)
                );
                continue;
            }
        }
        assert_eq!(
            f.app.direct_status(owner, &receipt.id),
            Ok(DirectStatus::Expired)
        );
        if action != "shutdown" {
            f.app
                .authenticate(SensitiveString::new("synthetic".into()))
                .unwrap();
            assert_eq!(
                f.app.direct_status(owner, &receipt.id),
                Ok(DirectStatus::Expired)
            );
        }
    }
}
#[test]
fn launch_failure_is_durable_closed_and_store_failure_prevents_launch() {
    let f = fixture();
    let launcher = Launcher {
        fail: true,
        ..Launcher::default()
    };
    let receipt = f
        .app
        .submit_direct(f.app.human_owner(), input(), &launcher)
        .unwrap();
    assert_eq!(receipt.status, DirectStatus::Expired);
    f.app.lock().unwrap();
    assert_eq!(
        f.app.direct_status(f.app.human_owner(), &receipt.id),
        Ok(receipt.status)
    );
    let f = fixture();
    std::fs::remove_file(f.dir.path().join("provider/provider-state.json")).unwrap();
    let launcher = Launcher::default();
    assert!(
        f.app
            .submit_direct(f.app.human_owner(), input(), &launcher)
            .is_err()
    );
    assert_eq!(launcher.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn failed_desktop_handoff_changes_only_its_own_request() {
    let f = fixture();
    let owner = f.app.human_owner();
    let first = f
        .app
        .submit_direct(owner, input(), &Launcher::default())
        .unwrap();
    let failed = f
        .app
        .submit_direct(
            owner,
            input(),
            &Launcher {
                fail: true,
                ..Launcher::default()
            },
        )
        .unwrap();
    assert_ne!(first.id, failed.id);
    assert_eq!(failed.status, DirectStatus::Expired);
    assert_eq!(
        f.app.direct_status(owner, &first.id),
        Ok(DirectStatus::Pending)
    );
    assert_eq!(f.app.direct_status(owner, &failed.id), Ok(failed.status));
}
#[test]
fn ownerless_legacy_and_other_owner_have_no_authority() {
    let f = fixture();
    let owner = f.app.human_owner();
    let receipt = f
        .app
        .submit_direct(owner, input(), &Launcher::default())
        .unwrap();
    assert_eq!(
        f.app.direct_status(
            AuthenticatedHuman::from_peer_uid(owner.uid() + 1),
            &receipt.id
        ),
        Err(DirectRequestError::Unauthorized)
    );
    let mut state = records(&f);
    state["requests"][0]
        .as_object_mut()
        .unwrap()
        .remove("direct");
    std::fs::write(
        f.dir.path().join("provider/provider-state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    assert_eq!(
        f.app.direct_status(owner, &receipt.id),
        Err(DirectRequestError::NotFound)
    );
}
#[test]
fn malformed_new_metadata_and_outcomes_are_rejected() {
    for field in [
        "owner_uid",
        "created_at_unix_seconds",
        "lifecycle_epoch",
        "binding_digest",
        "review",
    ] {
        let f = fixture();
        let receipt = f
            .app
            .submit_direct(f.app.human_owner(), input(), &Launcher::default())
            .unwrap();
        let mut state = records(&f);
        state["requests"][0]["direct"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        std::fs::write(
            f.dir.path().join("provider/provider-state.json"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        assert_eq!(
            f.app.direct_status(f.app.human_owner(), &receipt.id),
            Err(DirectRequestError::Unavailable),
            "{field}"
        );
    }
    for (lifecycle, outcome) in [
        (
            "completed",
            serde_json::json!({"status":"completed","exit_code":999}),
        ),
        ("pending", serde_json::json!({"status":"denied"})),
        (
            "failed",
            serde_json::json!({"status":"failed","reason":"secret-sentinel"}),
        ),
    ] {
        let f = fixture();
        let receipt = f
            .app
            .submit_direct(f.app.human_owner(), input(), &Launcher::default())
            .unwrap();
        let mut state = records(&f);
        state["requests"][0]["status"] = lifecycle.into();
        state["requests"][0]["direct"]["review"]["status"] = outcome;
        std::fs::write(
            f.dir.path().join("provider/provider-state.json"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        assert!(
            f.app
                .direct_status(f.app.human_owner(), &receipt.id)
                .is_err()
        );
    }
}
#[test]
fn supported_closed_outcomes_project_without_new_decision_handlers() {
    for (lifecycle, status) in [
        ("pending", DirectStatus::Pending),
        ("approved", DirectStatus::Approved),
        ("running", DirectStatus::Running),
        ("denied", DirectStatus::Denied),
        ("invalidated", DirectStatus::Expired),
        ("completed", DirectStatus::Completed { exit_code: 17 }),
        (
            "failed",
            DirectStatus::Failed {
                reason: DirectFailure::ExecutionUnavailable,
            },
        ),
    ] {
        let f = fixture();
        let receipt = f
            .app
            .submit_direct(f.app.human_owner(), input(), &Launcher::default())
            .unwrap();
        let mut state = records(&f);
        state["requests"][0]["status"] = lifecycle.into();
        state["requests"][0]["direct"]["review"]["status"] = serde_json::to_value(&status).unwrap();
        if matches!(status, DirectStatus::Approved | DirectStatus::Running) {
            let record: DirectRecord =
                serde_json::from_value(state["requests"][0]["direct"].clone()).unwrap();
            state["requests"][0]["direct"]["approval"] =
                serde_json::to_value(record.approval_binding()).unwrap();
        }
        std::fs::write(
            f.dir.path().join("provider/provider-state.json"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        assert_eq!(
            f.app.direct_status(f.app.human_owner(), &receipt.id),
            Ok(status.clone())
        );
        if status.is_terminal() {
            f.app.lock().unwrap();
            assert_eq!(
                f.app.direct_status(f.app.human_owner(), &receipt.id),
                Ok(status)
            );
        }
    }
}

#[test]
fn semantic_record_guards_are_independent_of_the_integrity_seal() {
    let f = fixture();
    let receipt = f
        .app
        .submit_direct(f.app.human_owner(), input(), &Launcher::default())
        .unwrap();
    let state = records(&f);
    let original: DirectRecord =
        serde_json::from_value(state["requests"][0]["direct"].clone()).unwrap();
    let epoch = state["lifecycle_epoch"].as_u64().unwrap();
    type Mutation = (&'static str, Box<dyn Fn(&mut DirectRecord)>);
    let cases: Vec<Mutation> = vec![
        ("id", Box::new(|r| r.review.id = "bad".into())),
        ("owner", Box::new(|r| r.owner_uid = u32::MAX)),
        ("epoch", Box::new(move |r| r.lifecycle_epoch = epoch + 1)),
        (
            "time",
            Box::new(|r| r.created_at_unix_seconds = r.review.expires_at_unix_seconds),
        ),
        (
            "requester",
            Box::new(|r| r.review.requester = "caller identity".into()),
        ),
        (
            "operation",
            Box::new(|r| r.review.operation = "bad command".into()),
        ),
        ("empty effect", Box::new(|r| r.review.effect.clear())),
        (
            "effect length",
            Box::new(|r| r.review.effect = "a".repeat(257)),
        ),
        (
            "effect control",
            Box::new(|r| r.review.effect = "bad\nvalue".into()),
        ),
        ("target", Box::new(|r| r.review.target.clear())),
        (
            "argument count",
            Box::new(|r| {
                r.review.arguments = vec!["x".into(); 33];
                r.review.arguments_digest = arguments_digest(&r.review.arguments);
            }),
        ),
        (
            "argument value",
            Box::new(|r| {
                r.review.arguments[0] = "\0".into();
                r.review.arguments_digest = arguments_digest(&r.review.arguments);
            }),
        ),
        (
            "empty credentials",
            Box::new(|r| r.review.credentials.clear()),
        ),
        (
            "credential count",
            Box::new(|r| r.review.credentials = vec![r.review.credentials[0].clone(); 17]),
        ),
        ("label", Box::new(|r| r.review.credentials[0].label.clear())),
        (
            "executable",
            Box::new(|r| r.review.executable_digest = "z".repeat(64)),
        ),
        (
            "policy",
            Box::new(|r| r.review.policy_digest = "A".repeat(64)),
        ),
        (
            "args digest",
            Box::new(|r| r.review.arguments_digest = "a".repeat(64)),
        ),
        ("one time", Box::new(|r| r.review.one_time.clear())),
        (
            "exit low",
            Box::new(|r| r.review.status = DirectStatus::Completed { exit_code: -1 }),
        ),
        (
            "exit high",
            Box::new(|r| r.review.status = DirectStatus::Completed { exit_code: 256 }),
        ),
    ];
    assert!(original.validate(&receipt.id, epoch));
    for (name, mutate) in cases {
        let mut record = original.clone();
        mutate(&mut record);
        record.seal();
        assert!(!record.validate(&receipt.id, epoch), "{name}");
    }
    for mutate in [
        |r: &mut DirectRecord| r.owner_uid += 1,
        |r: &mut DirectRecord| r.created_at_unix_seconds += 1,
        |r: &mut DirectRecord| r.review.effect.push('!'),
    ] {
        let mut record = original.clone();
        mutate(&mut record);
        assert!(!record.validate(&receipt.id, epoch));
    }
    for status in [
        DirectStatus::Completed { exit_code: 0 },
        DirectStatus::Completed { exit_code: 255 },
    ] {
        let mut record = original.clone();
        record.review.status = status;
        assert!(record.validate(&receipt.id, epoch));
    }
}

#[test]
fn identifiers_digest_and_closed_contracts_have_independent_vectors() {
    assert_eq!(
        arguments_digest(&["staging".into(), "safe".into(), "3".into()]),
        "5f7632c79786683ef5cfe8669337fdc0c51d262946238bb39b973984bab2ed4a"
    );
    for id in ["", "short", &"A".repeat(44), &"/".repeat(43)] {
        assert!(!valid_request_id(id));
    }
    for status in [
        DirectStatus::Pending,
        DirectStatus::Approved,
        DirectStatus::Running,
    ] {
        assert!(!status.is_terminal());
    }
    for status in [
        DirectStatus::Denied,
        DirectStatus::Expired,
        DirectStatus::Completed { exit_code: 0 },
        DirectStatus::Failed {
            reason: DirectFailure::ExecutionUnavailable,
        },
    ] {
        assert!(status.is_terminal());
    }
    for authority in [
        "uid",
        "id",
        "created_at_unix_seconds",
        "expires_at_unix_seconds",
        "session",
        "launcher",
    ] {
        let mut json = serde_json::json!({"operation":"deploy","revision":null,"values":["staging","safe","3"]});
        json[authority] = serde_json::json!("sentinel");
        assert!(
            serde_json::from_value::<DirectSubmission>(json).is_err(),
            "{authority}"
        );
    }
}
#[test]
fn launch_crossing_deadline_returns_terminal_receipt_and_cannot_revive() {
    struct Slow(Arc<AtomicU64>);
    impl DirectReviewLauncher for Slow {
        fn launch(&self, _: &str) -> Result<(), DirectRequestError> {
            self.0.store(310, Ordering::SeqCst);
            Ok(())
        }
    }
    let f = fixture();
    let receipt = f
        .app
        .submit_direct(f.app.human_owner(), input(), &Slow(f.monotonic.clone()))
        .unwrap();
    assert_eq!(receipt.status, DirectStatus::Expired);
}

#[test]
fn provider_constructor_enforces_each_request_lifetime_boundary() {
    for (lifetime, valid) in [
        (Duration::ZERO, false),
        (Duration::from_millis(999), false),
        (Duration::from_secs(1), true),
        (Duration::from_secs(300), true),
        (Duration::from_secs(86400), true),
        (Duration::from_secs(86401), false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let app = ProviderApplication::new_with_request_lifetime(
            Provider::start(dir.path().join("provider")).unwrap(),
            Box::new(Backend),
            Box::new(Clock {
                monotonic: Arc::new(AtomicU64::new(0)),
                wall: Arc::new(AtomicU64::new(1700000000)),
                on_wall_read: Arc::new(Mutex::new(None)),
            }),
            lifetime,
        );
        assert_eq!(app.is_ok(), valid, "{lifetime:?}");
        if let Err(error) = app {
            assert_eq!(error, SessionError::InvalidRequest);
        }
    }
}

#[test]
fn redacted_output_contracts_reject_unknown_secret_session_and_output_fields() {
    let f = fixture();
    let receipt = f
        .app
        .submit_direct(f.app.human_owner(), input(), &Launcher::default())
        .unwrap();
    let review = f
        .app
        .review_direct(f.app.human_owner(), &receipt.id)
        .unwrap();
    for field in ["secret", "session", "raw_output"] {
        for valid_status in [
            DirectStatus::Pending,
            DirectStatus::Approved,
            DirectStatus::Denied,
            DirectStatus::Expired,
            DirectStatus::Running,
            DirectStatus::Completed { exit_code: 255 },
            DirectStatus::Failed {
                reason: DirectFailure::ReviewUnavailable,
            },
        ] {
            let mut status = serde_json::to_value(valid_status).unwrap();
            status[field] = "protected-sentinel".into();
            assert!(
                serde_json::from_value::<DirectStatus>(status).is_err(),
                "status {field}"
            );
        }
        let mut receipt = serde_json::to_value(&receipt).unwrap();
        receipt[field] = "protected-sentinel".into();
        assert!(
            serde_json::from_value::<SubmissionReceipt>(receipt).is_err(),
            "receipt {field}"
        );
        let mut review = serde_json::to_value(&review).unwrap();
        review[field] = "protected-sentinel".into();
        assert!(
            serde_json::from_value::<DirectReview>(review).is_err(),
            "review {field}"
        );
    }
}

#[test]
fn status_wire_requires_variant_fields_and_bounded_exit_codes() {
    for invalid in [
        serde_json::json!({"status":"pending","exit_code":0}),
        serde_json::json!({"status":"expired","reason":"review_unavailable"}),
        serde_json::json!({"status":"completed"}),
        serde_json::json!({"status":"completed","exit_code":-1}),
        serde_json::json!({"status":"completed","exit_code":256}),
        serde_json::json!({"status":"failed"}),
    ] {
        assert!(serde_json::from_value::<DirectStatus>(invalid).is_err());
    }
    for code in [0, 255] {
        assert_eq!(
            serde_json::from_value::<DirectStatus>(
                serde_json::json!({"status":"completed","exit_code":code})
            )
            .unwrap(),
            DirectStatus::Completed { exit_code: code }
        );
    }
}

#[test]
fn correctly_sealed_other_owner_record_is_not_disclosed_to_current_human() {
    let f = fixture();
    let owner = f.app.human_owner();
    let receipt = f
        .app
        .submit_direct(owner, input(), &Launcher::default())
        .unwrap();
    let mut state = records(&f);
    let mut direct: DirectRecord =
        serde_json::from_value(state["requests"][0]["direct"].clone()).unwrap();
    direct.owner_uid = owner.uid() + 1;
    direct.seal();
    state["requests"][0]["direct"] = serde_json::to_value(direct).unwrap();
    std::fs::write(
        f.dir.path().join("provider/provider-state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    assert_eq!(
        f.app.direct_status(owner, &receipt.id),
        Err(DirectRequestError::NotFound)
    );
    assert_eq!(
        f.app.review_direct(owner, &receipt.id),
        Err(DirectRequestError::NotFound)
    );
}

#[test]
fn duplicate_ids_and_stale_pending_epochs_are_rejected_independently() {
    for case in ["duplicate", "stale_pending_epoch"] {
        let f = fixture();
        let owner = f.app.human_owner();
        let receipt = f
            .app
            .submit_direct(owner, input(), &Launcher::default())
            .unwrap();
        let mut state = records(&f);
        if case == "duplicate" {
            let duplicate = state["requests"][0].clone();
            state["requests"].as_array_mut().unwrap().push(duplicate);
        } else {
            let mut record: DirectRecord =
                serde_json::from_value(state["requests"][0]["direct"].clone()).unwrap();
            record.lifecycle_epoch -= 1;
            record.seal();
            // The record is otherwise valid; only an unexecuted request's
            // mismatch with the current store epoch makes it inadmissible.
            assert!(record.validate(&receipt.id, state["lifecycle_epoch"].as_u64().unwrap()));
            state["requests"][0]["direct"] = serde_json::to_value(record).unwrap();
        }
        std::fs::write(
            f.dir.path().join("provider/provider-state.json"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        assert_eq!(
            f.app.direct_status(owner, &receipt.id),
            Err(DirectRequestError::Unavailable),
            "{case}"
        );
    }
}

#[test]
fn provider_records_preserve_distinct_authenticated_peer_uids() {
    let f = fixture();
    let root = f.dir.path().join("provider");
    drop(f.app);
    let mut provider = Provider::start(&root).unwrap();
    // Exercise the trusted adapter-to-core contract with identities independent
    // of whichever UID happens to run the test suite (including root in CI).
    for uid in [0, 1, 4242] {
        let owner = AuthenticatedHuman::from_peer_uid(uid);
        let review = provider
            .create_direct(owner, input(), 100, 400, || true)
            .unwrap();
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("provider-state.json")).unwrap())
                .unwrap();
        let record = state["requests"].as_array().unwrap().last().unwrap();
        assert_eq!(record["direct"]["owner_uid"], uid);
        assert_eq!(
            provider.direct_review(owner, &review.id).unwrap().id,
            review.id
        );
        assert_eq!(
            provider.direct_review(AuthenticatedHuman::from_peer_uid(uid + 1), &review.id),
            Err(DirectRequestError::NotFound)
        );
    }
}

#[test]
fn admission_change_during_provider_time_read_prevents_record_and_desktop() {
    // The wall-clock port is a real submission boundary, after initial admission
    // and before durable creation. It lets each revocation condition stand alone.
    for case in [
        "closing",
        "request_boundary",
        "request_after",
        "session_boundary",
        "session_after",
    ] {
        let lifetime = if case.starts_with("session") {
            Duration::from_secs(86400)
        } else {
            DEFAULT_REQUEST_LIFETIME
        };
        let f = fixture_with_lifetime(lifetime);
        let monotonic = f.monotonic.clone();
        let app = Arc::downgrade(&f.app);
        *f.on_wall_read.lock().unwrap() = Some(Box::new(move || match case {
            "closing" => app.upgrade().unwrap().close_admission(),
            "request_boundary" => monotonic.store(310, Ordering::SeqCst),
            "request_after" => monotonic.store(311, Ordering::SeqCst),
            "session_boundary" => monotonic.store(910, Ordering::SeqCst),
            "session_after" => monotonic.store(911, Ordering::SeqCst),
            _ => panic!("unknown admission test case"),
        }));
        let launcher = Launcher::default();
        assert_eq!(
            f.app.submit_direct(f.app.human_owner(), input(), &launcher),
            Err(DirectRequestError::Locked),
            "{case}"
        );
        assert!(
            records(&f)["requests"].as_array().unwrap().is_empty(),
            "{case}"
        );
        assert_eq!(launcher.calls.load(Ordering::SeqCst), 0, "{case}");
    }
}

#[test]
fn exact_metadata_and_input_size_limits_remain_usable() {
    let f = fixture();
    let mut submitted = input();
    // A valid integer with a long spelling isolates the raw input length guard
    // from policy range and persisted normalized-value validation.
    submitted.values[2] = "0".repeat(256);
    let receipt = f
        .app
        .submit_direct(f.app.human_owner(), submitted, &Launcher::default())
        .unwrap();
    assert_eq!(
        f.app
            .review_direct(f.app.human_owner(), &receipt.id)
            .unwrap()
            .arguments[2],
        "0"
    );
    let state = records(&f);
    let mut record: DirectRecord =
        serde_json::from_value(state["requests"][0]["direct"].clone()).unwrap();
    record.review.effect = "e".repeat(256);
    record.review.target = "t".repeat(256);
    record.review.arguments = vec!["a".repeat(256); 32];
    record.review.arguments_digest = arguments_digest(&record.review.arguments);
    record.review.credentials = vec![
        ReviewCredential {
            label: "c".repeat(256),
            use_type: CredentialUse::Login
        };
        16
    ];
    record.seal();
    assert!(record.validate(&receipt.id, state["lifecycle_epoch"].as_u64().unwrap()));
}

struct PasswordCheck;
impl ApprovalAuthenticator for PasswordCheck {
    fn authenticate(&self, password: SensitiveString) -> Result<(), SessionError> {
        if password.expose() == "approval-password-sentinel" {
            Ok(())
        } else {
            Err(SessionError::AuthenticationFailed)
        }
    }
}
fn approval(f: &Fixture, id: &str) -> AuthenticatedApproval {
    f.app
        .prepare_approval(f.app.human_owner(), id)
        .unwrap()
        .authenticate(
            SensitiveString::new("approval-password-sentinel".into()),
            &PasswordCheck,
        )
        .unwrap()
}
fn pending(f: &Fixture) -> String {
    f.app
        .submit_direct(f.app.human_owner(), input(), &Launcher::default())
        .unwrap()
        .id
}
#[test]
fn decision_approval_binds_exactly_and_audits_once_without_client_authority() {
    let f = fixture();
    let id = pending(&f);
    assert_eq!(
        f.app.commit_approval(approval(&f, &id)),
        Ok(DirectStatus::Approved)
    );
    let state = records(&f);
    let d: DirectRecord = serde_json::from_value(state["requests"][0]["direct"].clone()).unwrap();
    let expected_binding = ApprovalBinding {
        request_id: id.clone(),
        requester_uid: unsafe { libc::geteuid() },
        policy_digest: f
            .app
            .review_direct(f.app.human_owner(), &id)
            .unwrap()
            .policy_digest,
        arguments_digest: "5f7632c79786683ef5cfe8669337fdc0c51d262946238bb39b973984bab2ed4a".into(),
        expires_at_unix_seconds: 1700000300,
        lifecycle_epoch: state["lifecycle_epoch"].as_u64().unwrap(),
        record_digest: state["requests"][0]["direct"]["binding_digest"]
            .as_str()
            .unwrap()
            .to_owned(),
    };
    assert_eq!(d.approval.as_ref(), Some(&expected_binding));
    assert_eq!(
        d.audit,
        vec![DecisionAudit {
            binding: expected_binding,
            at_unix_seconds: 1700000000,
            outcome: DecisionOutcome::Approved
        }]
    );
    assert!(f.app.prepare_approval(f.app.human_owner(), &id).is_err());
    assert!(f.app.deny_direct(f.app.human_owner(), &id).is_err());
    assert_eq!(records(&f), state);
    assert_eq!(
        serde_json::to_string(&f.app.direct_status(f.app.human_owner(), &id).unwrap()).unwrap(),
        r#"{"status":"approved"}"#
    );
    for sentinel in [
        "approval-password-sentinel",
        "synthetic-password",
        "csrf",
        "token",
    ] {
        assert!(!serde_json::to_string(&state).unwrap().contains(sentinel));
    }
    f.app.lock().unwrap();
    assert_eq!(
        f.app.direct_status(f.app.human_owner(), &id),
        Ok(DirectStatus::Expired)
    );
    assert!(
        records(&f)["requests"][0]["direct"]
            .get("approval")
            .is_none()
    );
}
#[test]
fn decision_denial_is_immutable_without_password_and_restart_preserves_history() {
    let f = fixture();
    let id = pending(&f);
    assert_eq!(
        f.app.deny_direct(f.app.human_owner(), &id),
        Ok(DirectStatus::Denied)
    );
    let history = records(&f)["requests"][0].clone();
    assert!(f.app.deny_direct(f.app.human_owner(), &id).is_err());
    assert!(f.app.prepare_approval(f.app.human_owner(), &id).is_err());
    f.monotonic.store(310, Ordering::SeqCst);
    assert_eq!(
        f.app.direct_status(f.app.human_owner(), &id),
        Ok(DirectStatus::Denied)
    );
    f.app.lock().unwrap();
    assert_eq!(records(&f)["requests"][0], history);
    let root = f.dir.path().join("provider");
    drop(f.app);
    let _restarted = Provider::start(root.clone()).unwrap();
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("provider-state.json")).unwrap()).unwrap();
    assert_eq!(state["requests"][0], history);
}
#[test]
fn decision_missing_empty_wrong_failed_and_cancelled_authentication_grant_nothing() {
    struct Refused(SessionError);
    impl ApprovalAuthenticator for Refused {
        fn authenticate(&self, _: SensitiveString) -> Result<(), SessionError> {
            Err(self.0)
        }
    }
    for case in [
        "missing",
        "empty",
        "wrong",
        "oversized",
        "failed",
        "cancelled",
    ] {
        let f = fixture();
        let id = pending(&f);
        let before = records(&f);
        let prepared = f.app.prepare_approval(f.app.human_owner(), &id).unwrap();
        match case {
            "missing" => drop(prepared),
            "failed" | "cancelled" => assert!(
                prepared
                    .authenticate(
                        SensitiveString::new("approval-password-sentinel".into()),
                        &Refused(if case == "failed" {
                            SessionError::BackendUnavailable
                        } else {
                            SessionError::AuthenticationFailed
                        })
                    )
                    .is_err()
            ),
            _ => assert!(
                prepared
                    .authenticate(
                        SensitiveString::new(match case {
                            "empty" => String::new(),
                            "oversized" => "x".repeat(4097),
                            _ => "wrong-password-sentinel".into(),
                        }),
                        &PasswordCheck
                    )
                    .is_err()
            ),
        }
        assert_eq!(
            f.app.direct_status(f.app.human_owner(), &id),
            Ok(DirectStatus::Pending),
            "{case}"
        );
        assert_eq!(records(&f), before);
    }
}
#[test]
fn decision_authentication_releases_authority_and_rechecks_each_intervention() {
    use std::sync::mpsc;
    struct Blocked {
        entered: mpsc::Sender<()>,
        resume: Mutex<mpsc::Receiver<()>>,
    }
    impl ApprovalAuthenticator for Blocked {
        fn authenticate(&self, _: SensitiveString) -> Result<(), SessionError> {
            self.entered.send(()).unwrap();
            self.resume.lock().unwrap().recv().unwrap();
            Ok(())
        }
    }
    for action in [
        "approve",
        "deny",
        "expire",
        "session_expire",
        "policy",
        "policy_deleted",
        "lock",
        "lock_unlock",
        "shutdown",
    ] {
        let f = if action == "session_expire" {
            fixture_with_lifetime(Duration::from_secs(3600))
        } else {
            fixture()
        };
        let id = pending(&f);
        let prepared = f.app.prepare_approval(f.app.human_owner(), &id).unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let app = f.app.clone();
        let worker = std::thread::spawn(move || {
            let authenticated = prepared
                .authenticate(
                    SensitiveString::new("approval-password-sentinel".into()),
                    &Blocked {
                        entered: entered_tx,
                        resume: Mutex::new(resume_rx),
                    },
                )
                .unwrap();
            app.commit_approval(authenticated)
        });
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let expected = match action {
            "approve" => {
                f.app.commit_approval(approval(&f, &id)).unwrap();
                DirectStatus::Approved
            }
            "deny" => {
                f.app.deny_direct(f.app.human_owner(), &id).unwrap();
                DirectStatus::Denied
            }
            "expire" => {
                f.monotonic.store(310, Ordering::SeqCst);
                f.app.status().unwrap();
                DirectStatus::Expired
            }
            "session_expire" => {
                f.monotonic.store(910, Ordering::SeqCst);
                f.app.status().unwrap();
                DirectStatus::Expired
            }
            "policy" => {
                let mut draft = operation_draft();
                draft.targets.push("production".into());
                let previous = f
                    .app
                    .review_direct(f.app.human_owner(), &id)
                    .unwrap()
                    .policy_digest;
                let updated = f.app.activate_operation(draft).unwrap();
                assert_ne!(updated, previous);
                DirectStatus::Pending
            }
            "policy_deleted" => {
                let mut state = records(&f);
                state["operations"] = serde_json::json!([]);
                std::fs::write(
                    f.dir.path().join("provider/provider-state.json"),
                    serde_json::to_vec(&state).unwrap(),
                )
                .unwrap();
                DirectStatus::Pending
            }
            "shutdown" => {
                f.app.shutdown().unwrap();
                DirectStatus::Expired
            }
            _ => {
                f.app.lock().unwrap();
                if action == "lock_unlock" {
                    f.app
                        .authenticate(SensitiveString::new("synthetic".into()))
                        .unwrap();
                }
                DirectStatus::Expired
            }
        };
        // Intervening action has completed before releasing authentication.
        resume_tx.send(()).unwrap();
        assert!(worker.join().unwrap().is_err(), "{action}");
        assert_eq!(
            f.app.direct_status(f.app.human_owner(), &id),
            Ok(expected),
            "{action}"
        );
        let state = records(&f);
        let events = state["requests"][0]["direct"]
            .get("audit")
            .and_then(|v| v.as_array())
            .map_or(0, Vec::len);
        assert_eq!(
            events,
            usize::from(!action.starts_with("policy")),
            "{action}"
        );
    }
}
#[test]
fn decision_deadline_equality_wall_changes_and_prepared_binding_changes_are_isolated() {
    for (now, succeeds) in [(309, true), (310, false), (311, false)] {
        let f = fixture();
        let id = pending(&f);
        let authenticated = approval(&f, &id);
        f.wall.store(1, Ordering::SeqCst);
        f.monotonic.store(now, Ordering::SeqCst);
        assert_eq!(
            f.app.commit_approval(authenticated).is_ok(),
            succeeds,
            "{now}"
        );
        assert_eq!(
            f.app.direct_status(f.app.human_owner(), &id).unwrap(),
            if succeeds {
                DirectStatus::Approved
            } else {
                DirectStatus::Expired
            }
        );
    }
    for field in ["identity", "arguments", "expiry", "record", "policy"] {
        let f = fixture();
        let id = pending(&f);
        let authenticated = approval(&f, &id);
        let mut state = records(&f);
        let mut direct: DirectRecord =
            serde_json::from_value(state["requests"][0]["direct"].clone()).unwrap();
        match field {
            "identity" => direct.owner_uid += 1,
            "arguments" => {
                direct.review.arguments[2] = "4".into();
                direct.review.arguments_digest = arguments_digest(&direct.review.arguments);
            }
            "expiry" => direct.review.expires_at_unix_seconds += 1,
            "record" => direct.created_at_unix_seconds -= 1,
            "policy" => direct.review.policy_digest = "a".repeat(64),
            _ => panic!("unknown test case"),
        }
        direct.seal(); // Recompute unrelated integrity so it cannot mask semantic checks.
        assert!(direct.validate(&id, state["lifecycle_epoch"].as_u64().unwrap()));
        state["requests"][0]["direct"] = serde_json::to_value(direct).unwrap();
        std::fs::write(
            f.dir.path().join("provider/provider-state.json"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        assert!(f.app.commit_approval(authenticated).is_err(), "{field}");
        assert_eq!(records(&f)["requests"][0]["status"], "pending");
    }
}
#[test]
fn decision_persistence_failures_and_slow_commit_never_publish_authority() {
    use super::provider_store::WRITE_TEST_HOOK;
    for stage in [0, 1] {
        for slow in [false, true] {
            let f = fixture();
            let id = pending(&f);
            let authenticated = approval(&f, &id);
            let clock = f.monotonic.clone();
            WRITE_TEST_HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |observed| {
                    if observed != stage {
                        return false;
                    }
                    if slow {
                        clock.store(310, Ordering::SeqCst);
                        false
                    } else {
                        true
                    }
                }))
            });
            assert!(
                f.app.commit_approval(authenticated).is_err(),
                "stage={stage}, slow={slow}"
            );
            WRITE_TEST_HOOK.with(|hook| *hook.borrow_mut() = None);
            assert!(f.app.prepare_approval(f.app.human_owner(), &id).is_err());
            let root = f.dir.path().join("provider");
            drop(f.app);
            let _restarted = Provider::start(&root).unwrap();
            let state: serde_json::Value =
                serde_json::from_slice(&std::fs::read(root.join("provider-state.json")).unwrap())
                    .unwrap();
            assert_eq!(state["requests"][0]["status"], "invalidated");
            assert!(state["requests"][0]["direct"].get("approval").is_none());
        }
    }
}
#[test]
fn decision_restart_invalidates_pending_and_approved_with_single_expiry_event() {
    for approve in [false, true] {
        let f = fixture();
        let id = pending(&f);
        if approve {
            f.app.commit_approval(approval(&f, &id)).unwrap();
        }
        let root = f.dir.path().join("provider");
        drop(f.app);
        let provider = Provider::start(&root).unwrap();
        drop(provider);
        let _restarted_again = Provider::start(&root).unwrap();
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("provider-state.json")).unwrap())
                .unwrap();
        assert_eq!(state["requests"][0]["status"], "invalidated");
        let audit = state["requests"][0]["direct"]["audit"].as_array().unwrap();
        assert_eq!(audit.len(), if approve { 2 } else { 1 });
        assert_eq!(audit.last().unwrap()["outcome"], "expired");
    }
}

#[test]
fn decision_rechecks_credential_eligibility_and_deadline_after_backend_work() {
    for case in [
        "ineligible",
        "backend_error",
        "request_expiry",
        "session_expiry",
        "closing",
    ] {
        let f = if case == "session_expiry" {
            fixture_with_lifetime(Duration::from_secs(3600))
        } else {
            fixture()
        };
        let id = pending(&f);
        let authenticated = approval(&f, &id);
        let clock = f.monotonic.clone();
        let app = Arc::downgrade(&f.app);
        ELIGIBILITY_ACTION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || match case {
                "ineligible" => Ok(false),
                "backend_error" => Err(SessionError::BackendUnavailable),
                "request_expiry" => {
                    clock.store(310, Ordering::SeqCst);
                    Ok(true)
                }
                "session_expiry" => {
                    clock.store(910, Ordering::SeqCst);
                    Ok(true)
                }
                "closing" => {
                    app.upgrade().unwrap().close_admission();
                    Ok(true)
                }
                _ => panic!("unknown test case"),
            }))
        });
        assert!(f.app.commit_approval(authenticated).is_err(), "{case}");
        ELIGIBILITY_ACTION.with(|hook| *hook.borrow_mut() = None);
        assert_ne!(
            f.app.direct_status(f.app.human_owner(), &id).unwrap(),
            DirectStatus::Approved
        );
    }
}
#[test]
fn decision_does_not_unlock_or_renew_the_existing_provider_session() {
    let f = fixture();
    let id = pending(&f);
    f.monotonic.store(100, Ordering::SeqCst);
    let before = BACKEND_UNLOCKS.with(|count| count.get());
    f.app.commit_approval(approval(&f, &id)).unwrap();
    assert_eq!(BACKEND_UNLOCKS.with(|count| count.get()), before);
    f.monotonic.store(910, Ordering::SeqCst);
    assert_eq!(
        f.app.status(),
        Ok(super::application::SessionStatus::Locked)
    );
}

#[test]
fn decision_generation_and_password_bounds_are_independent_of_other_guards() {
    struct Permissive;
    impl ApprovalAuthenticator for Permissive {
        fn authenticate(&self, _: SensitiveString) -> Result<(), SessionError> {
            Ok(())
        }
    }
    let f = fixture();
    let id = pending(&f);
    for password in [String::new(), "x".repeat(4097)] {
        assert!(
            f.app
                .prepare_approval(f.app.human_owner(), &id)
                .unwrap()
                .authenticate(SensitiveString::new(password), &Permissive)
                .is_err()
        );
    }
    assert!(
        f.app
            .prepare_approval(f.app.human_owner(), &id)
            .unwrap()
            .authenticate(SensitiveString::new("x".repeat(4096)), &Permissive)
            .is_ok()
    );
    let mut prepared = f.app.prepare_approval(f.app.human_owner(), &id).unwrap();
    prepared.generation += 1;
    assert!(
        f.app
            .commit_approval(
                prepared
                    .authenticate(SensitiveString::new("valid".into()), &Permissive)
                    .unwrap()
            )
            .is_err()
    );
    assert_eq!(
        f.app.direct_status(f.app.human_owner(), &id),
        Ok(DirectStatus::Pending)
    );
    f.app.commit_approval(approval(&f, &id)).unwrap();
}
#[test]
fn decision_transition_matrix_rejects_every_illegal_edge_including_terminal_replays() {
    use super::provider_store::{RequestLifecycleStatus as R, RequestRecord};
    let f = fixture();
    pending(&f);
    let base: RequestRecord = serde_json::from_value(records(&f)["requests"][0].clone()).unwrap();
    let statuses = [
        DirectStatus::Pending,
        DirectStatus::Approved,
        DirectStatus::Denied,
        DirectStatus::Expired,
        DirectStatus::Running,
        DirectStatus::Completed { exit_code: 0 },
        DirectStatus::Failed {
            reason: DirectFailure::ExecutionUnavailable,
        },
    ];
    for from in &statuses {
        for next in &statuses {
            let mut record = base.clone();
            record.direct.as_mut().unwrap().review.status = from.clone();
            record.status = match from {
                DirectStatus::Pending => R::Pending,
                DirectStatus::Approved => R::Approved,
                DirectStatus::Denied => R::Denied,
                DirectStatus::Expired => R::Invalidated,
                DirectStatus::Running => R::Running,
                DirectStatus::Completed { .. } => R::Completed,
                DirectStatus::Failed { .. } => R::Failed,
            };
            let before = record.clone();
            let legal = matches!(
                (from, next),
                (
                    DirectStatus::Pending,
                    DirectStatus::Approved | DirectStatus::Denied | DirectStatus::Expired
                ) | (
                    DirectStatus::Approved,
                    DirectStatus::Running | DirectStatus::Expired
                ) | (
                    DirectStatus::Running,
                    DirectStatus::Completed { .. } | DirectStatus::Failed { .. }
                )
            );
            assert_eq!(
                record
                    .transition(next.clone(), DecisionOutcome::Expired, 1700000001)
                    .is_ok(),
                legal,
                "{from:?} -> {next:?}"
            );
            if !legal {
                assert_eq!(record, before);
            }
        }
    }
}

#[test]
fn decision_session_and_shutdown_during_persistence_are_independent_of_request_expiry() {
    use super::provider_store::WRITE_TEST_HOOK;
    for intervention in ["session", "shutdown"] {
        for stage in [0, 1] {
            let f = fixture_with_lifetime(Duration::from_secs(3600));
            let id = pending(&f);
            let authenticated = approval(&f, &id);
            let clock = f.monotonic.clone();
            let app = Arc::downgrade(&f.app);
            WRITE_TEST_HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |observed| {
                    if observed == stage {
                        if intervention == "session" {
                            clock.store(910, Ordering::SeqCst);
                        } else {
                            app.upgrade().unwrap().close_admission();
                        }
                    }
                    false
                }))
            });
            assert!(
                f.app.commit_approval(authenticated).is_err(),
                "{intervention} stage {stage}"
            );
            WRITE_TEST_HOOK.with(|hook| *hook.borrow_mut() = None);
            assert!(f.app.prepare_approval(f.app.human_owner(), &id).is_err());
            let state = records(&f);
            if stage == 0 {
                let audits = state["requests"][0]["direct"]
                    .get("audit")
                    .and_then(|v| v.as_array());
                assert!(
                    audits.is_none_or(|events| events.iter().all(|e| e["outcome"] != "approved")),
                    "expired authority must not persist approval: {intervention}"
                );
            }
            // After rename, durability can be uncertain; the full record is atomic
            // but unusable in this process and must expire before restart admits work.
            let root = f.dir.path().join("provider");
            drop(f.app);
            let _restarted = Provider::start(&root).unwrap();
            let state: serde_json::Value =
                serde_json::from_slice(&std::fs::read(root.join("provider-state.json")).unwrap())
                    .unwrap();
            assert_eq!(state["requests"][0]["status"], "invalidated");
            assert!(state["requests"][0]["direct"].get("approval").is_none());
        }
    }
}

#[test]
fn decision_closed_diagnostics_remain_actionable_and_redacted() {
    for (error, expected) in [
        (DirectRequestError::Unauthorized, "unauthorized human"),
        (DirectRequestError::Locked, "provider locked"),
        (DirectRequestError::InvalidRequest, "invalid request"),
        (DirectRequestError::StaleRevision, "stale policy revision"),
        (DirectRequestError::NotFound, "request unavailable"),
        (DirectRequestError::Unavailable, "provider unavailable"),
        (DirectRequestError::ReviewUnavailable, "review unavailable"),
        (
            DirectRequestError::AlreadyDecided,
            "request already decided",
        ),
        (
            DirectRequestError::AuthenticationFailed,
            "authentication failed",
        ),
    ] {
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn decision_legacy_explanations_preserve_terminal_history_and_never_restore_approval() {
    for (status, lifecycle) in [
        (DirectStatus::Pending, "pending"),
        (DirectStatus::Approved, "approved"),
        (DirectStatus::Denied, "denied"),
        (DirectStatus::Expired, "invalidated"),
        (
            DirectStatus::Failed {
                reason: DirectFailure::ReviewUnavailable,
            },
            "failed",
        ),
    ] {
        let f = fixture();
        let id = pending(&f);
        let mut state = records(&f);
        let mut direct: DirectRecord =
            serde_json::from_value(state["requests"][0]["direct"].clone()).unwrap();
        direct.review.one_time = LEGACY_ONE_TIME.into();
        direct.review.status = status.clone();
        direct.seal();
        state["requests"][0]["status"] = lifecycle.into();
        state["requests"][0]["direct"] = serde_json::to_value(&direct).unwrap();
        let previous = state["requests"][0].clone();
        let root = f.dir.path().join("provider");
        std::fs::write(
            root.join("provider-state.json"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        drop(f.app);
        let _restarted = Provider::start(&root).unwrap();
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("provider-state.json")).unwrap())
                .unwrap();
        if status.is_terminal() {
            assert_eq!(state["requests"][0], previous);
        } else {
            assert_eq!(state["requests"][0]["status"], "invalidated");
            assert!(state["requests"][0]["direct"].get("approval").is_none());
        }
        assert_eq!(state["requests"][0]["id"], id);
        assert_eq!(
            state["requests"][0]["direct"]["review"]["one_time"],
            LEGACY_ONE_TIME
        );
    }
}

#[test]
fn decision_current_approved_records_require_an_exact_binding() {
    let f = fixture();
    let id = pending(&f);
    let state = records(&f);
    let epoch = state["lifecycle_epoch"].as_u64().unwrap();
    let mut direct: DirectRecord =
        serde_json::from_value(state["requests"][0]["direct"].clone()).unwrap();
    direct.review.status = DirectStatus::Approved;
    assert!(!direct.validate(&id, epoch));
    direct.approval = Some(direct.approval_binding());
    assert!(direct.validate(&id, epoch));
    for field in [
        "request",
        "uid",
        "policy",
        "arguments",
        "expiry",
        "epoch",
        "seal",
    ] {
        let mut changed = direct.clone();
        let binding = changed.approval.as_mut().unwrap();
        match field {
            "request" => binding.request_id = "A".repeat(43),
            "uid" => binding.requester_uid += 1,
            "policy" => binding.policy_digest = "a".repeat(64),
            "arguments" => binding.arguments_digest = "a".repeat(64),
            "expiry" => binding.expires_at_unix_seconds += 1,
            "epoch" => binding.lifecycle_epoch += 1,
            "seal" => binding.record_digest = "a".repeat(64),
            _ => panic!("unknown test case"),
        }
        assert!(!changed.validate(&id, epoch), "{field}");
    }
}

#[test]
fn decision_system_audit_timestamps_record_the_actual_lifecycle_event() {
    use std::time::{SystemTime, UNIX_EPOCH};
    for action in ["lock", "restart", "failed_launch"] {
        let f = fixture();
        let root = f.dir.path().join("provider");
        if action != "failed_launch" {
            pending(&f);
        }
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        match action {
            "lock" => f.app.lock().unwrap(),
            "restart" => {
                drop(f.app);
                drop(Provider::start(&root).unwrap());
            }
            "failed_launch" => {
                let receipt = f
                    .app
                    .submit_direct(
                        f.app.human_owner(),
                        input(),
                        &Launcher {
                            fail: true,
                            ..Launcher::default()
                        },
                    )
                    .unwrap();
                assert_eq!(receipt.status, DirectStatus::Expired);
            }
            _ => panic!("unknown lifecycle fixture"),
        }
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("provider-state.json")).unwrap())
                .unwrap();
        let audit = state["requests"][0]["direct"]["audit"].as_array().unwrap();
        assert_eq!(audit.len(), 1, "{action}");
        let recorded = audit[0]["at_unix_seconds"].as_u64().unwrap();
        assert!(
            (before..=after).contains(&recorded),
            "{action}: event {recorded} outside {before}..={after}"
        );
    }
}

#[test]
fn decision_denied_and_clock_expired_audits_bind_exact_redacted_metadata() {
    for expired in [false, true] {
        let f = fixture();
        let id = pending(&f);
        let before = records(&f);
        let expected_binding = ApprovalBinding {
            request_id: id.clone(),
            requester_uid: unsafe { libc::geteuid() },
            policy_digest: f
                .app
                .review_direct(f.app.human_owner(), &id)
                .unwrap()
                .policy_digest,
            arguments_digest: "5f7632c79786683ef5cfe8669337fdc0c51d262946238bb39b973984bab2ed4a"
                .into(),
            expires_at_unix_seconds: 1700000300,
            lifecycle_epoch: before["lifecycle_epoch"].as_u64().unwrap(),
            record_digest: before["requests"][0]["direct"]["binding_digest"]
                .as_str()
                .unwrap()
                .to_owned(),
        };
        f.wall.store(1700000123, Ordering::SeqCst);
        let outcome = if expired {
            f.monotonic.store(310, Ordering::SeqCst);
            assert_eq!(
                f.app.direct_status(f.app.human_owner(), &id),
                Ok(DirectStatus::Expired)
            );
            DecisionOutcome::Expired
        } else {
            assert_eq!(
                f.app.deny_direct(f.app.human_owner(), &id),
                Ok(DirectStatus::Denied)
            );
            DecisionOutcome::Denied
        };
        let state = records(&f);
        let direct: DirectRecord =
            serde_json::from_value(state["requests"][0]["direct"].clone()).unwrap();
        assert_eq!(direct.approval, None);
        assert_eq!(
            direct.audit,
            vec![DecisionAudit {
                binding: expected_binding,
                at_unix_seconds: 1700000123,
                outcome,
            }]
        );
        for sentinel in [
            "approval-password-sentinel",
            "synthetic-password",
            "csrf",
            "token",
        ] {
            assert!(!serde_json::to_string(&state).unwrap().contains(sentinel));
        }
        assert!(f.app.deny_direct(f.app.human_owner(), &id).is_err());
        assert_eq!(records(&f), state);
    }
}
