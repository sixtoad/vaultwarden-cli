//! Production Touch ID approval v2 through the real companion dispatch, with
//! software P-256 keys (no Secure Enclave, no biometric prompt). Runs on Linux
//! and on native macOS (`--test-threads=1`, private TMPDIR under $HOME).
use super::*;
use crate::{
    access::{
        approval_v2::{self as v2, ApprovalContext},
        direct_request::{ApprovalBinding, DirectSubmission},
        history::{ApprovalMethod, HistoryOutcome},
        policy::OperationPolicyDraft,
    },
    adapters::approval_verifier::tests::{sign, software_key},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{EcdsaKeyPair, KeyPair};
use std::{os::unix::fs::PermissionsExt, sync::atomic::AtomicUsize};

const CLIENT: &[u8] = include_bytes!("../../../tests/companion-tls/client.pem");
const CLIENT_CA: &[u8] = include_bytes!("../../../tests/companion-tls/ca.pem");
const PASSWORD: &str = "synthetic-password";

#[cfg(target_os = "linux")]
mod platform {
    use crate::access::direct_request_tests::{Fixture, fixture, input, operation_draft};
    pub(super) struct Env(Fixture);
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
        pub fn draft(&self) -> crate::access::policy::OperationPolicyDraft {
            operation_draft()
        }
        pub fn submission(&self, operation: &str) -> super::DirectSubmission {
            let mut input = input();
            operation.clone_into(&mut input.operation);
            input
        }
        pub fn operation(&self) -> &'static str {
            "deploy"
        }
    }
}
#[cfg(target_os = "macos")]
mod platform {
    use crate::adapters::native::tests::{Fixture, operation_draft, submission};
    pub(super) struct Env(Fixture);
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
        pub fn draft(&self) -> crate::access::policy::OperationPolicyDraft {
            operation_draft()
        }
        pub fn submission(&self, operation: &str) -> super::DirectSubmission {
            submission(operation)
        }
        pub fn operation(&self) -> &'static str {
            "native-version"
        }
    }
}
use platform::Env;

struct Password(AtomicUsize);
impl ApprovalAuthenticator for Password {
    fn authenticate(&self, password: SensitiveString) -> Result<(), SessionError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        if password.expose() == PASSWORD {
            Ok(())
        } else {
            Err(SessionError::AuthenticationFailed)
        }
    }
}
struct Dispatch(AtomicUsize);
impl ExecutionDispatcher for Dispatch {
    fn available(&self) -> bool {
        true
    }
    fn dispatch(&self, _: &str) -> Result<(), SessionError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
struct Svc {
    env: Env,
    service: Companion,
    password: Arc<Password>,
    dispatch: Arc<Dispatch>,
}
fn write_private(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}
fn me() -> String {
    identity::fingerprint(&CertificateDer::from_pem_slice(CLIENT).unwrap())
}
fn other() -> String {
    "b".repeat(64)
}
fn setup(admin: bool) -> Svc {
    let env = Env::new();
    let root = env.root();
    let server = write_private(
        &root,
        "server.pem",
        include_bytes!("../../../tests/fixtures/provider-tls/server.pem"),
    );
    let key = write_private(
        &root,
        "server-key.pem",
        include_bytes!("../../../tests/fixtures/provider-tls/server-key.pem"),
    );
    let ca = write_private(&root, "client-ca.pem", CLIENT_CA);
    let administrators = if admin { vec![me()] } else { vec![] };
    let store = write_private(
        &root,
        identity::STORE_FILE,
        serde_json::json!({"version":2,"identities":[{"fingerprint":me(),"label":"Synthetic Mac"},{"fingerprint":other(),"label":"Other Mac"}],"administrators":administrators})
            .to_string()
            .as_bytes(),
    );
    let password = Arc::new(Password(AtomicUsize::new(0)));
    let dispatch = Arc::new(Dispatch(AtomicUsize::new(0)));
    let service = Companion::bind("127.0.0.1:0".parse().unwrap(), &server, &key, &ca, &store)
        .unwrap()
        .with_approval_authenticator(password.clone())
        .with_execution_dispatcher(dispatch.clone());
    Svc {
        env,
        service,
        password,
        dispatch,
    }
}
fn body(response: &Response) -> serde_json::Value {
    serde_json::from_str(&response.body).unwrap()
}
impl Svc {
    fn send(&self, device: &str, command: Command) -> Response {
        self.service.dispatch(device, command, self.env.app())
    }
    fn request(&self) -> String {
        self.request_for(self.env.operation())
    }
    fn request_for(&self, operation: &str) -> String {
        self.env
            .app()
            .submit_direct(
                self.env.app().human_owner(),
                self.env.submission(operation),
                self.service.request_launcher().as_ref(),
            )
            .unwrap()
            .id
    }
    fn prepare(
        &self,
        device: &str,
        operation: management::BiometricOperation,
        target: &str,
    ) -> Response {
        self.send(
            device,
            Command::BiometricPrepare {
                version: 2,
                operation,
                target: management::Target {
                    kind: management::Kind::ApprovalClient,
                    id: target.into(),
                },
            },
        )
    }
    /// Online enrollment exactly as a companion performs it.
    fn enroll_as(&self, device: &str, key: &EcdsaKeyPair, password: &str) -> Response {
        let prepared = self.prepare(device, management::BiometricOperation::Enroll, device);
        assert_eq!(prepared.status, 200, "{}", prepared.body);
        let prepared = body(&prepared);
        let public_key = key.public_key().as_ref().to_vec();
        let transcript = v2::enroll_transcript(
            prepared["provider_identity"].as_str().unwrap(),
            device,
            &public_key,
            prepared["ticket"].as_str().unwrap(),
            prepared["action_id"].as_str().unwrap(),
        )
        .unwrap();
        self.send(
            device,
            enroll_command(&prepared, &public_key, &sign(key, &transcript), password),
        )
    }
    fn enroll(&self, key: &EcdsaKeyPair) -> String {
        let response = self.enroll_as(&me(), key, PASSWORD);
        assert_eq!(response.status, 200, "{}", response.body);
        let key_id = body(&response)["biometric_key_id"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(key_id, v2::key_id(key.public_key().as_ref()));
        key_id
    }
    fn review(&self, id: &str) -> serde_json::Value {
        let response = self.send(
            &me(),
            Command::Review {
                version: 2,
                request_id: id.into(),
            },
        );
        assert_eq!(response.status, 200);
        body(&response)
    }
    /// Clear this device's per-minute attempt budget (and any old tickets).
    fn cool(&self) {
        self.env.clock().fetch_add(61, Ordering::SeqCst);
    }
    fn status(&self, id: &str) -> DirectStatus {
        self.env
            .app()
            .direct_status(self.env.app().human_owner(), id)
            .unwrap()
    }
}
fn enroll_command(
    prepared: &serde_json::Value,
    public_key: &[u8],
    signature: &[u8],
    password: &str,
) -> Command {
    Command::BiometricEnroll {
        version: 2,
        action_id: prepared["action_id"].as_str().unwrap().into(),
        ticket: prepared["ticket"].as_str().unwrap().into(),
        password: SensitiveString::new(password.into()),
        public_key: URL_SAFE_NO_PAD.encode(public_key),
        enroll_signature: URL_SAFE_NO_PAD.encode(signature),
    }
}
/// Rebuild the transcript solely from the v2 Review response, as PR B will.
fn companion_transcript(review: &serde_json::Value, key_id: &str) -> Vec<u8> {
    let b = &review["approval_binding"];
    let text = |key: &str| b[key].as_str().unwrap().to_owned();
    let parsed: DirectReview = serde_json::from_value(review["review"].clone()).unwrap();
    assert_eq!(
        v2::hex(&v2::review_digest_value(&review["review"]).unwrap()),
        text("review_digest")
    );
    assert_eq!(b["ticket"], review["ticket"]);
    v2::approval_transcript(
        &ApprovalContext {
            provider_identity: &text("provider_identity"),
            approval_client: &text("approval_client"),
            ticket: &text("ticket"),
            ticket_deadline_unix_ms: b["ticket_deadline_unix_ms"].as_u64().unwrap(),
            review: &parsed,
        },
        &ApprovalBinding {
            request_id: text("request_id"),
            requester_uid: 0,
            agent_owner: None,
            policy_digest: text("policy_digest"),
            arguments_digest: text("arguments_digest"),
            expires_at_unix_seconds: b["expires_at_unix_seconds"].as_u64().unwrap(),
            lifecycle_epoch: 0,
            record_digest: text("record_digest"),
        },
        b["generation"].as_u64().unwrap(),
        key_id,
    )
    .unwrap()
}
fn proof(id: &str, ticket: &str, key_id: &str, signature: &[u8]) -> Command {
    Command::Decision {
        version: 2,
        request_id: id.into(),
        ticket: ticket.into(),
        decision: Decision::Approve,
        password: None,
        proof: Some(ProofWire {
            key_id: key_id.into(),
            signature: URL_SAFE_NO_PAD.encode(signature),
        }),
    }
}
fn password_decision(id: &str, ticket: &str) -> Command {
    Command::Decision {
        version: 2,
        request_id: id.into(),
        ticket: ticket.into(),
        decision: Decision::Approve,
        password: Some(SensitiveString::new(PASSWORD.into())),
        proof: None,
    }
}
fn ticket(review: &serde_json::Value) -> String {
    review["ticket"].as_str().unwrap().into()
}
/// Sign the review as an honest companion and submit the proof.
fn approve(s: &Svc, key: &EcdsaKeyPair, key_id: &str, id: &str) -> Response {
    let review = s.review(id);
    let signature = sign(key, &companion_transcript(&review, key_id));
    s.send(&me(), proof(id, &ticket(&review), key_id, &signature))
}

#[test]
fn biometric_enroll_then_proof_approval_commits_and_records_method() {
    let s = setup(false);
    let key = software_key();
    let key_id = s.enroll(&key);
    let id = s.request();
    // v1 review is byte-compatible: no approval_binding member.
    let v1 = body(&s.send(
        &me(),
        Command::Review {
            version: 1,
            request_id: id.clone(),
        },
    ));
    assert_eq!(v1["version"], 1);
    assert!(v1.get("approval_binding").is_none());
    let review = s.review(&id);
    let b = &review["approval_binding"];
    assert_eq!(review["version"], 2);
    assert_eq!(b["domain"], "dev.vaultwarden.provider.approval.v2");
    assert_eq!(b["action"], "approve");
    assert_eq!(
        b["provider_identity"],
        s.service.provider_fingerprint.as_str()
    );
    assert_eq!(b["approval_client"], me().as_str());
    assert_eq!(b["key_id"], key_id.as_str());
    assert_eq!(b["biometric_allowed"], true);
    assert_eq!(b["generation"], review["generation"]);
    let signature = sign(&key, &companion_transcript(&review, &key_id));
    let response = s.send(&me(), proof(&id, &ticket(&review), &key_id, &signature));
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        body(&response),
        serde_json::json!({"version":2,"status":{"status":"approved"}})
    );
    assert_eq!(s.status(&id), DirectStatus::Approved);
    assert_eq!(s.dispatch.0.load(Ordering::SeqCst), 1);
    // Enrollment used one password check; the proof approval used none.
    assert_eq!(s.password.0.load(Ordering::SeqCst), 1);
    let history = s.env.app().companion_history(None).unwrap();
    let approved = history
        .iter()
        .find(|e| e.request_id == id && e.outcome == HistoryOutcome::Approved)
        .unwrap();
    assert_eq!(
        approved.approval,
        Some(ApprovalMethod::Biometric {
            key_id: key_id.clone()
        })
    );
    // Replayed ticket and proof: the ticket is consumed exactly once.
    let replay = s.send(&me(), proof(&id, &ticket(&review), &key_id, &signature));
    assert_eq!(replay.status, 409);
    assert_eq!(s.dispatch.0.load(Ordering::SeqCst), 1);
}

#[test]
fn biometric_proof_replayed_on_new_ticket_is_refused() {
    let s = setup(false);
    let key = software_key();
    let key_id = s.enroll(&key);
    let id = s.request();
    let first = s.review(&id);
    let old_signature = sign(&key, &companion_transcript(&first, &key_id));
    let second = s.review(&id);
    assert_ne!(ticket(&first), ticket(&second));
    let response = s.send(&me(), proof(&id, &ticket(&second), &key_id, &old_signature));
    assert_eq!(response.status, 422, "{}", response.body);
    assert_eq!(s.status(&id), DirectStatus::Pending);
    // The old ticket was replaced by the second review and cannot be used.
    let stale = s.send(&me(), proof(&id, &ticket(&first), &key_id, &old_signature));
    assert_eq!(stale.status, 409);
    assert_eq!(s.dispatch.0.load(Ordering::SeqCst), 0);
    assert_eq!(approve(&s, &key, &key_id, &id).status, 200);
}

#[test]
fn biometric_stale_generation_changed_review_and_expired_ticket_are_refused() {
    for case in ["generation", "review", "expiry", "after_wall_deadline"] {
        let s = setup(false);
        let key = software_key();
        let key_id = s.enroll(&key);
        let id = s.request();
        let review = s.review(&id);
        let signature = sign(&key, &companion_transcript(&review, &key_id));
        match case {
            "generation" => s.service.state.lock().unwrap().tickets[0].generation += 1,
            "review" => s.service.state.lock().unwrap().tickets[0]
                .review
                .effect
                .push_str(" changed"),
            "expiry" => s.env.clock().store(75, Ordering::SeqCst),
            // A provider-side deadline other than the one signed: never accepted.
            _ => {
                let mut state = s.service.state.lock().unwrap();
                let ms = state.tickets[0].deadline_unix_ms.as_mut().unwrap();
                *ms += 1;
            }
        }
        let response = s.send(&me(), proof(&id, &ticket(&review), &key_id, &signature));
        assert_ne!(response.status, 200, "{case}");
        assert_eq!(s.status(&id), DirectStatus::Pending, "{case}");
        assert_eq!(s.dispatch.0.load(Ordering::SeqCst), 0, "{case}");
    }
}

#[test]
fn biometric_other_device_key_retired_key_and_cross_domain_signatures_are_refused() {
    let s = setup(false);
    let old = software_key();
    let old_id = s.enroll(&old);
    let new = software_key();
    let new_id = s.enroll(&new);
    assert_ne!(old_id, new_id);
    let id = s.request();
    // Retired key after re-enrollment, both by its id and under the new id.
    assert_eq!(approve(&s, &old, &old_id, &id).status, 422);
    assert_eq!(approve(&s, &old, &new_id, &id).status, 422);
    // A retired key can never be enrolled again, here or on another device.
    assert_eq!(s.enroll_as(&me(), &old, PASSWORD).status, 400);
    assert_eq!(s.enroll_as(&other(), &old, PASSWORD).status, 400);
    s.cool();
    // Another device's enrolled key does not approve for this device.
    let foreign = software_key();
    let response = s.enroll_as(&other(), &foreign, PASSWORD);
    assert_eq!(response.status, 200, "{}", response.body);
    let foreign_id = v2::key_id(foreign.public_key().as_ref());
    assert_eq!(approve(&s, &foreign, &foreign_id, &id).status, 422);
    // Enrolling the same key on two devices is refused.
    assert_eq!(s.enroll_as(&me(), &foreign, PASSWORD).status, 400);
    // The synthetic contract domain and the enroll domain never approve.
    let review = s.review(&id);
    let mut synthetic = companion_transcript(&review, &new_id);
    let domain = b"dev.vaultwarden.companion.synthetic.v1";
    let mut framed = (domain.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(domain);
    synthetic.splice(0..4 + v2::APPROVAL_DOMAIN.len(), framed);
    let response = s.send(
        &me(),
        proof(&id, &ticket(&review), &new_id, &sign(&new, &synthetic)),
    );
    assert_eq!(response.status, 422);
    let review = s.review(&id);
    let enroll_domain = v2::enroll_transcript(
        &s.service.provider_fingerprint,
        &me(),
        new.public_key().as_ref(),
        &ticket(&review),
        &id,
    )
    .unwrap();
    let response = s.send(
        &me(),
        proof(&id, &ticket(&review), &new_id, &sign(&new, &enroll_domain)),
    );
    assert_eq!(response.status, 422);
    assert_eq!(s.status(&id), DirectStatus::Pending);
    assert_eq!(s.dispatch.0.load(Ordering::SeqCst), 0);
    assert_eq!(approve(&s, &new, &new_id, &id).status, 200);
}

#[test]
fn biometric_device_revocation_removes_key_in_same_write() {
    let s = setup(false);
    let key = software_key();
    let key_id = s.enroll(&key);
    let id = s.request();
    let review = s.review(&id);
    let signature = sign(&key, &companion_transcript(&review, &key_id));
    identity::revoke_online(&s.env.root(), &me(), "local_owner").unwrap();
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&s.service.identity_store).unwrap()).unwrap();
    assert_eq!(raw["version"], 3);
    // An empty key list is omitted (rollback-compatible shape).
    assert!(raw.get("biometric").is_none());
    assert_eq!(raw["retired_biometric_keys"], serde_json::json!([key_id]));
    assert!(
        identity::biometric_key(&s.service.identity_store, &me())
            .unwrap()
            .is_none()
    );
    let response = s.send(&me(), proof(&id, &ticket(&review), &key_id, &signature));
    assert_eq!(response.status, 403);
    assert_eq!(s.status(&id), DirectStatus::Pending);
}

#[test]
fn biometric_password_and_proof_are_exclusive_and_sizes_are_bounded() {
    let id = URL_SAFE_NO_PAD.encode([1u8; 32]);
    let t = "c".repeat(64);
    let key_id = "d".repeat(64);
    let sig = URL_SAFE_NO_PAD.encode([0x30u8; 70]);
    let decision = |version, decision, password: Option<&str>, proof: Option<(&str, &str)>| {
        Command::Decision {
            version,
            request_id: id.clone(),
            ticket: t.clone(),
            decision,
            password: password.map(|p| SensitiveString::new(p.into())),
            proof: proof.map(|(key_id, signature)| ProofWire {
                key_id: key_id.into(),
                signature: signature.into(),
            }),
        }
    };
    assert!(decision(2, Decision::Approve, None, Some((&key_id, &sig))).valid());
    assert!(decision(2, Decision::Approve, Some(PASSWORD), None).valid());
    assert!(decision(1, Decision::Approve, Some(PASSWORD), None).valid());
    assert!(decision(2, Decision::Deny, None, None).valid());
    // Both or neither.
    assert!(!decision(2, Decision::Approve, Some(PASSWORD), Some((&key_id, &sig))).valid());
    assert!(!decision(2, Decision::Approve, None, None).valid());
    // Deny is never signed; v1 has no proof; unknown versions fail closed.
    assert!(!decision(2, Decision::Deny, None, Some((&key_id, &sig))).valid());
    assert!(!decision(1, Decision::Approve, None, Some((&key_id, &sig))).valid());
    assert!(!decision(3, Decision::Approve, Some(PASSWORD), None).valid());
    // Malformed key ids and signature sizes.
    for bad in ["D".repeat(64), "d".repeat(63), String::new()] {
        assert!(!decision(2, Decision::Approve, None, Some((&bad, &sig))).valid());
    }
    for len in [0usize, 7, 73, 100] {
        let bad = URL_SAFE_NO_PAD.encode(vec![0x30u8; len]);
        assert!(
            !decision(2, Decision::Approve, None, Some((&key_id, &bad))).valid(),
            "{len}"
        );
    }
    for bad in [format!("{sig}="), sig.replace('_', "/") + "+", "!!".into()] {
        assert!(!decision(2, Decision::Approve, None, Some((&key_id, &bad))).valid());
    }
    // Enrollment keys must be 65-byte uncompressed points.
    let key = software_key();
    let public_key = key.public_key().as_ref().to_vec();
    let enroll = |key: &[u8], sig_len: usize| Command::BiometricEnroll {
        version: 2,
        action_id: id.clone(),
        ticket: t.clone(),
        password: SensitiveString::new(PASSWORD.into()),
        public_key: URL_SAFE_NO_PAD.encode(key),
        enroll_signature: URL_SAFE_NO_PAD.encode(vec![0x30u8; sig_len]),
    };
    assert!(enroll(&public_key, 70).valid());
    assert!(!enroll(&public_key[..33], 70).valid());
    assert!(!enroll(&public_key[..64], 70).valid());
    let mut wrong = public_key.clone();
    wrong[0] = 0x02;
    assert!(!enroll(&wrong, 70).valid());
    assert!(!enroll(&public_key, 73).valid());
    // Wire parsing: a body carrying both is refused before dispatch.
    let both = format!(
        r#"{{"command":"decision","version":2,"request_id":"{id}","ticket":"{t}","decision":"approve","password":"{PASSWORD}","proof":{{"key_id":"{key_id}","signature":"{sig}"}}}}"#
    );
    let wire = format!(
        "POST /v1/companion HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        both.len(),
        both
    );
    assert!(read_command(&mut wire.as_bytes()).is_err());
    let extra = r#"{"command":"decision","version":2,"request_id":"x","ticket":"y","decision":"approve","proof":{"key_id":"a","signature":"b","extra":1}}"#;
    assert!(serde_json::from_str::<Command>(extra).is_err());
}

#[test]
fn biometric_rate_limit_applies_to_the_proof_path() {
    let s = setup(false);
    let key = software_key();
    let key_id = s.enroll(&key);
    let id = s.request();
    let wrong = software_key();
    // Enrollment consumed one attempt of this device's per-minute budget.
    for attempt in 0..5 {
        let review = s.review(&id);
        let signature = sign(&wrong, &companion_transcript(&review, &key_id));
        let response = s.send(&me(), proof(&id, &ticket(&review), &key_id, &signature));
        assert_eq!(
            response.status,
            if attempt < 4 { 422 } else { 429 },
            "{attempt}"
        );
    }
    assert_eq!(s.status(&id), DirectStatus::Pending);
    s.env.clock().store(200, Ordering::SeqCst);
    assert_eq!(approve(&s, &key, &key_id, &id).status, 200);
}

#[test]
fn biometric_require_password_policy_refuses_proof_but_not_password() {
    let s = setup(false);
    let key = software_key();
    let key_id = s.enroll(&key);
    let mut draft: OperationPolicyDraft = s.env.draft();
    draft.id = "password-only".into();
    draft.require_password = true;
    s.env
        .app()
        .create_operation(s.env.app().human_owner(), draft)
        .unwrap();
    let id = s.request_for("password-only");
    let review = s.review(&id);
    assert_eq!(review["approval_binding"]["biometric_allowed"], false);
    let signature = sign(&key, &companion_transcript(&review, &key_id));
    let response = s.send(&me(), proof(&id, &ticket(&review), &key_id, &signature));
    assert_eq!(response.status, 422);
    assert_eq!(s.status(&id), DirectStatus::Pending);
    let review = s.review(&id);
    assert_eq!(
        s.send(&me(), password_decision(&id, &ticket(&review)))
            .status,
        200
    );
    // Default policies still allow Touch ID.
    let id = s.request();
    assert_eq!(approve(&s, &key, &key_id, &id).status, 200);
}

#[test]
fn biometric_registry_migrates_v2_and_rejects_inconsistent_v3() {
    let s = setup(true);
    let path = s.service.identity_store.clone();
    // A v2 registry (written by the previous release) loads with no keys.
    assert!(identity::biometric_key(&path, &me()).unwrap().is_none());
    assert_eq!(identity::enrolled(&path).unwrap().len(), 2);
    let key = software_key();
    let key_id = s.enroll(&key);
    let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(raw["version"], 3);
    assert_eq!(raw["administrators"], serde_json::json!([me()]));
    assert_eq!(raw["biometric"][0]["key_id"], key_id.as_str());
    assert_eq!(raw["biometric"][0]["fingerprint"], me().as_str());
    let write = |value: serde_json::Value| {
        std::fs::write(&path, value.to_string()).unwrap();
        identity::enrolled(&path)
    };
    let mut v2_with_keys = raw.clone();
    v2_with_keys["version"] = 2.into();
    assert!(write(v2_with_keys).is_err());
    let mut unknown_device = raw.clone();
    unknown_device["biometric"][0]["fingerprint"] = "e".repeat(64).into();
    assert!(write(unknown_device).is_err());
    let mut wrong_id = raw.clone();
    wrong_id["biometric"][0]["key_id"] = "e".repeat(64).into();
    assert!(write(wrong_id).is_err());
    let mut retired_current = raw.clone();
    retired_current["retired_biometric_keys"] = serde_json::json!([key_id]);
    assert!(write(retired_current).is_err());
    let mut extra = raw.clone();
    extra["biometric"][0]["extra"] = true.into();
    assert!(write(extra).is_err());
    assert!(write(raw).is_ok());
}

#[test]
fn biometric_enrollment_needs_fresh_password_valid_proof_and_own_device() {
    let s = setup(false);
    let key = software_key();
    let public_key = key.public_key().as_ref().to_vec();
    // Wrong password: refused, nothing stored.
    assert_eq!(s.enroll_as(&me(), &key, "wrong").status, 422);
    assert!(
        identity::biometric_key(&s.service.identity_store, &me())
            .unwrap()
            .is_none()
    );
    // Proof by a different key, or over another ticket, is refused.
    let prepared = body(&s.prepare(&me(), management::BiometricOperation::Enroll, &me()));
    let transcript = v2::enroll_transcript(
        prepared["provider_identity"].as_str().unwrap(),
        &me(),
        &public_key,
        &"f".repeat(64),
        prepared["action_id"].as_str().unwrap(),
    )
    .unwrap();
    let response = s.send(
        &me(),
        enroll_command(&prepared, &public_key, &sign(&key, &transcript), PASSWORD),
    );
    assert_eq!(response.status, 422);
    let prepared = body(&s.prepare(&me(), management::BiometricOperation::Enroll, &me()));
    let other_key = software_key();
    let transcript = v2::enroll_transcript(
        prepared["provider_identity"].as_str().unwrap(),
        &me(),
        &public_key,
        prepared["ticket"].as_str().unwrap(),
        prepared["action_id"].as_str().unwrap(),
    )
    .unwrap();
    let response = s.send(
        &me(),
        enroll_command(
            &prepared,
            &public_key,
            &sign(&other_key, &transcript),
            PASSWORD,
        ),
    );
    assert_eq!(response.status, 422);
    // The enroll ticket is single use even after a refusal.
    let response = s.send(
        &me(),
        enroll_command(&prepared, &public_key, &sign(&key, &transcript), PASSWORD),
    );
    assert_eq!(response.status, 409);
    assert!(
        identity::biometric_key(&s.service.identity_store, &me())
            .unwrap()
            .is_none()
    );
    // Another device: never enrollable by this caller (admin or not).
    assert_eq!(
        s.prepare(&me(), management::BiometricOperation::Enroll, &other())
            .status,
        403
    );
    let admin = setup(true);
    assert_eq!(
        admin
            .prepare(&me(), management::BiometricOperation::Enroll, &other())
            .status,
        403
    );
    // An identity-revoke ticket never authorizes enrollment.
    let revoke_ticket = body(&admin.send(
        &me(),
        Command::IdentityPrepare {
            version: 2,
            target: management::Target {
                kind: management::Kind::ApprovalClient,
                id: me(),
            },
        },
    ));
    let transcript = v2::enroll_transcript(
        &admin.service.provider_fingerprint,
        &me(),
        &public_key,
        revoke_ticket["ticket"].as_str().unwrap(),
        revoke_ticket["action_id"].as_str().unwrap(),
    )
    .unwrap();
    let response = admin.send(
        &me(),
        enroll_command(
            &revoke_ticket,
            &public_key,
            &sign(&key, &transcript),
            PASSWORD,
        ),
    );
    assert_eq!(response.status, 409);
    // An approval-domain signature is not proof of possession.
    let prepared = body(&s.prepare(&me(), management::BiometricOperation::Enroll, &me()));
    let id = s.request();
    let review = s.review(&id);
    let approval_sig = sign(
        &key,
        &companion_transcript(&review, &v2::key_id(&public_key)),
    );
    let response = s.send(
        &me(),
        enroll_command(&prepared, &public_key, &approval_sig, PASSWORD),
    );
    assert_eq!(response.status, 422);
    assert!(
        identity::biometric_key(&s.service.identity_store, &me())
            .unwrap()
            .is_none()
    );
}

#[test]
fn biometric_key_revocation_keeps_device_and_admin_may_revoke_others() {
    let s = setup(false);
    let key = software_key();
    let key_id = s.enroll(&key);
    let revoke = |svc: &Svc, device: &str, target: &str, password: &str| {
        let prepared = svc.prepare(device, management::BiometricOperation::Revoke, target);
        if prepared.status != 200 {
            return prepared;
        }
        let prepared = body(&prepared);
        svc.send(
            device,
            Command::BiometricRevoke {
                version: 2,
                target: management::Target {
                    kind: management::Kind::ApprovalClient,
                    id: target.into(),
                },
                action_id: prepared["action_id"].as_str().unwrap().into(),
                ticket: prepared["ticket"].as_str().unwrap().into(),
                password: SensitiveString::new(password.into()),
            },
        )
    };
    assert_eq!(revoke(&s, &me(), &me(), "wrong").status, 422);
    // A non-admin cannot touch another device's key.
    assert_eq!(revoke(&s, &me(), &other(), PASSWORD).status, 403);
    let response = revoke(&s, &me(), &me(), PASSWORD);
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(body(&response)["revoked_key_id"], key_id.as_str());
    let id = s.request();
    assert_eq!(approve(&s, &key, &key_id, &id).status, 422);
    // Device still approves with a password.
    let review = s.review(&id);
    assert_eq!(
        review["approval_binding"]["key_id"],
        serde_json::Value::Null
    );
    assert_eq!(review["approval_binding"]["biometric_allowed"], false);
    assert_eq!(
        s.send(&me(), password_decision(&id, &ticket(&review)))
            .status,
        200
    );
    // The revoked key never returns.
    s.cool();
    assert_eq!(s.enroll_as(&me(), &key, PASSWORD).status, 400);

    let admin = setup(true);
    let foreign = software_key();
    assert_eq!(admin.enroll_as(&other(), &foreign, PASSWORD).status, 200);
    let foreign_id = v2::key_id(foreign.public_key().as_ref());
    // v3 inventory exposes the key id; v2 rows stay byte-compatible.
    let list = |version| {
        body(&admin.send(
            &me(),
            Command::IdentityList {
                version,
                limit: 10,
                after: None,
            },
        ))
    };
    let v3 = list(3);
    assert_eq!(v3["version"], 3);
    let row = |list: &serde_json::Value, id: &str| {
        list["identities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(row(&v3, &other())["biometric_key_id"], foreign_id.as_str());
    assert_eq!(row(&v3, &me())["biometric_key_id"], serde_json::Value::Null);
    assert!(row(&list(2), &other()).get("biometric_key_id").is_none());
    let response = revoke(&admin, &me(), &other(), PASSWORD);
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(body(&response)["revoked_key_id"], foreign_id.as_str());
    assert_eq!(
        row(&list(3), &other())["biometric_key_id"],
        serde_json::Value::Null
    );
}

struct AcceptAll;
impl BiometricApprovalVerifier for AcceptAll {
    fn verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> Result<(), SessionError> {
        Ok(())
    }
}
#[test]
fn biometric_accepting_verifier_still_needs_enrolled_current_key_and_fresh_ticket() {
    // Defense in depth: the key-id, enrollment and ticket checks are not
    // delegated to the signature primitive.
    let mut s = setup(false);
    let key = software_key();
    let key_id = s.enroll(&key);
    s.service = Companion::bind(
        "127.0.0.1:0".parse().unwrap(),
        &s.env.root().join("server.pem"),
        &s.env.root().join("server-key.pem"),
        &s.env.root().join("client-ca.pem"),
        &s.service.identity_store,
    )
    .unwrap()
    .with_approval_authenticator(s.password.clone())
    .with_execution_dispatcher(s.dispatch.clone())
    .with_biometric_verifier(Arc::new(AcceptAll));
    let id = s.request();
    let review = s.review(&id);
    let junk = vec![0x30u8; 70];
    assert_eq!(
        s.send(&me(), proof(&id, &ticket(&review), &"e".repeat(64), &junk))
            .status,
        422
    );
    let review = s.review(&id);
    assert_eq!(
        s.send(&me(), proof(&id, &ticket(&review), &key_id, &junk))
            .status,
        200
    );
    assert_eq!(
        s.send(&me(), proof(&id, &ticket(&review), &key_id, &junk))
            .status,
        409
    );
    assert_eq!(s.dispatch.0.load(Ordering::SeqCst), 1);
}

struct RevokeDuringVerify(PathBuf);
impl BiometricApprovalVerifier for RevokeDuringVerify {
    fn verify(&self, key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), SessionError> {
        // Key revocation lands after verification but before the commit gate.
        identity::revoke_biometric_online(&self.0, &me(), &me()).unwrap();
        crate::adapters::approval_verifier::RingBiometricVerifier.verify(key, message, signature)
    }
}
#[test]
fn biometric_key_revoked_after_verification_is_stale_at_commit() {
    let mut s = setup(false);
    let key = software_key();
    let key_id = s.enroll(&key);
    s.service = Companion::bind(
        "127.0.0.1:0".parse().unwrap(),
        &s.env.root().join("server.pem"),
        &s.env.root().join("server-key.pem"),
        &s.env.root().join("client-ca.pem"),
        &s.service.identity_store,
    )
    .unwrap()
    .with_approval_authenticator(s.password.clone())
    .with_execution_dispatcher(s.dispatch.clone())
    .with_biometric_verifier(Arc::new(RevokeDuringVerify(s.env.root())));
    let id = s.request();
    let response = approve(&s, &key, &key_id, &id);
    assert_eq!(response.status, 409, "{}", response.body);
    assert_eq!(s.status(&id), DirectStatus::Pending);
    assert_eq!(s.dispatch.0.load(Ordering::SeqCst), 0);
}

fn identity_target(id: &str) -> management::Target {
    management::Target {
        kind: management::Kind::ApprovalClient,
        id: id.into(),
    }
}
#[test]
fn biometric_prepare_flood_cannot_starve_admin_identity_revocation() {
    // A stolen, non-admin device floods key-management prepares; the
    // administrator can still revoke it online.
    let s = setup(true);
    for _ in 0..300 {
        s.prepare(&other(), management::BiometricOperation::Enroll, &other());
        s.prepare(&other(), management::BiometricOperation::Revoke, &other());
    }
    let prepared = s.send(
        &me(),
        Command::IdentityPrepare {
            version: 2,
            target: identity_target(&other()),
        },
    );
    assert_eq!(prepared.status, 200, "{}", prepared.body);
    let prepared = body(&prepared);
    let response = s.send(
        &me(),
        Command::IdentityRevoke {
            version: 2,
            target: identity_target(&other()),
            action_id: prepared["action_id"].as_str().unwrap().into(),
            ticket: prepared["ticket"].as_str().unwrap().into(),
            password: SensitiveString::new(PASSWORD.into()),
        },
    );
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(body(&response)["revocation"], "recorded");
    assert!(
        !identity::enrolled(&s.service.identity_store)
            .unwrap()
            .iter()
            .any(|entry| entry.fingerprint == other())
    );
}
#[test]
fn biometric_prepare_replaces_the_actors_previous_ticket_for_that_operation() {
    let s = setup(false);
    let key = software_key();
    let public_key = key.public_key().as_ref().to_vec();
    let signed = |prepared: &serde_json::Value| {
        let transcript = v2::enroll_transcript(
            prepared["provider_identity"].as_str().unwrap(),
            &me(),
            &public_key,
            prepared["ticket"].as_str().unwrap(),
            prepared["action_id"].as_str().unwrap(),
        )
        .unwrap();
        enroll_command(prepared, &public_key, &sign(&key, &transcript), PASSWORD)
    };
    let first = body(&s.prepare(&me(), management::BiometricOperation::Enroll, &me()));
    // A revoke prepare does not displace the enroll ticket...
    let revoke = body(&s.prepare(&me(), management::BiometricOperation::Revoke, &me()));
    // ...another device's enroll prepare does not either...
    assert_eq!(
        s.prepare(&other(), management::BiometricOperation::Enroll, &other())
            .status,
        200
    );
    // ...but a second enroll prepare by this device replaces the first.
    let second = body(&s.prepare(&me(), management::BiometricOperation::Enroll, &me()));
    assert_eq!(s.send(&me(), signed(&first)).status, 409);
    assert_eq!(s.password.0.load(Ordering::SeqCst), 0);
    assert_eq!(s.send(&me(), signed(&second)).status, 200);
    let response = s.send(
        &me(),
        Command::BiometricRevoke {
            version: 2,
            target: identity_target(&me()),
            action_id: revoke["action_id"].as_str().unwrap().into(),
            ticket: revoke["ticket"].as_str().unwrap().into(),
            password: SensitiveString::new(PASSWORD.into()),
        },
    );
    assert_eq!(response.status, 200, "{}", response.body);
}
#[test]
fn biometric_ticket_is_bound_to_action_target_and_operation() {
    let s = setup(true);
    let key = software_key();
    let public_key = key.public_key().as_ref().to_vec();
    let enroll_with = |prepared: &serde_json::Value, action_id: &str| {
        let transcript = v2::enroll_transcript(
            prepared["provider_identity"].as_str().unwrap(),
            &me(),
            &public_key,
            prepared["ticket"].as_str().unwrap(),
            action_id,
        )
        .unwrap();
        let mut command = enroll_command(prepared, &public_key, &sign(&key, &transcript), PASSWORD);
        if let Command::BiometricEnroll { action_id: a, .. } = &mut command {
            action_id.clone_into(a);
        }
        s.send(&me(), command)
    };
    // Another action id, honestly signed, is not the prepared action.
    let prepared = body(&s.prepare(&me(), management::BiometricOperation::Enroll, &me()));
    let foreign_action = URL_SAFE_NO_PAD.encode([7u8; 32]);
    assert_eq!(enroll_with(&prepared, &foreign_action).status, 409);
    // A revoke ticket never enrolls.
    let revoke = body(&s.prepare(&me(), management::BiometricOperation::Revoke, &me()));
    assert_eq!(
        enroll_with(&revoke, revoke["action_id"].as_str().unwrap()).status,
        409
    );
    assert!(
        identity::biometric_key(&s.service.identity_store, &me())
            .unwrap()
            .is_none()
    );
    // An admin's revoke ticket for its own device never revokes another's key.
    let foreign = software_key();
    assert_eq!(s.enroll_as(&other(), &foreign, PASSWORD).status, 200);
    let revoke = body(&s.prepare(&me(), management::BiometricOperation::Revoke, &me()));
    let response = s.send(
        &me(),
        Command::BiometricRevoke {
            version: 2,
            target: identity_target(&other()),
            action_id: revoke["action_id"].as_str().unwrap().into(),
            ticket: revoke["ticket"].as_str().unwrap().into(),
            password: SensitiveString::new(PASSWORD.into()),
        },
    );
    assert_eq!(response.status, 409, "{}", response.body);
    assert!(
        identity::biometric_key(&s.service.identity_store, &other())
            .unwrap()
            .is_some()
    );
    assert_eq!(s.password.0.load(Ordering::SeqCst), 1);
}
fn registry_json(s: &Svc) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(&s.service.identity_store).unwrap()).unwrap()
}
fn write_registry(s: &Svc, value: &serde_json::Value) {
    std::fs::write(&s.service.identity_store, value.to_string()).unwrap();
}
fn revoke_key(s: &Svc, device: &str, target: &str) -> Response {
    let prepared = s.prepare(device, management::BiometricOperation::Revoke, target);
    assert_eq!(prepared.status, 200, "{}", prepared.body);
    let prepared = body(&prepared);
    s.send(
        device,
        Command::BiometricRevoke {
            version: 2,
            target: identity_target(target),
            action_id: prepared["action_id"].as_str().unwrap().into(),
            ticket: prepared["ticket"].as_str().unwrap().into(),
            password: SensitiveString::new(PASSWORD.into()),
        },
    )
}
fn retired_ids(count: usize) -> Vec<serde_json::Value> {
    (0..count).map(|i| format!("{i:064x}").into()).collect()
}
#[test]
fn biometric_full_retired_list_forgets_oldest_id_instead_of_refusing() {
    let s = setup(true);
    let key = software_key();
    let key_id = s.enroll(&key);
    let mut raw = registry_json(&s);
    raw["retired_biometric_keys"] = retired_ids(256).into();
    write_registry(&s, &raw);
    let response = revoke_key(&s, &me(), &me());
    assert_eq!(response.status, 200, "{}", response.body);
    let retired = registry_json(&s)["retired_biometric_keys"].clone();
    assert_eq!(retired.as_array().unwrap().len(), 256);
    assert_eq!(retired[0], format!("{:064x}", 1));
    assert_eq!(retired[255], key_id.as_str());
    // Full: a new enrollment is never refused for the bound...
    s.cool();
    let second = s.enroll(&software_key());
    assert_eq!(registry_json(&s)["retired_biometric_keys"], retired);
    // ...and a re-enrollment forgets the oldest retired id (bounded LRU).
    s.cool();
    s.enroll(&software_key());
    let after = registry_json(&s)["retired_biometric_keys"].clone();
    assert_eq!(after.as_array().unwrap().len(), 256);
    assert_eq!(after[0], format!("{:064x}", 2));
    assert_eq!(after[254], key_id.as_str());
    assert_eq!(after[255], second.as_str());
    // Device revocation of a device with a key is never blocked either.
    let foreign = software_key();
    assert_eq!(s.enroll_as(&other(), &foreign, PASSWORD).status, 200);
    identity::revoke_online(&s.env.root(), &other(), &me()).unwrap();
    let raw = registry_json(&s);
    assert_eq!(raw["retired_biometric_keys"].as_array().unwrap().len(), 256);
    assert_eq!(raw["retired_biometric_keys"][0], format!("{:064x}", 3));
    assert_eq!(
        raw["retired_biometric_keys"][255],
        v2::key_id(foreign.public_key().as_ref()).as_str()
    );
}
/// A private provider root with no running provider, for offline commands.
fn offline_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    write_private(root.path(), ".provider-state.lock", b"");
    root
}
fn granted_records(raw: &serde_json::Value) -> Vec<serde_json::Value> {
    raw["audit"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "granted_administrator")
        .cloned()
        .collect()
}
/// `identities` enabled devices (maximal escaped labels), a key on this
/// device, Touch ID housekeeping at its caps (256 retired ids, 64 Touch ID
/// audit records), padded with other audit to within 2 bytes of 64 KiB.
fn registry_at_touch_id_caps(identities: usize) -> serde_json::Value {
    let mut devices = vec![serde_json::json!({"fingerprint": me(), "label": "Synthetic Mac"})];
    for i in 1..identities {
        devices.push(serde_json::json!({"fingerprint": format!("{:064x}", 1000 + i), "label": "\"".repeat(128)}));
    }
    devices.last_mut().unwrap()["label"] = "x".into();
    let key = software_key();
    let public_key = key.public_key().as_ref();
    let mut raw = serde_json::json!({
        "version": 3,
        "identities": devices,
        "administrators": [],
        "biometric": [{"fingerprint": me(), "key_id": v2::key_id(public_key), "public_key": URL_SAFE_NO_PAD.encode(public_key), "enrolled_generation": 1}],
        "retired_biometric_keys": retired_ids(256),
        "audit": (0..64)
            .map(|i| serde_json::json!({"fingerprint": me(), "actor": me(), "action": "biometric_enrolled", "key_id": format!("{:064x}", 5000 + i)}))
            .collect::<Vec<_>>(),
    });
    let fits = |raw: &serde_json::Value| raw.to_string().len() <= 65536;
    for i in 0..128 {
        let audit = raw["audit"].as_array_mut().unwrap();
        audit.push(serde_json::json!({"fingerprint": format!("{:064x}", 9000 + i), "actor": "local_owner", "action": "granted_administrator"}));
        if !fits(&raw) {
            raw["audit"].as_array_mut().unwrap().pop();
            break;
        }
    }
    // Other audit is OLDER than Touch ID audit, so oldest-first trimming of
    // any record would drop it; only Touch ID records may go.
    let audit = raw["audit"].as_array_mut().unwrap();
    audit.rotate_left(64);
    assert_eq!(audit[0]["action"], "granted_administrator");
    // Lengthen the last label until the file cannot grow by another byte.
    let last = identities - 1;
    for grow in ["\"", "x"] {
        loop {
            let mut label = raw["identities"][last]["label"]
                .as_str()
                .unwrap()
                .to_owned();
            if label.len() >= 128 {
                break;
            }
            label.push_str(grow);
            let before = raw["identities"][last]["label"].clone();
            raw["identities"][last]["label"] = label.into();
            if !fits(&raw) {
                raw["identities"][last]["label"] = before;
                break;
            }
        }
    }
    assert!(
        raw.to_string().len() > 65536 - 2,
        "{}",
        raw.to_string().len()
    );
    raw
}
fn assert_only_touch_id_housekeeping_trimmed(
    store: &Path,
    before: &serde_json::Value,
    identities: usize,
) {
    let bytes = std::fs::read(store).unwrap();
    assert!(bytes.len() <= 65536, "{}", bytes.len());
    let after: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(identity::enrolled(store).unwrap().len(), identities);
    // Identities and non-Touch-ID audit are never trimmed...
    for device in before["identities"].as_array().unwrap() {
        assert!(after["identities"].as_array().unwrap().contains(device));
    }
    let kept = granted_records(&after);
    assert!(kept.starts_with(&granted_records(before)));
    // ...nor the enrolled key; the oldest Touch ID audit records went first.
    assert_eq!(after["biometric"], before["biometric"]);
    let touch_id = after["audit"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "biometric_enrolled")
        .collect::<Vec<_>>();
    assert!(touch_id.len() < 64);
    assert_eq!(touch_id.last().unwrap()["key_id"], format!("{:064x}", 5063));
    assert_eq!(
        after["retired_biometric_keys"],
        before["retired_biometric_keys"]
    );
}
#[test]
fn biometric_housekeeping_at_caps_never_blocks_offline_enrollment() {
    let root = offline_root();
    let raw = registry_at_touch_id_caps(62);
    let store = write_private(
        root.path(),
        identity::STORE_FILE,
        raw.to_string().as_bytes(),
    );
    let certificate = write_private(
        root.path(),
        "other.pem",
        include_bytes!("../../../tests/companion-tls/other.pem"),
    );
    let ca = write_private(root.path(), "client-ca.pem", CLIENT_CA);
    let added = identity::enroll(root.path(), &certificate, &ca, "Other Mac").unwrap();
    assert_only_touch_id_housekeeping_trimmed(&store, &raw, 63);
    assert!(
        identity::list(root.path())
            .unwrap()
            .iter()
            .any(|i| i.fingerprint == added)
    );
}
#[test]
fn biometric_housekeeping_at_caps_never_blocks_administrator_grant() {
    let root = offline_root();
    let raw = registry_at_touch_id_caps(62);
    let store = write_private(
        root.path(),
        identity::STORE_FILE,
        raw.to_string().as_bytes(),
    );
    identity::grant_administrator(root.path(), &me()).unwrap();
    assert_only_touch_id_housekeeping_trimmed(&store, &raw, 62);
    assert!(identity::administrator(&store, &me()));
    let granted = granted_records(&registry_json_at(&store));
    assert_eq!(granted.last().unwrap()["fingerprint"], me().as_str());
}
fn registry_json_at(store: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(store).unwrap()).unwrap()
}
#[test]
fn biometric_revocation_forgets_oldest_state_to_stay_under_the_read_limit() {
    let s = setup(true);
    let mut raw = registry_json(&s);
    // 62 more enabled devices with maximal (escaped) labels, a key on every
    // device but `other`, and Touch ID audit history.
    let label = "\"".repeat(128);
    let mut identities = raw["identities"].as_array().unwrap().clone();
    for i in 0..62 {
        identities
            .push(serde_json::json!({"fingerprint": format!("{:064x}", 1000 + i), "label": label}));
    }
    let mut biometric = Vec::new();
    for identity in identities.iter().filter(|i| i["fingerprint"] != other()) {
        let key = software_key();
        let public_key = key.public_key().as_ref();
        biometric.push(serde_json::json!({"fingerprint": identity["fingerprint"], "key_id": v2::key_id(public_key), "public_key": URL_SAFE_NO_PAD.encode(public_key), "enrolled_generation": 1}));
    }
    let audit: Vec<_> = (0..64)
        .map(|i| serde_json::json!({"fingerprint": me(), "actor": me(), "action": "biometric_enrolled", "key_id": format!("{:064x}", 5000 + i)}))
        .collect();
    raw["version"] = 3.into();
    raw["identities"] = identities.into();
    raw["biometric"] = biometric.into();
    raw["audit"] = audit.into();
    raw["retired_biometric_keys"] = serde_json::json!([]);
    // Retired ids until the file is within one id of the 64 KiB read limit.
    let mut count = 0;
    while {
        raw["retired_biometric_keys"] = retired_ids(count + 1).into();
        raw.to_string().len() <= 65536
    } {
        count += 1;
    }
    raw["retired_biometric_keys"] = retired_ids(count).into();
    assert!(count < 256, "{count}");
    write_registry(&s, &raw);
    assert_eq!(
        identity::enrolled(&s.service.identity_store).unwrap().len(),
        64
    );
    // Revoking the keyless device adds an audit record past the limit; it
    // still succeeds by forgetting the oldest Touch ID audit entry.
    identity::revoke_online(&s.env.root(), &other(), &me()).unwrap();
    let after = std::fs::read(&s.service.identity_store).unwrap();
    assert!(after.len() <= 65536);
    let after: serde_json::Value = serde_json::from_slice(&after).unwrap();
    let audit = after["audit"].as_array().unwrap();
    assert_eq!(audit.last().unwrap()["action"], "revoked");
    assert!(audit.len() < 65);
    assert_eq!(
        after["retired_biometric_keys"].as_array().unwrap().len(),
        count
    );
    assert!(identity::enrolled(&s.service.identity_store).is_ok());
}
#[test]
fn biometric_enroll_and_revoke_are_audited_and_old_records_stay_readable() {
    let s = setup(true);
    let mut raw = registry_json(&s);
    // A record written by the previous release (no key_id).
    raw["audit"] = serde_json::json!([{"fingerprint": me(), "actor": "local_owner", "action": "granted_administrator"}]);
    write_registry(&s, &raw);
    let key = software_key();
    let key_id = s.enroll(&key);
    let foreign = software_key();
    assert_eq!(s.enroll_as(&other(), &foreign, PASSWORD).status, 200);
    let foreign_id = v2::key_id(foreign.public_key().as_ref());
    assert_eq!(revoke_key(&s, &me(), &other()).status, 200);
    s.cool();
    assert_eq!(revoke_key(&s, &me(), &me()).status, 200);
    assert_eq!(
        registry_json(&s)["audit"],
        serde_json::json!([
            {"fingerprint": me(), "actor": "local_owner", "action": "granted_administrator"},
            {"fingerprint": me(), "actor": me(), "action": "biometric_enrolled", "key_id": key_id},
            {"fingerprint": other(), "actor": other(), "action": "biometric_enrolled", "key_id": foreign_id},
            {"fingerprint": other(), "actor": me(), "action": "biometric_revoked", "key_id": foreign_id},
            {"fingerprint": me(), "actor": me(), "action": "biometric_revoked", "key_id": key_id},
        ])
    );
    // A Touch ID record without its key id, or in a version 2 file, is refused.
    let mut raw = registry_json(&s);
    raw["audit"][1].as_object_mut().unwrap().remove("key_id");
    write_registry(&s, &raw);
    assert!(identity::enrolled(&s.service.identity_store).is_err());
    let mut raw = registry_json(&s);
    raw["audit"][1]["key_id"] = key_id.as_str().into();
    raw["audit"][0]["key_id"] = key_id.as_str().into();
    write_registry(&s, &raw);
    assert!(identity::enrolled(&s.service.identity_store).is_err());
    let mut raw = registry_json(&s);
    raw["audit"][0].as_object_mut().unwrap().remove("key_id");
    raw["version"] = 2.into();
    raw.as_object_mut()
        .unwrap()
        .remove("retired_biometric_keys");
    write_registry(&s, &raw);
    assert!(identity::enrolled(&s.service.identity_store).is_err());
}
#[test]
fn biometric_registry_without_touch_id_state_is_written_as_version_2() {
    // An older binary (version 2, closed fields) can still read a registry
    // that never used Touch ID, whatever writes it.
    let s = setup(true);
    identity::revoke_online(&s.env.root(), &other(), &me()).unwrap();
    let raw = registry_json(&s);
    assert_eq!(raw["version"], 2);
    let mut keys: Vec<_> = raw.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "administrators",
            "audit",
            "identities",
            "revoked",
            "version"
        ]
    );
    // Touch ID state makes it version 3, and it stays so after a revocation
    // (the retired id must survive a downgrade-reading binary refusing it).
    let key = software_key();
    s.enroll(&key);
    assert_eq!(registry_json(&s)["version"], 3);
    s.cool();
    assert_eq!(revoke_key(&s, &me(), &me()).status, 200);
    assert_eq!(registry_json(&s)["version"], 3);
}
#[test]
fn biometric_review_without_provider_wall_clock_keeps_password_approval() {
    let s = setup(false);
    let key = software_key();
    let key_id = s.enroll(&key);
    let id = s.request();
    s.service.state.lock().unwrap().wall_clock_unavailable = true;
    let review = s.review(&id);
    assert_eq!(review["approval_binding"], serde_json::Value::Null);
    assert!(review["ticket"].is_string());
    // The ticket has no signing deadline: a proof is refused.
    let junk = vec![0x30u8; 70];
    assert_eq!(
        s.send(&me(), proof(&id, &ticket(&review), &key_id, &junk))
            .status,
        422
    );
    let review = s.review(&id);
    assert_eq!(
        s.send(&me(), password_decision(&id, &ticket(&review)))
            .status,
        200
    );
}
#[test]
fn biometric_lock_after_review_makes_decisions_stale_like_passwords() {
    // Documented: `biometric_allowed` is key/policy eligibility only. Lock is
    // signalled as for passwords: `session` reports it, a lock ends pending
    // requests (a fresh review is terminal, no ticket, no binding), and a
    // decision on a ticket from before the lock is `stale`.
    let s = setup(false);
    let key = software_key();
    let key_id = s.enroll(&key);
    let id = s.request();
    let review = s.review(&id);
    assert_eq!(review["approval_binding"]["biometric_allowed"], true);
    let signature = sign(&key, &companion_transcript(&review, &key_id));
    let other_id = s.request();
    let before = s.review(&other_id);
    s.env.app().lock().unwrap();
    let session = body(&s.send(&me(), Command::Session { version: 1 }));
    assert_eq!(session["state"], "locked");
    assert_eq!(
        s.send(&me(), proof(&id, &ticket(&review), &key_id, &signature))
            .status,
        409
    );
    assert_eq!(
        s.send(&me(), password_decision(&other_id, &ticket(&before)))
            .status,
        409
    );
    let after = s.review(&id);
    assert_eq!(after["ticket"], serde_json::Value::Null);
    assert_eq!(after["approval_binding"], serde_json::Value::Null);
    assert_eq!(s.dispatch.0.load(Ordering::SeqCst), 0);
}
#[test]
fn biometric_key_survives_a_companion_restart() {
    let mut s = setup(false);
    let key = software_key();
    let key_id = s.enroll(&key);
    // A new service over the same files (the registry is reloaded from disk),
    // with the production verifier.
    s.service = Companion::bind(
        "127.0.0.1:0".parse().unwrap(),
        &s.env.root().join("server.pem"),
        &s.env.root().join("server-key.pem"),
        &s.env.root().join("client-ca.pem"),
        &s.service.identity_store,
    )
    .unwrap()
    .with_approval_authenticator(s.password.clone())
    .with_execution_dispatcher(s.dispatch.clone());
    let id = s.request();
    let review = s.review(&id);
    assert_eq!(review["approval_binding"]["key_id"], key_id.as_str());
    let response = approve(&s, &key, &key_id, &id);
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(s.dispatch.0.load(Ordering::SeqCst), 1);
}
