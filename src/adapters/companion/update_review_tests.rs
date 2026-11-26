//! Issue 48 phase 2: an update review is approved from a companion only when
//! the client asserts the `update-review.v1` capability in its decision. The
//! Touch ID v2 transcript is unchanged; its review digest covers the block.
use super::*;
use crate::access::update_test_support::{
    self as vault, FIRST_REVISION, update_draft, update_submission,
};

fn with_capabilities(mut command: Command, names: &[&str]) -> Command {
    let Command::Decision { capabilities, .. } = &mut command else {
        panic!("a decision command");
    };
    *capabilities = Some(names.iter().map(|name| (*name).to_owned()).collect());
    command
}
impl Svc {
    fn update_request(&self) -> String {
        let app = self.env.app();
        app.create_operation(app.human_owner(), update_draft(&self.env.draft().image_id))
            .unwrap();
        app.submit_direct(
            app.human_owner(),
            update_submission(),
            self.service.request_launcher().as_ref(),
        )
        .unwrap()
        .id
    }
}

#[test]
fn update_review_carries_the_block_under_the_review_digest_and_needs_the_capability() {
    vault::reset();
    let s = setup(false);
    let key = software_key();
    let key_id = s.enroll(&key);
    let id = s.update_request();
    let review = s.review(&id);
    let update = &review["review"]["update"];
    assert_eq!(update["expected_revision"], FIRST_REVISION);
    assert_eq!(update["fields"], serde_json::json!(["password"]));
    assert_eq!(
        review["review"]["effect"],
        "UPDATE personal vault item (no create)"
    );
    // Eligibility stays advisory; the decision is where the provider refuses.
    assert_eq!(review["approval_binding"]["biometric_allowed"], true);
    // A valid proof from a client that did not assert the capability.
    let signature = sign(&key, &companion_transcript(&review, &key_id));
    let response = s.send(&me(), proof(&id, &ticket(&review), &key_id, &signature));
    assert_eq!(response.status, 422, "{}", response.body);
    assert_eq!(s.status(&id), DirectStatus::Pending);
    // Unknown capability names are ignored, never a substitute.
    let review = s.review(&id);
    let signature = sign(&key, &companion_transcript(&review, &key_id));
    let response = s.send(
        &me(),
        with_capabilities(
            proof(&id, &ticket(&review), &key_id, &signature),
            &["update-review.v2", "other-thing.v1"],
        ),
    );
    assert_eq!(response.status, 422, "{}", response.body);
    assert_eq!(s.status(&id), DirectStatus::Pending);
    // The same proof path with the capability approves.
    let review = s.review(&id);
    let signature = sign(&key, &companion_transcript(&review, &key_id));
    let response = s.send(
        &me(),
        with_capabilities(
            proof(&id, &ticket(&review), &key_id, &signature),
            &["other-thing.v1", UPDATE_REVIEW_CAPABILITY],
        ),
    );
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(s.status(&id), DirectStatus::Approved);
}

#[test]
fn companion_password_approval_of_an_update_also_needs_the_capability() {
    vault::reset();
    let s = setup(false);
    let id = s.update_request();
    let review = s.review(&id);
    let response = s.send(&me(), password_decision(&id, &ticket(&review)));
    assert_eq!(response.status, 422, "{}", response.body);
    assert_eq!(s.status(&id), DirectStatus::Pending);
    let review = s.review(&id);
    let response = s.send(
        &me(),
        with_capabilities(
            password_decision(&id, &ticket(&review)),
            &[UPDATE_REVIEW_CAPABILITY],
        ),
    );
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(s.status(&id), DirectStatus::Approved);
    // Other reviews never need it, and a capability there changes nothing.
    s.cool();
    let id = s.request();
    let review = s.review(&id);
    let response = s.send(
        &me(),
        with_capabilities(
            password_decision(&id, &ticket(&review)),
            &[UPDATE_REVIEW_CAPABILITY],
        ),
    );
    assert_eq!(response.status, 200, "{}", response.body);
}

#[test]
fn capability_lists_are_closed_in_shape_version_two_and_approve_only() {
    let decision = |version, decision: Decision, names: Option<Vec<&str>>| {
        let password =
            matches!(decision, Decision::Approve).then(|| SensitiveString::new(PASSWORD.into()));
        Command::Decision {
            capabilities: names.map(|names| names.into_iter().map(str::to_owned).collect()),
            version,
            request_id: "A".repeat(43),
            ticket: "a".repeat(64),
            decision,
            password,
            proof: None,
        }
    };
    assert!(decision(2, Decision::Approve, Some(vec![UPDATE_REVIEW_CAPABILITY])).valid());
    assert!(decision(2, Decision::Approve, Some(vec!["a.v1", "b-c.v10"])).valid());
    assert!(decision(2, Decision::Approve, None).valid());
    for names in [
        vec![],
        vec![UPDATE_REVIEW_CAPABILITY, UPDATE_REVIEW_CAPABILITY],
        vec!["Update-review.v1"],
        vec!["update-review"],
        vec!["update-review.v"],
        vec!["update-review.v01"],
        vec!["update review.v1"],
        vec![".v1"],
        vec!["-x.v1"],
        vec!["x-.v1"],
    ] {
        assert!(
            !decision(2, Decision::Approve, Some(names.clone())).valid(),
            "{names:?}"
        );
    }
    let long = format!("{}.v1", "a".repeat(62));
    assert!(!decision(2, Decision::Approve, Some(vec![long.as_str()])).valid());
    let many: Vec<String> = (0..17).map(|i| format!("c{i}.v1")).collect();
    assert!(
        !decision(
            2,
            Decision::Approve,
            Some(many.iter().map(String::as_str).collect())
        )
        .valid()
    );
    let sixteen: Vec<String> = (0..16).map(|i| format!("c{i}.v1")).collect();
    assert!(
        decision(
            2,
            Decision::Approve,
            Some(sixteen.iter().map(String::as_str).collect())
        )
        .valid()
    );
    assert!(!decision(1, Decision::Approve, Some(vec![UPDATE_REVIEW_CAPABILITY])).valid());
    assert!(!decision(2, Decision::Deny, Some(vec![UPDATE_REVIEW_CAPABILITY])).valid());
}
