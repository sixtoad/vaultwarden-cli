//! Explicit opt-in production rehearsal. Default cargo tests exercise only
//! non-provisioning guards and the dependency-free credential checker.
#![cfg(target_os = "linux")]
#[path = "support/protected_rehearsal.rs"]
mod support;

#[test]
fn terminal_status_accepts_exact_outcome_and_rejects_every_terminal_mismatch() {
    use vaultwarden_cli::access::protocol::{AgentFailure, AgentStatus};
    let terminal = [
        AgentStatus::Denied,
        AgentStatus::Expired,
        AgentStatus::Completed { exit_code: 0 },
        AgentStatus::Completed { exit_code: 1 },
        AgentStatus::Failed {
            category: AgentFailure::ExecutionNonzero,
        },
        AgentStatus::Failed {
            category: AgentFailure::ExecutionSignaled,
        },
        AgentStatus::Failed {
            category: AgentFailure::ExecutionUnavailable,
        },
        AgentStatus::Failed {
            category: AgentFailure::ExecutionRejected,
        },
        AgentStatus::Failed {
            category: AgentFailure::ReviewUnavailable,
        },
    ];
    for expected in &terminal {
        for observed in &terminal {
            let result =
                support::agent_terminal_status(&serde_json::to_value(observed).unwrap(), expected);
            if observed == expected {
                assert!(result.unwrap());
            } else {
                assert_eq!(
                    format!("{:#}", result.unwrap_err()),
                    "restricted agent poll terminal status mismatch"
                );
            }
        }
    }
}

#[test]
fn terminal_status_waits_only_for_valid_nonterminal_progress() {
    use vaultwarden_cli::access::protocol::AgentStatus;
    for state in [
        AgentStatus::Pending,
        AgentStatus::Approved,
        AgentStatus::Running,
    ] {
        assert!(
            !support::agent_terminal_status(
                &serde_json::to_value(&state).unwrap(),
                &AgentStatus::Denied
            )
            .unwrap()
        );
    }
    let mut observations = ["pending", "approved", "running", "denied"].into_iter();
    let mut polls = 0;
    support::wait_for_agent_terminal(
        || {
            polls += 1;
            Ok(serde_json::json!({"state":{"status":observations.next().unwrap()}}))
        },
        &AgentStatus::Denied,
    )
    .unwrap();
    assert_eq!(polls, 4);
}

#[test]
fn terminal_status_mismatch_malformed_and_rejection_stop_after_one_poll() {
    use vaultwarden_cli::access::protocol::AgentStatus;
    for (observation, message) in [
        (
            serde_json::json!({"state":{"status":"completed","exit_code":0}}),
            "restricted agent poll terminal status mismatch",
        ),
        (
            serde_json::json!({"state":{"status":"synthetic-secret"}}),
            "restricted agent poll status invalid",
        ),
        (
            serde_json::json!({}),
            "restricted agent poll status invalid",
        ),
    ] {
        let mut polls = 0;
        let error = support::wait_for_agent_terminal(
            || {
                polls += 1;
                assert_eq!(polls, 1, "unexpected second poll");
                Ok(observation.clone())
            },
            &AgentStatus::Denied,
        )
        .unwrap_err();
        assert_eq!(format!("{error:#}"), message);
        assert_eq!(polls, 1);
    }
    let mut polls = 0;
    let error = support::wait_for_agent_terminal(
        || {
            polls += 1;
            anyhow::bail!("restricted agent poll rejected: busy")
        },
        &AgentStatus::Denied,
    )
    .unwrap_err();
    assert_eq!(polls, 1);
    assert_eq!(format!("{error:#}"), "restricted agent poll rejected: busy");
}

#[test]
fn terminal_status_malformed_data_and_unsupported_expectations_are_safe() {
    use vaultwarden_cli::access::protocol::AgentStatus;
    let payload = "synthetic-secret https://localhost/#capability request-id";
    for state in [
        serde_json::json!(null),
        serde_json::json!([payload]),
        serde_json::json!({"status":payload}),
        serde_json::json!({"status":"completed","exit_code":payload}),
        serde_json::json!({"status":"completed","exit_code":-1}),
        serde_json::json!({"status":"completed","exit_code":256}),
        serde_json::json!({"status":"failed","category":payload}),
        serde_json::json!({"status":"denied","password":payload}),
        serde_json::json!({"status":"pending","password":payload}),
    ] {
        let error = support::agent_terminal_status(&state, &AgentStatus::Denied).unwrap_err();
        assert_eq!(format!("{error:#}"), "restricted agent poll status invalid");
    }
    for expected in [
        AgentStatus::Pending,
        AgentStatus::Approved,
        AgentStatus::Running,
    ] {
        let error =
            support::agent_terminal_status(&serde_json::json!({"status":"pending"}), &expected)
                .unwrap_err();
        assert_eq!(format!("{error:#}"), "rehearsal expected status invalid");
    }
}

#[test]
fn restricted_agent_rejections_preserve_only_closed_categories_and_action() {
    for (action, label) in [
        (support::AgentAction::Submit, "submit"),
        (support::AgentAction::Poll, "poll"),
    ] {
        for category in [
            "unauthorized",
            "malformed",
            "unsupported_version",
            "replay",
            "stale_revision",
            "invalid_arguments",
            "locked",
            "busy",
            "unavailable",
        ] {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "protocol_version": 1, "status": "rejected", "category": category
            }))
            .unwrap();
            let error = support::agent_response(action, &bytes).unwrap_err();
            assert_eq!(
                format!("{error:#}"),
                format!("restricted agent {label} rejected: {category}")
            );
        }
    }
}

#[test]
fn restricted_agent_malformed_responses_never_reflect_payloads_or_parser_errors() {
    let payload = "synthetic-secret https://localhost/#capability request-id private-key";
    let mut invalid: Vec<Vec<u8>> = [
        serde_json::json!({"protocol_version":1,"status":"rejected","category":payload}),
        serde_json::json!({"protocol_version":1,"status":"rejected","category":{"password":payload}}),
        serde_json::json!({"protocol_version":1,"status":"rejected","category":null}),
        serde_json::json!({"protocol_version":1,"status":"rejected"}),
        serde_json::json!({"protocol_version":1,"status":"rejected","category":"busy","error":payload}),
        serde_json::json!({"protocol_version":2,"status":"rejected","category":"busy"}),
        serde_json::json!({"protocol_version":payload,"status":"rejected","category":"busy"}),
        serde_json::json!({"protocol_version":1,"status":payload,"category":"busy"}),
        serde_json::json!({"protocol_version":1,"status":"pending","request_id":payload}),
        serde_json::json!({"protocol_version":1,"status":"status","request_id":"A".repeat(43),"state":{"status":payload}}),
        serde_json::json!({"error":payload}),
        serde_json::json!([payload]),
        serde_json::json!(null),
    ]
    .iter()
    .map(|value| serde_json::to_vec(value).unwrap())
    .collect();
    invalid.extend([
        vec![],
        vec![0xff],
        format!("{{\"{payload}\":").into_bytes(),
        br#"{"protocol_version":1,"status":"rejected","category":"busy","category":"synthetic-secret"}"#.to_vec(),
        format!("{{\"protocol_version\":1,\"status\":\"rejected\",\"category\":\"busy\"}} {payload}").into_bytes(),
        vec![b' '; vaultwarden_cli::access::protocol::MAX_RESPONSE_FRAME_BYTES + 1],
    ]);
    for (action, label) in [
        (support::AgentAction::Submit, "submit"),
        (support::AgentAction::Poll, "poll"),
    ] {
        for bytes in &invalid {
            let error = support::agent_response(action, bytes).unwrap_err();
            assert_eq!(
                format!("{error:#}"),
                format!("restricted agent {label} response invalid")
            );
        }
    }
}

#[test]
fn restricted_agent_valid_observations_keep_their_redacted_shape() {
    for (action, value) in [
        (
            support::AgentAction::Submit,
            serde_json::json!({"protocol_version":1,"status":"pending","request_id":"A".repeat(43)}),
        ),
        (
            support::AgentAction::Poll,
            serde_json::json!({"protocol_version":1,"status":"status","request_id":"A".repeat(43),"state":{"status":"completed","exit_code":0}}),
        ),
        (
            support::AgentAction::Poll,
            serde_json::json!({"protocol_version":1,"status":"status","request_id":"A".repeat(43),"state":{"status":"failed","category":"execution_nonzero"}}),
        ),
    ] {
        assert_eq!(
            support::agent_response(action, &serde_json::to_vec(&value).unwrap()).unwrap(),
            value
        );
    }
}

#[test]
fn browser_failure_stages_never_reflect_child_data() {
    for stage in [
        "provider-unlock",
        "request-find",
        "human-decision",
        "request-terminal",
    ] {
        assert_eq!(
            support::browser_failure_stage(
                &serde_json::json!({"gate": stage, "error":"synthetic-secret"})
            ),
            stage
        );
    }
    for reply in [
        serde_json::json!({"gate":"synthetic-secret https://localhost/#capability"}),
        serde_json::json!({"gate": {"password":"synthetic-secret"}}),
        serde_json::json!({}),
    ] {
        assert_eq!(support::browser_failure_stage(&reply), "unspecified");
    }
}

#[test]
#[ignore = "run scripts/rehearse-protected-workflow.sh; creates only disposable owned resources"]
fn production_chain() {
    if let Err(error) = support::run() {
        panic!("protected rehearsal failed: {error}");
    }
}

#[test]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn credential_checker_rejects_wrong_missing_and_ambient_fields() {
    support::check_fixture().unwrap();
}

#[test]
fn blocked_stdin_descendant_pipes_and_continuous_output_are_bounded_and_reaped() {
    support::bounded_pipes_regression().unwrap();
}

#[test]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[ignore = "runner preflight requires Cargo and Node; explicitly run with rehearsal dependencies"]
fn missing_desktop_prerequisite_fails_before_provisioning() {
    support::missing_prerequisite_regression().unwrap();
}

#[test]
#[ignore = "requires actual subordinate user namespaces; no provider resources are provisioned"]
fn restricted_identity_refuses_inaccessible_directory_before_provisioning() {
    support::restricted_traversal_regression().unwrap();
}

#[test]
fn cleanup_acceptance_rejects_retained_private_root_independently() {
    support::cleanup_removal_regression().unwrap();
}

#[test]
fn docker_disconnect_ownership_and_post_removal_retry_are_fail_closed() {
    support::docker_absence_regression().unwrap();
}

#[test]
fn private_stdout_and_stderr_capture_preserves_leaks_and_rejects_overflow() {
    support::private_capture_regression().unwrap();
}

#[test]
fn controller_stdout_audits_trailing_leaks_overflow_and_uncertain_eof() {
    support::controller_output_regression().unwrap();
}

#[test]
fn cleanup_retries_retain_controller_identity_and_reject_uncertain_metadata() {
    support::cleanup_observation_regression().unwrap();
}

#[test]
fn human_display_requires_private_owned_runtime_and_actual_socket() {
    support::human_display_regression().unwrap();
}

#[test]
fn namespace_map_requires_a_distinct_unprivileged_identity() {
    assert_eq!(
        support::subordinate_id("user:100000:65536\n", "user"),
        Some(100000)
    );
    for map in [
        "user:0:65536",
        "other:100000:65536",
        "user:1000:0",
        "user:bad:1",
    ] {
        assert_eq!(support::subordinate_id(map, "user"), None);
    }
}
