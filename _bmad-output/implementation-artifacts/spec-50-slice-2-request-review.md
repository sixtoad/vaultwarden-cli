---
title: 'Issue 50 slice 2: request review detail, all states'
type: 'feature'
created: '2026-11-19'
status: 'in-review'
baseline_commit: 'bd9e815'
context:
  - '/Volumes/sixto_dev/ai/vaultwarden-cli-wt/plan-50.md (sections 1, 2.2, 4 slice 2, 5; outside the repo)'
  - '_bmad-output/implementation-artifacts/spec-50-slice-1-shell-conformance.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The request review is one flat column of twenty `FactRow`s with the password field, Touch ID, Approve, Deny and Cancel all inline, and every non-pending status collapses into one "Request is final" panel that even says "cancelled". It does not match direction A and does not distinguish executing, completed, failed, denied, expired or outcome unknown.

**Approach:** Split the review into header, scope facts, consequence, verification details, validity countdown, a two-step authorization step, a deny confirmation and one view per final status, all over the existing controllers.

## Boundaries & Constraints

**Always (owner decisions, binding):** verification details (three digests, one-time scope, exact deadline, raw status) are rendered below the consequence and never collapsed; approval takes two steps ("Approve…" opens an authorization step bound to the review's request ID) with Touch ID as the primary button when it can approve, password otherwise; "Cancelled" never appears as a request status; `effect` is shown verbatim and never parsed into authority; every existing review `Key` keeps a `SelectableText` with the verbatim Rust projection; selection, navigation, notification and back close the step and clear every password (existing `clearPasswords`); the countdown never re-enables a decision after it reached zero for that load.

**Ask First:** any controller, Rust, protocol, native or generated-binding change.

**Never:** origin device beyond today's management origin, command output, `create`/`ssh` review extensions, list summaries, Activity/Devices/Settings restyle, new dependencies.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Pending | status pending, canDecide | header "Awaiting your approval" + mono ID, facts, consequence, verification, countdown, Deny… / Approve… | — |
| Authorize, Touch ID | step open, `touchId.canApprove` | Touch ID filled primary; password field + outlined password approve; Cancel authorization | Touch ID refused: message, password stays |
| Authorize, password only | no Touch ID or cannot approve | password field + filled "Approve once with password"; Touch ID note when offered | empty password: provider rejects as today |
| Deny confirm | Deny… tapped | notice "Nothing will execute", Keep reviewing / Deny this request | — |
| Expired ticket | clock ≥ min(load + 55 s, expiresAt) | Approve/Deny disabled, step closed, "Review expired" + Reload review | stays expired until a new load |
| Executing | approved / running | "Approved · not completed" / "Running · not completed", do not approve again | — |
| Completed | completed{exit_code N} | "Completed · exit code N" | missing code: "exit code not reported" |
| Failed | failed{reason} | "Failed" + reason verbatim | — |
| Denied / Expired | denied / expired | own label and sentence | — |
| Unreadable | status not JSON / unknown | "Status not readable", final, no controls | — |
| Outcome unknown | `recoveryId` non-empty | notice: may have run, check original status only | — |

</frozen-after-approval>

## Code Map

- `companion/lib/provider/request_review.dart` -- composes the review (pending vs final), keeps keys
- `companion/lib/provider/review/` -- new: `review_status.dart` (status classification), `request_header.dart`, `scope_facts.dart`, `consequence.dart`, `validity.dart`, `authorization_step.dart`, `deny_confirm.dart`, `final_state.dart`, `outcome_unknown.dart`
- `companion/lib/provider/request_panes.dart` -- detail pane wiring, expired/loading/unavailable variants
- `companion/lib/provider/page.dart` -- step/deny state bound to request ID, review load clock, cleared in every navigation method
- `companion/lib/provider/requests_view.dart` -- recovery notice uses `OutcomeUnknownNotice`
- `scripts/mutate-provider-controller.py` -- page-level mutants for the step

## Tasks & Acceptance

**Execution:**
- [x] `lib/provider/review/*` -- components above, each ≤ ~200 lines
- [x] `lib/provider/request_review.dart`, `request_panes.dart`, `page.dart` -- two-step flow, deny confirm, final views, clock seam (`ProviderPage.clock`)
- [x] tests -- re-drive existing approve/deny/cancel finders through the step (helpers in `provider_support.dart`); new `review_states_test.dart` and `review_authorization_test.dart`; goldens `review_states_golden_test.dart` (16 per host)
- [x] `scripts/mutate-provider-controller.py` -- add step mutants (password clear on selection, approve after expiry, request-ID binding)

**Acceptance Criteria:**
- Given the suite, when run with `--concurrency=2`, then every test passes on macOS 27 arm64.
- Given `scripts/mutate-provider-controller.py`, then every mutation is caught.
- Given `flutter analyze`, then no issues.

## Spec Change Log

- 2026-11-19 review round 1 (edge-case + acceptance reviewers, read-only, against
  committed objects): patched a changed scope on the Touch ID re-review keeping
  the step open, expiry not clearing typed passwords, a failed reload looping on
  a stale expired notice, wall-clock skew stretching the 55 s ticket (production
  clock is now wall start + monotonic stopwatch), the absent pane showing another
  request's status without context, and Deny/Approve not stacking at large text.
  Added tests for the absent-pane expiry, decision in flight and loading. The
  acceptance "HIGH" (mutants missing) read HEAD before the script commit; the
  script was committed with 18/18 caught. KEEP: step bound to the raw
  `reviewId`, never `review.id` (the escaped projection); verification details
  above the decision controls. Deferred: deferred-work.md "#50 slice 2".

## Verification

**Commands:**
- `flutter analyze` -- expected: No issues found
- `TMPDIR=$HOME/.vwtmp flutter test --concurrency=2` -- expected: all pass
- `python3 scripts/mutate-provider-controller.py <evidence>` -- expected: all caught
