# Issue 50: independent implementation review

Three independent reviewers inspected the first-slice changes on 2026-10-27:
an implementation-diff-only adversarial reviewer, an edge-case path reviewer,
and an acceptance auditor with the approved specification and context documents.
No reviewer modified source or executed tests during inspection.

## Actionable patches

1. **Dark selected-control contrast:** the light dark-mode `primary` color still
   used a white `onPrimary`, making default checkbox marks hard to distinguish.
   Correct the semantic pair while retaining the separate filled-button colors;
   extend the contrast assertion to cover selected controls.
2. **Request scroll position:** resetting the current scroll position before
   changing destinations could still allow PageStorage to restore an old Requests
   offset. Back/cancel also retained the detail offset in a long inbox. Disable
   implicit offset restoration and explicitly reset navigation; regress with a
   long inbox rather than only the single-request fixture.
3. **Locked Activity action:** match the inbox's locked-state eligibility for
   opening a fresh review. This is an affordance fix, not an authority bypass;
   Rust/controller admission remains authoritative.

These are implementation patches within the approved intent, not specification
changes. The edge-case reviewer found no additional unhandled paths. The
acceptance auditor found no scope or request-lifecycle violations.

## Findings not promoted to defects

The review also proposed focus announcements, inbox performance measurement,
additional setup/unlock/password matrix tests and stricter mutation attribution.
Inspection did not establish a new failure in those paths: all secret controllers
share the existing clearing callback, native setup and unlock retain their
existing lifecycle handling, and the mutation results include pristine/restored
controls and assertion logs. These suggestions are not claimed as implemented.

The large-text action capture was inspected directly: the password field and
approve/deny/cancel controls are visible. Targeting the password label positions
that entire group in the viewport; it does not omit the actions as suggested.

## Delivery boundary

The full host gate remains non-green because the unchanged native `install-save`
mutation depends on a CI-only production-namespace installation test. This is
already disclosed in the [capability/evidence checklist](issue-50-capabilities.md).
The packaged native TLS smoke also remains CI-only. Do not describe local
verification as a full green host gate or close the parent issue on this slice.

Final patch verification is recorded in that checklist and its evidence files.
