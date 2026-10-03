# Story 1.9 workflow review

Three independent, context-free reviewers assessed the complete implementation
and evidence diff: blind hunter, edge-case hunter and verification-gap reviewer.
The first attempt reached the session thread limit for two layers; both retries
succeeded. All results were collected before classification or fixes.

The blind reviewer returned 10 findings, the edge reviewer 3, and the verification
reviewer 2. All 15 receive individual verdicts below, before shared root causes
are grouped. Reviewers' suggestions are not accepted automatically.


| Finding | Verdict | Evidence and route |
| --- | --- | --- |
| B1: foreign-owner history | high | `correctly_sealed_other_owner_record_is_not_disclosed_to_current_human` establishes a valid foreign record; review filters owner but history flattens every direct record. Patch: apply the same record-owner predicate. |
| B2: refresh during session mutation | medium | `act` increments the epoch only at entry and immediately enables refresh. A newly admitted refresh can retain that epoch after lock completes. Patch: block refresh throughout queued mutations and invalidate on settlement. |
| B3: history after browser retirement | medium | `retireSession` disables request/session controls but neither advances history epoch nor clears rows. A held authorized response can repaint after retirement. Patch: retire history together with the session. |
| B4: history blocks initial request review | medium | The initializer awaits `loadHistory` before unhiding/starting review; a stalled fetch postpones every subsequent review action. Patch: start history independently. |
| B5: misleading history failure guidance | medium | Storage/render failures share 403 with authorization; UI only prescribes fresh authentication. Patch: static guidance covering smaller limits, fresh authentication and provider unavailability without changing the protocol. |
| B6: legacy denial information destroyed | false | Migration retains `status: {status: denied}` and the exact legacy `at_unix_seconds`, in addition to unchanged attribution. `legacy_unknown` is conservative cause classification; the claimed loss of what happened does not occur. No change. |
| B7: no-audit migration loses proven submission facts | false | The surviving snapshot retains `created_at_unix_seconds`, requester, revision and final status. There was no legacy submission audit event to preserve; adding another inferred row duplicates retained creation facts. No event-time or attribution data is lost. |
| B8: large-history query blocks other actions | maybe-false | Full-state loading/validation already occurs through the existing serialized reader; the new sort adds size-dependent cost. No representative workload or latency threshold demonstrates the claimed user-visible blockage. Defer as unverified medium: measure realistic large histories and lock latency before choosing bounded selection/storage changes. Retention remains outside user scope. |
| B9: runner ignores configured dependency paths | low | Unconditional assignments overwrite caller `VW_UI_DEPS` and `CERTUTIL`, preventing reproduction using alternate installed paths. Patch: honor configured paths and validate selected browser dependencies. |
| B10: unknown check selection reports success | medium | Filtering an unknown `STORY19_CHECKS` yields an empty loop and the all-required-success message. Patch: reject unknown/empty selections and label partial runs explicitly. |
| E1: foreign-owner history | high | Independently corroborates B1 at the same missing predicate. Same root cause and patch as B1. |
| E2: stalled initial history prevents review | medium | Initializer ordering confirms B4. Starting history independently removes the demonstrated coupling; a new timeout policy is unnecessary for this fix. Same patch as B4. |
| E3: post-lock repaint from refresh during lock | medium | Epoch/admission trace confirms B2. Same root cause and patch as B2. |
| V1: legacy multi-event migration gap | medium | Filed verified gap: existing legacy test has one approval; no-audit test has none. Neither reaches Approved-to-Running reconstruction. Patch: completed legacy three-event fixture, exact phases/times/attribution and two restarts. |
| V2: history-triggered expiry gap | medium | Filed verified gap: other reads/revocation trigger expiry before existing history assertions. Patch: Pending and Approved monotonic deadlines reached with history as the first read, exact durable expiry and no duplicates. |

All fifteen findings classified before grouping. Patch groups: B1/E1, B2/E3,
B3, B4/E2, B5, B9, B10, V1 and V2. B6/B7 rejected on specific retained-field
refutations. B8 deferred as unverified medium with the measurement needed stated.
No intent/spec loopback is needed: all confirmed fixes are local corrections,
add no public interface and guard only demonstrated states.


The original implementation agent completed every patch group. Focused checks
passed: 26 history tests, one foreign-owner regression, 29 loopback tests, the
extended real-Firefox harness, and nine isolated verification-runner guard cases.
Parent verification finished: 28 semantic and 16 generated mutations caught,
838 tests on each of stable and Rust 1.88, 12 focused integrations, Firefox,
real-systemd cleanup/recovery, formatting, strict Clippy and diff checks all passed.
Source hashes were unchanged. All confirmed findings and verification gaps are
resolved. One unverified performance measurement remains deferred as stated above.

The implementation is ready for the human approval checkpoint. No commit, push
or PR has occurred.

## Native CI extension review

| Finding | Verdict | Evidence and route |
| --- | --- | --- |
| B1: doctest coverage removed | low | Cargo documents --all-targets as lib/bins/tests/benches/examples, omitting the previous default doctest pass. Add explicit doc invocations to preserve the CI contract. Patch: three feature combinations. |
| B2: browser fixture Cargo flags | medium | The new offline/locked warm build is followed by a separate spawn with neither flag at direct-request.mjs:19. Patch: pass both flags on the actual fixture launch. |
| B3: runner Firefox provisioning | false | Official Ubuntu runner installation supports x64/ARM Firefox, and the job explicitly tests executable presence and prints its version. Using the runner browser is intentional environment coverage; incompatibility fails visibly rather than skips. Pinning another browser is not required to establish this claim. |
| B4: stalled history fetch | medium | loadHistory sets loading/disabled before awaiting fetch and only clears in finally; an unresolved response never reaches finally. Existing held-response browser fixture demonstrates this state. Patch: bounded abort covering fetch/body and test recovery after the deadline. |
| B5: auditless legacy submission loss | false | Carried from original B7: the final snapshot retains created_at, requester, revision and final status; the old audit contains no submission event. The constructed migration entry is not evidence of a lost original event. |
| B6: legacy denial ambiguity | false | Carried from original B6: exact Denied status and event timestamp remain in the event; legacy_unknown conservatively categorizes cause. The claimed loss is disproved by retained fields. |
| B7: large-history latency | maybe-false | Carried from original B8: full decoding already occurs under the serialized reader; sort cost has no demonstrated representative latency threshold. Existing unverified-medium measurement deferral remains, without duplicating it. |
| B8: invisible label format characters | low | Policy label validation permits U+200B/U+2060/U+FEFF and current display helpers leave them invisible. Patch: make those three explicit escapes in both existing display projections, with independent examples. |
| B9: CLI newline bound | low | terminal_json accepts MAX_OUTPUT bytes and output subsequently appends one newline. Patch: include that byte in the existing bound and verify exact/one-over complete output boundaries. |
| B10: browser selected-limit false positive | medium | The count is already one before selecting one, so the wait may resolve before refresh and hardcoding the default limit preserves the assertion. Patch: multiple real events, await the completed response, verify newest-only then larger limit. |
| E1: unknown semantic mutation filter | medium | Reviewer reproduced zero cases and a success exit; the selector filters without validating supplied names. Patch: reject explicit empty/unknown/mixed invalid selectors before running any mutations, with isolated runner guards. |
| V1: browser limit verification gap | medium | Accepted as filed verified gap: the single-event browser and adapter fixtures cannot distinguish selected 1 from hardcoded default 50. Same root cause/fix as B10. |

All twelve findings classified before grouping. Patch groups: B1, B2, B4, B8, B9, B10/V1, E1. B3/B5/B6 rejected on specific evidence. B7 is carried from the existing measurement deferral. No new intent or public interface is required; each patch corrects existing configuration, rendering, loading, or verification behavior at a demonstrated boundary.

All seven patch groups are complete. Final stable/MSRV all-target suites, integrations, Firefox/systemd, six doctest configurations, 17 runner guard cases and static checks passed. Three fixture plus twelve CLI/browser mutations were caught; no unresolved survivor or equivalent remains. See [final native CI evidence](1-9-native-ci.md). Hosted runs require the pending publication approval.
