# Story 2.1 workflow review

All three required BMAD review layers ran independently: blind, edge-case and verification-gap. All returned before triage began; no layer was skipped. Review input was the complete baseline-to-worktree diff, including untracked files.

## Individual triage

| Finding | Verdict | Evidence and route |
|---|---|---|
| Blind 1: listing exceeds frame limit after many tombstones | low | Verified: list projects all bindings and write_frame caps 2 MiB. Rejected under the low-frequency rule: thousands of deliberate human pairings are needed; pagination adds protocol/public-surface complexity. Record scale limitation. |
| Blind 2: pairing succeeds after closure while waiting | medium | Verified: pair_agent checks closing only before gate acquisition; close_admission takes only release_gate. Pairing can persist/publish after closure. Patch: recheck after gate acquisition and under release_gate before publication; deterministic closure interleavings. No new public surface. |
| Blind 3: cleanup budget excludes blocked authority/storage | medium | Verified: gate acquisition and synchronous storage precede the cleanup wait. Deferred as pre-existing shared lifecycle behavior: baseline lock/shutdown/cancel use the same unbounded authority acquisition before their 20-second cleanup wait. This story publishes agent denial before that gate; no later authorization/release is granted while blocked. End-to-end bounded I/O requires a separate lifecycle redesign. |
| Blind 4: retained request_agents entries | low | Verified: entries last for the session process. Rejected under the low-frequency rule: current production has no agent submission transport, and a future long-lived deployment with many requests is needed for material memory impact; cleanup rules would add lifecycle complexity. Durable request/history retention is also unbounded. |
| Blind 5: legacy agent_audit:null accepted | low | Verified: serde Option treats explicit null as absent, but only an empty schema-1 registry migrates and schema 2 rejects null. No binding/audit authority is recovered or omitted. Rejected under the low-frequency rule: manually altered legacy empty state; distinguishing syntactic absence requires additional deserialization machinery. |
| Blind 6: leading-hyphen labels rejected by CLI | medium | Verified: label validator accepts printable ASCII but Pair.label lacks allow_hyphen_values. Patch the existing argument and real-process wire fixture. |
| Blind 7: slow revoke response not tested | medium | Verified: wire test responds immediately and delayed-response socket test uses Status with 2.1-second delay. Patch with a valid AgentRevoke response after the old 10-second deadline. |
| Blind 8: semantic runner success with unresolved classifications | low | Verified: campaign only prints completion after recording survivors/timeouts/infrastructure outcomes. Patch a direct nonzero final exit for any non-caught outcome; retain classification evidence. |
| Blind 9: runner timeout leaves descendants | medium | Verified: subprocess.run timeout kills only its immediate child before the semantic runner restores source. Patch runner subprocess execution to use a dedicated process group, kill the group on timeout, and wait for command termination before restoration. |
| Blind 10: MSRV evidence absent | low | Verified: optional msrv-all-targets command is defined but no run recorded; user-required all-targets ran on stable 1.98. Patch the evidence report to explicitly state Rust 1.88 is unverified; no MSRV result claimed. |
| Edge 1: stale status on polling after deadline | medium | Verified: application.agent_status reads provider status without admit/expire_requests, unlike human review_direct. Patch by applying the existing lifecycle refresh before the exact owner/binding lookup; test request and session expiry with the synthetic clock. This is the existing internal check, not Story 2.3 transport. |
| Verification gap 1: revoke response beyond old timeout | medium | Accepted as pre-verified: filed repository search demonstrates direct cleanup tests bypass exchange and transport fixtures reply before 10 seconds. Patch the delayed-response socket coverage. |

Grouping after individual verdicts: Blind 7 and Verification gap 1 share one missing transport-timeout oracle; all other accepted findings are independent. All patch fixes are local corrections, add no public surface, and address demonstrated states. No intent/spec loopback is needed.


## Resolution

The original implementation subagent applied every accepted patch. Parent read the
patch delta and verified it stayed within the triaged correction. Focused results:
21 application tests, 21 socket tests (one existing isolated entry-point ignore),
7 CLI tests and 2 runner regression tests passed. All six additional mutation probes were caught, and full post-patch verification
passed: 878 reported suite passes (71 live-service gated), real-systemd, Firefox,
strict lint and formatting. Final totals and evidence are in 2-1-verification.md.

The shared gate/I/O latency issue is recorded in the workflow deferred-work log.
No public API, signed transport, polling transport or frozen intent changed.

Retained limitations: listing is one response capped at 2 MiB; tombstones and
runtime request ownership metadata are retained; schema-1 empty registries accept
an explicit null agent_audit as absent (schema 2 rejects it). None restores agent
authority. Rust 1.88 is unverified; executed checks use stable Rust 1.98.
