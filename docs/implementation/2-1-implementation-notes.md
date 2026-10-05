# Story 2.1 implementation handoff

Controlling specification: `_bmad-output/implementation-artifacts/spec-2-1-pair-and-revoke-restricted-agent-identity.md` in the parent workspace. This is the historical initial handoff; final checks, added coverage, mutation results and human publication approval are recorded in [2-1-verification.md](2-1-verification.md).

## Implemented behavior

- Canonical nonweak Ed25519 public keys, computed SHA-256 fingerprints, bounded printable ASCII labels, restricted numeric UID/GID, immutable random IDs, permanently reserved keys, enabled-label uniqueness, and retained revoked tombstones.
- Explicit schema 2 with closed binding/audit records. The only schema-1 migration is empty legacy pairings; existing human request seals and history remain compatible. Every read/write validates binding identity, immutable administrative audit and historical requester references.
- Human-authenticated `agent pair|list|revoke` on the existing private socket, including locked-vault administration. Revoke accepts only immutable IDs and has a 30-second client response deadline for the provider's 20-second cleanup wait. Public keys do not appear in views/audit.
- Internal OS identity lookup and exact ownership polling contracts; no agent signature or polling transport. Synthetic admitted work is constructed only through cfg(test) helpers. Human review and execution authority remains distinct from requester identity.
- Agent request owners and approval bindings include ID, label, fingerprint, UID/GID; agent seals use a separate versioned digest while human seals retain their historical representation. Browser review explicitly prefixes agent identity and includes its fingerprint, including when a label resembles the human presentation.
- Per-binding revocation tokens publish under the release gate before waiting for the backend gate. Admission, claim and decision persistence use the gate-to-release order and fence the final write. Registered executions carry immutable binding IDs; successful scoped revocation does not change the global lifecycle epoch.
- Revoke atomically persists the tombstone, administrative audit and expiration of only unclaimed owned work, then waits outside authority locks for affected registered executions. Retry still waits; claimed/running work stays nonterminal until cleanup. Running work requires Reaped evidence, and uncertainty, impossible NotStarted evidence or persistence failure closes admission.

## Verification performed

Commands ran outside the sandbox through the secure temporary-directory wrapper: the sandbox remaps `/` and `/home` ownership and correctly causes the wrapper to reject unsafe ancestry. No HOME override or directory-mode change was used.

- `scripts/with-secure-test-tmpdir.sh cargo test --all-targets --offline --locked`: exit 0, 864 tests passed and 13 intentional harness tests ignored, plus benchmark smoke checks. See `2-1-evidence/core-all-targets.log.gz`.
- After the final explicit-agent presentation and direct cleanup-postcondition polish, `scripts/with-secure-test-tmpdir.sh cargo test --offline --locked --lib agent_`: exit 0, 26 passed. See `2-1-evidence/core-final-agent.log.gz`.
- `cargo fmt --all` was applied; formatting and whitespace checks are recorded by the final handoff.

An earlier full library integration attempt found two regressions, subsequently fixed: universally guarded human persistence lost an already-durable terminal receipt, and Serde's unit AgentList variant ignored unknown fields. Human admission retains its existing receipt semantics; AgentList now uses a closed empty-struct wire variant. The successful all-target run includes both regressions.

Focused coverage includes isolated invalid key/label/UID/GID checks, registry/audit/schema migration, OS and exact poll ownership, global fail-closed polling, independent application/provider human guards, locked private-socket lifecycle, CLI subprocesses, durable restart/re-pair attribution, pair/revoke write failures before and after rename, read failures, pending/approved scoped invalidation, two concurrently running agents, retry waiting, uncertain/impossible cleanup evidence, blocked backend resolution, final release, admission before and during persistence, and sealed-owner tampering.

## Remaining verification at the initial handoff

This section is historical. See [current verification](2-1-verification.md) for subsequent work.

The parent agent owns the next sequential phase: real-systemd selective revocation with independent descendant observations; scoped cargo-mutants and semantic mutation evidence; strict Clippy; final formatting, full-suite and whitespace checks; workflow reviews and the human checkpoint. No real-systemd or mutation success is claimed here.

Useful semantic mutation targets are key canonicality/weakness, OS matching, reused keys and enabled labels, schema/audit validation, exact poll-owner matching, typed owner digest/approval binding, historical binding reference validation, scoped request invalidation, token publication/backend/final-release checks, persistence failure closure, waiting for matching executions, and Reaped evidence for Running. The current running/retry test coordinates through channels but its negative try-receive assertion alone is not a complete deterministic skipped-wait detector; strengthen if a semantic skipped-wait mutation survives. A dedicated actual 20-second scoped cleanup-timeout test has not been added; existing uncertainty/manager suites and new agent uncertainty tests cover fail-closed cleanup errors.
