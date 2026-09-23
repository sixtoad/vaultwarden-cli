---
title: 'Story 1.3: Unlock and Lock the Provider Vaultwarden Session'
type: feature
created: 2026-09-23
status: done
baseline_commit: 91a6a662cdfb6b27edba2ca93cd3735b630a1931
context:
  - '{project-root}/docs/implementation/epic-1-context.md'
  - '{project-root}/docs/implementation/1-3-planning-notes.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The provider starts locked but lacks a human unlock path and exclusive, revocable Vaultwarden session authority.

**Approach:** Add backend-neutral ports, provider-owned session/backend adapters, and a protected loopback password UI. Serialize authority checks, resolution, and revocation; expose only redacted outcomes.

## Boundaries & Constraints

**Always:** Follow Story 1.3, the architecture spine, and canonical SPEC. Only provider core calls `SecretBackend`; raw vault items and `CipherOutput` stay inside adapters. Core imports no config, keyring, socket, HTTP, or browser infrastructure. Passwords enter only through the human loopback/provider-session path. Reusable authority uses provider-owned memory/keyring, never access state or audit. Preserve every quick-dev checkpoint.

**Ask First:** Scope changes; commit, push, or PR without approval of implementation and complete test evidence.

**Never:** Passwords in argv, environment, agent IPC, logs, URLs, state, audit, or status; session/secret disclosure; plaintext session fallback; automatic unlock after restart; WebAuthn; agent-facing resolution; later-story approval/execution features.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected behavior | Failure |
|---|---|---|---|
| Unlock | Authenticated loopback browser, valid password, compatible backend | Bounded session becomes usable | Fixed redacted category |
| Admission | Locked, expired, or incompatible | No item/secret backend call | Fail closed |
| Compatibility | Unknown/malformed version or API | No cipher/sync resolution | Incompatible backend |
| Authority loss | Lock, expiry, restart | Clear memory/keyring; invalidate unexecuted work | Remain locked if cleanup fails |
| Race | Unlock/resolution concurrent with lock | Serialized authority; no late usable result | Discard stale completion |
| Hostile browser | Wrong host/origin/cookie/CSRF, replayed launch | No authentication/backend call | Redacted rejection |

</frozen-after-approval>

## Code Map

- `src/access/provider.rs`, `provider_store.rs`: lifecycle, policy admission, durable invalidation and epoch.
- `src/access/ports.rs`: existing eligibility port; new authority contracts.
- `src/config.rs`, `api.rs`, `commands.rs`, `crypto/`, `models.rs`: configuration, API and decryption extraction sources.
- `src/bin/vaultwarden-accessd.rs`: daemon composition and lifecycle loop.

## Tasks & Acceptance

**Execution:**
- [x] `src/access/ports.rs` — define `SecretBackend`, `ProviderSession`, `ApprovalAuthenticator`, clock contract, backend-neutral bindings and redacted zeroizing value types.
- [x] `src/adapters/session.rs`, `src/config.rs` — extract silent password/key derivation and strict provider keyring facilities; clear reusable keys/tokens on authority loss; preserve direct CLI behavior.
- [x] `src/adapters/vaultwarden.rs`, `src/api.rs` — probe metadata before session activation/resolution; accept initially only Vaultwarden 1.36.0/API 2025.12.0; resolve immutable bindings and selected fields without exporting raw items.
- [x] `src/access/application.rs`, `provider.rs`, `provider_store.rs` — own session/backend behind one authority gate; gate existing eligibility calls; revoke before fallible cleanup; invalidate epochs/work on lock, expiry and restart. Keep resolver private to core. Check expiry before each binding, after slow eligibility and before activation persistence; do not hide another probe between the core deadline check and item fetch.
- [x] `src/adapters/loopback_ui.rs` — implement loopback password POST, one-use desktop launch capability, trusted HTTPS with provider-owned certificate/key, Secure HttpOnly/SameSite session and independent launch-issued browser proof; exact Host/Origin/CSRF checks; bounded concurrent parsing, overload revocation, input limits and redacted responses.
- [x] `src/adapters/mod.rs`, `src/lib.rs`, `src/access.rs`, `src/bin/vaultwarden-accessd.rs`, `Cargo.toml` — compose adapters, expiry timer, unconditional startup session clearing and stop/join-before-final-revocation cleanup (including worker errors).
- [x] `src/access/application.rs`, `src/access/provider.rs`, adapter test modules, `tests/provider_session.rs` — test matrix using counting backends, mock HTTP/keyring, injected clock, deterministic race barriers and disclosure sentinels.
- [x] `docs/access-mvp.md`, `docs/implementation/1-3-test-evidence.md` — document setup, compatibility, lifecycle and evidence; correct WebAuthn-first guidance.

**Acceptance Criteria:**
- Given a locked or incompatible provider, when eligibility/resolution is attempted, then the item backend is never called.
- Given password/session/secret sentinels, when success and failure paths run, then every external surface remains redacted.
- Given stored session material and pending work, when lock, expiry or restart occurs, then memory/keyring authority clears and work cannot resume after re-unlock.
- Given racing resolution/unlock and lock, when lock returns, then no stale completion restores authority or releases a secret.
- Given keyring/store cleanup failure, when authority is revoked, then the provider remains unusable and reports only a stable category.
- Given unsupported metadata, when compatibility is probed, then failure precedes any item or sync call.

## Spec Change Log

### Iteration 2 — independent review 1 (2026-09-23)

Trigger: shutdown resurrection, stale-keyring restart, browser cookie/port takeover, slow-client starvation and expiry gaps. Amend non-frozen UI/composition/admission tasks: trusted TLS identity; launch-only independent browser proof; concurrent bounded parsing with fail-closed overload; unconditional startup clear; stop/join before final clear; per-binding and pre-persistence deadline checks. Avoid cookie-only CSRF recovery, plaintext stale-page password delivery, authority surviving worker shutdown, and post-expiry cipher admission. KEEP: all ports/core ownership, private consumption, mutex revocation, cleanup poison, keyring separation, compatibility/decryption restrictions, zeroization/redaction and existing meaningful tests/hardening. Full dispositions and preservation instructions: `1-3-review-results.md`. Frozen intent unchanged.

### Iteration 3 — independent review 2 (2026-09-23)

Trigger: suspend extends sessions; failed state validation skips startup keyring cleanup; backend errors bypass post-I/O expiry cleanup; synchronous status delays signal observation; browser mutations reorder; shutdown admission misses eligibility/policy checks; individual cipher keys are ignored. Amend non-frozen lifecycle, composition, browser and adapter tasks: suspend-aware monotonic time; cleanup after exclusive writer acquisition but before state validation; post-backend checks on both outcomes; responsive signal-driving task with irreversible closure; ordered browser mutation queue; closing checks before eligibility/policy persistence; provider-local account/org-to-item key derivation. Carry patches for escaped-body bounds, error-path password zeroization, stale no-config launch cleanup and accurate last-action UI wording. Avoid preserving stale authority or mis-decrypting valid individual-key logins. KEEP all iteration-2 boundary/security behavior and regression tests listed in review results. Frozen intent unchanged.

## Iteration 3 correction tasks

- [x] `src/adapters/session.rs` — suspend-aware monotonic clock, tested clock boundary/failure semantics without wall-clock extension.
- [x] `src/access/provider.rs`, `src/access/provider_store.rs`, `src/bin/vaultwarden-accessd.rs` — clear old keyring session once exclusive ownership is acquired, before any fallible state validation; never clear on a competing writer; clear stale launch artifact for no-config startup.
- [x] `src/access/application.rs` — check authority after all backend results, including errors; check closing before eligibility and final policy admission; preserve post-persistence revocation.
- [x] `src/bin/vaultwarden-accessd.rs` — keep signal reception responsive to delayed session/status work and close admission before waiting.
- [x] `src/adapters/loopback_ui.rs`, `tests/provider_session.rs` — serialize browser mutation clicks, bound worst-case JSON encoding, zeroize partially deserialized passwords, and accurately label last-action results.
- [x] `src/adapters/vaultwarden.rs` — decode and authenticate optional item keys inside adapter; test personal/org item-key login fields and malformed/tampered keys without exporting wire data.
- [x] Relevant tests and evidence — regressions for each correction; all four required checks before another independent review; retain previous outcomes only for unchanged production functions and document mapping.

## Design Notes

TLS certificate and unencrypted private-key PEM files must be provider-owned regular no-symlink files, bounded and mode-checked; fail closed for absent/unusable identity. Human installs trust for the provider identity; daemon never edits trust stores. Browser proof is returned only with successful one-time launch exchange, held in sessionStorage, required with cookie for all mutations, and never embedded in GET responses. Clear password DOM before fetch; disable/refuse plaintext transport. Per-connection TLS and HTTP deadlines apply before any application lock. Exhausted bounded parser capacity triggers authority revocation. Serialize admission through consumption/disposal; no public raw-value test helper. Check expiry at admission and by timer. Clear persisted authority before serving; failed cleanup prevents re-unlock. Separate provider/CLI keyring namespaces. See planning notes for provisioning and metadata contracts.

## Verification

Iteration 3: all 617 harness tests and Firefox checks pass. Complete expanded scope
is 289 mutations: 251 caught, 33 compiler rejections and five classified survivors;
no unresolved timeouts. 176 outcomes are retained only for byte-identical functions,
and 113 revised/new mutations were rerun. The one new survivor was caught after
fixture hardening. Full evidence is linked below.

Iteration 1 verified 596 harness tests and classified all 195 mutations, then failed independent review. Its evidence is historical. Iteration 2 verified 609 harness tests, actual Firefox transport behavior, and all 254 current mutations: 221 caught, 5 classified survivors, 28 compiler rejections, no unresolved timeouts. All four required checks completed before second review. See [evidence](1-3-test-evidence.md).

Run before review, recording outputs and mutation classifications:

- `cargo fmt --all -- --check`
- `cargo test --all-targets --quiet`
- `cargo mutants -f 'src/access.rs' -f 'src/access/**' -f 'src/adapters/**' -f 'src/api.rs' -f 'src/config.rs' -f 'src/bin/vaultwarden-accessd.rs' -- --all-targets` — scope to changed files, including additional extractions; fix/classify every survivor and record other outcomes.
- `git diff --check`

Then quick-dev review and human presentation; rerun checks after fixes. No publication before approval.

## Suggested Review Order

Implementation and independent review are complete. On 2026-09-23, the human
approved the implementation and complete test evidence, authorizing commit, push,
and PR creation.

**Authority and revocation**

- Start with the shared gate that serializes unlock, resolution, expiry, and lock.
  [application.rs:23](../../src/access/application.rs#L23)

- Inspect revocation before cleanup and irreversible shutdown admission closure.
  [application.rs:47](../../src/access/application.rs#L47)

- Keep resolved values private; recheck authority after backend completion.
  [application.rs:157](../../src/access/application.rs#L157)

- Clear crashed session authority only after acquiring exclusive writer ownership.
  [provider_store.rs:125](../../src/access/provider_store.rs#L125)

- Observe shutdown promptly while backend work holds the authority gate.
  [vaultwarden-accessd.rs:105](../../src/bin/vaultwarden-accessd.rs#L105)

**Human password boundary**

- Authenticate loopback requests using trusted TLS, one-use launch, and independent browser proof.
  [loopback_ui.rs:184](../../src/adapters/loopback_ui.rs#L184)

- Bound concurrent clients and revoke authority on transport saturation.
  [loopback_ui.rs:97](../../src/adapters/loopback_ui.rs#L97)

**Provider backend and session ownership**

- Reject unsupported metadata before unlocking or fetching items.
  [vaultwarden.rs:240](../../src/adapters/vaultwarden.rs#L240)

- Authenticate item keys and decrypt only selected fields inside the adapter.
  [vaultwarden.rs:103](../../src/adapters/vaultwarden.rs#L103)

- Separate provider keyring records from CLI credentials and clear revocable material.
  [session.rs:68](../../src/adapters/session.rs#L68)

- Count suspend time and fail closed on clock faults.
  [session.rs:25](../../src/adapters/session.rs#L25)

**Contracts, verification, and setup**

- Review backend-neutral ports and redacted secret containers.
  [ports.rs:32](../../src/access/ports.rs#L32)

- Exercise the actual HTTPS password boundary and externally visible responses.
  [provider_session.rs:35](../../tests/provider_session.rs#L35)

- Inspect complete test results, mutation classifications, browser evidence, and documented limits.
  [1-3-test-evidence.md:1](1-3-test-evidence.md#L1)

- Follow human provisioning and trusted loopback launch instructions.
  [access-mvp.md:13](../access-mvp.md#L13)
