# Acceptance and verification

This is a test plan, not executed evidence. No native fingerprint test, enrollment
or implementation has occurred during specification. Existing CI cannot replace
human hardware acceptance.

## Automated gates

| Capability | Required evidence |
| --- | --- |
| CAP-1 | Correct local enrollment; missing/unknown/replaced/revoked key rejection; transport enrollment alone insufficient; private-file/link/ownership enforcement; bounded registry migration; wrong provider/client/key binding rejected. |
| CAP-2 | Rust/Swift golden vectors; tamper each transcript binding and signature; malformed/noncanonical encodings rejected; one dispatch under replay/concurrent duplicate and password-versus-biometric races; no approval from client boolean or transport authentication alone. |
| CAP-2 / CAP-4 | Challenge/request/session expiry, lock/unlock generation change, restart, policy/executable/argument/review change and agent revocation between review, signature verification and final commit all reject stale authority. |
| CAP-3 | Cancellation/unavailable/lockout never sends approval; explicit password choice gets fresh review and input; denial needs no authentication prompt; no silent OS-password, cached-unlock, software-key or automatic password fallback. |
| CAP-2 / CAP-3 | Stale native completion after selection, reconnect, setup replacement, sleep or session invalidation is discarded; double-click and concurrent prompts cannot create duplicate attempts; cancelled contexts cannot sign later work. |
| CAP-4 | Revocation/replacement retires outstanding tickets; lost local key does not auto-enroll; certificate renewal does not inherit key authorization; unchanged v1 clients and password approvals work; unsupported v2 differs from TLS/network failure. |
| CAP-5 | Lost decision response causes status-only recovery; pending/unknown outcome stays uncertain; no signature/decision replay; audit method/key reference is redacted; failed audit persistence prevents dispatch. |
| All | Existing CA/hostname/leaf-pin/client-certificate negatives, unknown fields, body/key/signature sizes, rate/concurrency/ticket caps, log/output redaction and unchanged execution containment. |

Security mutations must be attributable, applied one at a time and restored
exactly. At minimum remove signature verification, a request/review binding,
device/key binding, single-use consumption, expiry/generation recheck and the
late-callback guard separately; each relevant test must fail for the intended
reason. Verify the restored baseline passes. Hardware biometric enforcement
needs a real signing attempt, not only a mock returning authenticated=true.

Run existing formatting, all-target/all-feature Clippy, locked default/all/no-default
feature and documentation tests, Rust 1.88 checks, cargo audit/deny, native Swift
tests and affected real integration suites. Run tests and mutations before
implementation review; all mandatory CI must finish. Verify actual coverage-step
results rather than treating a non-blocking green job as proof of coverage.

## Native feasibility gate: M1 Mac mini

Coordinate readiness with the operator. Record macOS version/build, keyboard
Touch ID availability, exact app/source build and code-signing profile. Use a
dedicated test key and synthetic request data, not personal vault credentials.

Demonstrate key creation and reopen after app exit; absence of raw private-key
export; protected signing requiring Touch ID; no signing from an unlocked Mac
alone; cancellation and lockout rejection; and two consecutive operations each
requiring a new touch. Document actual prompt behavior and key access after a
rebuild/update. Never silently replace an inaccessible key to make the test pass.

Changing the macOS fingerprint set is a separate operator-approved action.
If authorized, demonstrate that the old test key becomes unusable and recovery
requires explicit replacement. Do not enroll/remove fingerprints automatically.
If not performed, mark that hardware acceptance case pending, not passed.

If the current development signing profile cannot meet enforced access,
persistence and explicit update recovery, pause for a signing/provisioning
decision. A successful ordinary Mac unlock is hardware availability evidence,
not proof of this application's signing policy.

## Integrated operator acceptance

Use the existing private-network provider/companion trust model, a disposable
Vaultwarden environment, synthetic scoped credentials and a real restricted
agent identity. Any host setup change requires separate approval; do not replace
or stop an existing provider merely to run this plan.

1. Unlock the provider with its existing password flow. Show that Touch ID cannot unlock a locked vault.
2. Submit a noninteractive agent request and open its notification. Nothing executes until the operation is reviewed and explicitly approved.
3. Click Approve with Touch ID, cancel, and establish that no approval/dispatch occurred. Obtain a fresh review for the next attempt.
4. Approve two successive requests, each with a separate real touch. Observe exactly one permitted execution per request and only redacted agent results.
5. Demonstrate denial and explicit password approval independently; neither reuses a biometric proof or stored password.
6. Exercise stale/expired/revoked proof and a lost-response case using controlled fixtures; observe no stale execution or automatic retry. Query authoritative status for uncertain outcomes.
7. Revoke the approval key through trusted administration, restart as required, and prove old proofs fail while intentional password-only operation remains possible. Explicitly enroll a replacement only with operator approval.
8. Preserve redacted evidence and remove only owned test resources after independently confirming termination. Never publish private keys, credentials, raw challenges/signatures or biometric material.

## Completion boundary

Done means native gate, automated/security/mutation checks, full CI and the
coordinated synthetic M1 demonstration pass for the implemented source. Missing
hardware evidence remains an explicit acceptance blocker, not a reason to
weaken authentication. Public notarization, a new provider platform and biometric
vault unlock are not completion requirements.
