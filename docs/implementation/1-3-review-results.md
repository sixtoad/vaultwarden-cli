# Story 1.3 independent review, iteration 1

Three independent reviewers ran without conversation context at the parent model capability: blind adversarial, edge-case, acceptance. All reviewed the complete tracked/untracked diff after the four pre-review checks. Findings below are deduplicated and validated against implementation and architecture.

## Disposition: bad_spec; rederive implementation (iteration 2)

- **P1, shutdown ordering** — all three reviewers: daemon locks before joining UI; an accepted partial unlock can recreate keyring authority afterward. Plan must require irreversible admission shutdown or join-before-final-cleanup, including worker failure.
- **P1, browser credential isolation** — blind reviewer: cookie is host-scoped, not port-scoped; cookie-only GET recovers CSRF. Plan must forbid obtaining mutation proof with a cookie alone. Secure HttpOnly SameSite cookie plus independent per-launch origin-held proof, issued once and never returned by GET.
- **P1, replacement listener** — blind reviewer: stale HTTP password form posts to whoever binds the old port after crash. Plan lacked server authentication. Require HTTPS using a human-provisioned, browser-trusted server identity and provider-owned key; no HTTP password interface or certificate-warning bypass. A replacement with an untrusted certificate cannot receive the form body.
- **P2, restart cleanup** — all reviewers: no-config startup skips keyring clearing. Clear provider revocable session before configuration branches, including malformed setup paths; cleanup failure blocks admission.
- **P2, expiry through eligibility** — acceptance reviewer: each binding and final policy persistence need deadline checks; duplicated adapter probe can cross expiry before cipher fetch. Plan must define one checked probe sequence and per-binding admission, expiry-before-commit invalidation.
- **P2, unauthenticated connection starvation** — blind reviewer: serial request parsing permits slow clients to monopolize Lock. Bound concurrent parsing and total deadlines; saturation must revoke usable authority, and shutdown must join workers before final clear.

These are outside frozen intent: the protected loopback path, backend ownership, authority-loss semantics, and no-disclosure requirements remain unchanged. Human provisioning already exists; TLS adds explicit server identity provisioning without changing machine/browser trust automatically. No native password path or WebAuthn is introduced.

## Patch observations incorporated into rederivation

- Parse cookie pairs, rejecting duplicate session cookie names, instead of comparing the entire Cookie header (edge reviewer).
- Clear password input before awaiting network I/O; report stable failures (blind reviewer).

## KEEP instructions extracted before rollback

Preserve backend-neutral ports, private scoped consumption, serialized authority gate, cleanup poisoning, monotonic 15-minute limit, strict provider-only keyring namespace, no CLI session restoration, metadata-only exact compatibility policy, no redirects/proxy and bounded requests, selective immutable-ID decryption, explicit MAC enforcement despite CLI opt-out, redacted stable errors, zeroizing secret containers, core infrastructure boundary, and all previously verified tests and hardening. Preserve no publication without approval. Retain complete first-pass test/mutation evidence as historical evidence only.

Snapshot before mandated rollback: `target/story-1-3-evidence/review-1-implementation/`; complete diff: `target/story-1-3-evidence/review-all.diff`. No commits/staging/publication. Restore retained code only through a new implementation pass against the amended non-frozen plan.


## Iteration 2 review dispatch — pending

All four requested pre-review checks completed: formatting, 609 passing all-targets
tests, 254 mutation outcomes (221 caught, 28 compiler rejections, five individually
classified survivors, no unresolved timeouts), and whitespace validation.
Production/test fingerprints are recorded in `1-3-tested-files.json`.

The attempt to spawn a fresh no-context blind reviewer failed with
`agent thread limit reached`. Listing agents returned only the root task, so no
fresh independent reviewers were available. Per quick-dev step 4, generated the
three independent review prompts and halted instead of substituting self-review
or carrying forward the earlier reviews. Second-round review is NOT complete.

- [Blind reviewer prompt](1-3-review-prompt-blind.md)
- [Edge-case reviewer prompt](1-3-review-prompt-edge.md)
- [Acceptance reviewer prompt](1-3-review-prompt-acceptance.md)

Run each in a separate fresh session and return its findings to this task. Then
deduplicate/classify findings, complete any required loopback or patch/reverification,
and follow step 5 for the human implementation/evidence checkpoint. Do not commit,
push or open a PR. Current spec status remains `in-review`.


### Reviewer retry

On the human's request to retry, all three fresh-session reviewers started
successfully: blind adversarial, edge-case, and acceptance. All tested file
fingerprints still match the completed evidence. The manual fallback is no longer
needed; findings and triage will be recorded here before the human checkpoint.


## Iteration 2 findings and disposition — bad_spec; iteration 3

All three fresh no-context reviewers completed. Acceptance found no actionable
discrepancy and independently checked source hashes, all mutation records/logs and
browser evidence. Blind and edge reviewers found additional reachable gaps.

Accepted bad_spec corrections outside frozen intent:

- P2: Linux monotonic Instant excludes suspend, extending a nominal 15-minute
  session across sleep. Require suspend-aware monotonic elapsed time.
- P2: Startup validates durable state after acquiring its writer lock but before
  keyring clear. Corrupt state or a changed registered executable leaves a crashed
  provider's revocable record. Clear after exclusive ownership, before state
  decoding/validation; never clear a competing provider's session.
- P2: Slow failing compatibility/resolution returns bypass expiry cleanup. Recheck
  authority after every backend result, success or error, before propagating it.
- P2: Blocking status in the async signal-driving task delays observing shutdown.
  Keep signal reception responsive while session work owns the gate; publish
  irreversible closure before waiting for cleanup.
- P2: Concurrent browser mutation fetches can process Lock before an earlier
  Unlock. Serialize human mutations in click order.
- P2: Shutdown closing flag must also gate each eligibility call and final policy
  admission, so admitted activation cannot knowingly persist after closure.
- P2: Supported Vaultwarden metadata can return per-item encrypted keys; the
  reused Cipher schema drops them. Derive item keys inside the provider adapter
  using account/org parent keys before decrypting fields; fail closed for invalid
  keys and maintain MAC requirements.

Patch observations to carry into rederivation:

- Make the encoded JSON body bound sufficient for every permitted 4096-byte
  password; verify escaped passwords through actual transport.
- Zeroize the deserialized password even on later JSON validation failure.
- Remove stale launch artifacts in no-config startup once ownership is held.
- Make UI outcome wording explicit about being the last action result; do not
  imply continuously refreshed live authority status.

No frozen intent changed. Policy persistence during a time-boundary crossing does
not by itself resurrect session/request authority: post-persistence revocation
remains mandatory. Browser certificate validation already rejects unusable SAN,
validity and usage; local duplication is not required for the stated boundary.

### KEEP instructions before rollback

Preserve all iteration-2 ports and provider-only ownership; private scoped consumption; serialized revocation and cleanup poisoning; strict keyring namespaces and no CLI restoration; exact metadata compatibility/no redirects/no proxy/bounds; immutable selected-field decryption and mandatory MAC; trusted HTTPS and launch-only independent proof; no cookie-based proof recovery; bounded concurrent parsing with overload revocation; secure setup/TLS files; worker reaping; no late unlock after shutdown; all 609 passing tests, browser checks and 254 individually mapped mutation outcomes as historical evidence. No password/secret exposure or new agent resolver, no WebAuthn, and no publication.

Snapshot: `target/story-1-3-evidence/review-2-implementation/`. All iteration-2
evidence is historical until affected verification completes. No staging or
commit. Full reviewed diff: `target/story-1-3-evidence/review-2-all.diff`.

## Iteration 3 — independent review complete

Three fresh reviewers completed without conversation context at the parent model
capability: blind adversarial, edge-case, and acceptance. The reviewed inputs were
`target/story-1-3-evidence/review-3-blind.diff` and `review-3-all.diff`, with
project/spec access restricted by reviewer role. No production or test code
changed after the final verification and review dispatch.

No remaining intent-gap, bad-spec, or patch findings. The acceptance auditor
independently checked tested file fingerprints, raw 617-test output, Firefox
assertions/logs, and all 289 mutation mappings. All 176 retained outcomes apply to
46 byte-identical production functions. Formatting and diff checks also passed
the auditor's independent rerun.

One confirmed pre-existing hardening issue is deferred: the shared
`StretchedKeys::decrypt_symmetric_key` helper drops a temporary decrypted key
buffer without zeroization. The helper is unchanged from the baseline. Its
allocator residue is not a reachable session or an external disclosure surface;
provider-owned live keys and the revocable keyring record are cleared on lock.
See [deferred work](deferred-work.md) for a focused follow-up and validation scope.

All Story 1.3 acceptance requirements are satisfied within the documented test
limits. The human approved implementation and complete evidence on 2026-09-23,
authorizing commit, push and PR creation. No publication occurred before approval.
