# Issue 48: approved updates and rotation of existing secrets

Status: phase 1 (trusted CLI `update`) implemented on
`feature/issue-48-update-secrets`; phase 2 (protected provider `update`) is
specified here and deferred to the next PR.

Background: the create-only feature (#43, PR #44) is described in
[secret-storage.md](../secret-storage.md). This document reuses its vocabulary:
destination (`account_id`, `folder`, `folder_id`, `reference`), field selectors
(`password`, `notes`, `custom:NAME`), the fresh terminal challenge, the durable
metadata-only journal and the receipt (`attempt_id`, `item_id`, `status`).
Vaultwarden **1.36.0** remains the verified backend
([`ciphers.rs`](https://github.com/dani-garcia/vaultwarden/blob/1.36.0/src/api/core/ciphers.rs):
`PUT /api/ciphers/<id>`, `update_cipher_from_data`).

## 1. Scope

In scope:

1. Replacing the stored value of selected existing fields (`password`, `notes`,
   `custom:NAME`) of one existing **personal** Login item, addressed by its
   immutable item ID.
2. Preserving everything else about the item: ID, type, wrapped item key,
   name, folder, organization (none), username, URIs, TOTP, every unselected
   custom field (name, value, type, order), password history, favorite,
   reprompt, attachments.
3. Fresh human authorization per mutation, bound to the exact item, binding,
   fields and expected revision.
4. Exact verification through a fresh authenticated read.
5. Rotation guidance and consumer behaviour (section 6).

Out of scope (unchanged non-goals): creating fields, deleting fields or items,
renaming/moving items, organization writes, upserts, and issuing or revoking
credentials at any external service.

## 2. Phase 1 surface: `vaultwarden-cli update`

```sh
vaultwarden-cli update --id ITEM_UUID \
  --account ACCOUNT_UUID --folder homelab/production \
  --reference homelab/production/github/deploy-token \
  [--expected-revision REVISION] [--prompt]
```

Values come from `--prompt` (one hidden password) or a bounded JSON document on
stdin in exactly the create format (`password`, `notes`, `fields[]`; 64 KiB,
at most 32 custom fields, the same name rules, `vw-access` reserved, unknown
or duplicate keys refused). Each key present selects that field for
replacement; absent keys are preserved. There is no `--yes`.

Sequence (every step that fails stops before the PUT, with no receipt unless a
journal exists):

1. Validate arguments; load the unlocked session; full sync.
2. Resolve the folder label to exactly one folder ID; check the account
   binding (`check_sync`).
3. Refuse if any earlier update journal for this server and item is still
   `uncertain` (section 5).
4. `GET /api/ciphers/ITEM` (bounded raw JSON). Check the item binding
   (`check_item`: ID, not deleted, personal, folder ID, decrypted name equals
   the reference's item name). Record `revisionDate` as the expected revision;
   if `--expected-revision` was given it must equal it.
5. Read the new values; build the update plan against this snapshot (refuses
   unsupported shapes and missing fields before any prompt).
6. Show the review on the controlling terminal: `UPDATE personal vault item`,
   item ID, account and server, folder label and ID, reference, expected
   revision, fields replaced. Never values. Require `update <random 128-bit
   challenge>` typed on the terminal. No terminal, a wrong answer or EOF:
   refusal, no PUT.
7. Fresh sync (bindings again) and fresh GET. The revision must still equal the
   reviewed revision, and the binding must still hold; otherwise refuse
   (`item changed since review`), no PUT.
8. Re-encrypt only the selected values with the item's effective key (the
   wrapped item key, or the user key for legacy items without one) and fresh
   IVs, through the existing `CryptoKeys::encrypt` path. Build the body from
   the fresh snapshot, sending every preserved component's ciphertext verbatim
   and `lastKnownRevisionDate` = the reviewed revision.
9. fsync a metadata-only journal (`uncertain`), then exactly one PUT.
10. A success response whose ID equals the item → `updated_unverified`, saved;
    then fresh sync + fresh GET + exact comparison → `verified`.
11. Print only the receipt JSON on stdout; exit non-zero unless `verified`.

## 3. Decisions

Each decision lists context, options, choice, reason and how to reverse it.

### D1. Target addressing: immutable ID plus the full destination binding

- Context: the issue requires preserving identity and account/folder/reference
  bindings. A name lookup could select the wrong item.
- Options: (a) `--id` only, displaying whatever name/folder the item has —
  simplest, but nothing proves the human meant that namespace; (b) `--journal`
  of the original create — strong, but items created elsewhere have none;
  (c) `--id` plus `--account/--folder/--reference`, verified with the existing
  `Destination::check_sync`/`check_item` — works for every canonical item and
  reuses the read-field binding rules.
- Choice: (c). Reason: no fallback from ID to name, same fail-closed checks as
  create and journal-bound reads, no dependence on local history.
- Consequence: items outside the canonical namespace rules cannot be updated by
  this command. Reverse: accept `--journal` as an alternative binding source,
  or relax the namespace check behind an explicit flag.

### D2. Expected revision is Vaultwarden's `revisionDate`, checked twice client-side and once server-side

- Context: concurrent edits between review and write must be rejected.
  Vaultwarden 1.36 compares `lastKnownRevisionDate` with the stored
  `updated_at` and refuses (HTTP 400) only when the stored revision is more
  than **one second** newer; an unparsable value is only logged, not refused.
- Options: (a) rely on the server check alone — coarse (1 s) and silently
  disabled on a parse error; (b) client-side compare only — leaves a race
  between the final GET and the PUT; (c) both: exact string equality on the
  reviewed GET and on a fresh GET after the challenge, then send the exact
  `revisionDate` string back as `lastKnownRevisionDate`.
- Choice: (c). Reason: exact comparison covers edits during review; the server
  check narrows the remaining GET→PUT window. Optional `--expected-revision`
  lets a caller pin the revision it inspected earlier.
- Residual risk (documented): an edit landing inside the GET→PUT window and
  within one second of the reviewed revision can be overwritten. Vaultwarden
  offers no compare-and-swap; the verification read still detects a value
  mismatch only for selected fields. Reverse: none needed; tighten if a future
  Vaultwarden offers exact preconditions (e.g. `If-Match`).

### D3. A missing field is refused, never added

- Context: the selected field may not exist on the item (no password, no
  notes, no such custom field).
- Options: (a) add it — convenient, but adding changes the item's schema,
  which read policies and field mappings bind; it is a creation, not a
  replacement; (b) refuse.
- Choice: (b) refuse before the review (`selected field missing`). Reason:
  update means replacing an existing value; schema changes deserve their own
  reviewed operation. Reverse: add an explicit `--add-missing` mode with its
  own review line ("ADD field").

### D4. Field kinds that may be replaced

- Context: custom fields have types (text, hidden, boolean, linked); `vw-access`
  is the protected eligibility marker.
- Choice: replace `password` (Login items only), `notes`, and custom fields of
  type text or hidden, keeping the original type. Refuse boolean and linked
  fields, `custom:vw-access`, duplicate decrypted field names, non-Login items
  and organization items. Reason: booleans/links have no secret value; the
  marker is policy metadata. Reverse: widen the allowed list in
  `secret_update::plan_update`.

### D5. Notes-only updates are allowed

- Context: create requires a password or a custom field. For update, notes is
  a legitimate selector on its own.
- Choice: the update parser accepts any non-empty selection, including notes
  alone; every other create rule is shared (`SecretImport::validate_update`).
  Reverse: call `validate` instead.

### D6. Password history and password revision date are preserved, not appended

- Context: Bitwarden clients push the old password into `passwordHistory` and
  set `login.passwordRevisionDate` when a password changes.
- Options: (a) emulate them — keeps the old secret recoverable in the vault
  (useful for rollback) but retains the value rotation is meant to retire;
  (b) preserve both verbatim.
- Choice: (b). Reason: the CLI never decrypts or re-stores the old value, and
  rotation should not keep the retired secret by default. Rollback is the
  consumer's job (section 6). Reverse: append an encrypted history entry and
  set the date in `plan_update`, with a review line saying so.

### D7. Preserve by verbatim ciphertext, verify by ciphertext equality

- Context: Vaultwarden's PUT replaces the whole item from the request; every
  omitted component is lost.
- Choice: build the body from the fresh GET's raw JSON (camelCase, the shape
  Vaultwarden 1.36 returns; other shapes are refused), sending preserved
  components unchanged. Verification requires the fresh read to return the
  same ciphertext for every preserved encrypted string (name, key, notes,
  username, TOTP, URIs, every unselected field name/value and every field
  type and order) and exactly the new plaintext for every selected field.
  Reason: Vaultwarden stores strings as sent; ciphertext equality is stronger
  than plaintext equality and needs no extra decryption. Reverse: compare
  decrypted plaintext instead if a backend re-encrypts.

### D8. Journal per attempt; an uncertain update blocks further updates of that item

- Context: create's journal slot is per destination and permanent. Updates
  repeat over an item's life.
- Options: (a) no journal; (b) one slot per item, replaced on terminal states
  (loses history, racy); (c) one file per attempt
  (`write-attempts/update-<sha256(server, item)>-<attempt>.json`), fsynced
  before the PUT, plus a scan that refuses a new update while any earlier
  attempt for the item is `uncertain`.
- Choice: (c), mandatory like create's. Reason: an uncertain mutation is never
  replayed automatically, and the human must resolve it before authorizing
  another write to the same item. Reverse: drop the scan in
  `WriteJournal::ensure_no_uncertain_update`.

### D9. Reconciling an uncertain update

- Context: after an interrupted PUT the CLI does not know whether it committed.
- Choice: `reconcile --journal J --id ITEM` (read-only) re-checks the bindings
  and compares the current `revisionDate` with the journal's
  `expected_revision`. Unchanged → `failed` (nothing was written to the item
  since the attempt was recorded). Changed → `updated_unverified` (someone
  wrote; the original values are gone after the process ended, so it can never
  become `verified`). It never PUTs. Reason: unblocks D8 with an honest status.
  Caveat (documented): a request still in flight inside a slow server could in
  principle commit after the reconcile read. Reverse: keep the receipt
  `uncertain` and require deleting the journal by hand.

### D10. New receipt status `updated_unverified`

- Context: create's `created_unverified` would mislabel an update.
- Choice: add `WriteStatus::UpdatedUnverified` (`updated_unverified`). Existing
  statuses keep their meaning. Reverse: remove the variant (only update paths
  produce it).

### D11. HTTP outcome mapping is create's

- Choice: 400/401/403/404/405/422 → `failed` (Vaultwarden validates, including
  the stale-revision check, before committing); network errors, other statuses,
  oversized or unparsable bodies, or a response for another ID → `uncertain`.
  Errors never include server bodies or payloads. Reverse: per-status changes
  in `ApiClient::update_cipher`.

## 4. Value handling

- Plaintext lives only in `Zeroize`/`Zeroizing` buffers (`SecretImport`), is
  encrypted locally, and is never formatted into errors, the review, stdout,
  stderr or the journal. The journal holds server, destination, item ID,
  selectors, expected revision and the receipt.
- Values are UTF-8 strings preserved byte for byte (spaces, line breaks, NUL);
  `read-field` returns them exactly afterwards.
- The old value is never decrypted by `update` except to verify; it is not
  retained (D6).

## 5. Outcomes

| Status | Meaning for an update |
| --- | --- |
| `failed` | Definite rejection (including a stale revision), or reconcile proved the item unchanged since the attempt. |
| `uncertain` | The journal exists; whether the PUT committed is unknown. Blocks further updates of the item until reconciled. |
| `updated_unverified` | The server accepted the PUT (or reconcile saw a newer revision), but exact comparison with the new values did not succeed. |
| `verified` | A fresh read matched every new value exactly and every preserved component verbatim, under the same bindings. |

Nothing is ever retried automatically. A new update after `failed` or
`updated_unverified` is a new, separately authorized mutation against the
then-current revision.

## 6. Rotation semantics

- **Replacing the stored value** (in scope): the vault item now holds the new
  value. Nothing at the external service changes.
- **Issuing a new credential and revoking the old one** (out of scope): the
  consumer (operator or a reviewed protected producer) must, in order:
  1. issue the new credential at the external service while the old one still
     works (overlap window);
  2. store it with `vaultwarden-cli update` and wait for `verified`;
  3. switch consumers; confirm they authenticate with the new value;
  4. revoke the old credential at the service.
  If step 2 ends `failed`, revoke the *new* credential (or retry the store
  explicitly); if `uncertain` or `updated_unverified`, reconcile and read the
  field back before revoking anything. Revoking before a verified store can
  lock everyone out.
- **Consumers holding the old value**: a value already delivered (an
  environment variable of a running process, a file, a copy) is not recalled
  or changed by an update; it keeps working only as long as the external
  service accepts it. Later reads (`read-field`, `get`, `run`, protected read
  operations) return the new value. This follows
  [secret-access-boundary.md](../secret-access-boundary.md): no process is
  stopped and no delivered copy is claimed erased.
- **In-flight protected runs**: a run whose secrets were already read keeps the
  old values; a run that reads after the update receives the new values. There
  is no snapshot isolation across a run's separate reads. Operators who need
  a consistent set should rotate between runs.

## 7. Phase 2 (specified, not implemented): protected provider `update`

Analogous to the protected create (`CreateEffect`, fd 3 producer frame).

- **Policy**: a new closed `update` effect alongside `create`, mutually
  exclusive with it, `ssh` and credentials:
  `{"server","item_id","destination":{account_id,folder,folder_id,reference},"fields":[...]}`.
  `fields` uses the create selector rules; `custom:vw-access` is refused. The
  policy pins the item ID and binding; it **cannot** pin a revision (it changes
  on every update and would make the policy single-use).
- **Request/review**: at review time the provider performs the D1 binding
  checks and a GET, and puts into `DirectReview` an `update` object:
  `{item_id, destination, fields, expected_revision}` plus the effect line
  `UPDATE personal vault item (no create)`. Values are never present: the
  producer has not run yet. The reviewer sees item, binding, fields and the
  expected revision.
- **Execution**: after approval, run the producer exactly as for create (fd 3
  frame, same schema must equal `fields` exactly, same limits). Then fresh sync
  and GET; refuse if the revision differs from the reviewed
  `expected_revision` (the approval is stale and consumed), journal in private
  provider state, PUT with `lastKnownRevisionDate`, verify as D7. The provider
  never reruns a producer or a PUT; an uncertain result is reconciled with
  `vw-access reconcile-write` using D9's revision comparison.
- **Touch ID v2**: no transcript change. The `update` object is part of the
  review JSON, so the existing `review_digest` (field 14) binds item, fields
  and expected revision; the record and policy digests bind the policy. A
  revision change after approval is caught by the execution check above.
  Compatibility: a companion that does not understand `update` must not sign
  it. The provider sets `biometric_allowed: false` for update reviews unless
  the approval client advertises an `update-review` capability
  (see [issue-50-capabilities.md](issue-50-capabilities.md)), so older
  companions fall back to password approval with the loopback review showing
  the update block.
- **History and replies**: agent replies and human history carry the receipt
  and selectors only, never values.

## 8. Acceptance tests (phase 1)

Implemented in `tests/secret_update.rs` (a stateful fake Vaultwarden over a
real pseudo-terminal) and unit tests in `src/secret_update.rs`:
success with exact read-back; stale `--expected-revision`; concurrent edit
between review and write; server stale rejection (400); denied challenge; no
terminal; malformed input; missing field; interrupted write (`uncertain`,
blocks the next update, reconcile); verification mismatch
(`updated_unverified`); plaintext absent from stdout, stderr, the review and
the journal; preservation of unselected components.

`scripts/mutate-secret-update.py EVIDENCE_DIR` weakens each update guard in
turn (challenge, expected-revision pin, review recheck, pre-decision field check,
verification gate, reconcile rule, uncertain block, `lastKnownRevisionDate`,
field kinds, exact value, identity and unselected-field preservation, response
shape and identity) and requires the focused tests to fail; the last report is
`issue-48-mutations/report.json` (14 of 14 caught). Two first-run escapes were
real test weaknesses (tampered values encrypted under the wrong key, so a MAC
failure masked the comparison; a PascalCase probe that serde already refused)
and were fixed in the tests.

Phase 2 acceptance (next PR): denial, expiry, cancellation, lock during a
pending request, stale revision after approval, producer failure, interrupted
PUT, Touch ID v2 review digest over the update block, consumption after
rotation.
