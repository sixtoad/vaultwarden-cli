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
   name, folder, organization (none), username, URIs (with `match` and
   `uriChecksum`), TOTP, passkeys (`fido2Credentials`), every other login
   member, every unselected custom field (name, value, type, `linkedId`,
   order), existing password-history entries, favorite, reprompt,
   attachments. Like official Bitwarden clients, a replaced password or hidden
   field value is added to password history (D6).
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
   `uncertain` (section 5). This early check spares a useless review; the
   authoritative one is step 7.
4. `GET /api/ciphers/ITEM` (bounded raw JSON). Check the item binding
   (`check_item`: ID, not deleted, personal, folder ID, decrypted name equals
   the reference's item name). Record `revisionDate` as the expected revision;
   if `--expected-revision` was given it must equal it.
5. With `--prompt`, refuse an item without a stored password before asking
   for the secret. Read the new values; build the update plan against this
   snapshot (refuses unsupported shapes and missing fields before any prompt).
6. Show the review on the controlling terminal: `UPDATE personal vault item`,
   item ID, account and server, folder label and ID, reference, expected
   revision, fields replaced, and which replaced values go to password history.
   Never values. Require `update <random 128-bit challenge>` typed on the
   terminal. No terminal, a wrong answer, EOF or Ctrl-C: refusal, no PUT (D12).
7. Take the item's exclusive update lock without waiting
   (`write-attempts/update-<hash>-.lock`; another holder: refuse, no PUT) and
   re-check that no attempt for the item is `uncertain` (D8). Hold the lock
   until the final receipt is saved. Fresh sync (bindings again) and fresh
   GET. The revision must still equal the reviewed revision, and the binding
   must still hold; otherwise refuse (`item changed since review`), no PUT.
8. Re-encrypt only the selected values with the item's effective key (the
   wrapped item key, or the user key for legacy items without one) and fresh
   IVs, through the existing `CryptoKeys::encrypt` path. Build the body from
   the fresh snapshot, sending every preserved component's ciphertext verbatim,
   the password-history entries and `passwordRevisionDate` of D6, and
   `lastKnownRevisionDate` = the reviewed revision.
9. fsync a metadata-only journal (`uncertain`), then exactly one PUT.
10. A success response whose ID equals the item → `updated_unverified`, saved;
    then fresh sync + fresh GET + exact comparison with the sent body (D7) →
    `verified`.
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
  `updated_at` and refuses (HTTP 400) only when
  `updated_at.signed_duration_since(last_known).num_seconds() > 1`.
  `num_seconds()` truncates, so the stored revision must be at least **two
  whole seconds** newer: an edit less than 2 s newer than the sent revision is
  accepted. An unparsable value is only logged, not refused.
- Options: (a) rely on the server check alone — coarse (under 2 s) and silently
  disabled on a parse error; (b) client-side compare only — leaves a race
  between the final GET and the PUT; (c) both: exact string equality on the
  reviewed GET and on a fresh GET after the challenge, then send the exact
  `revisionDate` string back as `lastKnownRevisionDate`.
- Choice: (c). Reason: exact comparison covers edits during review; the server
  check narrows the remaining GET→PUT window. Optional `--expected-revision`
  lets a caller pin the revision it inspected earlier.
- Residual risk (documented): an edit landing inside the GET→PUT window and
  less than two seconds after the reviewed revision can be overwritten. Vaultwarden
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

### D6. Password history and password revision date follow official clients

Owner decision 2026-11-22 (reverses the first draft, kept below as the
rejected option): match the official Bitwarden clients, so the replaced value
stays recoverable in the vault and the item looks exactly as if a Bitwarden
client had edited it.

- Context: official clients (`CipherService` in `bitwarden/clients`, applied
  when an existing Login is saved) do the following, and Vaultwarden stores
  `passwordHistory` and the `login` object verbatim:
  - if the old password is non-empty and differs from the new one, insert
    `{password: <old>, lastUsedDate: <now>}` at the front of
    `passwordHistory` and set `login.passwordRevisionDate` to the same time;
    otherwise keep the old `passwordRevisionDate`;
  - for every existing **hidden** custom field with a non-empty name and value
    whose value changed (or which disappeared), insert
    `{password: "<name>: <old value>", lastUsedDate: <now>}` at the front, in
    the item's field order (so the last such field ends up first);
  - keep only the newest **five** entries; an empty list becomes `null`.

  Entries are EncStrings under the item's effective key (fresh IVs); dates
  are JavaScript ISO strings (`2026-11-22T09:30:00.123Z`). This is written
  from knowledge of the client source, not from a copy checked here; the live
  test confirms that Vaultwarden 1.36.0 stores and returns what is sent.
- Options: (a) emulate the clients exactly; (b) preserve both members
  verbatim (first draft, rejected: the CLI never decrypts the old value, and
  rotation does not keep the retired secret in the vault; rollback is left to
  the consumer).
- Choice: (a). `plan_update` decrypts the old password and each **selected**
  hidden field (authenticated, `Zeroizing`), compares with the new plaintext,
  encrypts the entries with the item key, prepends them in the client order,
  truncates to `PASSWORD_HISTORY_LIMIT` (5) and sets `passwordRevisionDate`.
  Text fields and notes never go to history (clients do not either). Only
  selected fields can change, so unselected hidden fields never add entries.
  Where clients would re-trim an already over-long history without adding
  anything, the CLI sends it verbatim (official clients never produce more than
  five, so this only differs for histories written by other tools). The review
  says which old values go to history; verification expects the sent history
  and date exactly (D7).
- Reason: a rollback path (section 6) that every Bitwarden client already
  shows ("Password history"), and no divergence from what users expect.
- Consequence: the retired value remains in the vault (encrypted, readable by
  anyone who can decrypt the item) until it ages out after five further
  changes or the item is deleted. Revoking the old credential at its service
  (section 6) is what retires it; deleting a history entry needs a Bitwarden
  client. Reverse: drop the history step in `plan_update` (option b) and
  compare `passwordHistory`/`passwordRevisionDate` with the fresh read again.

### D7. Preserve by verbatim ciphertext, verify by ciphertext equality

- Context: Vaultwarden's PUT replaces the whole item from the request; every
  omitted component is lost.
- Choice: build the body from the fresh GET's raw JSON (camelCase, the shape
  Vaultwarden 1.36 returns; other shapes are refused), sending preserved
  components unchanged. Verification compares the fresh read with the body
  that was sent: `type`, `folderId`, `organizationId`, `key`, `name`,
  `favorite`, `reprompt` and `passwordHistory` equal; the whole `login`
  object equal member by member except a selected `password` (so username,
  TOTP, URIs with `match` and `uriChecksum`, `fido2Credentials`,
  `passwordRevisionDate` and any other member; a dropped passkey fails);
  every field object equal (name, type, `linkedId`, any other member), except
  a selected field's value; the same decrypted field names in the same order;
  attachments unchanged from the pre-write read except their download `url`
  (it carries a per-response token); and exactly the new plaintext for every
  selected field.
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
- Lock: after the decision, `WriteJournal::lock_update` takes an exclusive,
  non-blocking `flock` on `update-<hash>-.lock` and only then re-runs the
  scan; the lock is held across the fresh read, `journal.begin`, the PUT and
  the final receipt. A second invocation for the same item that decides while
  the first holds it is refused (`another update of this item is in
  progress`), with no journal and no PUT; one that decides after the first
  ended `uncertain` is refused by the re-check. Without waiting, a hung first
  process cannot leave a human blocked at a prompt; the lock is released by
  the kernel when the process exits. The `<hash>` covers the server URL with
  scheme and host lowercased and trailing slashes removed, so spellings of
  one server share one lock and one block.

### D9. Reconciling an uncertain update

- Context: after an interrupted PUT the CLI does not know whether it committed.
- Choice: `reconcile --journal J --id ITEM` (read-only) validates `ITEM` as a
  lowercase UUID before any request, refuses another item than the journal's,
  re-checks the account binding and compares the current `revisionDate` with
  the journal's `expected_revision`. Unchanged → the item binding must still
  hold, and the result is `failed` (nothing was written to the item since the
  attempt was recorded). Changed → `updated_unverified` (someone wrote; the
  original values are gone after the process ended, so it can never become
  `verified`). A move, rename or trash also changes the revision, so an item
  moved or trashed after the attempt reconciles to `updated_unverified`
  without the folder/name binding. It never PUTs. Like `update`, it prints
  the receipt and exits non-zero unless the receipt is `verified` (so an
  update reconcile always exits non-zero once it resolves; `create`'s
  reconcile keeps its exit-0 behaviour, unchanged by this issue). Reason:
  unblocks D8 with an honest status. Caveat (documented): a request still in
  flight inside a slow server could in principle commit after the reconcile
  read.
- By hand: an item deleted permanently (the GET fails) cannot be reconciled.
  Confirm in a Bitwarden client that it is gone, then move the journal file
  out of `write-attempts/` (archive it, do not edit it); that removes the
  block. Do the same if the account itself is gone.
- Reverse: keep the receipt `uncertain` and require archiving the journal by
  hand.

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

### D12. The terminal challenge has no expiry; EOF and Ctrl-C refuse

- Context: a human may leave the challenge unanswered for a long time.
- Options: (a) a bounded timeout — `rpassword` reads `/dev/tty` blocking, so a
  timeout needs a separate reader thread or raw terminal handling, which
  this phase does not add; (b) no expiry.
- Choice: (b), by design. The approval covers only the reviewed revision:
  after the answer, the fresh read must still show it (step 7), so a late
  answer to a changed item writes nothing, and the lock plus the uncertain
  re-check run after the answer, not before. End of input (Ctrl-D) and
  Ctrl-C (SIGINT) at the challenge end the process with no PUT, no journal
  and nothing on stdout (`tests/secret_update.rs`). Reverse: add a timeout
  around the prompt if a reviewer requires one.

### D13. Vaultwarden's encrypted notes limit is a known server-side refusal

- Context: Vaultwarden refuses a cipher whose encrypted `notes` string exceeds
  its configured limit (believed to be 10,000 characters by default). The
  exact value and check could not be confirmed from code available while
  writing this phase, so the CLI does not guess it.
- Choice: no client-side pre-check. A too-long encrypted `notes` value is a
  definite HTTP 400 → `failed`, nothing written (D11). The encrypted string is
  about 4/3 of the plaintext plus roughly 100 characters of type, IV and MAC.
  Reverse: once the limit is confirmed from Vaultwarden's source, refuse
  before the review in `plan_update`.

## 4. Value handling

- Plaintext lives only in `Zeroize`/`Zeroizing` buffers (`SecretImport`), is
  encrypted locally, and is never formatted into errors, the review, stdout,
  stderr or the journal. The journal holds server, destination, item ID,
  selectors, expected revision and the receipt.
- Values are UTF-8 strings preserved byte for byte (spaces, line breaks, NUL);
  `read-field` returns them exactly afterwards.
- `update` decrypts the old password and old selected hidden values only to
  decide and write the password-history entries of D6 (in `Zeroizing`
  buffers); the entries are re-encrypted with the item key. Old values are
  never printed, journaled or kept after the process ends.

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
- **Rollback** (the old value is in password history, D6): if the new value
  must be withdrawn (it does not work, or the switch has to be undone before
  the old credential is revoked):
  1. open the item in a Bitwarden client (web vault, desktop or mobile) and
     read the previous value from *Password history* (for a hidden field the
     entry reads `NAME: old value`);
  2. run a new, separately approved `vaultwarden-cli update` for the same
     field with the old value (it becomes the stored value; the withdrawn new
     value moves into history in turn), and wait for `verified`;
  3. switch consumers back and confirm them; revoke the new credential at the
     service if it was issued.

  Rollback works only while the old credential has not been revoked at its
  service, and while the entry is still among the newest five (each later
  change pushes one out). The CLI never deletes a history entry.
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
- **Touch ID v2 transcript**: unchanged. The `update` object is an optional
  member of the review JSON, so the existing `review_digest` (field 14)
  already binds item, fields and expected revision; the record and policy
  digests bind the policy. A revision change after approval is caught by the
  execution check above.
- **Two prerequisites that do not exist yet** (phase 2 must add both before
  any update review can be approved biometrically):
  1. **A new protocol element for companion capability.** No `update-review`
     capability exists today: neither the companion protocol
     ([companion-protocol.md](../companion-protocol.md)) nor the capability
     design ([issue-50-capabilities.md](issue-50-capabilities.md)) defines a
     way for a companion to state that it renders and understands an `update`
     block. Phase 2 must specify that element (name, where it is sent, how it
     is authenticated and bound to the pairing) and version it.
  2. **A provider-side refusal.** Today `biometric_allowed` is advisory: it is
     computed for the review (`src/adapters/companion.rs`, the
     `approval_binding` object, `key_id.is_some() && !password_required`), and
     the biometric proof path refuses only when the policy requires a
     password (`require_password`). A companion that ignored the flag could
     still sign. Phase 2 must make the provider refuse a biometric proof for
     an update review unless the approving companion advertised the new
     capability, and test that refusal; password approval with the loopback
     review showing the update block remains the fallback.
- **History and replies**: agent replies and human history carry the receipt
  and selectors only, never values.

## 8. Acceptance tests (phase 1)

Implemented in `tests/secret_update.rs` (a stateful fake Vaultwarden behind a
TCP relay that can drop a connection, over a real pseudo-terminal) and unit
tests in `src/secret_update_tests.rs` and `src/write_journal.rs`:
success with exact read-back and official-client password history and
revision date; history only for changed non-empty values, newest five, ISO
timestamps; stale `--expected-revision`; concurrent edit between review and
write; server stale rejection (400); denied challenge, EOF and Ctrl-C at the
challenge; no terminal; malformed input; missing field, also before the
`--prompt` secret prompt; interrupted write as HTTP 500 and as a connection
dropped after the write applied (`uncertain`, blocks the next update,
reconcile); two concurrent invocations (lock held; uncertain re-check after
the lock); reconcile exit codes, ID validation and a trashed item;
verification mismatch, a dropped passkey and a changed URI `match`
(`updated_unverified`); plaintext absent from stdout, stderr, the review and
the journal; preservation of unselected components. The live test against
Vaultwarden 1.36.0 (`tests/live/secret_storage.rs`) checks that the server
stores the history and revision date verbatim; CI runs it in the
`live-vaultwarden` job, where a missing server fails instead of skipping.

`scripts/mutate-secret-update.py EVIDENCE_DIR` weakens each update guard in
turn (challenge, expected-revision pin, review recheck, pre-decision and
pre-prompt field checks, verification gate, item lock, its uncertain re-check
and exclusivity, normalized journal server, reconcile rules (unchanged
revision, moved/trashed item, ID validation, exit code), uncertain block,
`lastKnownRevisionDate`, field kinds, password-history entries, revision date,
changed-only history, hidden-field history, five-entry limit, exact value,
identity, whole-login, field-object, unselected-field and attachment
comparison, response shape, send errors as `uncertain`, response identity) and
requires the focused tests to fail; the last report is
`issue-48-mutations/report.json` (31 of 31 caught). Two first-run escapes were
real test weaknesses (tampered values encrypted under the wrong key, so a MAC
failure masked the comparison; a PascalCase probe that serde already refused)
and were fixed in the tests.

Phase 2 acceptance (next PR): denial, expiry, cancellation, lock during a
pending request, stale revision after approval, producer failure, interrupted
PUT, Touch ID v2 review digest over the update block, consumption after
rotation.
