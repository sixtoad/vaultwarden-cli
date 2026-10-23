# Protected secret storage composed acceptance

Execution date: 2026-10-22. This is an automated native-client acceptance run;
no human UI approval is claimed. Creation, separately authorized consumption, denial, actual lost-response
interruption, read-only durable recovery and identity-checked cleanup passed. Two
post-restart native unlock attempts failed while the provider unlocked; the retained
second payload reports a transport error. The first raw error was not retained.
That acknowledgement failure remains unresolved. A second restart and unchanged-source
native unlock succeeded in 2.297 seconds. This is a completed acceptance campaign
with an open native reliability finding, not an entirely clean native-client pass.

## Source and environment

- Production baseline: `88b6934f1b8cd6fcbc3462bd4cea41628eac1768`
  (`Merge pull request #42 from sixtoad/feature/companion-provider-flow`).
- Worktree: `vaultwarden-storage-acceptance`, branch
  `test/secret-storage-acceptance`; acceptance harness changes are uncommitted.
- Linux provider: `192.168.1.235`; production CompanionCore native client runs
  on the authorized Mac mini `192.168.1.120`.
- Real disposable backend: `vaultwarden/server:1.36.0`, loopback-only HTTPS,
  container tmpfs storage, private certificate authority and private Secret
  Service/D-Bus. No production vault, companion installation, user configuration
  or trust store is used.
- The provider is a bounded cfg-test fixture using production authorization,
  `VaultwardenBackend::from_setup`, its password approval authenticator, the
  production execution worker and actual systemd process supervision. Because
  normal cfg-test keyring initialization is intentionally disabled, this fixture
  explicitly installs the production D-Bus Secret Service keyring store.
- The Mac driver compiles with production `CompanionCore`, pins the provider
  leaf and private CA, uses mutual TLS, validates the full create effect, and
  restores/verifies the original keychain search list after each invocation.
- Producer and consumer are self-contained static ELF images. The producer
  writes a bounded private fd3 frame; the consumer accepts only the fixed target,
  expected injected value, and the two allowed locale variables. Neither prints
  the credential. Creation does not provision consumption permission.

## Executed checks

| Scenario | Required evidence | Result |
| --- | --- | --- |
| Fresh setup | Locked provider, real distinct agent UID, no consumer policy | Passed: native unlock observed locked; agent UID 100007 |
| Create | Fresh native approval, one encrypted server item, verified receipt | Passed: one POST/commit/item; verified receipt; native and agent exit zero |
| Consume | Explicit immutable-ID/namespace policy, separate approval, exit zero | Passed: explicit policy provisioning, new native decision, consumer exit zero |
| Deny | Native denial, unchanged item/POST counts, no execution-start event | Passed: zero items, POSTs, receipts and execution-start events |
| Lost POST response | Server commits once; proxy discards successful response; uncertain receipt | Passed: total two POSTs/commits/items; one dropped reply; uncertain receipt |
| Durable recovery | Restart locked; unlock; selected real ID reconciles to created_unverified | Receipt/count checks passed; two initial unlock acknowledgements failed; a second restart unlock passed in 2.297 s |
| Retarget/fresh replay | Rejected retarget; unchanged item and POST counts | Retarget rejected; fresh replay approval rejected as stale; no new POST/item/execution |
| Cleanup | Owned services/container absent; keyring/identities removed; Mac search list restored | Passed: owned services stopped, container absent, private bootstrap/agent material removed; zero execution units; Mac directory removed and keychain restored |

Safe machine-readable evidence is retained in
[`secret-storage-acceptance-evidence/`](secret-storage-acceptance-evidence/).
[`provenance.json`](secret-storage-acceptance-evidence/provenance.json) records the
baseline, all acceptance source hashes, installed fixture/CLI/helper/image hashes
and actual distinct agent identity. Snapshots record the complete measured HTTP
method/path counts. Native reports record session/list/review/decision/status
request counts and each keychain restoration result.

The successfully created item is `8a2262d5-a44b-4aa5-8be3-dbe2a7c4fdeb`, at
`storage-acceptance/create`. Its receipt is `verified`. The independent inventory
authenticated its wrapped per-item key, value and eligibility marker. The explicit
consumer policy selected this immutable ID and namespace; the production consumer
completed with exit zero under a separate native approval. The actual interrupted
commit is `06f807a1-5ef8-4896-9be8-d9da30cb7d05`, at
`storage-acceptance/interrupt`. Its request
`3lv_lmqTsR_cohm-dAtGIxAtbrAeCTpWnHJfa1dvGNg` finished
`failed/execution_unavailable` with an `uncertain` receipt and no known item ID.
The independent server inventory and proxy, not a fabricated receipt, establish
that this request committed once.

Execution-start observations come from durable production history recorded after
supervisor `ExecConfirmed`. HTTP counters are measured by the HTTPS fault proxy;
it forwards the actual request, reads the successful server response, records
the committed immutable ID, and drops that one client response. It never edits
receipts. Vault inventory is independently read directly from the disposable
backend and decrypted privately to compare synthetic values; only counts, IDs,
fixed synthetic item names and comparison booleans are published.

## Post-restart native acknowledgement limitation

The same durable provider restarted locked, retaining the uncertain receipt and
exactly two committed items. Two native unlock attempts then failed while the provider nevertheless became
unlocked. The first controller discarded native stdout on a nonzero SSH exit, so
its raw native error payload was not retained. The subsequent direct retry
returned the generic transport error. The transcript-derived summary explicitly
distinguishes these evidence limits in
[`earlier-unlock-failures-summary.json`](secret-storage-acceptance-evidence/earlier-unlock-failures-summary.json). A subsequent
production-native session query confirmed `unlocked`. Read-only reconciliation
selected the actual committed immutable ID and returned `created_unverified`;
repeating that reconciliation stayed `created_unverified`. Selecting the other
actual item ID was rejected. Counts remained two POSTs, two commits and two items.

A second restart with unchanged provider/native code reproduced the locked state
and completed native unlock successfully in 2.297 seconds. That successful retry
does not explain or fix the two earlier failures.

A fresh signed `storage-interrupt` submission reached pending review. Its native
approval was rejected with `stale`; it acquired no receipt and no execution-start
event. It did not cause another POST. This is an approval rejection, not a
successful second creation or an automatically retried interrupted write. A fresh
native denial then closed that pending request. The final replay snapshot contains
exactly the original three execution-start events (create, consume, interruption),
two committed items, two cipher POSTs and one dropped reply.

Read-only investigation found a five-second request/resource timeout in
production `macos/Sources/CompanionCore/Trust.swift`. Provider unlock performs
synchronous compatibility requests, KDF work, keyring access and backend token
exchange; individual backend HTTP calls permit ten seconds. Successful provider
unlock does not depend on receiving the client's acknowledgement, and the server
resets its response-write deadline after dispatch. These facts are consistent
with a slow successful unlock outlasting the native deadline, but existing logs
do not measure the authentication stages, so the cause is **not proven**.
Companion rate limiting returns an explicit rejection, and a fresh provider has
empty attempt counters. No production timeout or authentication behavior was
changed to make this run pass. Do not describe this campaign as an entirely
error-free native interaction.

## Verification and preliminary failures

- `cargo build --locked --bins`: parent build completed before fixture use.
- `cargo test --locked --lib --no-run`: passed after adding the fixture and
  native Secret Service store initialization.
- `python3 tests/secret-storage-acceptance-test.py`: **4 passed**. Covers API GET,
  JSON/form requests and authorization placement; authenticated decryption and
  tamper rejection; wrapped per-item keys and exact namespace validation; a real local TLS proxy that commits one POST, loses exactly
  one response, and returns an unchanged count on the next read.
- Initial helper-test attempt was blocked by the execution sandbox's socket
  restriction. The same tests passed with authorized loopback socket access.
- Protected-create Rust regression: **7 passed** using
  `scripts/with-secure-test-tmpdir.sh`. The initial invocation without that wrapper
  failed fixture image registration because ordinary `/tmp` ancestry is unsafe;
  this was an invocation issue, not a composed acceptance pass.
- First provisioning attempt: private D-Bus configuration lacked a `<listen>`
  element. Fixed the isolated configuration; the recorded failed bus and private
  artifacts were cleaned. Initial cleanup also exposed an ownership boundary:
  subordinate UID can delete its seed, while provider UID must remove the empty
  directory in its provider-owned parent. Cleanup was corrected and retried.
- Second provisioning attempt: function-local `import urllib.parse` caused
  `UnboundLocalError` for JSON requests. Moved the import to module scope and
  added request-construction regression coverage. Its uniquely owned services,
  container and private artifacts were cleaned.
- Third provisioning attempt reached readiness with a locked provider,
  distinct agent UID `100007`, and no consumer policy. Subsequent deny, create,
  consume and interrupted-write scenarios passed as recorded above.

An initial post-create inventory observation also failed because the observer used
the account key directly for item fields. Production creation correctly uses a
wrapped per-item key. The observer now unwraps and validates that key, validates
the immutable folder and full reference, and authenticates the synthetic marker.
A focused regression covers this format and rejects a different folder. This
observation failure did not change provider receipts or backend contents.

These preliminary failures are retained honestly; none counts as successful
composed storage acceptance. No production code fixes, deployment or push have
been performed.

## Disclosure checks

The recorded scan examined 39 files against ten known synthetic secret values
and authorization-material patterns. It found no plaintext/authentication material
in agent stdout/stderr, native output, provider journal, durable provider state,
sanitized observations or private service logs. Source/setup files intentionally
containing synthetic fixtures were excluded. This is bounded evidence over those
captured files and known values, not a proof that arbitrary undiscovered channels
could never disclose data. See
[`redaction-scan.json`](secret-storage-acceptance-evidence/redaction-scan.json).

## Cleanup and completion

Identity-checked cleanup stopped the uniquely owned provider, HTTPS proxy,
private keyring and D-Bus services; verified and removed the labelled disposable
container; and removed the subordinate-agent signing material and private
bootstrap/keyring/TLS directory. An additional audit found the provider inactive,
zero owned execution units and no owned execution runtime. The unique Mac test
directory was removed, and each retained native report verified keychain search
list restoration and temporary-keychain deletion. See
[`cleanup.json`](secret-storage-acceptance-evidence/cleanup.json) and
[`cleanup-extra.json`](secret-storage-acceptance-evidence/cleanup-extra.json).
Sanitized evidence and the private durable fixture reports remain; raw secrets
and configuration are not part of this evidence directory.

The final proxy totals, including the additional successful restart unlock, are
19 version GETs, 19 config GETs, five token POSTs, 20 sync GETs, two cipher POSTs,
five exact reads of the verified item and two exact reads of the recovered item.
Exactly two writes committed and exactly one successful response was discarded.
No further write occurred during recovery, retarget rejection or fresh replay.
[`final-proxy-counts.json`](secret-storage-acceptance-evidence/final-proxy-counts.json)
retains those measured counts. No production code changed; nothing was deployed
or pushed. Human UI acceptance and resolution of the intermittent native unlock
failure remain outside what this campaign establishes.

## Post-review harness guards (not used in the completed campaign)

Review identified test-harness weaknesses after the campaign had finished. The
following changes affect future acceptance runs only; no historical capture,
original source hash or installed-binary hash has been replaced. The original
`source_sha256` and `installed_binary_sha256` values in `provenance.json` remain
campaign-era evidence. Its separate `post_review_harness` section records the
revised test-only source hashes and focused validation.

- Cleanup now checks provider state even when readiness failed before the
  invocation record was saved. An active provider without a nonempty matching
  recorded invocation blocks cleanup before stopping or deleting resources,
  retaining recovery material. A regression covers absent, empty and mismatched
  invocation records and verifies that no stop/deletion occurs.
- The native driver decodes and validates every command-dependent configuration
  field before creating a keychain. Poll exhaustion and scenario mismatches fail:
  denial must be denied, create/consume must complete with exit zero, and the
  injected interruption must fail with `execution_unavailable`. Attempted and
  completed request counts, per-request elapsed totals and overall operation
  elapsed time are retained after errors. The original keychain search list is
  captured before creation, then restored and verified after temporary-keychain
  deletion.
- Inventory regressions now reject always-true comparison flags by checking a
  wrong password and missing/wrong eligibility markers. The fault-proxy regression
  checks actual status/body on ordinary POSTs both before and after the injected
  fault: three POSTs commit, only the middle reply is lost, and exactly one loss
  is recorded.

Focused Python validation: `python3 tests/secret-storage-acceptance-test.py`
passed **5 tests** in 1.051 seconds. The separate focused Mac regression also
**passed**, compiling unchanged production CompanionCore with
`StorageAcceptance.swift` and `StorageAcceptanceTests.swift` using
`-D STORAGE_ACCEPTANCE_TESTS -parse-as-library`. It verified configuration guards,
scenario outcomes, exhausted polling, failure counters/timing and actual temporary
keychain deletion/restoration. These regression checks do not
establish that the revised driver was used in the earlier composed campaign, and
they do not resolve its intermittent native unlock finding.

## Reproduction

Build production binaries and the library test binary, then run these helpers
with access to the real user systemd manager, subordinate UID namespace and
Docker. They print only public/sanitized metadata; keep their root private.

```sh
cargo build --locked --bins
cargo test --locked --lib --no-run
python3 tests/secret-storage-acceptance.py prepare 192.168.1.235
python3 tests/secret-storage-acceptance.py start "$FIXTURE_ROOT"
python3 tests/secret-storage-acceptance.py mac-config "$FIXTURE_ROOT" unlock
```

Copy the private native configuration, PKCS12 identity and CA to a unique
owner-only Mac directory, replacing only the configuration's artifact paths.
Compile `macos/Tests/Fixtures/StorageAcceptance.swift` with production
`CompanionCore` sources and invoke it with that owner-0600 configuration path.
Passwords are never command arguments or published outputs.

Submit `storage-create`, `storage-deny`, `storage-interrupt` and later
`storage-consume` with `submit ROOT OPERATION`; for each, use a new native
`approve` or `deny` configuration and decision. Before consumption run
`provision-consumer ROOT ACTUAL_CREATED_ID`. Before interrupted creation run
`arm-drop ROOT`. Use `snapshot ROOT` to capture independent inventory and proxy
counts. Use `stop ROOT`, then `resume ROOT` to retain the same durable provider;
unlock through the Mac before `reconcile ROOT REQUEST_ID ACTUAL_COMMITTED_ID`.
A retarget uses another actual vault ID, and a fresh signed submission of the
same create operation must not issue a further POST.

Run `cleanup ROOT` after retaining sanitized evidence and scanning private
captures for disclosure. Cleanup checks service invocation IDs and container
ownership before stopping/removing resources; uncertainty retains recovery
material. Remove the unique Mac test directory after verifying each native
invocation restored its original keychain search list. Do not publish raw setup,
bootstrap, private TLS, signing seed, approval ticket or session material.
