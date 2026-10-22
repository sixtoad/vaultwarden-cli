# Secret storage implementation evidence

Date: 2026-10-22. Baseline: `d27d2fadf7b41be5059c8583d3385952a65b0c11`.
The approved `spec-vaultwarden-secret-storage.md` has no frontmatter context files.
Operator usage, exact command syntax and recovery are in [secret-storage.md](../secret-storage.md).

## Implementation mapping

- `secret_storage.rs`, `crypto/crypto_keys.rs`, `models.rs`: closed bounded import,
  authenticated encryption, fresh wrapped item keys, unified Key decoding, exact
  field reads and canonical destination bindings.
- `api.rs`, `commands.rs`, `main.rs`, `write_journal.rs`: create-only POST,
  per-attempt controlling-terminal authorization, exact reads, metadata-only durable
  receipts and read-only recovery; collision rejection and no explicit-ID fallback.
- `access/{policy,ports,application,provider,provider_store,direct_request,history}.rs`:
  operator-owned create effects, preserved read-policy revisions, one-use authority,
  durable certainty transitions, human reconciliation and redacted history.
  Existing provisioning entry points accept the extended closed draft schema; no
  second provisioning implementation was needed.
- `adapters/vaultwarden.rs`: authenticated scoped creation, fresh private verification,
  existing personal/organization wrapped-key reads, exact marker and namespace checks.
- `adapters/execution.rs` and `adapters/supervisor/bridge.rs`: sealed fixed-capacity
  provider-private output descriptor, framed import after reaping; existing manager
  and execution-helper entry points carry this extension without new authority.
- `adapters/loopback_ui.rs`, `macos/Sources/CompanionCore/Protocol.swift`, and
  `macos/Sources/ApprovalCompanion/App.swift`: explicit creation review. At this
  baseline `companion/lib/main.dart` is a synthetic Touch ID demo, not the production
  approval client; it remains unchanged. The production native decoder rejects
  unknown effects/invalid payloads; older closed decoders reject new create fields.
- README and operator guide describe supported backend, fixed schema, manual read
  provisioning, folder/account scope and recovery without replay.

## Matrix to tests

| Spec scenario | Executed coverage |
| --- | --- |
| Import | `secret_storage::tests::imports_reject_unknown_duplicate_and_oversized_input_without_echo`; live `trusted_cli_uses_fresh_terminal_authorization_and_durable_receipt` exercises real PTY approval/denial and stdin JSON. |
| Protected creation | `protected_create_requires_fresh_approval_and_keeps_private_values_out_of_history`; denied/expired/locked/cancelled/malformed cases; `protected_create_cancelled_after_producer_completion_never_posts`; actual helper `private_producer_frame_crosses_only_the_bounded_descriptor_and_requires_reaping`. |
| Read | `account_folder_reference_identity_deletion_and_duplicate_fields_fail_closed`; live `create_and_select_each_secret_representation_verbatim` creates password/custom/mixed notes forms and checks actual CLI selected bytes; existing adapter exact-ID/marker/selected-field regressions. |
| Wrapped item key | `encryption_roundtrip_preserves_values_and_requires_wrapped_key`; adapter `personal_and_organization_item_keys_authenticate_before_selected_fields`; model duplicate Key decoding test; live production wrapped encryption. |
| Interrupted write | `create_cipher_never_retries_or_echoes_server_body_and_retains_certainty`; protected uncertainty/created-unverified and simulated crash/restart tests; `durable_uncertain_receipt_blocks_restart_repetition_and_never_contains_values`; protected read-only reconciliation test prevents retarget/replay. |
| Names collide | Storage destination test rejects same-folder collision/duplicate folders; command `normalized_environment_collisions_fail_closed` rejects inter-item normalized names and built-in/custom field overlap; existing ambiguous-name tests. |
| Namespace mismatch | `namespace_is_canonical_not_normalized` and binding test cover wrong account, wrong folder, duplicate folders, moved/deleted/wrong-ID item, invalid item key and duplicate fields. |
| Write authorization | Real terminal denial leaves vault unchanged; unapproved/reused protected authority fails; locked/expired/cancelled tests; no update variant in closed draft/CLI schemas. Native invalid/unknown creation payload tests. |

## Final verification

All inputs were synthetic. Live credentials belonged only to a disposable
Vaultwarden 1.36.0 container. Tests ran after the independent review fixes;
subsequent test-only lint corrections received focused reruns.

| Check | Result and evidence |
| --- | --- |
| `./scripts/with-secure-test-tmpdir.sh cargo test` | PASS: 1063 passed, 0 failed, 21 ignored; `/tmp/vw-storage-final-full.log`. Ignored/environment-dependent live tests are not independent backend evidence. |
| Disposable-server `cargo test --test live_tests secret_storage -- --nocapture` through secure TMPDIR with the live URL/admin-token variables | PASS: 2 passed, zero skipped; `/tmp/vw-storage-review-fixes-live.log`. Exercises actual CLI create/read, redirected-stderr terminal approval/denial, explicit-ID uncertain recovery, no retargeting, unchanged vault contents. |
| `./scripts/with-secure-test-tmpdir.sh bash scripts/test-systemd-supervisor.sh` | PASS: 39 real-manager scenarios across 2 integration tests, plus 1 distinct-principal material-isolation test; zero ignored in these runs; `/tmp/vw-storage-final-systemd.log`. |
| Production backend, scoped application, replay-after-restart, policy-boundary and journal regressions | PASS: 11 targeted tests; `/tmp/vw-storage-review-fixes-unit.log`. Final journal concurrency and test-only lint reruns: `/tmp/vw-storage-review-fixes-journal.log`, `/tmp/vw-storage-final-test-lint-fixes.log`. |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS; `/tmp/vw-storage-final-clippy.log`. |
| `cargo fmt --all -- --check`, `git diff --check` | PASS. |
| `./scripts/check-native-fixtures.sh` | PASS: x86_64 and AArch64 exit/output/producer fixtures assemble. |
| `scripts/test-macos-companion.sh` on the authorized Mac mini | PASS: 15 protocol, 8 app-model, 8 URLSession TLS tests; 20 bundle TLS cases, zero skipped; fixture/watchdog checks, release build and signing verification. Source snapshot, matching SHA-256 manifest, log and evidence: `/tmp/vw-storage-final-native-se53jlz4`. Nothing installed. |
| `cargo audit`, `cargo deny --locked check all` | PASS with refreshed advisory database; `/tmp/vw-storage-final-audit.log`, `/tmp/vw-storage-final-deny.log`. Existing allowed yanked `inout 0.2.3` warning remains. |

The exact justfile lint command adds `-W clippy::pedantic -W clippy::nursery`
and **fails on pre-existing baseline debt**. An isolated archive of the baseline
with the same toolchain reports 376 library / 692 library-test errors; the final
feature reports 375 / 691, with no new unique diagnostics after review corrections. Final diagnostics are in
`/tmp/vw-storage-final-strict.{jsonl,stderr}`; baseline artifacts are
`/tmp/vw-secret-storage-baseline-clippy.{jsonl,stderr}`. Compiler totals include
messages repeated between targets. Introduced diagnostics were corrected without
cleaning up unrelated baseline code; this stricter gate is not reported as passing.

Minimal lockfile security updates are `rustls-webpki` 0.103.15 → 0.103.16 and
`webpki-root-certs` 1.0.9 → 1.0.10. The already-locked `tempfile` dependency moved
from dev-only to production use for atomic metadata-journal publication.

There is no standalone architecture guard script in this baseline. Source-boundary
inspection confirms application code uses backend/supervisor ports, imported
plaintext has no Serialize/Debug implementation, and the producer receives no
backend credential capability.

## Independent review corrections

Journal publication writes and syncs a unique private temporary file before atomic
no-clobber publication, then syncs the directory and its parent before POST. Every
later save uses a new temporary file. Tests exercise abandoned partial files,
concurrent initial publication with one winner, preserved complete receipts and
replay refusal. Journal/provider destination identity uses the backend's equivalent
trailing-slash server handling.

Trusted import displays effects and reads approval through the same controlling
terminal. Both policy and native decoding enforce at most 32 custom fields, valid
canonical namespaces and valid markers; maximum-length references remain valid
review labels. Post-create verification rechecks the namespace with a fresh sync.

Production backend HTTP contracts exercise create, verify, reconcile and scoped
reads, including authenticated replacement values and changed namespaces. Scoped
application tests prove namespace propagation and reject changed folder/reference
before execution. A distinct freshly approved request after restart cannot repeat
an uncertain write. Explicit-ID CLI recovery persists `created_unverified`, rejects
retargeting and does not mutate the vault.

## Limits

Protected lifecycle tests and production backend HTTP contracts are separate from
the live CLI tests. The full agent → systemd → live-vault creation chain and logged-in
Mac/Linux interactive acceptance were not exercised as one composed scenario.
The existing real-systemd supervisor suite and the actual bounded producer/helper
descriptor test both passed. AArch64 fixtures were assembled, not executed.
Cross-platform Rust compilation was not verified; the available Mac Rust toolchain
is older than the repository minimum. Swift validation is separate evidence.

Receipts never persist original secret values, so recovery cannot upgrade uncertain
storage to verified equality. Independent CLI/provider stores and external vault
clients cannot atomically reserve a vault-wide name; concurrent separately approved
writes may collide, as documented in the operator guide. Later reads bind exact IDs.
