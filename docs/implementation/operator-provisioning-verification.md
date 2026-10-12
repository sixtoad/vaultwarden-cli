# Operator provisioning verification

Scope: initial create-only image registration and operation creation through the
owner human socket and `vw-access`, on branch `feature/operator-provisioning` from
baseline `1cad5ac41caeafebf51a9dde689ceff03c116326`. No real credentials, installation,
deployment, commit, push or PR is part of this change.

## Implementation evidence

- `policy.rs` exposes strict registration/draft/inspection metadata. Registration
  uses the narrow `ImageVerifier` port implemented by production
  `LinuxExecutablePreparer::prepare`, discarding its prepared capability without
  launch or credential resolution.
- The application checks the authenticated human owner separately from socket
  peer authentication. Creation requires the live session. Registration and
  creation serialize under the authority gate and preserve existing IDs,
  including identical retries. Inspection works while locked.
- The shared activation path now passes closure, session expiry and lock epoch
  guards into durable replacement. Store errors remain unavailable errors and
  close admission; post-rename uncertainty poisons the store. Existing execution
  preparation and per-request approval remain in force.
- Policy files are closed-schema regular files bounded to 128 KiB; human frames
  remain bounded to 2 MiB; inspection results above 1 MiB return an explicit
  oversized-result error. Diagnostics do not include parser input or OS details.

## Acceptance coverage

`access::provisioning_tests` exercises wrong-owner access, locked writes/inspection,
restart persistence, image and operation duplicate races, unrelated-policy
preservation, first/later Login binding and SSH ineligibility, incorrect digest,
symlink, writable image, unsupported ELF, pre-commit expiry/closure/lock intent, post-rename expiry,
persistence faults with committed-record recovery after restart, shared activation
guards, closed input and unavailable image preparation. Both actual list methods
reject valid metadata above the inspection bound. This inspection-only fixture
seeds through provisioning and expands the snapshot using strict image/policy
constructors; registration/create acceptance itself remains API-only.
The backend asserts complete item IDs, fields and operation-specific markers,
and panics if provisioning attempts Login or SSH secret resolution.

`tests/direct_request.rs` provisions from empty state through the real CLI/socket,
checks persisted identity/revision after restart and locked inspection, and then
submits a signed restricted-identity request at the application identity boundary,
which remains pending approval. This new signed-request check supplies the UID/GID
to the application; actual kernel peer-identity coverage comes from the separately
executed multi-UID/GID namespace matrix recorded below.
Its existing HTTPS approval flow also starts with CLI-provisioned image and Login
policy. CLI rejection checks assert nonzero status, empty stdout and exact redacted
stderr for duplicate creations and locked writes. A second operation's committed
socket response is discarded, then inspection before/after restart proves its
identity and an identical retry conflicts. `tests/human_cli.rs` and human socket
tests check malformed sentinel-secret input, valid whitespace-padded oversized
JSON, bounded symlink/directory/FIFO rejection, unsupported profiles and rejected
list arguments. Agent protocol decoding rejects provisioning commands.

The shared direct-request fixture now uses production registration and create
methods. Deliberate state corruption/replacement in existing negative lifecycle
tests remains fault injection, not provisioning setup.

## Commands and results

Full command logs for this run are retained in
`/home/sixtocantolla/sessions/day-to-day/_bmad-output/implementation-artifacts/operator-provisioning-logs.6yQA1y`
(with the original run logs also in `/tmp/operator-provisioning-logs`).
Tests use the checked-in private temporary-directory wrapper; ordinary `/tmp`
ancestry is intentionally not accepted for registered executable artifacts.

- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passed.
- Focused final provisioning suite after mutation restoration: 9 passed, zero
  failures/ignored. This includes the existing legacy-state reprovisioning test
  matched by the filter and all eight new provisioning tests.
- `scripts/with-secure-test-tmpdir.sh cargo test --workspace --all-targets --locked`:
  passed, 1,021 reported passes, zero failures, 16 ignored; benchmark smoke checks
  also passed. The repeated `--all-features` and `--no-default-features` commands
  each passed with the same totals.
- These ordinary runs include 75 live-account cases that return early without
  configured live environment variables. They are not live-validation passes.
  Several ignored library entries are subprocess helpers exercised by their
  parent tests; real manager, namespace, browser and companion acceptance remains
  separately gated.
- `scripts/with-secure-test-tmpdir.sh cargo test --locked --test direct_request`:
  both actual CLI/socket acceptance flows passed. The first full-suite attempt
  correctly rejected a fixture containing raw machine code without an ELF header;
  that fixture was corrected and the complete suite was repeated successfully.
- `scripts/test-live.sh`: passed its private-keyring isolation preflight and all
  79 configured live cases (zero failures/ignored, 701.33 seconds), against its
  own synthetic Vaultwarden 1.36.0 container at a dynamically allocated loopback
  port. The runner removed its owned container and network successfully.
- `scripts/with-secure-test-tmpdir.sh scripts/test-systemd-supervisor.sh`: passed
  both real systemd tests (93.76 seconds), including descendant/crash recovery,
  cleanup uncertainty and application revocation scenarios; also passed the
  separately invoked real distinct-principal SSH-material isolation test.
- `env VW_AGENT_NAMESPACE=1 TMPDIR=/tmp unshare --user --map-auto --map-root-user
  --fork cargo test --offline --locked --test agent_submission
  real_linux_peer_matrix_and_noninteractive_cli -- --ignored --exact --nocapture`:
  passed the real multi-UID/GID peer and noninteractive CLI matrix (6.80 seconds).
- Compiled mutation checks: all six were caught by assertion failures after
  successful compilation, not by build failures. Each isolated mutation was
  restored before handoff; SHA-256 verification confirmed exact restoration of
  the application, provider, store and execution-adapter source files to the
  versions used by the complete passing test runs. Formatting/diff checks and
  the focused suite passed after restoration.
- Independent review: three layers completed after initial verification. Findings
  were triaged; focused fixes and final-code verification are recorded below.

The full runs above precede the review fixes. Focused review-fix verification:

- `scripts/with-secure-test-tmpdir.sh cargo test --locked --lib access::provisioning_tests`:
  10 passed, zero failures/ignored (38.18 seconds).
- `scripts/with-secure-test-tmpdir.sh cargo test --locked --test human_cli --test direct_request`:
  19 human CLI and 2 direct-request tests passed, zero failures/ignored. An initial
  compile exposed a diagnostic-lifetime mismatch in the new assertion helper;
  the static diagnostic parameter was corrected before this successful rerun.
- Formatting and diff whitespace checks passed. No broader tests were rerun by
  the implementation worker; complete final-tree verification remains with the
  parent workflow. Logs are `review-fixes-provisioning.log`,
  `review-fixes-cli.log` (initial compile failure), and `review-fixes-cli-final.log`
  in the retained log directory above.

## Final-code verification after review

All three reviewers completed. The edge-case layer returned no findings. The
general and verification-gap reports led to the focused corrections above;
the two-second response-timeout claim was disproved by the ten-second client
deadline. The existing uncapped whole-store read/validation cost is deferred as
provider-wide storage-budget work, not claimed solved by the response-size limit.

Final logs are retained at
`/home/sixtocantolla/sessions/day-to-day/_bmad-output/implementation-artifacts/operator-provisioning-final.ZUpkYt`.

- Formatting, complete-diff whitespace and all-feature Clippy checks passed.
- Default, all-features and no-default-features full workspace runs each passed:
  1,023 reported passes, zero failures, 16 ignored, plus benchmark smoke checks.
  As above, 75 unconfigured live-account early returns in each ordinary run are
  excluded from executed live coverage.
- Configured live run: 79 passed, zero failures/ignored, 819.74 seconds; separate
  isolation preflight passed. Owned container `vw-live-live-jvypo5-vaultwarden-1`
  and network `vw-live-live-jvypo5_default` were removed successfully.
- Real systemd: both tests passed in 97.30 seconds, plus the separately invoked
  distinct-principal material test. Multi-UID/GID agent matrix passed in 8.18 seconds.
- All six final-code mutations compiled and were caught by failing tests. Each
  change was reversed, and SHA-256 checks confirmed exact restoration. A mutation
  patch-text mismatch stopped the harness before applying the next mutation;
  restoration was checked before the remaining cases ran. This was not a test pass.
- Restored, unmutated provisioning suite: 10 passed, zero failures/ignored
  (45.33 seconds); final complete-diff whitespace check passed.
- No commit, push, deployment or real credential access was performed.

| Invariant bypassed | Test evidence |
| --- | --- |
| Application owner check | Wrong-owner inspection returned `Ok([])` instead of `Unauthorized`. |
| Operation duplicate rejection | Eight racing creations succeeded instead of exactly one. |
| Production image preparation | A writable executable was registered instead of rejected. |
| Login eligibility | An ineligible binding produced a created operation. |
| Final durable commit guard | An operation remained in state after commit-time expiry. |
| Persistence failure closes admission | A write fault returned without closing admission. |

## Limits

Behavioral review is the operator's declaration; a digest and ELF validation
cannot prove it. Artifacts must remain at pinned paths with unchanged bytes and
permissions; every state read validates all registered artifacts. Socket loss
does not establish rollback: inspect the record to reconcile. SSH provisioning
does not provide or install a compatible SSH executable. Same-UID agents remain
outside the supported trust boundary.
