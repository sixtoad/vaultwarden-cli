# Story 1.4 verification evidence

Baseline: `5e5941bc3ce19c9437532900e2b530d093eff7e8` (updated main). Branch:
`feature/one-time-human-direct-request`. Stories 1.1–1.3 were merged in PRs
19, 20 and 21 before this worktree was created. This evidence records the verified pre-commit worktree. The human approved
the implementation and evidence on 2026-09-24.

## Acceptance coverage

| Requirement | Executed evidence |
| --- | --- |
| Policy-permitted CLI input and authenticated human | Real `vw-access` request/no-wait/wait/status tests over private Unix sockets; kernel `SO_PEERCRED`, server authentication, UID vectors, bounded frames and redacted parser errors |
| Provider-owned pending request | Random IDs, canonical argument digest, active policy revision, provider timestamps, five-minute default and durable ownership verified by core tests and Unix/HTTPS integration |
| Independent admission rejection | Wrong owner, locked provider, unknown operation/fields, stale revision, disallowed target, invalid choice/integer, missing/extra/oversized arguments each independently reject with no record or desktop call; authority changes during admission are separately tested |
| Complete non-secret review | All requested metadata displayed through trusted loopback HTTPS; safe text rendering excludes credential values, immutable item IDs, environment mappings, sessions and raw output |
| Desktop capability, session and CSRF | 256-bit randomness, one-use exchange, private artifact/path-only launcher, Secure/HttpOnly/SameSite Strict cookie, independent session-bound proof, replay and crossed-session attacks, Host/Origin enforcement |
| Status and lifecycle | Pending/expiry/lock/restart/shutdown and non-resurrection; terminal states and bounded exit/failure information through fixtures; actual waiting CLI emits receipt then expiry without resubmission |
| Accessibility | Real Firefox keyboard actions, computed visible focus, meaningful labels and atomic live confirmations; axe reports zero violations |

The [matrix audit](1-4-evidence/review-2-verification/matrix-audit.json) maps every
frozen planning row to exact tests found passing in the full-suite output.
Negative cases use otherwise valid inputs; integrity-sensitive records are
resealed when testing a separate semantic guard. No production inspection
accessor was introduced solely for tests.

## Final ordinary verification

Every command below finished with exit **0** on unchanged source/test/Cargo
fingerprints. [Results](1-4-evidence/review-2-verification/results.json),
[counts](1-4-evidence/review-2-verification/summary.json) and the
[full test output](1-4-evidence/review-2-verification/all-targets.log) are retained.

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
git diff --check
cargo build --bin vw-access
VW_UI_DEPS=/tmp/vw-story14-browser/node_modules node tests/ui/direct-request.mjs
```

Cargo reported **685 passed**, **0 failed**, and **3 ignored fixture entries**;
**13 benchmark smoke checks** passed. Of the 685 reported passes, **71 existing
live-backend entries return early when live server/admin configuration is absent**.
They did not exercise Vaultwarden here; **614 tests exercised their bodies**. All three fixtures
were explicitly exercised: the browser fixture by the successful Firefox
harness, the fixed-launcher child by its desktop wrapper, and the descriptor
fixture twice by its exhaustion/valid-zero wrapper. These are not three
unverified behaviors. The suite includes all library, binary, integration and
benchmark targets. Linux local socket access was enabled for these runs.

Firefox **151.0.2** used a disposable profile trusting only the synthetic CA,
with `acceptInsecureCerts:false`. Axe passed **24 applicable checks**, with
**0 violations** for WCAG 2 A/AA and 2.1 AA. The harness also passed automatic
artifact navigation, fragment removal, safe DOM rendering, launch replay and
missing/invalid proof rejection (403), prior session preservation, concurrent fresh-cookie launches, transient polling
recovery, stable detail/live-region DOM, argument positions, keyboard
activation, a computed solid 3px focus outline, and Pending → Expired → Expired
while locked. Its six known BiDi/cross-origin or blocked-favicon diagnostics
are recorded by exact category; unexpected diagnostics: **0**. See the
[Firefox output](1-4-evidence/review-2-verification/firefox-accessibility.log).

## Mutation verification

The current scope contains **347 generated mutations**: **299 caught**, **42
compiler-rejected**, **3 equivalent under the observable security contract**,
**1 equivalent only under the bounded polling-time contract**, and **2 inactive,
unassessed non-Linux mutations**. Unresolved meaningful survivors, timeouts and
unrelated-failure catches in the reconciled scope: **0**. Supplementary isolated
manual mutations: **24 caught** (18 Rust plus 6 real Firefox cases). No mutation
score combines these distinct categories.

The post-review campaign completed all **44** selected mutations: **41 caught,
3 compiler-rejected**, exit **0**. All changed complete functions/constants were
rerun; **303** earlier audited results carry forward only after byte-identical
complete function/constant and relative mutation matching. Thus 303 + 44 = 347.
The earlier complete campaigns and their provenance remain recorded; results
from their superseded functions are not counted twice. **198** mechanically
unchanged binding-name lint mutations were excluded with normalized baseline
comparisons. The complete inventory contained **940** generated cases before
change scoping. Manual cases supplement generated mutations with strict DTOs,
CSRF, replay, randomness, persistence, concurrency, lifetime wiring, worker
capacity, safe DOM rendering and accessibility behavior.

The only test file changed after the immutable Rust snapshot was the browser
harness: its synthetic valid submissions now retry the exact fail-fast provider
contention response within ten attempts/450 ms of total retry delay. Ambiguous
transport errors, other rejections and partial output still fail immediately.
The Rust campaign never executes that JavaScript file; all Rust/Cargo inputs
remain identical. All ordinary checks and all six browser mutations were rerun
with the final harness. Initial compilation-timeout, altered-synchronization and
unrelated-contention browser attempts are excluded from current results.

See the [classification summary](1-4-evidence/mutation-summary.json),
[per-mutant ledger](1-4-evidence/mutation-ledger.jsonl), and exact commands for
[run 2](1-4-evidence/mutation-run-2/command.json) and
[run 3](1-4-evidence/mutation-run-3/command.json), and current
[run 4](1-4-evidence/mutation-run-4/command.json). Commands select the library,
both access binaries, direct-request, human-CLI and provider-session integration
targets; unrelated commands/crypto/config/models/TOTP test modules are filtered
only for mutation runs. The ordinary all-target suite remains unfiltered.
Snapshots and build caches are isolated. Relevant failure assertions and compiler
errors were audited; two earlier raw catches caused only by an unrelated desktop
timeout were rejected as evidence and retested in the current scope.

| Surviving mutation | Classification and evidence |
| --- | --- |
| `expire_requests` retention `<` → `<=` | Observable equivalent: `expire_direct` first invalidates at `now >= deadline`; retaining the already-terminal map entry at equality cannot resurrect authority, change persisted status or reuse the unique ID. The next clock advance removes it. |
| Desktop `run_bounded` `<` → `<=` | Bounded-time contract equivalent, **not timing-identical**: exact equality permits one additional 10 ms polling interval. Both already check child completion before the deadline guard and allow polling overshoot; both bound and reap the launcher without conferring request authority. |
| Two socket flag OR → XOR substitutions | Exact Linux bitset equivalent: flags 1, 2048 and 524288 are pairwise disjoint; both expressions evaluate to 526337. See the [numeric proof](1-4-evidence/socket-flag-equivalence.json). |
| Non-Linux `peer_uid` fallback → `Ok(0)` / `Ok(1)` | Inactive and unassessed on Linux, **not equivalent**. Production fallback still rejects; no non-Linux authentication support is claimed. |

Meaningful earlier survivors led to independent admission-boundary, UID-vector,
metadata/size-boundary, duplicate-ID/epoch, per-request launch-failure, socket
worker/error/backlog/descriptor, browser-session-limit and scheduled-cleanup tests.
The final campaign catches their applicable current mutations. Strict status
wire deserialization additionally fixes Serde unit variants accepting unknown
fields; manual mutations verify that fix and exit-code bounds. No timeout or
uncovered security mutation is relabeled as equivalent.


## Independent review and patches

All three context-free BMAD review layers completed. Eight defect/test-gap
groups were patched: fail-fast admission, post-persistence receipt preservation,
concurrent browser launch serialization, polling recovery, stable detail/status
DOM, selected subcommand help, configured lifetime wiring, and worker saturation.
The alleged argument-separator ambiguity was disproved by policy validation;
numbered argument rows remain a readability/accessibility improvement. Exact
finding verdicts and accepted limitations are in [review results](1-4-review-results.md).
Human acceptance was recorded on 2026-09-24; publication was not requested.

## Scope and limitations

- Operation activation currently exists as a provider API without a user-facing
  provisioning command. The tested fixtures provision policies; a fresh install
  does not yet offer an end-to-end operation setup workflow.
- Story 1.5 decision logic and later execution are absent. Approved, denied,
  running, completed and execution-failure projections use fixtures; no approval
  or execution shortcut exists.
- The human trust boundary is Linux kernel peer credentials plus the approved
  separate-UID deployment model. Caller-supplied labels confer no authority.
  Non-Linux peer-authentication branches fail closed and were not exercised.
- Tests use synthetic backend/keyring data. No real Vaultwarden account or
  protected process was used. No manual screen-reader session was performed.
- Production desktop handoff is fixed `/usr/bin/xdg-open`, with private artifact
  path only, allowlisted environment and null streams. Its actual invocation
  was tested in a disposable HOME/MIME association; the Firefox fixture uses a
  test-only opener. Successful launch means handoff, not proof a human viewed it.
- Desktop timeout cleanup proves kill/reap of the immediate opener only;
  detached descendant cleanup is not supervised. Failed handoff capabilities
  are not registered and their artifacts are removed.
- Up to 64 browser sessions remain until restart. Repeated cookie loss can
  exhaust that bound; existing recognized sessions still work, and restart
  recovers new-session capacity. Fresh exchange at capacity fails closed.
- Launch pruning synchronously scans validated history and hashes executable
  identities before accepting new HTTPS connections. Large-history/large-image
  latency is unmeasured; no performance bound is claimed.
- Baseline Clippy failed under Rust/Clippy 1.98.0 on existing denied binding
  lints. Mechanical named ignored bindings preserve redaction and cleanup;
  current all-target/all-feature Clippy passes without disabling those lints.

Earlier sandbox failures, interrupted copy attempts, invalid shared-cache
mutation attempts and unrelated desktop timeouts are retained as historical
raw evidence under `target/story-1-4-evidence/`; none is counted as successful
security verification. Presentation logs remove trailing whitespace only;
exact patch strings remain in `.patch.json` files. Source fingerprints and
per-mutant provenance distinguish historical results from current coverage.

After the final test run, the only Rust edit was a comment and formatting identifying a synthetic rejection-test sentinel for the repository secret scanner. Production logic and test assertions are unchanged; the [exact input audit](1-4-evidence/commit-input-audit.json) verifies that edit and every other verified input. Formatting, staged whitespace, and staged secret checks were rerun before the local commit.
