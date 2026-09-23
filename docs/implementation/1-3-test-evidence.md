# Story 1.3 test evidence — iteration 3

Baseline: `91a6a662cdfb6b27edba2ca93cd3735b630a1931`. The human approved implementation
and complete evidence on 2026-09-23, authorizing commit, push and PR. Earlier results
are archived in `review-1/` and `review-2/`; independent review prompted the
corrections described in [review results](1-3-review-results.md).

## Required checks

- `cargo fmt --all -- --check`: passed.
- `cargo test --all-targets --quiet`: **617 reported passed**, zero failed;
  benchmark smoke checks passed. [Complete output](1-3-all-targets.log).
- Scoped `cargo mutants`: **289 current mutations**, **251 caught**,
  **5 individually classified survivors**, **33 compiler rejections**,
  and **zero unresolved timeouts**. [Classifications](1-3-mutation-classifications.md)
  and [per-mutation outcomes](1-3-mutation-results.json).
- `git diff --check`: passed.

The [tested fingerprints](1-3-tested-files.json) cover changed production, tests,
fixtures and Cargo files. Toolchain: Rust/cargo 1.98.1, cargo-mutants 27.1.0.
No mutation-skip annotations were added to production security logic.

## Mutation scope and commands

Inventory comes from all changed function bodies and touched constants. We expand
`--in-diff` selection to the complete containing functions, so comparisons on
otherwise unchanged lines of edited functions are covered. Config changes only
initializer visibility; declarations do not change function behavior.

176 mutations retain individually mapped completed iteration-2 outcomes only
where the entire production function body is byte-identical. Every revised/new
mutation was rerun. Stable identity includes file, function, function-relative
location, column, replacement and genre. No unmapped mutation is counted.

```sh
cargo mutants --output target/story-1-3-evidence/mutation-run-9 \
  --jobs 3 --jobserver-tasks 6 --copy-target true \
  --timeout 120 --build-timeout 600 --cap-lints false \
  --re '<recorded selection>' \
  --cargo-arg=--lib --cargo-arg=--bin=vaultwarden-accessd \
  --cargo-arg=--test=provider_session -- -- \
  --skip commands:: --skip crypto:: --skip config:: --skip models:: --skip totp::
```

Run 10 selects the formerly surviving item-key format guard, with one worker
and otherwise the same arguments; exact argv is in `mutation-run-10-command.json`.

Only unrelated legacy test modules are skipped for mutation runs; the full suite
executes them. Every mutation runs access, adapter, daemon and HTTPS transport
checks. Exact argv, input snapshots, expanded scope, selections, logs and results
are under `target/story-1-3-evidence/`, including `mutation-run-9-command.json`.

- Run 9: 102 CaughtMutant, 10 Unviable, 1 MissedMutant.
- Run 10: 1 CaughtMutant.

## Behaviors verified

- Locked, incompatible and expired providers do not resolve items. Metadata-only
  compatibility precedes item access and enforces the exact supported version
  pair; redirects, malformed/oversized replies and transport failures fail closed.
- Lock, expiry, restart and shutdown invalidate authority and unexecuted work.
  Barriers exercise resolution/lock and delayed unlock/shutdown. Post-backend
  checks run on both success and error; closing gates eligibility/policy admission.
- Linux boot-time clock includes suspend; tests cover equal/backward/failing
  clock samples and exact conversion/deadline boundaries. Clock faults fail closed.
- Startup clears native-keyring revocable authority after exclusive writer
  acquisition but before state validation, including corrupt/missing state or
  changed executables; competing writers preserve the active provider's session.
  No-config startup removes stale launch artifacts. Cleanup failures remain closed.
- The signal-driving task remains responsive while a status check waits for
  delayed backend work, publishing irreversible admission closure before cleanup.
- Provider-specific keyring deletion preserves bootstrap and CLI credentials.
  No real user keyring is touched by fixtures; daemon subprocesses use an isolated
  unavailable session bus.
- Personal and organization item keys are authenticated before selected-field
  decryption. Missing/tampered MAC, malformed key, wrong parent and invalid lengths
  fail closed, including with the direct CLI insecure-MAC override enabled.
- Password/session/value sentinels remain absent from external error/debug/status,
  HTTP response, process-output, URL and durable access-state/audit surfaces.
  No raw vault item crosses the core port; resolved values stay privately scoped.
- Trusted HTTPS, one-use launch, exact Host/Origin, Secure HttpOnly SameSite cookie
  plus independent origin-held proof, duplicate-cookie rejection, deadlines,
  framing and overload revocation are tested. Setup/TLS FIFO rejection is bounded.
- Actual transport accepts all supported 4096-byte password encodings and rejects
  a decoded 4097th byte. Partial, duplicate and trailing JSON failures are rejected;
  partially deserialized passwords use a zeroizing container. The parser checks
  a complete oversized encoded body independently.
- Firefox 151.0.2 verifies ordered mutations with a deliberately delayed Unlock
  followed by Lock; input clearing; cookie-only and launch replay denial; plaintext
  rejection; and stale-page refusal to send HTTP to an untrusted replacement TLS
  listener. [Browser evidence](1-3-browser-evidence.md).

The initial all-targets attempt exposed a fixture assumption: rejecting an encoded
body over the limit can reset a connection before draining it, rather than return
HTTP 403. The decoded-length test now stays within the encoded bound. A separate
complete-body parser check verifies the encoded bound. These corrections changed
only tests; the final full run passed. Initial output is retained as
`all-targets-iteration-3-transport-fixture-failure.log`.

## Limits

No live Vaultwarden account or real desktop keyring service was exercised. Some
legacy live-test functions return early without configured credentials, so the
harness count is not live-server certification. Backend/keyring fixtures are
synthetic; crypto tests perform real derivation/decryption. Suspend behavior uses
injected samples and the documented Linux clock semantics, without suspending the
host. Firefox uses a disposable profile and fixture CA, with normal user/system
trust untouched. Local socket fixtures require execution outside the network
sandbox. Survivor gaps and compiler failures are reported explicitly above.

## Human checkpoint

The third independent review is complete, with no remaining Story 1.3 blockers.
The acceptance auditor independently validated fingerprints, raw test/browser
results and all mutation mappings. One pre-existing crypto scratch-buffer
hardening issue is recorded in [deferred work](deferred-work.md).
The human approved implementation and complete test evidence on 2026-09-23,
authorizing commit, push and PR creation. Tested production and test fingerprints
remain unchanged; only review and approval documentation changed afterward.
