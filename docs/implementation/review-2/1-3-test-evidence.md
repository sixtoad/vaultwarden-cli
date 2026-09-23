# Story 1.3 test evidence — iteration 2

Verified on 2026-09-23 against baseline `91a6a662cdfb6b27edba2ca93cd3735b630a1931`.
Implementation and complete evidence still require human approval before commit,
push or PR. Iteration 1 results are archived under `review-1/`; they do not approve
this revised implementation.

## Required checks

- `cargo fmt --all -- --check`: passed.
- `cargo test --all-targets --quiet`: **609 reported passed**, zero failed;
  benchmark smoke checks passed. [Complete output](1-3-all-targets.log).
- Scoped `cargo mutants`: **254 current mutations**, **221 caught**,
  **5 individually classified survivors**, **28 unviable**,
  **zero unresolved timeouts**. [Classifications](1-3-mutation-classifications.md)
  and [per-mutation outcomes](1-3-mutation-results.json).
- `git diff --check`: passed.

The [tested file fingerprints](1-3-tested-files.json) cover changed production,
tests, fixtures and Cargo files. No skip annotations were added to production
security logic. Mutation scope includes all changed access-core, session, backend,
loopback and daemon function bodies. The existing config initializer changes only
visibility; declarations and dependency features produce no behavior mutations.
Toolchain: Rust/cargo 1.98.1, cargo-mutants 27.1.0.

## Mutation commands and runs

Diff inputs include untracked Rust files as well as tracked changes. Runs 5 and 7
together test every one of the 254 current production mutations on iteration 2;
no earlier implementation result is reused. Runs 6 and 8 override selected results
after regression-test improvements. Production code is identical across these runs.

```sh
cargo mutants --in-diff target/story-1-3-evidence/implementation-iteration-2-final.diff \
  --output target/story-1-3-evidence/mutation-run-N \
  --jobs 2 --jobserver-tasks 6 --copy-target true \
  --timeout 120 --build-timeout 600 --cap-lints false \
  --re '<recorded run selection>' \
  --cargo-arg=--lib --cargo-arg=--bin=vaultwarden-accessd \
  --cargo-arg=--test=provider_session -- -- \
  --skip commands:: --skip crypto:: --skip config:: --skip models:: --skip totp::
```

Run 5 used three jobs and a 240-second build timeout; subsequent runs used the
limits above. Only unrelated legacy test modules are skipped for mutation runs;
the full all-targets suite executes them. All access, adapter and daemon tests,
including real HTTPS loopback fixtures, run for each mutation. Initial and hardened
source diffs, selections/regexes, inventory JSON, logs and outcomes remain under
`target/story-1-3-evidence/`. Run 8 selects
`replace \| with & in (load_setup|identity_file)`.

- Run 5: 128 CaughtMutant, 9 Timeout, 12 Unviable, 6 MissedMutant.
- Run 6: 1 Unviable, 11 CaughtMutant.
- Run 7: 82 CaughtMutant, 15 Unviable, 1 MissedMutant, 1 Timeout.
- Run 8: 2 CaughtMutant.

An initial run-8 attempt failed while copying changing Cargo build output during
the all-targets build; it ran no mutations and is archived as `mutation-run-8-copy-failure`.
The completed sequential rerun supplies the reported evidence.

## Behaviors verified

- Locked/incompatible/expired providers do not resolve items. Compatibility
  metadata calls precede item access; expiry is rechecked between slow stages,
  each binding, policy persistence and secret consumption.
- A monotonic 15-minute maximum and earlier token expiry revoke authority.
  Lock, expiry and restart invalidate pending/approved work; failed keyring or
  state cleanup leaves admission closed. Barriers exercise racing resolution,
  delayed unlock and irreversible shutdown.
- Mock native-keyring integration verifies revocable record deletion while
  preserving separate bootstrap/CLI credentials. No-config startup also clears
  revocable state before serving; daemon subprocesses use an isolated unavailable
  bus and never touch the user's real keyring.
- Compatibility is metadata-only and accepts the documented exact version pair.
  Redirects, malformed/oversized responses and unsupported metadata fail before
  item reads. Immutable bindings and selected-field decryption enforce type,
  eligibility marker, ambiguity and MAC checks, including legacy CLI MAC opt-out.
- Password/session/value sentinels remain absent from external Debug/Display,
  status, HTTP, process output, URL and durable access-state/audit surfaces.
  Secret containers are zeroizing, non-serializable and privately consumed.
- Trusted HTTPS, one-use launch, exact Host/Origin, Secure HttpOnly SameSite
  cookie plus independent origin-held proof, duplicate-cookie rejection, framing,
  size/deadline limits, slow-client concurrency and overload revocation are tested.
  Repeated completed connections are reaped. Unsafe setup/TLS files are rejected,
  including valid-content FIFOs without blocking.
- Actual Firefox 151.0.2 verified unlock/lock, cookie-only denial, launch replay,
  password-input clearing, plaintext rejection, and stale-page protection from
  a replacement listener with an untrusted certificate.
  [Browser evidence](1-3-browser-evidence.md).

## Limits

No live Vaultwarden account or real desktop OS-keyring service was used. Existing
live-test functions return early without their configured environment; 609 is the
Rust harness count, not live-server certification. Backend/keyring fixtures are
synthetic; cryptographic fixtures perform real derivation/decryption. The browser
uses a disposable profile and fixture CA without changing normal browser or
machine trust. Socket tests ran outside the network sandbox to bind local fixtures.

Five mutation survivors are explicitly classified: two equivalent open-flag
changes, an equivalent unbuffered TCP flush, an untested non-loopback peer guard,
and missing fatal accept-error injection. The latter two are fixture gaps, not
claimed equivalences or caught tests. Production guards remain intact. Compiler
rejections are reported separately from behavioral catches.

## Review checkpoint

Iteration 1 independent review triggered rederivation. The second independent
blind, edge-case and acceptance review is pending: reviewer spawning failed with
`agent thread limit reached`, so the required three fresh-session prompts were
generated under the quick-dev fallback. See
[review results](1-3-review-results.md). Human implementation/evidence approval
remains pending, and nothing has been committed, pushed or submitted as a PR.
