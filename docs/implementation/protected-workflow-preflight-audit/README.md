# Preflight matrix audit supplement — 2026-10-14

This bounded follow-up closes the missing executed negative-traversal evidence
and audits direct executable prerequisites. It does not replace the source or
evidence manifests in `../protected-workflow-corrections/`.

Only three executable-source files changed: `scripts/rehearse-protected-workflow.sh`,
`tests/support/protected_rehearsal.rs`, and `tests/protected_rehearsal.rs`.
`preflight-delta.patch` records the exact delta; `source.sha256` fingerprints
those final files. Comparing the original 126-file source manifest reports
exactly these three changed files and 123 unchanged files
(`historical-source-comparison.log`). Its expected mismatch is provenance,
not a failed verification. Original manifests and logs remain unchanged.

The production traversal preflight now calls the extracted shared guard without
changing its behavior. The new explicitly ignored host regression invokes that
same guard through the real restricted namespace and capability-dropping command.
It verifies restricted UID 1, permits an accessible directory, refuses a 0755
child behind an owned 0700 ancestor, then permits the same child after changing
only that disposable ancestor to 0755. It removes the fixture and independently
asserts absence. Only empty owned directories beneath `/tmp` are involved;
no real home permissions or environment, subordinate mappings, host trust,
services, containers, browser, provider state or credentials are changed.

Direct executable audit covered the runner, Rust harness and browser controller.
Previously omitted `chown`, `dd`, external `test`, shell and bootstrap paths are
now checked. Fixed runtime dependencies are checked at their actual executable
paths, preventing Bash's builtin `test` from satisfying `/usr/bin/test`.
Cargo and Node retain PATH discovery; configurable browser tools retain their
existing checks. The original B7 prerequisite list is preserved. This checks
direct invocations, not the recursive internal dependency graph of system tools.

Sequential verification on the final delta:

- Formatting, shell syntax and workspace/all-targets/all-features Clippy with
  warnings denied passed (`fmt.log`, `shell-syntax.log`, `clippy.log`).
- Focused default/all-features/no-default-features suites each passed 16 tests,
  zero failed, two ignored, in 0.50 s (`focused-*.log`). The ignored cases are
  production provisioning and the explicit restricted-namespace regression.
- The actual restricted-namespace regression was separately executed with
  approved host permissions: one passed, zero failed/ignored, 0.02 s
  (`restricted-traversal-host.log`). This is actual negative traversal evidence,
  not an inferred result from successful normal preflight.
- Final source fingerprints and scoped whitespace checks passed
  (`final-source-check.log`, `whitespace.log`). Logs were scanned for the fixed
  rehearsal credential corpus and private-key headers before retention.

Commands, run sequentially from the repository:

```sh
cargo fmt --all -- --check
bash -n scripts/rehearse-protected-workflow.sh
cargo clippy --offline --locked --workspace --all-targets --all-features -- -D warnings
scripts/with-secure-test-tmpdir.sh cargo test --offline --locked --test protected_rehearsal
scripts/with-secure-test-tmpdir.sh cargo test --offline --locked --all-features --test protected_rehearsal
scripts/with-secure-test-tmpdir.sh cargo test --offline --locked --no-default-features --test protected_rehearsal
cargo test --offline --locked --test protected_rehearsal restricted_identity_refuses_inaccessible_directory_before_provisioning -- --ignored --exact --nocapture
```

Retained files are exact copies of `/tmp/vw-preflight-audit.CrEMZY` outputs,
including empty success logs and original trailing whitespace. `evidence.sha256`
checks this supplement independently. No full workspace, live, GUI, production
rehearsal or human suite was rerun; the earlier successful human and broader
evidence remains tied to its historical fingerprint. No mutations, commit or
push occurred. Task checkboxes and overall acceptance remain parent-owned.
