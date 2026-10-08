# Story 3.1 semantic mutation evidence

All 52 independent mutants were killed: 43 by the initial tests and 9 after test-only improvements. There are no unresolved survivors, equivalent claims, unviable mutants, timeouts, or infrastructure failures. No production changes were needed.

## Method and baselines

The campaign used `/tmp/vw-story31-mutations/source`, a separate copy of the reviewed worktree. Each candidate changed one behavior, ran to completion, and restored its source before the next candidate. Each case records its diff, full command, exit code, assertions, elapsed time, candidate hashes and restored hashes. The original and final restoration manifests match their corresponding baselines. Root source changes during the campaign were limited to four test files.

Initial unmodified baselines: SSH-focused tests 14/14, unsupported-backend denial 1/1, and trusted Firefox browser suite. After test improvements: SSH-focused tests 16/16 and the trusted Firefox browser suite. The parent workflow owns the complete final regression suite.

## Measured gaps and test improvements

- Exact duplicate JSON spelling was not independently tested; added valid-payload duplicates for identity, numeric type, deletion, SSH object and all three required key fields.
- The policy verifier default denial lacked a direct SSH test; added an unsupported verifier whose login fallback panics.
- Fingerprint negatives combined invalid prefix/encoding/size; added otherwise-valid wrong-prefix data, a single invalid base64 character, and 31/33-byte boundary vectors.
- Comparison-only digest tests could not detect omission of constant SSH use/profile members; added an independently calculated golden version-3 projection.
- Directory/pin review expectations reused the projection helper; replaced them with explicit expected values.
- Browser history searched for `ssh`, which also appeared in the operation ID; the history-only mutant proved this masking, and the assertion now requires `Backup SSH (ssh)`.
- Activation unknown-member coverage now explicitly includes remote, host, command, key path, options and working-directory selectors.

The constant-field omissions are treated as revision-format regressions, not equivalents: omitting either changes the version-3 digest and would invalidate previously stored revisions. The independent golden fixture protects that serialization contract.

## Completed cases

| Mutant | Initial classification | Final classification | Initial / rerun seconds |
|---|---|---|---|
| `policy-immutable-uuid` | killed | killed | 110.19 |
| `policy-explicit-ssh-use` | killed | killed | 20.95 |
| `backend-exact-uuid` | killed | killed | 17.04 |
| `backend-actual-type-five` | killed | killed | 16.38 |
| `backend-undeleted` | killed | killed | 16.75 |
| `backend-required-ssh-body` | killed | killed | 30.04 |
| `backend-nonempty-key-field` | killed | killed | 31.34 |
| `backend-duplicate-members` | survived | killed | 26.05 / 23.26 |
| `backend-default-deny` | killed | killed | 68.19 |
| `verifier-default-deny` | survived | killed | 32.33 / 23.91 |
| `no-generic-targets` | killed | killed | 20.99 |
| `no-generic-schemas` | killed | killed | 29.09 |
| `no-mixed-credentials` | killed | killed | 21.73 |
| `working-directory-validation` | killed | killed | 17.6 |
| `resource-path-validation` | killed | killed | 17.2 |
| `host-validation` | killed | killed | 18.91 |
| `explicit-nonzero-port` | killed | killed | 16.99 |
| `user-validation` | killed | killed | 29.17 |
| `absolute-unambiguous-path` | killed | killed | 27.65 |
| `numeric-host-ambiguity` | killed | killed | 31.53 |
| `fingerprint-sha256-prefix` | survived | killed | 39.05 / 16.94 |
| `fingerprint-exact-32-bytes` | killed | killed | 19.81 |
| `fingerprint-base64-decoding` | survived | killed | 18.7 / 17.84 |
| `ssh-request-arguments` | killed | killed | 19.85 |
| `ssh-unknown-authority-members` | killed | killed | 28.09 |
| `digest-omit-id` | killed | killed | 27.28 |
| `digest-omit-image` | killed | killed | 16.43 |
| `digest-omit-item_id` | killed | killed | 15.48 |
| `digest-omit-use_type` | survived | killed | 16.39 / 20.25 |
| `digest-omit-working_directory` | killed | killed | 15.94 |
| `digest-omit-destination-host` | killed | killed | 20.96 |
| `digest-omit-destination-port` | killed | killed | 19.15 |
| `digest-omit-destination-user` | killed | killed | 34.97 |
| `digest-omit-destination-resource_path` | killed | killed | 28.25 |
| `digest-omit-destination-host_fingerprint` | killed | killed | 18.7 |
| `digest-omit-image-image_id` | killed | killed | 17.99 |
| `digest-omit-image-execution_root` | killed | killed | 20.13 |
| `digest-omit-image-path` | killed | killed | 19.15 |
| `digest-omit-image-sha256` | killed | killed | 17.3 |
| `digest-omit-image-profile` | survived | killed | 19.48 / 21.16 |
| `review-fixed-target` | killed | killed | 19.9 |
| `review-credential-label` | killed | killed | 15.23 |
| `review-credential-use` | killed | killed | 17.96 |
| `review-working-directory` | survived | killed | 17.67 / 22.06 |
| `review-host-pin` | survived | killed | 16.13 / 16.38 |
| `activation-eligibility` | killed | killed | 22.25 |
| `approval-eligibility` | killed | killed | 22.28 |
| `ssh-execution-entrypoint-guard` | killed | killed | 18.91 |
| `ui-host-pin` | killed | killed | 108.38 |
| `ui-working-directory` | killed | killed | 98.13 |
| `ui-credential-use` | killed | killed | 89.08 |
| `ui-history-credential-use` | survived | killed | 99.68 / 99.28 |

## Reproducibility and artifacts

[Summary and exact results](summary.json.gz), [single-change plan](plan.json.gz), [compressed test-only fixes](test-improvements.diff.gz), and compressed per-mutant patches in `diffs/` retain the exact patch bytes. Patches are compressed because unified-diff blank context lines intentionally contain a space; storing those as source text triggers whitespace checks. [Compressed per-case evidence](case-evidence.tar.gz) retains all logs, commands, individual results and full source/restoration manifests; its checksum is in `archive.sha256`. The archive includes both initial-survivor and successful rerun evidence.

`prepare.py`, `initial-runner.py`, `runner.py`, `extra.py`, `rerun.py`, and `add_independent_tests.py` preserve the executed workflow. The scripts use the local secure-HOME test wrapper, existing Cargo target cache and installed browser dependencies; they never replace HOME or access a real backend account. Cargo dependency resolution ran offline and locked; fixtures used synthetic credentials and local servers.

Initial mutants and reruns used `cargo test --offline --locked --lib ssh_`, except the unsupported backend mutation (the dedicated provider-session integration test) and actual rendering mutations (the Firefox script). Full argv are recorded per case.

## Shared-cache handoff correction

The first parent final Firefox run detected the last history mutant still embedded in the shared Cargo lib-test executable even though both restored source copies were correct. Cargo reused a relative-path/mtime fingerprint across worktrees. [Diagnostic hashes and expression counts](../cache-contamination.json) preserve this evidence. Parent removed only this package's build artifacts with `cargo clean -p vaultwarden-cli --offline` and reran the complete final sequence. The earlier parent attempt is retained as development evidence, not final acceptance evidence. Future reproduction must use an isolated mutation target directory or clean package artifacts before returning to the main worktree; source restoration alone is insufficient across shared-target worktrees.

## Independent review audit

The parent inspected every final failing test or browser assertion and recorded them in [the classification audit](classification-audit.json). Every kill targets the affected SSH behavior; the broad historical runner classifier was not treated as sufficient evidence alone. Rust baselines ran 14 then 16 SSH tests and the unsupported-backend baseline ran one; successful browser baselines emitted their completion report. No zero-test baseline or unrelated browser failure was counted.

These scripts are historical execution snapshots, with the exact local checkout, browser dependencies and pre-improvement baseline used in the campaign. They are not a portable rerun entry point. Reconstructing the initial campaign requires the archived original source hashes and reversal of `test-improvements.diff.gz`; running `prepare.py` against the final checkout instead creates the final test baseline. Any replay must configure its own paths and isolated Cargo target directory, and check the named failed assertions and executed test counts.
