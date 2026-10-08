# Main-branch integration

The user requested resolving PR #33 merge conflicts. This merges main commit `d1efb1034fcf500c8dd21ebf485a07d928a07059` into companion commit `a25c642b874af76dadfb18fc62bd178fdd1fb9e0`, preserving both histories and leaving other worktrees untouched.

The only textual conflict was `src/access/direct_request_tests.rs`: main's complete file is retained verbatim and the two unchanged companion tests are appended. Both sets of tests remain. Two non-SSH test fixtures explicitly initialize fields introduced by main: `material_root: None` in the companion supervisor and `ssh: None` in its operation policy.

The automatic merge retains the companion's exact-review/generation checks and final commit deadline, together with main's SSH eligibility, protected-material lifecycle and execution cleanup. The daemon passes its state root to the updated supervisor constructor. CI retains both mapped-principal setup and the native companion job.

All 15 native verification inputs are byte-identical to their recorded passing snapshot. No native implementation or app installation changed. Main adds optional SSH-specific review data; native closed-schema decoding rejects those unsupported reviews. SSH operations and app-managed tunnelling remain outside the companion's approved scope.

Merge verification passed: default all-targets reported 1003 passes, with 71 unavailable live-backend early returns excluded (932 exercised), 16 ignored and zero failures; 13 benchmark smokes passed. Formatting, strict all-feature/all-target Clippy and native-fixture checks passed. Two real-systemd tests and the mapped-principal SSH-material isolation test passed separately. See [results](results.json), [log manifest](log-manifest.json) and [source hashes](source-hashes.json). All/no-default execution profiles and native tests were not repeated for this merge; hosted CI remains separate. This integration does not close the separately pending final installed Mac correct-password/notification acceptance gate.
