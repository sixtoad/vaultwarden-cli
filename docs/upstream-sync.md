# Upstream synchronization

This repository is an independently maintained fork of
[haydonryan/vaultwarden-cli](https://github.com/haydonryan/vaultwarden-cli).
Our protected-operation provider, human approvals and agent access do not depend
on upstream accepting those features. Keep the original MIT license and copyright
notice when distributing the derived project.

## Policy

Use `origin` for `sixtoad/vaultwarden-cli` and `upstream` for the original project.
Import upstream on a new branch/worktree based on our current `origin/main`,
resolve differences deliberately, and submit a PR to our repository. Do not
rebase or force-push published `main`, and do not push our feature branches to
upstream. Standalone upstream contributions are a separate decision.

Preserve the merge commit when integrating a full upstream sync PR: use GitHub's
**Create a merge commit**, not squash or rebase merge. Upstream must remain an
ancestor of our main branch so subsequent syncs compare against the correct base.
For selective cherry-picks, record the original commit and why a full merge was
not appropriate; cherry-picking does not establish that upstream ancestry.

After integration, verify the recorded upstream revision is an ancestor:

```bash
git fetch origin main
git merge-base --is-ancestor 255f644fd2f28537c282fca24ce881d9cc27ce08 origin/main
```

Exit status 0 confirms ancestry; replace the revision for subsequent syncs.

## 2026-10-15 sync

- Fork baseline: `c56413ad54be0e0cca110b9bff23afd2510498f0`.
- Upstream revision: `255f644fd2f28537c282fca24ce881d9cc27ce08`.
- Common ancestor: `2fc3236b2cd4d43ad58eb8134177fa327ba6eded`.
- Incoming history: 38 upstream-only commits, with changes to five files.

Import the upstream dependency graph and source/assertion cleanups. Resolve the
manifest and lockfile with our additional dependencies and features intact.
Specifically:

- Keep `clap`; do not reintroduce upstream's `argy` dependency or its former
  machine-local path. Keep the provider's Tokio features and Reqwest blocking API.
- Take Reqwest 0.13.5, RSA 0.10.0-rc.19 and rstest 0.27; retain the rustls 0.23.46
  security floor already present in our fork.
- Keep our existing Clippy policy. Upstream's newly enabled blanket pedantic and
  nursery groups are not adopted as part of this dependency sync; existing CI
  still runs all-target/all-feature Clippy with warnings denied.
- Retain `test_get_by_uri_matches_when_name_does_not_match`. Although upstream
  removed it as redundant, its explicitly unrelated item name is a useful
  regression case for this fork.
- Keep the provider/agent/SSH/macOS behavior, live-test isolation and CI fixes.

Run formatting, Clippy, the feature test matrix, supported minimum Rust checks,
dependency audit/license checks and native CI before treating the sync as ready.
Unconfigured live-test early returns do not establish real-vault verification.

## Reproducing verification

Install the [ordinary Linux test prerequisites](../README.md#ordinary-test-prerequisites-linux)
first. From the repository root, verify the committed dependency graph:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
./scripts/with-secure-test-tmpdir.sh cargo test --locked --workspace --all-targets
./scripts/with-secure-test-tmpdir.sh cargo test --locked --workspace --all-targets --all-features
./scripts/with-secure-test-tmpdir.sh cargo test --locked --workspace --all-targets --no-default-features
./scripts/with-secure-test-tmpdir.sh cargo test --locked --doc --all-features
cargo +1.88.0 check --locked --all-targets --all-features
cargo audit
cargo deny check
```

For this networking/cryptographic dependency sync, also run the complete
[disposable live regression suite](../README.md#disposable-live-regression-suite-linux):
`./scripts/test-live.sh` without a filter. It provisions only a temporary local
Vaultwarden instance with synthetic credentials; do not substitute a personal
vault. Native/platform/browser/agent/systemd CI and the actual coverage step must
finish successfully in the sync PR before marking it ready.

### Local validation record (2026-10-15)

The resolved merge of the two revisions recorded above passed formatting,
Clippy, all three locked test configurations (each reported 1,042 passes, zero
failures and 21 ignored), all-feature doc tests, Rust 1.88.0 compatibility, cargo
audit and cargo deny. The retained URI regression test killed a negated URI-match
mutation and passed after exact source restoration; this is a focused probe,
not full mutation coverage. The sync PR records live-suite and remote CI results;
local results alone do not establish native-platform or real-vault readiness.
