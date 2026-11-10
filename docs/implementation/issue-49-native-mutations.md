# Issue 49: targeted mutation campaign for the macOS native adapter

Scope: `src/adapters/native/` — release race and supervision (`mod.rs`),
peer-token/cdhash binding (`Recipient::peer`, `image::dynamic`, `platform::audit`),
image/loader checks (`image.rs`), installed identities (`identity.rs`), kernel
evidence and no-writer opens (`platform.rs`), the natural reaper (`reaper.rs`) and
the producer output channel (`producer.rs`). It is a scoped campaign, not a
repository-wide score. No survivor exposed a production bug. Production behaviour
is unchanged; the only production-file edit is a `cfg(test)`-only identity-file
seam (see [identity](#identityrs)), compiled out of every non-test build.

## Method

Two layers, as in earlier campaigns (`1-9-mutation-classifications.md`):

- **Generated** (cargo-mutants 27.1.0) per file, through
  [`scripts/mutate-native-generated.sh`](../../scripts/mutate-native-generated.sh).
  cargo-mutants copies the tree below a private `$HOME` scratch directory with umask
  077 (the ancestry the native tests require), builds only the library test target
  without debug info and runs the selected tests serially in one process (the
  reaper and stopped-provider checks are process-global). Outcomes are cargo-mutants'
  own: *caught* (a test failed), *missed*, *unviable* (does not compile) and
  *timeout* (300 s test or 900 s build budget exceeded). A timeout is never counted
  as caught here.
- **Semantic** faults for the behaviours the issue names, through
  [`scripts/mutate-native-adapter.py`](../../scripts/mutate-native-adapter.py):
  each fault needs a passing unmutated run of its named test and then that test's
  `test result: FAILED`; build failures are not catches. Sources are restored and
  their hashes recorded in `results.json`.

`initial-*` runs use the unmodified `origin/main` sources (`7bc3753`); `final-*`
runs use this branch, including the new tests. Evidence lists are in
[`issue-49-native-mutations/`](issue-49-native-mutations/).

<!-- RESULTS -->
