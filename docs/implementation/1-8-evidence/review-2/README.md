# Review 2 focused corrections

The review's six requested corrections are implemented. Only tests covering edited
files were run here; the workflow owner runs full verification after source freeze.

- `manager.rs` passes the existing stop/reap deadline into process inventory and
  checks the remaining budget at every entry and before accepting absence. The
  deterministic regression exhausts its budget on the second of three entries;
  interrupted observation returns `CleanupUncertain`. It also distinguishes an
  exhausted empty inventory from a still-live empty inventory. The focused manager
  group passed **8/8**, including exact typed properties and independent reaping
  tests; the amended budget regression passed again as one exact test.
- Transient units request string `CollectMode=inactive-or-failed`; ownership checks
  the Unit property. The exact contract test asserts its signature and value.
  `failed-launch-recovery` observes automatic unit unloading without reset-failed,
  proves its lease remains, then recovers/removes it through independent process
  observation. Both failed-launch scenarios additionally observe `LoadState=not-found`
  before harness cleanup can reset failed state. Baseline and restored live trials pass.
- The test script obtains helper, library and test executable paths from Cargo JSON,
  deriving the dependency directory from that reported artifact location. The
  custom-target trial physically relocated the build cache, passed with the default
  `target` absent before and after, then restored it in `finally`.
- `access-mvp.md` makes trusted reviewed operations and the provider UID boundary
  explicit, including deliberate manager/cgroup manipulation, while preserving
  the separate restricted agent-principal requirement.
- Native fixture exit 23 and self-SIGKILL modes run through the production helper
  and application supervisor. Tests assert exact in-memory and durable
  `ExecutionNonzero`/`ExecutionSignaled` failures, the existing generic API error,
  independent cleanup and journal sentinel absence. Both baselines and restored
  trials pass. Mapping either wait status to success is caught by the exact
  application status assertion. Scoped provider journals record the expected
  reason versus incorrect `Completed`; the outer harness subsequently fails its
  completion barrier. These are confirmed inner assertion failures, not timeout-only
  mutation classifications.
- The synchronized pre-exec SIGKILL regression confirms actual empty error-pipe
  EOF, exactly Failed/Reaped reports, no start-authorizing ExecConfirmed report,
  socket EOF and ECHILD. Bridge baseline/restored groups pass **9/9**; ignoring the
  trace result is caught immediately. See [preexec-regression.md](preexec-regression.md).

The authoritative [systemd v255 unit documentation](https://raw.githubusercontent.com/systemd/systemd/v255/man/systemd.unit.xml)
defines `CollectMode=inactive-or-failed` and records its addition in v236. Unit
unloading does not replace the retained lease's independent cleanup proof.

Replay the live selected regressions with:

```sh
scripts/with-secure-test-tmpdir.sh python3 docs/implementation/1-8-evidence/review-2/status-and-target-regressions.py
```

`status-and-target-results.json` records each exit status and matching source hashes.
The replay mutates only one source at a time and restores source/cache in `finally`.
A development-only failed trial is retained in `status-test-development-failure.log`:
its test initially expected a successful API return for a durable failure, then was
corrected to preserve the existing generic-error API contract. No production change
was needed for that expectation.

Journal evidence uses the existing bounded per-provider stdout/stderr visibility
markers and successful reads; it does not claim a privileged global journal flush.
The production null-stream contract remains intact. The full live matrix now has
29 scenarios; this correction pass ran only the selected affected scenarios.
