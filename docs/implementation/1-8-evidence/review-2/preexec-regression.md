# Pre-exec SIGKILL regression

The helper's existing confirmation/report/reaping tail is extracted into
`report_exec_and_reap` without changing its security conditions. The new bridge
test calls this same production tail with a real traced child.

The child performs `PTRACE_TRACEME` and stops with `SIGSTOP`. Only the production
`trace_exec` handshake resumes it; its next action sends itself `SIGKILL` before
any exec event. There are no sleeps or probabilistic kill timing windows. A
separate runner process isolates `waitpid(-1)` from the test harness, and alarms
bound both fork branches.

The regression requires all of the following:

- The error pipe actually returns zero bytes at EOF, with no error byte.
- The bridge reports exactly `Failed`, then `Reaped`, followed by socket EOF.
- No `ExecConfirmed` report is emitted. This is the only report that authorizes
  `control.started()` in `src/adapters/supervisor.rs`.
- `waitpid(-1, ..., WNOHANG)` returns `ECHILD` in the isolated runner, proving its
  child has been reaped. The test also waits for the runner before asserting the
  report sequence, including when the mutant emits the wrong report.

The [replay script](preexec-mutation.py) ran on the Linux host through the secure
temporary-directory wrapper. The sandbox attempt stopped in the wrapper because
its root directory ownership is mapped to `nobody`; no sandbox test result is
claimed.

| Run | Result | Evidence |
| --- | --- | --- |
| Bridge baseline | 9 passed | [baseline log](preexec-baseline.log) |
| Ignore trace result but still execute tracing | Caught, exit 101 | [mutant log](preexec-mutant.log), [exact diff](preexec-ignore-trace.diff) |
| Restored bridge tests | 9 passed | [restored log](preexec-restored.log) |

The mutant failed the report-sequence assertion with `Some(ExecConfirmed)`;
it compiled and did not time out. The replay script restores the original source
in `finally`, verifies byte equality, and records matching SHA-256 hashes in
[machine-readable results](preexec-results.json). Focused `rustfmt --check` and
`git diff --check` also passed. Full-suite verification is delegated to the root
workflow after all review corrections are assembled.
