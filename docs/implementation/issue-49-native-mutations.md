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

## Classification of initial survivors

### reaper.rs

Local initial run (pre-existing tests): 14 mutants, 5 caught, 6 missed, 3 unviable.
All six survivors are in the natural reaper's `waitpid` decision (`result == pid`,
`result < 0`, `== ECHILD`, and the `&&`/`||` joining them). The existing test let a
`/usr/bin/true` child exit before the first poll, so a reaper that freed a slot on
`0` (still running) or on any stale errno passed.
`foreign_reaped_pid_is_released_but_live_child_keeps_capacity_until_natural_exit`
first releases a PID this process already reaped (real `ECHILD`), which also leaves
`ECHILD` in the reaper thread's errno, then detaches a live `/bin/sleep 0.4` child and
requires its slot to stay owned across ~20 polls and to be freed only after the
natural exit, with the PID then gone (`ECHILD`). It never signals. It kills all six.

### producer.rs

Local initial run: 49 mutants, 31 caught, 11 missed, 2 timeouts, 5 unviable.

| Survivor | Classification |
| --- | --- |
| `21:42 + with *` (capacity ×4) | Killed: `reader_flags_the_first_byte_past_capacity_instead_of_buffering_more` drives `drain` with exactly `CAPACITY`, `CAPACITY + 1` and `2 × CAPACITY` bytes and requires the reader itself to stop and flag at `CAPACITY + 1`. |
| `105:22 > with ==`, `> with >=` (timeouts) | Killed instead of timing out: the same test runs the reader on a thread with a 10 s bound, so a reader spinning at end of file fails the test. |
| `142:9 Drop → ()` | Killed: `dropping_the_output_closes_the_read_end_while_a_writer_remains` requires `EPIPE` on the retained write end after the capability is dropped. |
| `49:21 delete -` (`[-1; 2]` → `[1; 2]`) | Equivalent: `pipe()` overwrites both slots on success and the value is unused on failure. |
| `68:72 \| with ^` | Equivalent: a new pipe's read end never has `O_NONBLOCK`, so `flags ^ O_NONBLOCK == flags \| O_NONBLOCK`. |
| `113:17 delete EINTR arm` | Equivalent: the read end is non-blocking, so `read` never sleeps and cannot return `EINTR`. |
| `162:31 < with <=` | Equivalent: a 4-byte input has length 0 or a length that cannot match, so both forms reject it. |
| `166:17 \|\| with &&` | Equivalent: a zero length (empty JSON) or a length above `MAX_IMPORT_BYTES` is independently rejected by `SecretImport::parse`, which also bounds input at `MAX_IMPORT_BYTES`. |
| `58:16 < with ==`, `< with <=`; `67:14 < with >`; `68:94 < with >` | Not killed, failure path only: `F_DUPFD_CLOEXEC` returns a descriptor ≥ 4 and `F_GETFL`/`F_SETFL` return 0 on a fresh pipe, so these differ only when the system call fails (descriptor exhaustion). Forcing that would need a process-wide `RLIMIT_NOFILE` change inside the shared test process; not attempted. |

