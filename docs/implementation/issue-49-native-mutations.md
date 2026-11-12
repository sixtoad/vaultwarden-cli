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

Both layers run in the opt-in workflow
[`native-mutations.yml`](../../.github/workflows/native-mutations.yml) on GitHub's
`macos-26` (Apple Silicon) runners, not on a development Mac. Each generated file runs
twice: **main** mutates and tests `origin/main`'s sources (the tests that existed
before this campaign) and **branch** uses this branch, so every survivor and every new
kill is compared on the same runner image. Evidence lists from the final run are in
[`issue-49-native-mutations/`](issue-49-native-mutations/) (`main-<file>/`,
`branch-<file>/`: cargo-mutants' `caught`, `missed`, `timeout`, `unviable` lists and
`outcomes.json.gz`; `semantic/results.json`).

### cargo-mutants must run natively

cargo-mutants 27.1.0 publishes only an `x86_64-apple-darwin` binary, which the
installer action ran under Rosetta. Its children then preferred the x86_64 slice of
universal tools, so the fixtures the tests compile with `/usr/bin/clang` were x86_64
and the arm64-only native spawn (`posix_spawnattr_setbinpref_np`, `count == 1`)
refused them: seven producer/spawn tests failed the unmutated baseline with
`ExecutionFailed` and `mod`, `platform`, `identity` and `producer` never ran (run
42730674659). It also hid kills: with x86_64 fixtures `image::signature` failed at
`macho()` before reaching the code signature checks. The workflow now builds
cargo-mutants once natively (`cargo install --locked`, `lipo -archs` printed) and the
wrapper refuses a cargo-mutants binary without an `arm64` slice.

<!-- RESULTS -->
## Results

Final run: workflow run
[**43209334431**](https://github.com/sixtoad/vaultwarden-cli/actions/runs/43209334431)
on `ed52aac` (after merging `main` at `c6a01ca`, which brought the Developer ID
publisher checks into `image.rs`); all 14 jobs green. Score =
caught / (caught + missed + timeout); unviable mutants are excluded. *Adjusted*
also excludes the survivors classified **equivalent** below.

| File | main (pre-campaign tests) | branch | branch adjusted |
| --- | --- | --- | --- |
| `reaper.rs` | 5 / 11 (45.5%) | 11 / 11 (100%) | 11 / 11 (100%) |
| `identity.rs` | 6 / 34 (17.6%) | 32 / 34 (94.1%) | 32 / 32 (100%) |
| `image.rs` | 171 / 213 (80.3%) | 197 / 213 (92.5%) | 197 / 208 (94.7%) |
| `mod.rs` | 46 / 89 (51.7%) | 83 / 89 (93.3%)¹ | 83 / 87 (95.4%) |
| `platform.rs` | 56 / 88 (63.6%) | 66 / 88 (75.0%) | 66 / 74 (89.2%) |
| `producer.rs` | 31 / 44 (70.5%) | 33 / 44 (75.0%) | 33 / 39 (84.6%) |
| **total** | 315 / 479 (65.8%) | 422 / 479 (88.1%) | 422 / 451 (93.6%) |

Unviable (excluded): reaper 3, identity 1, image 5, mod 8, platform 2, producer 5
on both legs. Timeouts: producer 2 on both legs (see producer.rs).

¹ cargo-mutants reports 84 caught: it also counts `129:20 > with >=` as caught, but
that mutant failed only the timing assertion `live_calls > 5` of
`native_supervision_maps_natural_exit_status_and_reports_reaped_cleanup` (the
previous run, 43176132176, missed it). It is not a genuine kill and is counted as
missed here.

Semantic faults (11): every fault caught on the branch (baseline passed, mutant
`test result: FAILED`): release race, implicit termination, peer-token PID, peer
cdhash, loader path, shared-cache dependency, reaper live child, producer before
reaping, producer overflow, identity root provider, no-writer group mode.

No survivor exposed a production bug. Each killing test below was shown to fail
against its exact mutant (applied by hand, targeted test run) and to pass unmutated.

## Survivors and kills by file

### reaper.rs

All six pre-campaign survivors sit in the natural reaper's `waitpid` decision.
`foreign_reaped_pid_is_released_but_live_child_keeps_capacity_until_natural_exit`
(a live `/bin/sleep` child keeps its slot across ~20 polls and is freed only after
its natural exit) kills `57:39 == with !=`, `58:44 < with ==`/`< with >` and
`60:41 == with !=`. It did not kill `58:44 < with <=` and `59:37 && with ||`: those
free a slot whose `waitpid` returned 0 when errno is `ECHILD`, but on Darwin the
reaper's `nanosleep` leaves `ETIMEDOUT` in errno between passes. They are killed by
`live_child_polled_after_an_echild_slot_in_the_same_pass_keeps_its_slot`: slot 0
holds an already-reaped PID and slot 1 a live child, so within one pass the slot-0
`ECHILD` is still errno when slot 1's `waitpid` returns 0.

### identity.rs

The `cfg(test)` identity-file seam (`TEST_IDENTITY_FILE`) lets the tests load
synthetic installed-identity files through every validation step except the
root-owner requirement, which synthetic files cannot meet; non-test builds compile
only the root-owned path. The `mutation_tests.rs` identity tests kill 26 of the 28
pre-campaign survivors. Remaining:

| Survivor | Classification |
| --- | --- |
| `43:9 \|\| with &&` (`rc != 0 && result.is_null() \|\| pw_uid != uid`) | Equivalent: when `getpwuid_r` finds no entry the zeroed `passwd` keeps `pw_uid == 0`, so the last clause rejects every unknown non-root UID, and UID 0 always exists. |
| `44:9 \|\| with &&` (`result.is_null() && pw_uid != uid`) | Equivalent: a found entry always has `pw_uid == uid`; a null result leaves `pw_uid == 0`, so the joined clause is true for every unknown non-root UID. |

### image.rs

Pre-campaign: 34 survivors; the boundary/header tests kill 26. Added for the CI run:
`native_fat_table_limits_header_overlap_and_adjacent_out_of_order_slices` (17 valid
slices; a non-native slice inside the fat table; adjacent slices listed out of file
order) kills `61:19`, `82:35 * with +`/`* with /`, `84:62 > with >=`;
`native_load_commands_must_fit_the_file_and_have_their_minimum_shape` (commands
claimed past the end of the file, which the `> with ==` mutant slices out of bounds and
panics on; a zero-size command; a dylib name inside its fixed fields) kills
`111:42 > with ==`, `120:21`, `126:32`;
`native_signature_policy_requires_the_hardened_runtime` (ad-hoc signature without
`--options runtime`) kills `271:29 \|\| with &&` and `271:14 & with \|`.
`slice_signature -> Ok(..)` survived only under Rosetta and is killed natively by the
existing ad-hoc signature test.

`main` (#80) added the publisher classification (`satisfies`, `publisher`,
`team_identifier`, `signing_information`); the image row grew from 199 to 213
viable mutants and the line numbers below are those of the merged file.

| Survivor | Classification |
| --- | --- |
| `111:42 > with >=` | Equivalent: a signed slice needs signature data after its load commands (`dataoff >= end`, `datasize > 0`, within the file), so `end == len` is rejected later in every case. |
| `176:13 delete forbidden-command arm` | Equivalent: those commands then reach the fail-closed `_` arm, same `UnsupportedImage`. |
| `238:13 \|\| with &&` (static code creation), `337:9 \|\| with &&` (`signing_information`) | Equivalent under the Security API contract: the out pointer is set exactly when the call returns `errSecSuccess`. |
| `285:36 \| with ^` (`satisfies`) | Equivalent: `STRICT_VALIDATE` and `NO_NETWORK_ACCESS` are disjoint bits. |
| `285:36 \| with &` (no flags) | Not killed: needs an Apple-anchored slice that only strict validation rejects. A byte appended to `/usr/bin/ssh` (after, or inside, its last slice) fails `codesign --strict` but per-slice `SecStaticCodeCheckValidity` accepted it with and without the strict flag, so no fixture distinguishes them. |
| `218:32 + with -`, `+ with *` (read bound 64 MiB + 1) | Not killed: distinguishing needs an Apple-anchored executable of 64 MiB or more; `macho()`'s own 64 MiB limit (killed) rejects any larger image. |
| `305:8 delete !`, `310:13 == with !=` (`publisher`); `316:5 team_identifier -> Ok(String::new())`, `-> Ok("xyzzy".into())`, `323:19 != with ==`, `324:9 \|\| with &&`, `324:12 delete !`, `326:45 \|\| with &&` (`team_identifier`) | Not killed (new code from #80): reachable only for a Developer ID Application signature that is not Apple's. CI has no signing identity; the release-fixture tests are `#[ignore]` (`VW_RELEASE_SIGNED_FIXTURE`), and an ad hoc signature carries no team identifier, so every such mutant still ends in `UnsupportedImage`. Killing them needs a Developer ID fixture of another team and one of `RELEASE_TEAM_ID`. |

### mod.rs

Pre-campaign: 43 survivors. New kills:
`native_executable_file_properties_each_reject_before_the_image_is_read` (an own
copy of `/usr/bin/ssh`, set-user-ID `/usr/bin/login`, non-executable
`/private/etc/hosts`: each must fail with `UnsafeSource` before the digest/Mach-O
checks) kills `125:9`, `126:9`, `127:9`, `128:9`, `129:9` (`\|\| with &&`) and
`128:21 & with \|`/`& with ^`; `native_supervision_detaches_only_a_live_consumer_to_the_reaper`
kills `316:16 > with ==`/`> with <` (the lost consumer must be reaped, not left a
zombie) and `> with >=` (a completed supervision must not detach PID 0, which makes
the reaper `waitpid(0)` and steal an exited sibling's status). The supervision tests
compare every direct child of the test process before and after a supervision, so
each runs its body in a re-executed copy of the test binary that runs only that
test (`isolated`); in the parallel lib run other tests' children otherwise appeared
in that view (CI run 43176147291). The supervision
fixtures are bounded (liveness ends after 20 s, the fixture server after 10 s) so
that the argument-vector mutants `107:5 -> Ok(vec![])`/`Ok(vec![Default::default()])`
end as caught instead of timeouts.

| Survivor | Classification |
| --- | --- |
| `235:9 available -> true` | Equivalent on every qualified host: `platform::available()` is true on native Apple Silicon (see platform.rs). |
| `448:13 \|\| with &&` (`posix_spawn != 0 && pid <= 0`) | Equivalent under the `posix_spawn` contract: it writes a positive PID exactly on success and leaves the zero-initialised PID on failure. |
| `457:9 Drop for Spawn -> ()` | Not killed: only leaks the spawn attribute and file-action objects (no descriptor is held by them). |
| `504:9 is_finished -> false` | Not killed: the worker owns its sender until `join`, so the thread can finish only by panicking in `run_execution`; no seam induces that. |
| `129:20 > with >=` | Not killed (see footnote ¹): needs a root-owned executable of exactly 64 MiB; `macho()` rejects anything larger independently. (`129:20 > with ==` and `> with <` are caught.) |

### platform.rs

Pre-campaign: 33 survivors. New kills:
`native_process_listing_skips_the_caller_and_holds_every_listed_process` (the
test binary is not "another process" with its own name; a uniquely named probe
placed behind `older / 3 + 64` newer children must still be listed, so a
quarter-sized buffer misses it whether the kernel lists newest or oldest first)
kills `65:27` and `93:32 * with +`. With a fixed 48 children the `93:32` kill
depended on the runner's process count (missed in run 43176132176); the probe makes
it deterministic. The test shares a lock with the isolated supervision copies, which
carry the same binary name; `native_peer_audit_fails_without_a_connected_peer` kills
`224:9`; `native_no_writer_open_never_blocks_on_a_fifo_component` kills
`173:74 \| with &` (dropping `O_NONBLOCK` blocks on a FIFO; the test is bounded).

| Survivor | Classification |
| --- | --- |
| `14:5 available -> true`; `28:18`, `28:64`, `29:25 && with \|\|`; `29:20 != with ==`; `29:75 == with !=` | Equivalent on every host the tests can run on: the binary is aarch64 and `sysctl.proc_translated` returns 0, so the first clause is true; the mutants differ only under translation or a failing `sysctlbyname`. |
| `98:36 / with *` | Equivalent through the only caller: the vector keeps its zero padding, and `other_process_named` skips PID 0. |
| `158:28 \| with ^`, `158:48 \| with ^`, `173:36`, `173:55`, `173:74 \| with ^` | Equivalent: the open flags are disjoint bits (`O_RDONLY` is 0). |
| `158:28 \| with &` | Equivalent: drops `O_DIRECTORY` when opening `/`, which is a directory. |
| `161:12 < with ==` | Equivalent: `-1` then reaches `openat`/`fstat` on an invalid descriptor and fails with `UnsafePath` anyway. |
| `158:48 \| with &` | Not killed: drops `O_CLOEXEC` on the transient `/` descriptor; observable only by a concurrent `exec` while it is open. |
| `161:12`, `176:20`, `201:12 < with <=` | Not killed: differ only when the call returns descriptor 0, i.e. when standard input is closed. |
| `201:12 < with ==`, `205:69 < with >` | Not killed, failure path only: `socket()`/`F_SETFD` on a fresh descriptor do not fail without descriptor exhaustion. |
| `72:67 == with !=` | Not killed: `ESRCH` occurs only when a listed process exits between listing and `proc_pidpath`. |
| `95:20 \|\| with &&` | Not killed: a full buffer needs more than 64 processes started between the two `proc_listpids` calls. |

### producer.rs

Pre-campaign: 11 survivors, 2 timeouts.
`reader_flags_the_first_byte_past_capacity_instead_of_buffering_more` now spells the
capacity from `MAX_IMPORT_BYTES + 4` (it used `CAPACITY` and so followed the mutant)
and kills `21:42 + with *`. `dropping_the_output_closes_the_read_end_while_a_writer_remains`
kills `142:9 Drop -> ()` and is bounded, so `68:9 \|\| with &&` and `68:72 \| with &`
(a blocking read end) fail it instead of hanging the run.

| Survivor | Classification |
| --- | --- |
| `49:21 delete -` (`[-1; 2]` → `[1; 2]`) | Equivalent: `pipe()` overwrites both slots on success and the value is unused on failure. |
| `68:72 \| with ^` | Equivalent: a new pipe's read end never has `O_NONBLOCK`, so `flags ^ O_NONBLOCK == flags \| O_NONBLOCK`. |
| `113:17 delete EINTR arm` | Equivalent: the read end is non-blocking, so `read` never sleeps and cannot return `EINTR`. |
| `162:31 < with <=` | Equivalent: a 4-byte input has length 0 or a length that cannot match, so both forms reject it. |
| `166:17 \|\| with &&` | Equivalent: a zero length (empty JSON) or a length above `MAX_IMPORT_BYTES` is independently rejected by `SecretImport::parse`, which also bounds input at `MAX_IMPORT_BYTES`. |
| `58:16 < with ==`, `< with <=`; `67:14 < with >`; `68:94 < with >` | Not killed, failure path only: `F_DUPFD_CLOEXEC` returns a descriptor ≥ 4 and `F_GETFL`/`F_SETFL` return 0 on a fresh pipe; forcing a failure needs a process-wide `RLIMIT_NOFILE` change in the shared test process. |
| `105:22 > with ==`, `> with >=` | Timeout (not counted as caught): the reader spins at end of file, so the first test that drops an output (`debug_is_redacted`) joins it forever. `reader_flags_the_first_byte_past_capacity_instead_of_buffering_more` bounds its own reader at 10 s, but every other producer consumer joins the spinning thread in the same process. |
