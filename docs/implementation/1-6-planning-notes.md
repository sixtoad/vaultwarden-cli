# Story 1.6 investigation and verification plan

Planning checkpoint approved on 2026-09-25. This records the approved investigation and
plan; completed results and remaining limitations are in [test evidence](1-6-test-evidence.md).

## Baseline and dependencies

- Worktree: `/home/sixtocantolla/sessions/day-to-day/vaultwarden-exact-protected-executable`
- Branch: `feature/verify-exact-protected-executable`
- Updated main: `fd6b7eb3dea18d686c844189772fb9e5673ec050`
- [Issue #10](https://github.com/sixtoad/vaultwarden-cli/issues/10) is open and has no comments as checked on 2026-09-24.

| Dependency | Merged PR | Merge commit |
|---|---|---|
| 1.1 provider foundation | [#19](https://github.com/sixtoad/vaultwarden-cli/pull/19) | `b71af8c31fd31a1ebb2b515210a0582b1bd8bf22` |
| 1.2 constrained operation | [#20](https://github.com/sixtoad/vaultwarden-cli/pull/20) | `91a6a662cdfb6b27edba2ca93cd3735b630a1931` |
| 1.3 provider session | [#21](https://github.com/sixtoad/vaultwarden-cli/pull/21) | `5e5941bc3ce19c9437532900e2b530d093eff7e8` |
| 1.4 human direct request | [#22](https://github.com/sixtoad/vaultwarden-cli/pull/22) | `041c10837c12a9a8d2b92b36eae5c634856bc9cc` |
| 1.5 exact one-time decision | [#23](https://github.com/sixtoad/vaultwarden-cli/pull/23) | `fd6b7eb3dea18d686c844189772fb9e5673ec050` |

All five implementations are present in main. No dependency branch is required.
The new worktree was clean before adding these planning files. Existing untracked
planning files in the original checkout were left intact.

Canonical planning files are absent here; use their originals under
`/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/`:

- `docs/stories/1-6-verify-exact-protected-executable.md`
- `docs/epics.md`
- `docs/architecture/architecture-vaultwarden-access-2026-09-01/ARCHITECTURE-SPINE.md`, especially AD-14–AD-18
- `docs/specs/spec-vaultwarden-access/SPEC.md`

Continuity: the completed Story 1.5 spec and checked-in test evidence establish
atomic approval, serialized durable state, authenticated requester binding,
provider-clock deadlines, and terminal immutability. Keep the configurable
five-minute request lifetime. Shared sprint-status belongs to Oriel, so its
numerically matching Story 1.6 must not be changed.

## Integration decisions

`ProviderApplication::Authority` owns live session authority through the mutex,
deadline, cleanup status, generation and closing flag. `Provider.lock_state`
is a startup representation and remains Locked; do not use it for execution
admission. Reuse `admit`, `expire_requests` and `commit_decision` patterns.

Add an approved-request counterpart to `Provider::prepare_direct` and
`decision_policy`, which currently require Pending. Revalidate exact persisted
approval binding, owner, epoch, Approved status, active policy, canonical
arguments and policy-derived target. Check authority before and after slow image
preparation, compatibility probing and each credential-eligibility call. Recheck
the durable binding before reporting preparation success. No secret resolution
or production child creation occurs in this story. A prepared image is not
approval authority; keep it internal and noncloneable. Story 1.7 must consume
approval atomically and revalidate before actual dispatch.

Extend private image bindings with an explicit execution root and versioned
self-contained static executable profile; include every authority-bearing field
in revision hashing and registry/policy equality. Legacy images must not silently
acquire this declaration: require re-provisioning, fail closed, preserve empty
default state and do not rewrite existing user data automatically.

Current policy integrity checks reopen and hash image paths during state reads.
They are preliminary checks only and cannot certify execution. Keep filesystem
execution mechanics in the adapter. Avoid a broad unrelated persistence refactor.
Existing fixtures use mode 0700 and weak ELF headers; update affected fixtures
deliberately, and directly test adapter guards so store validation cannot mask
missing execution checks.

## Exact image and supported closure

1. Traverse the absolute execution-root ancestry and every image-relative
   component using checked directory descriptors, never a check-then-open
   pathname sequence. Reject symlinks, invalid path components and escape.
   Require provider ownership of the execution root, descendants and image;
   system ancestors may be root-owned. Require root and descendant directories
   to be private mode 0700; ancestors must belong to root or the provider and
   have no group/other write or special bits. Do not allow sticky-directory
   exceptions. Test fixtures must use a secure parent rather than `/tmp`.
2. Inspect the opened source: regular file, expected UID, owner read/execute,
   no owner/group/other write bits and no setuid/setgid/sticky bits. Bound image
   size and parsing work; FIFOs/devices must not block preparation. Check source
   metadata around copying without treating metadata stability as immutability.
3. Copy the checked source into a private executable memfd, set restrictive
   permissions, and require WRITE/GROW/SHRINK/EXEC/SEAL seals. Read back seals.
   Hash and parse the final sealed object, comparing its SHA-256 to policy.
   This sealed descriptor is the verified object retained through execution;
   no source pathname is reopened to execute. Merely hashing a source before
   copying would leave the in-place-write race unresolved.
4. Initially accept native ELF64 ET_EXEC with validated header/table bounds,
   valid load segments and executable entry point. Reject scripts, PT_INTERP,
   PT_DYNAMIC, unsupported architecture/encoding/type, malformed/truncated
   structures, writable executable segments and executable stacks. Static PIE
   and dynamic executables are unsupported by this initial profile.
5. The provider-owned profile declares the pinned artifact has been reviewed
   as self-contained: no interpreter, helper, plugin, runtime-loaded code or
   mutable executable dependency. Structural ELF inspection does not prove
   arbitrary program behavior. A statically linked interpreter is still out
   of scope; do not certify it using its main hash or a filename blacklist.
   Correct operator provisioning is a trust assumption, not an extra runtime
   verification claim. Unknown/missing/unsupported profiles fail closed.
6. Consume the owned descriptor with `execveat(fd, "", argv, envp,
   AT_EMPTY_PATH)` inside an already supervised execution context. Construct
   explicit policy-derived argv and an empty environment for this story;
   reject NULs and excessive sizes before execution. The primitive replaces
   the calling process and does not implement a new production spawn path.
   Keep ProcessSupervisor/systemd ownership separate. Harmless test subprocesses
   exercise the real primitive; production secrets, login execution, stdout
   handling and descendant containment remain Stories 1.7/1.8.

RAII closes all source, directory and sealed descriptors on every error. Error
and Debug output use closed redacted categories; no paths, arguments, raw errno
text, backend values, environment or child output reach diagnostics.

## Authoritative compatibility evidence

- [execveat(2)](https://man7.org/linux/man-pages/man2/execveat.2.html): empty
  pathname plus AT_EMPTY_PATH selects the descriptor. Linux introduced the
  syscall in 3.19; the glibc wrapper arrived in 2.34. A direct libc syscall
  invocation can avoid requiring that wrapper. Scripts have interpreter and
  CLOEXEC pitfalls and are explicitly rejected.
- [memfd_create(2)](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
  and [file seals](https://man7.org/linux/man-pages/man2/F_ADD_SEALS.2const.html):
  require write and size seals; FUTURE_WRITE alone leaves existing writable
  mappings able to alter bytes. EXEC seals require Linux 6.3.
- [Kernel memfd execution policy](https://docs.kernel.org/userspace-api/mfd_noexec.html):
  request executable memfds explicitly. Kernel policy, seccomp or an LSM may
  prohibit them; return execution unavailable without a pathname fallback.
- [openat2(2)](https://man7.org/linux/man-pages/man2/openat2.2.html) and
  [ELF format](https://man7.org/linux/man-pages/man5/elf.5.html) document path
  resolution and executable structures. Descriptor-by-descriptor openat walks
  are also viable when every component is individually validated.
- [Rust 1.88 OwnedFd implementation](https://raw.githubusercontent.com/rust-lang/rust/1.88.0/library/std/src/os/fd/owned.rs)
  provides RAII and File conversions. Never construct OwnedFd from invalid or
  externally closed descriptors; test raw-descriptor errors below that boundary.
- `libc` and `sha2` are already direct dependencies. Locked libc 0.2.189 declares
  Rust 1.65 in its [manifest](https://raw.githubusercontent.com/rust-lang/libc/0.2.189/Cargo.toml).
  Inspect any newly used APIs against Rust 1.88 and declare any added crate directly.

Proposed platform floor is Linux 6.3 with executable memfds and required seals.
Current host: Linux 6.18.7 x86_64, rustc 1.98.1, cargo-mutants 27.1.0, cc and ld
available. The original plan required an actual Rust 1.88 run in addition to
documentation inspection; completed toolchain results are recorded in the test evidence.
Unsupported targets fail closed; evidence distinguishes tested from assumed platforms.

## Required verification and independent failure oracles

Use a harmless self-contained fixture with observable exit/argv/environment
behavior. Test valid preparation and real descriptor-backed execution. Test each
final/ancestor symlink, directory/special file, ownership mismatch, individual
write/special/missing-execute condition, digest mismatch, malformed/unsupported
ELF, unavailable syscall and invalid/closed descriptor independently. Start every
negative from an otherwise valid binding/fixture, with matching digest where the
guard under test is format or metadata. Failed FD tests must not violate Rust
ownership invariants or close unrelated concurrent-test descriptors.

Use private cfg(test) hooks, channels or barriers at open/copy/seal/hash/exec
boundaries. Test both pathname replacement and in-place writes through a writer
opened before permission hardening; include source edits after preparation,
growth/truncation, and direct attempts to mutate sealed bytes. Accept only safe
rejection or execution of the original pinned immutable content. Do not use
sleeps to create a race or add production inspection APIs for these tests.

Application tests cover wrong status, exact binding, owner/epoch, stale policy,
invalid target/arguments, deadline equality, lock/restart/shutdown, failed
compatibility and every credential's eligibility. Exercise invalidation during
slow preparation and backend calls. Rebuild record seals/bindings for semantic
negative tests so an unrelated integrity failure cannot mask a missing check.
Assert zero backend resolution calls and zero protected child launches for every
rejected preparation; separately assert preparation invocation where appropriate.
Validate descriptor cleanup in isolated subprocesses and sentinel-free redacted
Display/Debug output.

Before workflow-directed review, finish:

- `cargo fmt --all -- --check`
- `cargo test --all-targets` (report actual passes, ignored fixtures and live
  account early returns separately)
- real Linux descriptor execution integration tests, explicitly invoking any
  ignored subprocess fixtures through their parent harness
- `cargo +1.88.0 test --all-targets`, or clearly report the exact blocker;
  investigate preexisting MSRV failures separately from changed code
- `cargo clippy --all-targets --all-features -- -D warnings`
- scoped generated mutation tests plus manual mutations covering omitted guards,
  individual mode bits, descriptor/seal failures, digest bypass, path fallback,
  ordering and stale preconditions; fix meaningful survivors and give evidence
  for equivalent mutants, separating compiler rejection/timeouts/infrastructure
  errors from killed mutants
- `git diff --check`, including untracked content through a temporary index

Record exact commands/results, AC-to-test mapping, final source fingerprint,
mutation inventory/classifications, platform assumptions and limitations in
`docs/implementation/1-6-test-evidence.md`. Wait for all checks before declaring
review readiness. Use implementation subagents and workflow-directed review
subagents after plan approval. Stop again for human acceptance of implementation
and evidence. At this planning checkpoint, commit, push and PR creation were not
authorized. After completed implementation, verification and reviews, the user
authorized PR publication on 2026-09-25.
