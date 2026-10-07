# Story 3.2 planning evidence

Planning date: 2026-10-06. The user approved bmad-build Checkpoint 1 and continued on 2026-10-07.

## Checkout and inputs

- Worktree: `/home/sixtocantolla/sessions/day-to-day/vaultwarden-ssh-ephemeral-provider-material`.
- Branch: `feature/ssh-ephemeral-provider-material`.
- Fetched `origin/main` and worktree baseline: `fcc1bf3bb2977457572383d6da879e8c23a660ee`.
- [Story 3.1 PR #31](https://github.com/sixtoad/vaultwarden-cli/pull/31) is merged at that baseline; its source head was `eccdb3d2fb39c38da3decce7fb07e9a89cd52d41`. Ancestor check passed.
- [Story #18](https://github.com/sixtoad/vaultwarden-cli/issues/18) and [parent epic #4](https://github.com/sixtoad/vaultwarden-cli/issues/4) were read through GitHub CLI. Both are open and have no comments. The story delegates acceptance to the supplied story document.
- The existing source worktree has untracked planning documents. No Story 3.2 branch/worktree existed. Those documents and all other worktrees, including the macOS companion, were preserved.
- Read the supplied `vaultwarden-cli/docs/stories/3-2-execute-ssh-with-ephemeral-provider-material.md`, referenced `docs/architecture/architecture-vaultwarden-access-2026-09-01/ARCHITECTURE-SPINE.md`, and `_bmad-output/implementation-artifacts/vaultwarden-cli/epic-3-context.md` from the shared workspace.
- Read the completed Story 3.1 build spec, `docs/implementation/3-1-policy-contract.md`, verification report, exact final command results, mutation report, and relevant application, execution, supervisor and backend ports.

The story has prose `Status: ready-for-dev`, not build-spec frontmatter. The workflow therefore requires investigation, a generated implementation spec and Checkpoint 1 approval before dispatch. The renderer ran successfully exactly once from the shared BMAD root. Snapshot: `_bmad/render/bmad-build/day-to-day-d00ae63d9eda/1fb18c5ba28adad60cd9/`.

Shared sprint tracking belongs to Oriel, including a different Story 3.2. It must not be updated for this work. No applicable AGENTS.md was found in workspace ancestry or the new worktree.

## Continuity and verification requirements

Story 3.1 deliberately denies SSH at the common execution-authority boundary, before image preparation, secret resolution or launch. Its policy binds one immutable actual type-5 SSH-key item, fixed executable image, working directory, host/port/user/resource and SHA256 host fingerprint. It accepts no caller argument values or generic SSH selectors. Login revision formats remain compatible. Its UI explicitly says SSH execution is unavailable; that copy and its tests need updating with execution support.

The execution profile remains a reviewed self-contained ELF image executed from its verified descriptor. Process supervision reports workload outcome separately from `CleanupEvidence::{NotStarted, Reaped, Uncertain}`. Manager stop/reap and durable lease recovery precede accepting cleanup as complete. Existing application cancellation, revocation, exact approval and signed request ownership must survive the SSH extension.

Historical Story 3.1 final evidence records twenty successful commands: each all-target configuration reported 966 passed, 0 failed and 14 ignored, plus 13 benchmark smoke checks. These include 71 live-backend tests that return early without credentials; repeated configurations are not distinct-test counts. Real mapped-UID transport ran explicitly (1 passed), as did real systemd supervision (2 passed). The combined scoped mutation result was 55 killed with no unresolved survivors. These are predecessor evidence, not Story 3.2 results.

The prior campaign exposed stale mutant binaries through a shared Cargo target directory. Story 3.2 must isolate normal and mutation build artifacts and verify source restoration; source hashes alone are insufficient to establish a clean executable.

## Infrastructure preflight

Rust stable and 1.88.0 toolchains, `unshare`, UID/GID mapping helpers, systemd-run, Node, C/Clang and OpenSSH tools are installed. The sandbox denies user-bus access. An approved execution outside the sandbox returned `running` from `systemctl --user is-system-running`; mapped-UID `unshare --user --map-auto --map-root-user --fork /usr/bin/true` exited 0. These are infrastructure checks only, not process-supervision or cross-principal acceptance tests.

Implementation verification must run the required regression configurations, explicit real supervision and cross-principal scenarios, and scoped materialization/cleanup/interlock/disclosure mutations. Retain exact commands, logs, source manifests, test counts, named failing mutation assertions, survivors, skips and infrastructure failures. No unavailable check counts as a pass. No live credentials are needed for synthetic fixtures.

At the planning checkpoint no implementation, commit, push, PR creation or deployment had occurred.

## Host-key decision

On 2026-10-07 the user selected operator-provisioned public host keys. The provider will load them from provider-private storage, verify the exact destination host/port and policy-approved SHA256 fingerprint, then generate request-local pinned `known_hosts`. Missing or mismatched keys fail closed. No automatic acquisition or policy migration is planned. The spec records this decision; its Open Questions section is resolved. The user subsequently approved the spec with “Approved and continue”.

## Implementation handoff

The approved spec was reread before its status advanced through `ready-for-dev` to `in-progress`; its frozen intent is unchanged. Baseline remains `fcc1bf3bb2977457572383d6da879e8c23a660ee`. A fresh implementation subagent received the workflow's exact spec-only handoff. Implementation runs sequentially; parent verification and scoped mutations follow a stable source handoff. Normal and mutation build directories are isolated. No commit, push, PR or deployment is authorized yet.
