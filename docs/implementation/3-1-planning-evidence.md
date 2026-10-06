# Story 3.1 planning evidence

Planning date: 2026-10-06. The user approved the implementation specification and continued past Checkpoint 1. The findings below record the planning evidence.

## Checkout and dependencies

Worktree: `/home/sixtocantolla/sessions/day-to-day/vaultwarden-bind-ssh-key-fixed-operation`

Branch: `feature/bind-ssh-key-fixed-operation`

Fetched base: `origin/main`, full revision `0c5c1d9a2780132db0c4b313934dbe66716e0851`.

GitHub reports all prerequisite PRs merged into main. Each full merge identifier below was verified with `git merge-base --is-ancestor <revision> HEAD`. No dependency branch is required.

| Story | PR | Merge revision |
|---|---|---|
| 1.1 | #19 | b71af8c31fd31a1ebb2b515210a0582b1bd8bf22 |
| 1.2 | #20 | 91a6a662cdfb6b27edba2ca93cd3735b630a1931 |
| 1.3 | #21 | 5e5941bc3ce19c9437532900e2b530d093eff7e8 |
| 1.4 | #22 | 041c10837c12a9a8d2b92b36eae5c634856bc9cc |
| 1.5 | #23 | fd6b7eb3dea18d686c844189772fb9e5673ec050 |
| 1.6 | #24 | fc226624a722e82997f4a280776399971a96c7b4 |
| 1.7 | #25 | ffd8ed4c434f585b2bcb37b0ca9a8517538be662 |
| 1.8 | #26 | 7a0ebf352c2c8fd68d2fe73da896039e2f6a4e33 |
| 1.9 | #27 | 0ea6c996c2b1c3e5cef9e280667f884e0753e53b |
| 2.1 | #28 | 24ad5d14aa9b72f6e3ddb8cddae34f58335c52d3 |
| 2.2 | #29 | 6081c48764208c1adad03b9d5be31550ff850895 |
| 2.3 | #30 | 0c5c1d9a2780132db0c4b313934dbe66716e0851 |

Tracking discrepancy: issues #6 (1.2), #12 (1.8), and #16 (2.3) remain open despite merged implementation PRs. Other Epic 1–2 story issues are closed. This task does not change issue status.

## Inputs and workflow state

[Issue #17](https://github.com/sixtoad/vaultwarden-cli/issues/17) is open; its discussion contains no comments. Its body delegates acceptance to the story document and preserves the provider-only boundary.

Planning documents were read from `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli` because they are untracked there and absent from main: `docs/stories/3-1-bind-ssh-key-to-fixed-operation.md`, `docs/epics.md`, `docs/architecture/architecture-vaultwarden-access-2026-09-01/ARCHITECTURE-SPINE.md`, `docs/specs/spec-vaultwarden-access/SPEC.md`, and `docs/ux-designs/ux-vaultwarden-access-2026-08-31/.working/approval-flow-examples.md`.

The story's plain-text `Status: ready-for-dev` is not build-spec frontmatter; build step 2 therefore produces a reviewed implementation specification before dispatch. Global epic context and sprint tracking belong to the unrelated Oriel project and were not reused or modified. Vaultwarden context is scoped under `_bmad-output/implementation-artifacts/vaultwarden-cli/epic-3-context.md`. There is no earlier story in this epic.

Build skill rendered successfully exactly once from the shared BMAD project root. Active snapshot: `/home/sixtocantolla/sessions/day-to-day/_bmad/render/bmad-build/day-to-day-d00ae63d9eda/1fb18c5ba28adad60cd9/`. Planning halted at step-02 Checkpoint 1 and the user approved it; implementation and workflow reviews use subagents after that approval. All commits, pushes, and PR creation require later approval of completed implementation evidence.

## Investigation findings

- Existing `CredentialUse`, policy credential drafts, backend eligibility, and launch orchestration assume login credentials. SSH needs a distinct variant and metadata-only eligibility. Existing login eligibility decrypts selected fields and must not be reused for SSH.
- Shared CLI `src/models.rs` accepts numeric 5 or 6 as SSH and constructs an empty SSH body when absent. It is unsuitable for strict eligibility. The provider-private decoder must check actual type 5 and actual SSH object without decrypting keys. [Vaultwarden 1.36.0 cipher source](https://raw.githubusercontent.com/dani-garcia/vaultwarden/1.36.0/src/db/models/cipher.rs) defines type 5 and mandatory encrypted privateKey/publicKey/keyFingerprint fields. No SSH marker convention is defined by the planning contract.
- Current revision projection is version 2 and excludes non-authoritative labels/descriptions. Preserve existing login hashes and absent SSH serialization; hash every SSH authority component in a distinct projection.
- Structured destination fields avoid SCP shorthand and URL ambiguity. Fingerprint validation must decode exactly 32 bytes and enforce canonical SHA256/base64 form. Invalid endpoint, trust, and argument conditions need independent tests.
- Production launch iterates login bindings; an empty SSH iteration must never become an uncredentialed launch. Guard preparation and execution explicitly and persist a redacted terminal outcome when dispatched.
- Browser checks require Firefox, NSS certutil, puppeteer-core and axe-core. The parent found reusable dependencies under `/tmp/vw-story21-ui` and `/tmp/vw-story21-nss`; the completed browser result is recorded in verification evidence.

## Planned verification scope

Activation/persistence; immutable identity and actual item type; endpoint/directory/trust shape and consistency; every prohibited selector at activation and direct/signed admission; generic argument bypasses; normalization equivalence; each authority field's digest change and stale requests/approvals; browser fixed-target/SSH-use rendering; private-key and capability sentinels across persistence, responses, UI, audit, logs and diagnostics; zero private-key resolution/execution during validation and review; existing login regression.

Mutation evidence must include binding/type validation, target and argument restrictions, host trust, revision projections and review fields. Each mutant needs a passing unmodified baseline, a single controlled change, its diff, command, completed exit result and classification. Meaningful survivors require fixes; equivalent claims require evidence. No production inspection APIs solely for tests.
