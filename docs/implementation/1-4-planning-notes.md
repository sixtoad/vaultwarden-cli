# Story 1.4 planning evidence and design

## Workflow and dependency baseline

- Worktree: `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli-story-1-4`.
- Branch: `feature/one-time-human-direct-request`.
- Fetched `origin/main` baseline: `5e5941bc3ce19c9437532900e2b530d093eff7e8`.
- [Story 1.1 PR #19](https://github.com/sixtoad/vaultwarden-cli/pull/19), [Story 1.2 PR #20](https://github.com/sixtoad/vaultwarden-cli/pull/20), and [Story 1.3 PR #21](https://github.com/sixtoad/vaultwarden-cli/pull/21) are merged into this baseline. No dependency branch is needed. Issue #6 remains open despite merged implementation; issues #5 and #7 are closed.
- [Issue #8](https://github.com/sixtoad/vaultwarden-cli/issues/8) is open and has no discussion comments. Its body delegates acceptance to the story and requires provider-only secrets and redacted responses. Dependency issues also have no comments.
- The first two skill invocations failed because the renderer was sought inside the planning checkout. The current invocation successfully rendered from the actual BMAD installation root, `/home/sixtocantolla/sessions/day-to-day`, without changing the working directory.
- Current workflow snapshot: `_bmad/render/bmad-build/day-to-day-d00ae63d9eda/1fb18c5ba28adad60cd9/` under that installation root. Steps 1–2 require investigation, a draft spec, resolving open questions, and human checkpoint 1 before implementation.
- Draft spec: `/home/sixtocantolla/sessions/day-to-day/_bmad-output/implementation-artifacts/spec-1-4-submit-one-time-human-direct-request.md`.
- Shared `epic-1-context.md` and `sprint-status.yaml` belong to Oriel. Do not consume or update that unrelated sprint's identically numbered story. Project-specific context was compiled by a subagent at `_bmad-output/implementation-artifacts/vaultwarden-cli/epic-1-context.md`; its expected heading and nonempty contents were verified.
- No applicable `AGENTS.md` was found. The new worktree was clean at creation. The original planning checkout's untracked documents remain untouched.

## Required sources and continuity

The following canonical documents are absent from merged main and were read from `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/`:

- `docs/stories/1-4-submit-one-time-human-direct-request.md`
- `docs/epics.md`
- `docs/architecture/architecture-vaultwarden-access-2026-09-01/ARCHITECTURE-SPINE.md`
- `docs/specs/spec-vaultwarden-access/SPEC.md`
- `docs/ux-designs/ux-vaultwarden-access-2026-08-31/.working/approval-flow-examples.md`

Completed Story 1.2's spec and merged Story 1.3's `docs/implementation/spec-1-3-provider-session.md`, planning notes, review changes and test evidence supply continuity. Preserve policy positional arguments, approved-image registry, stable writer lock and atomic durable replacement. Preserve Story 1.3's authority mutex, suspend-aware clock, cleanup poison, closing gates, TLS identity, independent browser proof, bounded workers and shutdown ordering. Historical test counts are not evidence for this story.

Older UX examples show an actual username and script terminology. The canonical contract and explicit request govern: display credential labels/use types without resolved values and display executable identity digests. Do not implement script execution.

## Investigation conclusions

Three subagents compiled epic context and independently investigated core/persistence and UI/desktop boundaries. Planning has identified a cohesive feature across core, transport, UI and persistence. There are no deploys, account changes, real credential operations or irreversible production actions in this work. The implementation introduces durable request metadata, direct-human transport and redacted view contracts used by later stories. No implementation is authorized until checkpoint 1.

### Human transport and command behavior

The architecture already places provider and human in the desktop/session UID and agents in different restricted UIDs. Use a private Unix socket inside the provider's checked `0700` directory, with mode `0600`. Authenticate the connection using Linux kernel `SO_PEERCRED` before decoding; require the provider UID and derive the `local human terminal` identity internally. The client must also validate the server/socket boundary. Repeat admission and ownership checks for status. A caller-supplied label, UID, creation time, expiry, request ID or browser token is not an authority field.

Use narrow versioned human request/status envelopes with unknown-field rejection, length/time limits and stable redacted errors. Do not activate generalized agent protocol, pairing or signature paths from Epic 2. CLI parser failures must not echo rejected input values.

Existing policy describes ordered `Target`, `Choice` and `Integer` values, with no argument names. Use `vw-access request <operation> [--revision <digest>] -- <ordered values>`. If revision is absent, the provider selects the active revision; if supplied, exact mismatch rejects before creation. No policy-inspection API is needed. `status <id>` returns safe state; request waits by default, with a documented no-wait option. Client disconnection never grants authority or causes automatic resubmission.

### Core records, time and status

`ProviderApplication::gate` and `admit` govern usable session authority. `Provider::lock_state` is startup-only metadata and remains Locked even when the application session is usable; do not gate direct admission on that field. Reuse provider policy reloading and store integrity validation without trusting legacy caller-created `AccessRequest` timestamps or identity.

Normalize valid integers to canonical decimal, preserve ordered values and exact target/choice bytes, and hash a versioned normalized argument projection. Validate unknown operation, malformed/excess/unknown arguments, target constraints and explicit revision independently before generating/persisting a request or contacting the desktop. Generate IDs with the existing 32-byte CSPRNG implementation. Recheck admission after slow checks and before durable creation/launch.

Add validated typed metadata to schema-v1 request records compatibly; preserve legacy `{id,status}` records as ownerless and never actionable. Validate new record ID, owner, policy binding, normalized digest, timestamps, lifecycle and closed outcome fields. Preserve the existing stable lock inode, private atomic replacement, directory sync, validated reload and poison-on-uncertain-write safeguards. Tests must include old state and corrupt new records; no silent authority reconstruction from defaults.

Provider Unix time supplies display/persistence timestamps. Suspend-aware monotonic deadlines enforce expiry even when wall time moves backward. The human selected a five-minute default request lifetime; it remains provider-configurable and clients cannot choose expiry. Poll and timer paths must expire pending requests even with no active client. Lock/session expiry/restart/shutdown invalidate unexecuted requests and request-launch capabilities; re-unlock cannot revive them. Preserve valid terminal status while locked. No audit-retention policy or destructive pruning is added in this story.

Use a new closed redacted direct status projection rather than the older `Failed { message: String }` shape. Support Pending, Approved, Denied, Expired, Running, Completed and Failed with only allowed exit codes/closed failure categories. Map existing Invalidated to Expired. Test future lifecycle outcomes with fixtures rather than adding public decision/execution setters.

### Desktop and review boundary

Reuse literal `127.0.0.1`, trusted HTTPS identity, private launch artifacts, random 256-bit one-use exchange, Secure/HttpOnly/SameSite=Strict cookie, session-bound CSRF and launch-issued independent browser proof. Keep `/` a generic shell; retrieve review data only with both valid session and proof, never through cookie-only GET.

On accepted requests, generate a bounded request-scoped capability and private `0600` artifact inside the checked provider directory. Invoke a fixed trusted desktop launcher with only the artifact path, never the URL/capability, in its arguments. Null launcher standard streams and use only trusted provider desktop configuration. The artifact navigates to the loopback URL with capability in its fragment; remove the fragment before exchange. Do not let client fields choose launcher, URL, path or environment.

Consume each capability once, bind it to its request/epoch/deadline, and preserve existing valid browser sessions when another request opens. Return independent proof only after valid capability exchange. Bound sessions/capabilities and clean stale artifacts. Request expiry/lifecycle invalidation revokes unconsumed request capabilities without removing the ability to read terminal status through an otherwise valid human browser session. Launch failure must leave no reusable capability; persist and report a closed redacted review-unavailable outcome. Launcher success proves desktop handoff, not human viewing.

Render ID, authenticated requester, operation/effect, target, permitted arguments, credential labels/use types, executable/policy digests, expiry and one-time meaning using safe DOM text. Do not include immutable item IDs, environment mappings or resolved values. Add visible focus, semantic headings, programmatic names, keyboard controls and an atomic live status region. Review/status is read-only: no enabled Deny/Approve controls or decision handlers until Story 1.5. Explain this stage truthfully; do not simulate a successful approval or execution.

## Verification plan

- Finish formatting, the complete all-targets suite, repository CI clippy checks, and `git diff --check` before independent workflow review.
- Test actual private Unix transport and HTTPS paths with synthetic backends and isolated keyring fixtures. Negative cases each start from an otherwise valid request and alter one condition; assert specific rejection plus absence of durable records and desktop calls.
- Cover accepted CSPRNG ID shape, normalized digest vectors, client-time rejection, exact expiry, suspend/clock rollback, ownership, store failure, launch failure, lifecycle races, terminal immutability and compatibility.
- Cover launch replay, cookie flags, independent session proof, exact Host/Origin, CSRF mismatch/absence, hostile metadata escaping, stale epochs and no URL/token/credential/output disclosure through client, logs or public page.
- Check real Firefox keyboard-only navigation, computed visible focus, accessible names/roles, text/live announcements and status through expiry. Add automated accessibility auditing where supported. Report automated coverage separately from a manual screen-reader exercise.
- Existing disposable browser tooling is available at `/tmp/vw-story13-browser/check-iteration3.mjs` with `puppeteer-core`, Firefox and NSS `certutil` under `/tmp/vw-story13-nss/`. Only a disposable profile may trust synthetic fixture CA; preserve `acceptInsecureCerts:false`. Keep reproducible new browser harness/tests in the worktree, rather than relying solely on old `/tmp` scripts. `axe-core` was not present during investigation.
- Scope cargo-mutants to all changed security-sensitive function bodies and touched constants, including unchanged lines within changed functions. Save exact commands, complete raw results, source fingerprints and per-mutant classifications. Fix meaningful survivors and rerun affected verification. An uncovered mutant is not an equivalent; compiler rejections and timeouts have separate dispositions. Prior-story results do not certify modified logic.
- Wait for every required run to finish. Then invoke workflow-directed reviews, address findings, rerun affected complete checks and present AC mapping, exact results, classifications and limitations at the human implementation checkpoint. No commit/push/PR before that approval.

## Planning state

Investigation is complete and the human selected a five-minute default request lifetime. No open questions remain. The human approved the spec at checkpoint 1 and authorized implementation to continue in this session. Commit, push and PR creation remain prohibited until approval of completed implementation and test evidence.
