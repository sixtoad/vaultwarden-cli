# Story 1.7 mutation classifications

Scoped `cargo mutants --in-place` campaigns used the secure test wrapper and synthetic fixture tests.

| Scope | Result | Classification |
| --- | --- | --- |
| `ChildEnvironment::from_mappings` | 13 caught, 1 unviable, 0 missed | Exact entry and 32-KiB boundary tests fixed the initial five meaningful survivors. The unviable body-replacement mutant cannot compile because `ChildEnvironment` has no `Default`. |
| `run_fixture` / `discard_fd` bodies | 1 timeout, 1 unviable | Replacing `discard_fd` with success retains a pipe writer and deadlocks the 128-KiB dual-stream fixture; timeout is a caught failure. Replacing `run_fixture` with `Ok(Default::default())` is unviable because the result has no default. |
| `run_execution` / live authority | Final campaign: 12 caught, 1 unviable, 5 missed | The five remaining predicate mutations are redundant at the tested finish boundary because `execution_live_current` independently checks closing, revocation epoch and both deadlines immediately before terminal persistence. `claimed_execution_lock_intent_racing_resolution_prevents_launch` and `claimed_execution_rechecks_live_authority_before_terminal_persistence` demonstrate lock, deadline and closure invalidation; no invalidation leaves a `completed` state. |

The broader retry filter also included pre-existing admission and submission predicates outside Story 1.7. Those were kept out of the Story 1.7 classification rather than attributed to this change.
