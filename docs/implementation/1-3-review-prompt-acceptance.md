# Independent acceptance review

Start this review in a fresh session with no conversation history or earlier review results. Use the same model capability as the implementation session. This is read-only: do not edit, stage, commit, push, open a PR, or delegate. Return the findings to the human to paste into the original implementation task. Review the complete supplied diff; do not assume passing tests prove correctness.

Diff: `/home/sixtocantolla/sessions/day-to-day/vaultwarden-provider-session/target/story-1-3-evidence/review-2-all.diff`
Project read access: `/home/sixtocantolla/sessions/day-to-day/vaultwarden-provider-session`
Implementation spec: `/home/sixtocantolla/sessions/day-to-day/vaultwarden-provider-session/docs/implementation/spec-1-3-provider-session.md`

Read the entire implementation spec and every document listed in its frontmatter context, resolving `{project-root}` against the project above. Also read the canonical required sources:

- `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/docs/stories/1-3-unlock-and-lock-provider-session.md`
- `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/docs/architecture/architecture-vaultwarden-access-2026-09-01/ARCHITECTURE-SPINE.md`
- `/home/sixtocantolla/sessions/day-to-day/vaultwarden-cli/docs/specs/spec-vaultwarden-access/SPEC.md`

Check the implementation and tests against every acceptance criterion, constraint, architecture boundary and failure mode. Verify evidence claims without trusting their summaries. Report only actionable discrepancies, with priority, precise file/line, requirement violated, trigger and consequence. Explicitly state if no actionable findings remain. Do not use previous reviewer conclusions as evidence.
