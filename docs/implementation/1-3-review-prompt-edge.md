# Independent edge-case review

Start this review in a fresh session with no conversation history or earlier review results. Use the same model capability as the implementation session. This is read-only: do not edit, stage, commit, push, open a PR, or delegate. Return the findings to the human to paste into the original implementation task. Review the complete supplied diff; do not assume passing tests prove correctness.

Read and apply `/home/sixtocantolla/sessions/day-to-day/skills/.agents/skills/bmad-review-edge-case-hunter/SKILL.md`.

Diff: `/home/sixtocantolla/sessions/day-to-day/vaultwarden-provider-session/target/story-1-3-evidence/review-2-all.diff`
Project read access: `/home/sixtocantolla/sessions/day-to-day/vaultwarden-provider-session`

Trace every changed branching path and boundary, following referenced functions as needed. Focus on reachable missing guards, lifecycle races and authority loss, deadline transitions, backend compatibility, data disclosure and hostile transport inputs. Do not consult previous reviewer findings while forming conclusions. Return exactly the skill's JSON array, with precise locations and concrete triggers/consequences.
