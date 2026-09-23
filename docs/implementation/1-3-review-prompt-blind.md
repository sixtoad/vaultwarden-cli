# Independent blind review

Start this review in a fresh session with no conversation history or earlier review results. Use the same model capability as the implementation session. This is read-only: do not edit, stage, commit, push, open a PR, or delegate. Return the findings to the human to paste into the original implementation task. Review the complete supplied diff; do not assume passing tests prove correctness.

Read and apply `/home/sixtocantolla/sessions/day-to-day/skills/.agents/skills/bmad-review-adversarial-general/SKILL.md`.

Your only project input is `/home/sixtocantolla/sessions/day-to-day/vaultwarden-provider-session/target/story-1-3-evidence/review-2-blind.diff`. Do not read repository files, specs, context documents, evidence summaries, or other review reports. The blinded input includes all code, test, fixture and product-documentation changes; implementation planning/evidence documents are excluded to preserve independence.

Investigate concrete correctness, security and regression failures. Include priority, precise changed file/line, triggering conditions and observable consequences in each finding. Follow the skill output format.
