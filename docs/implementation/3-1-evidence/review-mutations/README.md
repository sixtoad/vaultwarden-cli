# Post-review SSH mutation checks

Three additional single-change mutants were killed against the final review fixes. The original campaign remains 52 killed; combined result is **55 killed, zero unresolved survivors or equivalent claims**.

| Mutant | Observed failure |
|---|---|
| HTTP decoder forwarding forced to `true` | Named production-backend negative test fails on the isolated wrong-ID response: `Ok(true)` versus `Ok(false)` |
| Pending SSH explanation changed to ordinary execution promise | Browser fails exact `One-time meaning` assertion, showing the incorrect promise |
| Approved SSH status changed to awaiting execution | Browser fails the exact unavailable-status wait at `direct-request.mjs:409`; this is the expected assertion deadline, not a campaign timeout |

The unmodified backend-negative test (one test) and complete Firefox baseline passed. [Results and expected assertions](results.json), [plan](plan.json), [summary](summary.json) and the historical [runner](run.py) record classification. Parent inspected the exact failure logs, not only the runner exit codes.

The source and Cargo target directory were both isolated under `/tmp/vw-story31-review-mutations`. Dependency artifacts were seeded using independent ordinary copies; own-package artifacts and incremental state were excluded. No hardlinks or shared mutable build state were used. Every case restored the exact source manifest, and the final manifest matches the root source. [Per-case evidence](case-evidence.tar.gz) retains patches, commands, timing, logs and all source/restoration hashes; its checksum is in `archive.sha256`.
