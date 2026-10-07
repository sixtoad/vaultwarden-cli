# Story 3.2 CI namespace follow-up

Baseline: `b27e8fd0d321e83299373bc3920e2a4170159415`. Date: 2026-10-07.

## Observed failure

[Run 37609162977](https://github.com/sixtoad/vaultwarden-cli/actions/runs/37609162977) failed both Real systemd jobs, on Ubuntu 24.04 x86_64 and ARM. Both completed all 39 supervision scenarios (two integration tests passed), then failed `distinct_agent_principals_cannot_read_live_provider_material`. The nested Python process raised `PermissionError: [Errno 1] Operation not permitted` at `os.setgroups([])`, before attempting access to either private file. This is a fixture privilege-transition failure, not a successful unauthorized material read.

The systemd job did not provision the namespace prerequisites already configured by the passing Real agent transport jobs. The exact Ubuntu restriction is not isolated by the logs, but the omitted setup includes uidmap/Python, subordinate UID/GID ranges and the Ubuntu AppArmor unprivileged-userns adjustment. The full failed logs are preserved in `3-2-evidence/ci-systemd-initial.log.gz` (SHA256 `dad3056970a85db080780d18dec8801d126682265feedb516e263014257188d9`).

## Change and review

The systemd job now mirrors that established setup on both architectures. A bounded preflight clears supplementary groups, changes to mapped UID/GID 8 and 10, and verifies the resulting identities before starting the manager or compiling. The job still runs as the non-root runner account. No production code, security assertion, namespace mapping oracle or test selection changed; no failure is converted into a skip.

The implementation subagent made the workflow-only patch. Parent reviewed the complete diff and independently parsed YAML, checked every systemd shell block with `bash -n`, and executed the exact two-principal preflight successfully. The reviewed workflow SHA256 is `bb5ec4599a60cb1b610425d20ccd02cfa9a60d1d319572835f1531c47752e56a`.

Local infrastructure already has uidmap/subordinate mappings and supports these transitions. Its AppArmor restriction sysctl is absent, so local success alone cannot establish that the Ubuntu-hosted failure is resolved; the updated GitHub jobs are the decisive check. This follow-up changes CI prerequisites only; the prior 31 security mutation results remain historical evidence against unchanged production/test source.

## Local verification history

The first complete follow-up run exited 101 after 91.08 seconds, reporting one passed and one failed integration test. It reached `app-ssh-lock`; the outer harness reported a barrier deadline with stage `recovered`. The retained provider journal identifies the actual earlier failure: after `f.app.lock()` succeeded, the independent `/proc` inventory assertion at `src/adapters/supervisor/real_tests.rs:1150` received `CleanupUncertain`. It did not report a remaining descendant (`Ok(false)`). The exact inventory ambiguity is not diagnosed: the scan can fail closed on filesystem errors, unstable process identity, missing cgroup information or exhausted budget. This local failure is separate from the hosted jobs' `setgroups` permission error and is not counted as a pass.

With unchanged source, the isolated principal check passed one test in 1.44 seconds and the isolated `app-ssh-lock` scenario passed one test in 5.12 seconds. The complete rerun exited 101 after 93.37 seconds, again reporting one passed and one failed integration test, this time at the `app-ssh-cancel` outer barrier. Neither full local follow-up run is counted as a pass. The targeted namespace preflight and material-principal check passed; hosted Ubuntu jobs must verify the CI prerequisite change.

Local command records, exact output, source hashes, preflight, workflow diff and first-failure diagnostic journals are retained in `3-2-evidence/ci-followup-local.tar.gz` (SHA256 `b68703df5017e01f2612edfd12f6879a728afadea96ba7bea0f3e29233f2ea58`). No production or test source changed from the previously verified commit.

The second provider journal confirms the same post-acknowledgment scan failure at `real_tests.rs:1150`: cancellation returned successfully, then `proc_empty()` returned `CleanupUncertain`. Its journal is `3-2-evidence/ci-cancel-scan-failure.log.gz` (SHA256 `0c97d7207d67a94e78c2c059631cbba8014edc988eb161ab197959bc85f57ca1`). The exact scan ambiguity remains unidentified.
