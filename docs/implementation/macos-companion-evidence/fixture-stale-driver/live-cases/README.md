# Isolated stale-authority acceptance

All three cases passed on **2026-10-07 15:47 UTC**, using a fresh loopback-only
provider on a random port for each case. Each used exactly one signed non-TTY
submission from real distinct UID 100007; no admission or decision retries were
performed, except the deliberate consumed-ticket denial replay in its named case.
No Mac endpoint, app configuration, production provider or source code changed.

| Case | API result | Durable result | Signed CLI |
|---|---|---|---|
| [Lock](lock/result.json) | Old approval ticket rejected HTTP409 `stale` after lock | submitted → invalidated; expired; no execution | Exit 1, expired |
| [Agent revocation](revoke-agent/result.json) | Old approval ticket rejected HTTP409 `stale` after agent binding revocation | submitted → invalidated; expired; no execution | Exit 1, unauthorized |
| [Denial replay](replay-deny/result.json) | First denial HTTP200; consumed ticket replay HTTP409 `stale` | submitted → denied; no execution | Exit 1, denied |

Each directory retains `driver.json`, `signed-cli.json`, `durable-audit.json`,
`finished.json`, source/binary hashes in `result.json`, and a verified byte/hash
`manifest.json`. CLI stderr was empty and no synthetic credential markers were
present. All three providers reported cleanup complete and their systemd units
were confirmed inactive. The lock/revocation fixture shutdown reports count zero
periodically observed requests because these cases completed before that observer
sampled the inbox; the signed admissions and canonical durable audits independently
prove the requests existed and were invalidated.

Sequence per case: `tests/companion-acceptance.py prepare 127.0.0.1`, `start ROOT`,
one concurrent `submit ROOT`; await its sole pending durable request, then run
`tests/companion-stale-acceptance.py CASE ROOT REQUEST_ID`, capture the terminal
CLI result and canonical audit, and `stop ROOT`. TLS used the fixture CA,
hostname, TLS 1.2 minimum, exact server leaf pin and enrolled client certificate.
The checked existing binaries were used without a Cargo build or mutation.

These are integrated Linux/API security witnesses. They do not establish a
native Mac UI observation, actual sleep/wake, or completion of overall acceptance.
