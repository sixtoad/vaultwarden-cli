# Sanitized storage acceptance evidence

See [the execution report](../secret-storage-acceptance.md) for conclusions and limitations.

- `provenance.json` and `native-sha256.txt`: exact baseline, uncommitted harness source hashes and installed executable hashes.
- `initial.json`, `denied.json`, `consumed.json`, `interrupted.json`: actual vault inventory, write counts, receipts and execution observations.
- `restarted.json`, `recovered.json`, `reconcile-again.json`, `retarget-rejected.json`, `replay-rejected.json`: durable recovery and no-repeat evidence.
- `mac-*.json`: inspected native client outputs, including explicit stale rejection; these are automated decisions, not human UI acceptance.
- `earlier-unlock-failures-summary.json`: transcript-derived failure summary; the first raw native error payload was discarded and is not reconstructed.
- `measured-restart-unlock.json`: unchanged-source restart/unlock succeeded in 2.297 seconds; does not explain the prior failures.
- `redaction-scan.json`: bounded scan of 39 captured files against ten known secret values and auth patterns.
- `cleanup.json`, `cleanup-extra.json`: identity-checked cleanup and additional absence/keychain checks.
- `final-proxy-counts.json`: complete final measured backend request counts.

No passwords, bearer tokens, client secrets, session keys, signing seeds, approval tickets or raw private setup files are included.

- `environment-after-run.json`: installed tool versions and cached image digest observed after cleanup; not a recovered container-image attestation.
- `mac-keychain-final-audit.json`: independent post-campaign absence of acceptance keychain entries and directories.
- `post-review-validation.json`: focused validation and cleanup of later test-only guard fixes; the original campaign was not rerun.
