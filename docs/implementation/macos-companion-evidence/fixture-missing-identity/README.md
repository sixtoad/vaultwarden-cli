# Missing-identity acceptance helper

The exact parent-reviewed Swift helper compiled on the authorized Mac with `xcrun swiftc`; exit 0 and identical source SHA256 before/after. See [compilation result](compile-results.json), [compiler log](compile.log), and [exact helper source](preference-check.swift). No compilation fix was needed.

Compilation itself did not execute any helper mode, access preferences or change app lifecycle/permissions. The later bounded check is recorded below. The binary is `/tmp/vw-companion-identity-check.egccmf/preference-check`.

Modes are `backup`, `break-identity`, `restore`, and `check`, each followed by the private backup-directory path. Writing modes require every ApprovalCompanion process stopped. Only `providerConfiguration.v1` in the companion preference domain is backed up and modified; the Keychain remains untouched. Output contains hashes/booleans rather than configuration or identity-reference bytes. The backup directory must be new for `backup`; subsequent modes verify ownership, permissions, file types and backup hashes.

After normal app startup, JSON reserialization may change bytes while preserving the exact decoded configuration and identity reference. Restoration checks exact original bytes before relaunch and semantic equality afterward. Unexpected operator configuration changes cause restoration to fail rather than being overwritten. Parent coordinates execution and records provider/operator acceptance separately.

## Bounded installed-app check and restoration

After the operator closed the app, backup mode verified the exact original configuration at 15:25:36 UTC. At 15:26:54 only its opaque identity reference was replaced with a nonempty invalid marker; the actual Keychain identity was unchanged. The app stayed closed through the independent pending-request expiry check.

The unchanged signature-verified installed binary launched as PID 68740 at 15:31:54 UTC. A read-only semantic check proved it was using the invalid reference. Parent independently observed zero provider HTTP commands at 15:32:33 UTC. Operator observation of the temporary UI state had not arrived when restoration began, so it is not claimed here.

At 15:33:29 UTC only verified PID 68740 was sent SIGTERM. After process absence was confirmed, helper restoration wrote and verified the exact backup bytes (SHA256 `c6122d912fce32c412e975c9b713b197bb6a8edc2c61824af535179e3da78a33`). The same installed binary reopened as PID 69135. Its postlaunch check verified the complete original configuration and identity reference, with no test substitution remaining. Startup JSON reserialization changed byte order as expected; exact restoration before launch and semantic restoration afterward are recorded separately.

No Keychain item, OS permission, trust setting or unrelated preference was changed. The private configuration backup remains only in the task-private Mac directory; repository evidence contains hashes/booleans, not the blob or reference. Parent records authenticated-read recovery and any later operator observation.

[Backup](backup-result.json), [substitution](break-identity-result.json), [invalid launch](invalid-identity-launch-result.json), [exact/semantic restoration](restore-result.json).
